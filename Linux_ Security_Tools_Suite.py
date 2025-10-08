# multi_tool_gui_hydra_nmap_nc_fixed.py
# 需求: pip install pyqt5
# 執行: python multi_tool_gui_hydra_nmap_nc_fixed.py

import sys, os, shlex, subprocess, shutil
from PyQt5 import QtCore, QtGui, QtWidgets

# ---------------- helpers ----------------
def is_windows(): return sys.platform.startswith("win")
def wsl_available():
    if not is_windows(): return False
    try:
        p = subprocess.run(["wsl", "echo", "ok"], capture_output=True, text=True, timeout=1)
        return p.returncode == 0
    except Exception:
        return False
def command_exists(cmd): return shutil.which(cmd) is not None

# escape single quotes for embedding in single quoted shell strings
def shell_single_quote_escape(s: str):
    # replace ' with '"'"' (the classic POSIX trick)
    return s.replace("'", "'\"'\"'")

# PowerShell mapping (improved ls output)
def build_powershell_command_str(cmd_list):
    exe = cmd_list[0].lower()
    args = cmd_list[1:]
    def q(s): return s.replace('"','\\"')
    if exe in ("ls","dir"):
        path = "." if not args else (args[-1] if not args[-1].startswith("-") else ".")
        ps = (
            f"Get-ChildItem -Force -LiteralPath \"{q(path)}\" | "
            "Select-Object @{Name='Mode';Expression={$_.Mode}},"
            "@{Name='LastWriteTime';Expression={$_.LastWriteTime}},"
            "@{Name='Length';Expression={$_.Length}},"
            "@{Name='Name';Expression={$_.Name}} | Format-Table -AutoSize | Out-String -Width 4096"
        )
        return ps
    if exe == "cat":
        path = args[-1] if args else "."
        return f"Get-Content -Raw -LiteralPath \"{q(path)}\""
    if exe == "whoami":
        return "whoami"
    if exe == "ping":
        cnt = "4"; host = args[-1] if args else "8.8.8.8"
        for i,a in enumerate(args):
            if a.startswith("-") and "c" in a:
                if i+1 < len(args): cnt = args[i+1]
        return f"ping -n {cnt} {q(host)}"
    if exe in ("traceroute","tracepath"):
        host = args[-1] if args else "8.8.8.8"
        return f"tracert {q(host)}"
    if exe in ("dig",):
        host = args[-1] if args else "example.com"
        return f"nslookup {q(host)}"
    return " ".join([q(x) for x in cmd_list])

def build_final_command(cmd_list, use_wsl=False):
    if use_wsl and is_windows():
        return ["wsl"] + cmd_list
    if is_windows() and not use_wsl:
        exe = cmd_list[0].lower()
        external = {"nmap","ncat","nc","hydra","john","hashid","tcpdump"}
        if exe in external and command_exists(exe):
            return cmd_list
        ps = build_powershell_command_str(cmd_list)
        return ["powershell","-NoProfile","-Command", ps]
    return cmd_list

# ---------------- worker ----------------
class CmdWorker(QtCore.QObject):
    output_line = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal()
    started = QtCore.pyqtSignal()

    def __init__(self, cmd_list, encoding="utf-8", use_wsl=False):
        super().__init__()
        self.cmd_list = cmd_list
        self.encoding = encoding
        self.use_wsl = use_wsl
        self._proc = None
        self._stop = False

    @QtCore.pyqtSlot()
    def run(self):
        self.started.emit()
        try:
            full_cmd = build_final_command(self.cmd_list, use_wsl=self.use_wsl)
            self._proc = subprocess.Popen(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding=self.encoding,
                errors="replace",
                bufsize=1
            )
            for line in self._proc.stdout:
                if self._stop: break
                self.output_line.emit(line.rstrip("\n"))
            if self._stop and self._proc.poll() is None:
                try: self._proc.terminate()
                except: pass
            if self._proc:
                self._proc.wait()
        except FileNotFoundError as e:
            self.output_line.emit(f"[ERROR] command not found: {e}")
        except Exception as e:
            self.output_line.emit(f"[ERROR] {e}")
        finally:
            self.finished.emit()

    def stop(self):
        self._stop = True
        try:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
        except: pass

# ---------------- base page ----------------
class ToolPageBase(QtWidgets.QWidget):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.worker = None
        self.thread = None
        self._build_ui()

    def main_window(self):
        w = self
        while w is not None and not isinstance(w, QtWidgets.QMainWindow):
            w = w.parent()
        return w

    def _build_ui(self):
        v = QtWidgets.QVBoxLayout(self)
        self.desc = QtWidgets.QPlainTextEdit(); self.desc.setReadOnly(True); self.desc.setFixedHeight(60); v.addWidget(self.desc)
        form = QtWidgets.QFormLayout()
        self.target_label = QtWidgets.QLabel("Target / Args:")
        self.target_edit = QtWidgets.QLineEdit(); self.target_edit.setPlaceholderText("Target / Args")
        form.addRow(self.target_label, self.target_edit)
        self.use_wsl_ck = QtWidgets.QCheckBox("使用 WSL 執行（Windows 用）")
        form.addRow("", self.use_wsl_ck)
        v.addLayout(form)
        self.extra_widget = QtWidgets.QWidget(); self.extra_layout = QtWidgets.QFormLayout(self.extra_widget); v.addWidget(self.extra_widget)
        h = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("Start"); self.stop_btn = QtWidgets.QPushButton("Stop"); self.stop_btn.setEnabled(False)
        h.addWidget(self.start_btn); h.addWidget(self.stop_btn); h.addStretch(); v.addLayout(h)
        self.progress = QtWidgets.QProgressBar(); self.progress.setTextVisible(False); self.progress.setVisible(False); v.addWidget(self.progress)
        self.output = QtWidgets.QPlainTextEdit(); self.output.setReadOnly(True); v.addWidget(self.output)
        self.start_btn.clicked.connect(self.on_start_clicked); self.stop_btn.clicked.connect(self.on_stop_clicked)

    def start_worker(self, cmd_list):
        mw = self.main_window()
        if not mw:
            self.output.appendPlainText("[ERROR] 找不到主視窗")
            return
        encoding = mw.encoding_combo.currentText()
        use_wsl = self.use_wsl_ck.isChecked()
        self.output.clear()
        self.output.appendPlainText(f"執行: {' '.join(cmd_list)}\n")
        if is_windows() and not use_wsl:
            exe = cmd_list[0].lower()
            if exe in {"nmap","hydra","john","tcpdump","hashid","ncat","nc"} and not command_exists(exe):
                self.output.appendPlainText(f"[WARN] 系統找不到 {exe}；請安裝或改勾 WSL")
        # start worker
        self.progress.setVisible(True); self.progress.setRange(0,0)
        self.worker = CmdWorker(cmd_list, encoding=encoding, use_wsl=use_wsl)
        self.thread = QtCore.QThread()
        self.worker.moveToThread(self.thread)
        self.worker.output_line.connect(self.output.appendPlainText)
        self.worker.finished.connect(self._on_finished)
        self.thread.started.connect(self.worker.run)
        self.thread.start()
        self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True)

    def _on_finished(self):
        self.output.appendPlainText("\n[Finished]")
        self.progress.setVisible(False); self.progress.setRange(0,100)
        self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        if self.thread:
            self.thread.quit(); self.thread.wait(); self.thread = None; self.worker = None

    def on_stop_clicked(self):
        if self.worker:
            self.worker.stop(); self.output.appendPlainText("[Stopping...]"); self.stop_btn.setEnabled(False)

    def on_start_clicked(self):
        raise NotImplementedError

# ---------------- Pages ----------------
class WhoamiPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setPlainText("顯示目前使用者 (whoami)。此頁無需 Target/Args")
        self.target_label.hide(); self.target_edit.hide()
    def on_start_clicked(self):
        self.start_worker(["whoami"])

class LsPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setPlainText("ls：列出目錄內容。Options 可填 -l/-la，Target 為路徑或留空。")
        self.opt = QtWidgets.QLineEdit(); self.opt.setPlaceholderText("-l -la"); self.extra_layout.addRow("Options:", self.opt)
    def on_start_clicked(self):
        opts = self.opt.text().strip(); path = self.target_edit.text().strip() or "."
        parts = ["ls"] + (shlex.split(opts) if opts else []) + [path]
        self.start_worker(parts)

class CatPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setPlainText("cat：程式內讀檔，使用狀態列編碼或自動嘗試多種編碼。")
        self.auto_ck = QtWidgets.QCheckBox("自動嘗試多種編碼 (utf-8 -> cp950 -> gbk)")
        self.extra_layout.addRow("", self.auto_ck)
    def on_start_clicked(self):
        f = self.target_edit.text().strip()
        if not f:
            self.output.appendPlainText("[ERROR] 請輸入檔案路徑"); return
        if not os.path.exists(f):
            self.start_worker(["cat", f]); return
        with open(f, "rb") as fh:
            b = fh.read()
        mw = self.main_window()
        enc = mw.encoding_combo.currentText() if mw else "utf-8"
        s = None
        try:
            s = b.decode(enc)
        except Exception:
            if self.auto_ck.isChecked():
                for e in ("utf-8","cp950","big5","gbk","utf-16"):
                    try:
                        s = b.decode(e); enc = e; break
                    except:
                        s = None
        if s is None:
            s = b.decode(enc, errors="replace")
            self.output.appendPlainText(f"[WARN] 無法用選定編碼完整解碼，使用 {enc} 並替換錯誤字元\n")
        self.output.appendPlainText(s)

class PingPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setPlainText("ping：測試連線 (Count 可設定)。")
        self.cnt = QtWidgets.QLineEdit("4"); self.extra_layout.addRow("Count:", self.cnt)
    def on_start_clicked(self):
        t = self.target_edit.text().strip() or "8.8.8.8"; cnt = self.cnt.text().strip() or "4"
        self.start_worker(["ping","-c",cnt,t])

class NcPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setPlainText("nc：connect 或 listen。若勾選 WSL，會執行 WSL 的 nc。")
        self.target_label.hide(); self.target_edit.hide()
        self.mode = QtWidgets.QComboBox(); self.mode.addItems(["connect","listen"])
        self.host = QtWidgets.QLineEdit("127.0.0.1"); self.port = QtWidgets.QLineEdit()
        self.extra_layout.addRow("Mode:", self.mode); self.extra_layout.addRow("Host:", self.host); self.extra_layout.addRow("Port:", self.port)
    def on_start_clicked(self):
        mode = self.mode.currentText(); h = self.host.text().strip() or "127.0.0.1"; p = self.port.text().strip()
        if not p:
            self.output.appendPlainText("[ERROR] 請輸入 port"); return
        use_wsl = self.use_wsl_ck.isChecked()
        exe = "nc" if use_wsl else ("nc" if command_exists("nc") else ("ncat" if command_exists("ncat") else "nc"))
        if mode == "connect":
            self.start_worker([exe, h, p])
        else:
            self.start_worker([exe, "-l", "-p", p])

class NmapPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setPlainText("nmap：掃描主機/埠。若在 WSL 下並需要 root，可勾 Use sudo 並輸入 WSL 密碼（會以 echo | sudo -S 執行，請注意安全）。")
        self.scan = QtWidgets.QComboBox(); self.scan.addItems(["-sT","-sS","-sU","-sn"])
        self.ports = QtWidgets.QLineEdit(); self.ports.setPlaceholderText("1-1024 or 22,80,443")
        self.extra = QtWidgets.QLineEdit(); self.extra.setPlaceholderText("-A -Pn -T4")
        self.sudo_ck = QtWidgets.QCheckBox("Use sudo (only takes effect if 使用 WSL 執行 勾選)")
        self.sudo_pass = QtWidgets.QLineEdit(); self.sudo_pass.setEchoMode(QtWidgets.QLineEdit.Password); self.sudo_pass.setPlaceholderText("WSL 密碼（只在 WSL + Use sudo 時使用）")
        self.extra_layout.addRow("Scan:", self.scan); self.extra_layout.addRow("Ports:", self.ports); self.extra_layout.addRow("Extra:", self.extra)
        self.extra_layout.addRow("", self.sudo_ck); self.extra_layout.addRow("WSL sudo 密碼:", self.sudo_pass)
    def on_start_clicked(self):
        target = self.target_edit.text().strip()
        if not target:
            self.output.appendPlainText("[ERROR] 請輸入 target"); return
        scan_flag = self.scan.currentText()
        cmd_parts = ["nmap", scan_flag]
        if self.ports.text().strip(): cmd_parts += ["-p", self.ports.text().strip()]
        if self.extra.text().strip(): cmd_parts += shlex.split(self.extra.text().strip())
        cmd_parts += ["-oN","-"] + shlex.split(target)
        # if WSL + use sudo -> wrap in bash -lc "echo 'pw' | sudo -S nmap ..."
        use_wsl = self.use_wsl_ck.isChecked()
        if use_wsl and self.sudo_ck.isChecked():
            pw = self.sudo_pass.text()
            if not pw:
                self.output.appendPlainText("[ERROR] 你勾選了 Use sudo，但未輸入 WSL 密碼"); return
            safe_pw = shell_single_quote_escape(pw)
            # build one-liner for bash -lc
            nmap_cmd_str = " ".join(shlex.quote(p) for p in cmd_parts)
            bash_cmd = f"echo '{safe_pw}' | sudo -S {nmap_cmd_str}"
            # run via wsl -> build_final_command will prefix wsl
            self.start_worker(["bash","-lc", bash_cmd])
            return
        # normal path
        self.start_worker(cmd_parts)

class TraceroutePage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setPlainText("traceroute：追蹤路由 (Windows 下為 tracert)。")
    def on_start_clicked(self):
        t = self.target_edit.text().strip() or "8.8.8.8"; self.start_worker(["traceroute", t])

class DigPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setPlainText("dig：DNS 查詢。+short 可簡短顯示答案。")
        self.short_ck = QtWidgets.QCheckBox("+short 模式 (只顯示簡短結果)"); self.extra_layout.addRow("", self.short_ck)
    def on_start_clicked(self):
        t = self.target_edit.text().strip() or "example.com"
        if self.short_ck.isChecked(): self.start_worker(["dig","+short",t])
        else: self.start_worker(["dig",t])

class CurlPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setPlainText("curl：HTTP(S) 客戶端，常用於檢查 header、狀態碼、模擬表單/下載檔案等。")
        self.method = QtWidgets.QComboBox(); self.method.addItems(["GET","HEAD","POST"]); self.extra_layout.addRow("Method:", self.method)
    def on_start_clicked(self):
        url = self.target_edit.text().strip()
        if not url: self.output.appendPlainText("[ERROR] 請輸入 URL"); return
        m = self.method.currentText()
        if m=="HEAD": self.start_worker(["curl","-I",url])
        elif m=="POST": self.start_worker(["curl","-X","POST",url])
        else: self.start_worker(["curl","-sS",url])

# ---------- Hydra page with conditional UI ----------
# ====== 替換整個 HydraPage 類別 ======
class HydraPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setPlainText(
            "hydra：暴力破解（請在授權環境使用）。\n"
            "選 Service 後會顯示該 Service 所需欄位。User/Pass 可選 Single 或 File（可手動編輯或用 Browse）。"
        )

        # Service 選擇
        self.service = QtWidgets.QComboBox()
        self.service.addItems(["ssh", "ftp", "http-get", "http-post-form"])
        self.extra_layout.addRow("Service:", self.service)

        # User mode radio + stacked UI (Single / File)
        self.user_single_rb = QtWidgets.QRadioButton("Single")
        self.user_file_rb = QtWidgets.QRadioButton("File")
        self.user_single_rb.setChecked(True)
        user_mode_h = QtWidgets.QHBoxLayout()
        user_mode_h.addWidget(self.user_single_rb)
        user_mode_h.addWidget(self.user_file_rb)
        self.extra_layout.addRow("User mode:", user_mode_h)

        self.user_stack = QtWidgets.QStackedWidget()
        # page 0: single
        self.user_single_widget = QtWidgets.QLineEdit()
        self.user_single_widget.setPlaceholderText("username (single)")
        p0 = QtWidgets.QWidget(); p0_l = QtWidgets.QHBoxLayout(p0); p0_l.addWidget(self.user_single_widget)
        # page 1: file (editable!)
        self.user_file_widget = QtWidgets.QLineEdit()    # <--- 可編輯
        self.user_file_browse = QtWidgets.QPushButton("Browse")
        p1 = QtWidgets.QWidget(); p1_l = QtWidgets.QHBoxLayout(p1); p1_l.addWidget(self.user_file_widget); p1_l.addWidget(self.user_file_browse)
        self.user_stack.addWidget(p0); self.user_stack.addWidget(p1)
        self.extra_layout.addRow("User (or file):", self.user_stack)

        # Pass mode radio + stacked UI
        self.pass_single_rb = QtWidgets.QRadioButton("Single")
        self.pass_file_rb = QtWidgets.QRadioButton("File")
        self.pass_single_rb.setChecked(True)
        pass_mode_h = QtWidgets.QHBoxLayout()
        pass_mode_h.addWidget(self.pass_single_rb)
        pass_mode_h.addWidget(self.pass_file_rb)
        self.extra_layout.addRow("Pass mode:", pass_mode_h)

        self.pass_stack = QtWidgets.QStackedWidget()
        self.pass_single_widget = QtWidgets.QLineEdit()
        self.pass_single_widget.setEchoMode(QtWidgets.QLineEdit.Password)
        p0p = QtWidgets.QWidget(); p0p_l = QtWidgets.QHBoxLayout(p0p); p0p_l.addWidget(self.pass_single_widget)
        self.pass_file_widget = QtWidgets.QLineEdit()    # <--- 可編輯
        self.pass_file_browse = QtWidgets.QPushButton("Browse")
        p1p = QtWidgets.QWidget(); p1p_l = QtWidgets.QHBoxLayout(p1p); p1p_l.addWidget(self.pass_file_widget); p1p_l.addWidget(self.pass_file_browse)
        self.pass_stack.addWidget(p0p); self.pass_stack.addWidget(p1p)
        self.extra_layout.addRow("Pass (or file):", self.pass_stack)

        # Threads
        self.threads = QtWidgets.QLineEdit("4")
        self.extra_layout.addRow("Threads (-t):", self.threads)

        # http-post-form specific (隱藏/顯示)
        self.hp_path = QtWidgets.QLineEdit("/doLogin")
        self.hp_userfield = QtWidgets.QLineEdit("uid")
        self.hp_passfield = QtWidgets.QLineEdit("passw")
        self.hp_extrafield = QtWidgets.QLineEdit()
        self.hp_failstr = QtWidgets.QLineEdit("Login Failed")
        self.hp_https_ck = QtWidgets.QCheckBox("Use HTTPS (https-post-form)")
        self.extra_layout.addRow("HTTP path (for post):", self.hp_path)
        self.extra_layout.addRow("User field (post):", self.hp_userfield)
        self.extra_layout.addRow("Pass field (post):", self.hp_passfield)
        self.extra_layout.addRow("Extra form params:", self.hp_extrafield)
        self.extra_layout.addRow("Failure string:", self.hp_failstr)
        self.extra_layout.addRow("", self.hp_https_ck)
        # 預設隱藏 http-post-form 欄位
        for w in (self.hp_path, self.hp_userfield, self.hp_passfield, self.hp_extrafield, self.hp_failstr, self.hp_https_ck):
            w.setVisible(False)

        # signals
        self.service.currentTextChanged.connect(self._on_service_changed)
        self.user_single_rb.toggled.connect(self._sync_user_stack)
        self.pass_single_rb.toggled.connect(self._sync_pass_stack)
        self.user_file_browse.clicked.connect(self._choose_user_file)
        self.pass_file_browse.clicked.connect(self._choose_pass_file)

        # init
        self._sync_user_stack(); self._sync_pass_stack(); self._on_service_changed(self.service.currentText())

    # ---------- UI helper ----------
    def _sync_user_stack(self):
        self.user_stack.setCurrentIndex(0 if self.user_single_rb.isChecked() else 1)

    def _sync_pass_stack(self):
        self.pass_stack.setCurrentIndex(0 if self.pass_single_rb.isChecked() else 1)

    def _choose_user_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose user list file")
        if path:
            self.user_file_widget.setText(path)
            self.user_file_rb.setChecked(True)
            self._sync_user_stack()

    def _choose_pass_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose password list file")
        if path:
            self.pass_file_widget.setText(path)
            self.pass_file_rb.setChecked(True)
            self._sync_pass_stack()

    def _on_service_changed(self, svc):
        is_http_post = (svc == "http-post-form")
        for w in (self.hp_path, self.hp_userfield, self.hp_passfield, self.hp_extrafield, self.hp_failstr, self.hp_https_ck):
            w.setVisible(is_http_post)
        # 調整 FormLayout 中 label 的可見性（讓隱藏欄位連同標籤一起隱藏）
        layout = self.extra_layout
        for i in range(layout.rowCount()):
            label_item = layout.itemAt(i, QtWidgets.QFormLayout.LabelRole)
            field_item = layout.itemAt(i, QtWidgets.QFormLayout.FieldRole)
            if label_item and field_item:
                widget = field_item.widget()
                if widget is not None:
                    visible = widget.isVisible()
                    label = label_item.widget()
                    if label:
                        label.setVisible(visible)

    # ---------- path conversion helper ----------
    def _convert_path_for_execution(self, path, use_wsl):
        """
        如果 use_wsl 為 True，嘗試把 Windows 路徑轉成 WSL 路徑：
        1) 先嘗試呼叫 `wsl wslpath -a <path>`（較可靠）
        2) 若失敗則以簡單替換 'C:\\' => '/mnt/c/' 並把反斜線換成斜線
        回傳轉換後的字串（若不需轉換直接回傳原 path）
        """
        if not use_wsl or not is_windows():
            return path
        # detect typical Windows drive path
        if len(path) >= 2 and path[1] == ":":
            try:
                # call wslpath via wsl
                p = subprocess.run(["wsl", "wslpath", "-a", path], capture_output=True, text=True, timeout=2)
                if p.returncode == 0 and p.stdout.strip():
                    return p.stdout.strip()
            except Exception:
                pass
            # fallback simple conversion
            drive = path[0].lower()
            tail = path[2:].replace("\\", "/")
            return f"/mnt/{drive}/{tail}"
        return path

    # ---------- build command and start ----------
    def on_start_clicked(self):
        svc = self.service.currentText()
        tgt = self.target_edit.text().strip()
        if not tgt:
            self.output.appendPlainText("[ERROR] 請輸入 target (host or host:port)")
            return

        use_wsl = self.use_wsl_ck.isChecked()

        # build user arg
        if self.user_single_rb.isChecked():
            user_val = self.user_single_widget.text().strip()
            if not user_val:
                self.output.appendPlainText("[ERROR] User empty"); return
            user_arg = ["-l", user_val]
        else:
            user_file = self.user_file_widget.text().strip()
            if not user_file:
                self.output.appendPlainText("[ERROR] User file 未填"); return
            # 檔案存在檢查：先用本機路徑檢查（能檢查 Windows 路徑）
            if not os.path.exists(user_file):
                self.output.appendPlainText(f"[WARN] User file 在此系統上找不到: {user_file}")
            # 若要在 WSL 執行，則轉換成 WSL 路徑
            file_for_cmd = self._convert_path_for_execution(user_file, use_wsl)
            user_arg = ["-L", file_for_cmd]

        # build pass arg
        if self.pass_single_rb.isChecked():
            pass_val = self.pass_single_widget.text().strip()
            if not pass_val:
                self.output.appendPlainText("[ERROR] Password empty"); return
            pass_arg = ["-p", pass_val]
        else:
            pass_file = self.pass_file_widget.text().strip()
            if not pass_file:
                self.output.appendPlainText("[ERROR] Pass file 未填"); return
            if not os.path.exists(pass_file):
                self.output.appendPlainText(f"[WARN] Pass file 在此系統上找不到: {pass_file}")
            pass_for_cmd = self._convert_path_for_execution(pass_file, use_wsl)
            pass_arg = ["-P", pass_for_cmd]

        threads = self.threads.text().strip() or "4"

        # build per service command
        if svc == "ssh":
            cmd = ["hydra"] + user_arg + pass_arg + ["-t", threads, f"ssh://{tgt}"]
        elif svc == "http-get":
            cmd = ["hydra"] + user_arg + pass_arg + ["-t", threads, f"http-get://{tgt}"]
        elif svc == "http-post-form":
            path = self.hp_path.text().strip().lstrip("/")
            ufield = self.hp_userfield.text().strip() or "uid"
            pfield = self.hp_passfield.text().strip() or "passw"
            extra = self.hp_extrafield.text().strip()
            fail = self.hp_failstr.text().strip() or "Login Failed"
            params = f"{ufield}=^USER^&{pfield}=^PASS^"
            if extra:
                if extra.startswith("&"): params += extra
                else: params += "&" + extra
            form = f"/{path}:{params}:{fail}"
            proto = "https-post-form" if self.hp_https_ck.isChecked() else "http-post-form"
            cmd = ["hydra"] + user_arg + pass_arg + ["-t", threads, f"{proto}://{tgt}{form}"]
        else:
            cmd = ["hydra"] + user_arg + pass_arg + ["-t", threads, f"{svc}://{tgt}"]

        if is_windows() and not command_exists("hydra") and not use_wsl:
            self.output.appendPlainText("[WARN] hydra 未安裝在 Windows；請安裝或改勾選 使用 WSL 執行")
        # start worker
        self.start_worker(cmd)

# ---------------- MainWindow ----------------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Linux Security Tools Suite")
        self.resize(1200,760)
        w = QtWidgets.QWidget(); self.setCentralWidget(w)
        h = QtWidgets.QHBoxLayout(w)

        self.list_widget = QtWidgets.QListWidget()
        tools = ["whoami","ls","cat","ping","nc","nmap","traceroute","dig","curl","hydra"]
        self.list_widget.addItems(tools); self.list_widget.setFixedWidth(170); h.addWidget(self.list_widget)

        self.stack = QtWidgets.QStackedWidget(); h.addWidget(self.stack,1)
        clsmap = {"whoami":WhoamiPage,"ls":LsPage,"cat":CatPage,"ping":PingPage,"nc":NcPage,"nmap":NmapPage,"traceroute":TraceroutePage,"dig":DigPage,"curl":CurlPage,"hydra":HydraPage}
        self.pages = {}
        for name in tools:
            p = clsmap[name](self); self.pages[name] = p; self.stack.addWidget(p)

        self.list_widget.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.list_widget.setCurrentRow(0)

        # status + encoding
        self.status = QtWidgets.QStatusBar(); self.setStatusBar(self.status)
        self.encoding_label = QtWidgets.QLabel("編碼:"); self.encoding_combo = QtWidgets.QComboBox()
        encs = ["utf-8","cp950","big5","gbk","shift_jis","iso-8859-1","windows-1252","euc-kr","utf-16"]
        self.encoding_combo.addItems(encs); self.encoding_combo.setCurrentText("utf-8"); self.encoding_combo.setFixedWidth(150)
        self.status.addPermanentWidget(self.encoding_label); self.status.addPermanentWidget(self.encoding_combo)
        note = QtWidgets.QLabel("⚠️ 僅在授權環境演示掃描/破解工具"); self.status.addPermanentWidget(note)
        men = self.menuBar(); env = men.addMenu("Env"); a = QtWidgets.QAction("Check WSL", self); a.triggered.connect(self.check_wsl); env.addAction(a)
        self.encoding_combo.currentTextChanged.connect(lambda e: self.status.showMessage(f"目前編碼: {e}",2000))

    def check_wsl(self):
        ok = wsl_available(); QtWidgets.QMessageBox.information(self, "WSL", f"WSL 可用: {ok}")

# ---------------- run ----------------
def main():
    app = QtWidgets.QApplication(sys.argv)
    if is_windows():
        try: app.setStyle("windowsvista")
        except: pass
    win = MainWindow(); win.show(); sys.exit(app.exec_())

if __name__ == "__main__":
    main()