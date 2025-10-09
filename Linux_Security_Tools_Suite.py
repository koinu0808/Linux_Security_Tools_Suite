import sys, os, shlex, subprocess, shutil, time
from PyQt5 import QtCore, QtGui, QtWidgets
import subprocess, sys

if sys.platform.startswith("win"):  # silent
    _orig_popen = subprocess.Popen
    def quiet_popen(*args, **kwargs):
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        return _orig_popen(*args, **kwargs)
    subprocess.Popen = quiet_popen

# ---------- helpers ----------
_wsl_cache = {"val": None, "ts": 0}
WSL_CACHE_TTL = 3.0

def is_windows(): return sys.platform.startswith("win")

def wsl_available(force=False):
    global _wsl_cache
    now = time.time()
    if not force and (_wsl_cache["val"] is not None and now - _wsl_cache["ts"] < WSL_CACHE_TTL):
        return _wsl_cache["val"]
    val = False
    if not is_windows():
        val = False
        _wsl_cache.update({"val": val, "ts": now})
        return val
    cmds = [["wsl","wslpath","/"], ["wsl","-l"], ["wsl","echo","ok"]]
    for c in cmds:
        try:
            p = subprocess.run(c, capture_output=True, text=True, timeout=1.0)
            if p.returncode == 0:
                val = True
                break
        except Exception:
            continue
    _wsl_cache.update({"val": val, "ts": now})
    return val

def command_exists(cmd): return shutil.which(cmd) is not None
def shell_single_quote_escape(s: str): return s.replace("'", "'\"'\"'")

def build_powershell_command_str(cmd_list):
    exe = cmd_list[0].lower()
    args = cmd_list[1:]
    def q(s): return s.replace('"','\\"')
    # map a few commands to PowerShell-friendly commands for Windows
    if exe in ("ls","dir"):
        path = "." if not args else (args[-1] if not args[-1].startswith("-") else ".")
        ps = (f"Get-ChildItem -Force -LiteralPath \"{q(path)}\" | "
              "Select-Object @{Name='Mode';Expression={$_.Mode}},"
              "@{Name='LastWriteTime';Expression={$_.LastWriteTime}},"
              "@{Name='Length';Expression={$_.Length}},"
              "@{Name='Name';Expression={$_.Name}} | Format-Table -AutoSize | Out-String -Width 4096")
        return ps
    if exe == "cat":
        path = args[-1] if args else "."
        return f"Get-Content -Raw -LiteralPath \"{q(path)}\""
    if exe == "whoami":
        return "whoami"
    if exe == "ping":
        cnt="4"; host = args[-1] if args else "8.8.8.8"
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
    # fallback - join safely
    return " ".join([q(x) for x in cmd_list])

def build_final_command(cmd_list, use_wsl=False):
    # 如果選擇使用 WSL，則應該在命令前加上 'wsl' 前綴
    if use_wsl and is_windows():
        return ["wsl"] + cmd_list  # 添加 wsl 前綴，確保在 WSL 中執行
    # 如果不使用 WSL 並且在 Windows 中，則使用 PowerShell 執行
    elif is_windows() and not use_wsl:
        exe = cmd_list[0].lower()
        external = {"nmap", "ncat", "nc", "hydra", "john", "hashid", "tcpdump"}
        if exe in external and command_exists(exe):
            return cmd_list
        ps = build_powershell_command_str(cmd_list)
        return ["powershell", "-NoProfile", "-Command", ps]
    return cmd_list

# ---------- worker ----------
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
            # 保持原來的 build_final_command 函式不變，並確保它返回的是正確的命令
            full_cmd = build_final_command(self.cmd_list, use_wsl=self.use_wsl)
            print("最終命令：", full_cmd)  # 用來檢查傳遞給 subprocess 的命令

            # 如果 full_cmd 是列表格式，我們需要將它轉換為命令字符串
            if isinstance(full_cmd, list):
                full_cmd = ' '.join(full_cmd)

            # 使用 subprocess 執行命令
            self._proc = subprocess.Popen(full_cmd, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, text=True,
                                           encoding=self.encoding, errors="replace", bufsize=1)
            
            for line in self._proc.stdout:
                if self._stop:
                    break
                self.output_line.emit(line.rstrip("\n"))
            
            if self._stop and self._proc and self._proc.poll() is None:
                try:
                    self._proc.terminate()
                except:
                    pass
            
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
        except:
            pass

# ---------- base page ----------
class ToolPageBase(QtWidgets.QWidget):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.worker = None; self.thread = None
        self._build_ui()

    def main_window(self):
        w = self
        while w is not None and not isinstance(w, QtWidgets.QMainWindow):
            w = w.parent()
        return w

    def _build_ui(self):
        # vertical layout - no inner frames, no groupboxes
        v = QtWidgets.QVBoxLayout(self)
        v.setContentsMargins(6,6,6,6)
        v.setSpacing(8)

        # description (flat)
        self.desc = QtWidgets.QLabel("")
        self.desc.setWordWrap(True)
        self.desc.setFixedHeight(56)
        v.addWidget(self.desc)

        # top: target + wsl checkbox
        top = QtWidgets.QHBoxLayout()
        form = QtWidgets.QFormLayout()
        self.target_label = QtWidgets.QLabel("Target / Args:")
        self.target_edit = QtWidgets.QLineEdit()
        self.target_edit.setPlaceholderText("Target or arguments")
        form.addRow(self.target_label, self.target_edit)
        top.addLayout(form,1)
        right = QtWidgets.QVBoxLayout()
        self.use_wsl_ck = QtWidgets.QCheckBox("使用 WSL 執行 (Windows)")
        right.addWidget(self.use_wsl_ck, 0, QtCore.Qt.AlignTop)
        right.addStretch()
        top.addLayout(right)
        v.addLayout(top)

        # options area - PLAIN widget (no border)
        self.options_box = QtWidgets.QWidget()
        self.options_layout = QtWidgets.QVBoxLayout(self.options_box)
        self.options_layout.setContentsMargins(0,0,0,0)
        self.options_scroll = QtWidgets.QScrollArea()
        self.options_scroll.setWidgetResizable(True)
        self.options_scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.options_scroll.setWidget(self.options_box)
        v.addWidget(self.options_scroll)

        # action buttons row
        actions = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("Start")
        self.stop_btn = QtWidgets.QPushButton("Stop"); self.stop_btn.setEnabled(False)
        actions.addWidget(self.start_btn); actions.addWidget(self.stop_btn); actions.addStretch()
        v.addLayout(actions)

        # progress (flat)
        self.progress = QtWidgets.QProgressBar(); self.progress.setVisible(False); self.progress.setTextVisible(False)
        self.progress.setFixedHeight(18)
        
        
        v.addWidget(self.progress)

        # output (monospace)
        self.output = QtWidgets.QPlainTextEdit(); self.output.setReadOnly(True)
        font = QtGui.QFont("Consolas" if is_windows() else "Monospace", 10)
        self.output.setFont(font)
        v.addWidget(self.output,1)

        # connect
        self.start_btn.clicked.connect(self.on_start_clicked)
        self.stop_btn.clicked.connect(self.on_stop_clicked)

    def start_worker(self, cmd_list):
        mw = self.main_window()
        if not mw:
            self.output.appendPlainText("[ERROR] 找不到主視窗")
            return
        use_wsl = self.use_wsl_ck.isChecked()
        encoding = mw.encoding_combo.currentText()
        self.output.clear()
        self.output.appendPlainText(f"執行: {' '.join(cmd_list)}\n")
        if is_windows() and not use_wsl:
            exe = cmd_list[0].lower()
            if exe in {"nmap","hydra","john","tcpdump","hashid","ncat","nc"} and not command_exists(exe):
                self.output.appendPlainText(f"[WARN] 系統找不到 {exe}；請安裝或改勾 WSL")
        self.progress.setVisible(True); self.progress.setRange(0,100); self.progress.setValue(50)
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
        self.progress.setValue(100); self.progress.setValue(100); self.progress.setVisible(False); self.progress.setRange(0,100)
        self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        if self.thread:
            self.thread.quit(); self.thread.wait(); self.thread = None; self.worker = None

    def on_stop_clicked(self):
        if self.worker:
            self.worker.stop(); self.output.appendPlainText("[Stopping...]"); self.stop_btn.setEnabled(False)

    def on_start_clicked(self):
        raise NotImplementedError

# ---------- pages ----------
class WhoamiPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("顯示目前使用者 (whoami)。此頁僅顯示是否使用 WSL 選項。")
        self.target_label.hide(); self.target_edit.hide()
        # hide options area entirely
        self.options_scroll.hide()

    def on_start_clicked(self):
        self.start_worker(["whoami"])

class LsPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("ls：列出目錄內容。Options 可填 -l/-la，Target 為路徑或留空。")
        form = QtWidgets.QFormLayout()
        self.opt = QtWidgets.QLineEdit(); self.opt.setPlaceholderText("-l -la")
        form.addRow("Options:", self.opt)
        self.options_layout.addLayout(form)
    def on_start_clicked(self):
        opts = self.opt.text().strip(); path = self.target_edit.text().strip() or "."
        parts = ["ls"] + (shlex.split(opts) if opts else []) + [path]
        self.start_worker(parts)

class CatPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("cat：讀檔並用左下編碼或自動嘗試多種編碼解碼（避免亂碼）。")
        row = QtWidgets.QHBoxLayout()
        self.auto_ck = QtWidgets.QCheckBox("Auto try encodings (utf-8 → cp950 → gbk)")
        row.addWidget(self.auto_ck); row.addStretch()
        self.options_layout.addLayout(row)
    def on_start_clicked(self):
        f = self.target_edit.text().strip()
        if not f:
            self.output.appendPlainText("[ERROR] 請輸入檔案路徑"); return
        if not os.path.exists(f):
            self.start_worker(["cat", f]); return
        with open(f,"rb") as fh:
            b = fh.read()
        mw = self.main_window(); enc = mw.encoding_combo.currentText() if mw else "utf-8"
        s = None
        try: s = b.decode(enc)
        except Exception:
            if self.auto_ck.isChecked():
                for e in ("utf-8","cp950","big5","gbk","utf-16"):
                    try:
                        s = b.decode(e); enc = e; break
                    except: s = None
        if s is None:
            s = b.decode(enc, errors="replace")
            self.output.appendPlainText(f"[WARN] decode with {enc} (errors replaced)\n")
        self.output.appendPlainText(s)

class PingPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("ping：測試連線 (Count 可設定)。")
        f = QtWidgets.QFormLayout()
        self.cnt = QtWidgets.QLineEdit("4")
        f.addRow("Count:", self.cnt)
        self.options_layout.addLayout(f)
    def on_start_clicked(self):
        t = self.target_edit.text().strip() or "8.8.8.8"; cnt = self.cnt.text().strip() or "4"
        self.start_worker(["ping","-c",cnt,t])

class NcPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("nc：connect 或 listen。若勾選 WSL，執行 WSL 的 nc。")
        self.target_label.hide(); self.target_edit.hide()
        f = QtWidgets.QFormLayout()
        self.mode = QtWidgets.QComboBox(); self.mode.addItems(["connect","listen"])
        self.host = QtWidgets.QLineEdit("127.0.0.1"); self.port = QtWidgets.QLineEdit()
        f.addRow("Mode:", self.mode); f.addRow("Host:", self.host); f.addRow("Port:", self.port)
        self.options_layout.addLayout(f)
    def on_start_clicked(self):
        mode = self.mode.currentText(); h = self.host.text().strip() or "127.0.0.1"; p = self.port.text().strip()
        if not p: self.output.appendPlainText("[ERROR] 請輸入 port"); return
        use_wsl = self.use_wsl_ck.isChecked()
        exe = "nc" if use_wsl else ("nc" if command_exists("nc") else ("ncat" if command_exists("ncat") else "nc"))
        if mode == "connect": self.start_worker([exe, h, p])
        else: self.start_worker([exe, "-l", "-p", p])

class NmapPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("nmap：掃描主機/埠。WSL + sudo 支援（會使用 echo PW | sudo -S 執行，注意風險）。")
        f = QtWidgets.QFormLayout()
        self.scan = QtWidgets.QComboBox(); self.scan.addItems(["-sT","-sS","-sU","-sn"])
        self.ports = QtWidgets.QLineEdit(); self.ports.setPlaceholderText("1-1024 or 22,80,443")
        self.extra = QtWidgets.QLineEdit(); self.extra.setPlaceholderText("-A -Pn -T4")
        self.sudo_ck = QtWidgets.QCheckBox("Use sudo (when using WSL)")
        self.sudo_pass = QtWidgets.QLineEdit(); self.sudo_pass.setEchoMode(QtWidgets.QLineEdit.Password)
        f.addRow("Scan:", self.scan); f.addRow("Ports:", self.ports); f.addRow("Extra:", self.extra)
        f.addRow("", self.sudo_ck); f.addRow("WSL sudo 密碼:", self.sudo_pass)
        self.options_layout.addLayout(f)
    def on_start_clicked(self):
        target = self.target_edit.text().strip()
        if not target: self.output.appendPlainText("[ERROR] 請輸入 target"); return
        cmd_parts = ["nmap", self.scan.currentText()]
        if self.ports.text().strip(): cmd_parts += ["-p", self.ports.text().strip()]
        if self.extra.text().strip(): cmd_parts += shlex.split(self.extra.text().strip())
        cmd_parts += ["-oN","-"] + shlex.split(target)
        use_wsl = self.use_wsl_ck.isChecked()
        if use_wsl and self.sudo_ck.isChecked():
            pw = self.sudo_pass.text()
            if not pw: self.output.appendPlainText("[ERROR] 勾選 Use sudo 但未填密碼"); return
            safe_pw = shell_single_quote_escape(pw)
            nmap_cmd_str = " ".join(shlex.quote(p) for p in cmd_parts)
            bash_cmd = f"echo '{safe_pw}' | sudo -S {nmap_cmd_str}"
            self.start_worker(["bash","-lc", bash_cmd]); return
        self.start_worker(cmd_parts)

class TraceroutePage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("traceroute：追蹤路由。請在 Options 欄直接輸入完整 traceroute 參數（例如 -4 -d -w 300 -m 30）。")
        form = QtWidgets.QFormLayout()
        self.opts_input = QtWidgets.QLineEdit()
        self.opts_input.setPlaceholderText("輸入 traceroute 參數，例如: -4 -d -w 300 -m 30")
        form.addRow("Options:", self.opts_input)
        self.options_layout.addLayout(form)
    def on_start_clicked(self):
        tgt = self.target_edit.text().strip()
        if not tgt: self.output.appendPlainText("[ERROR] 請輸入 target"); return
        use_wsl = self.use_wsl_ck.isChecked()
        opts = shlex.split(self.opts_input.text().strip()) if self.opts_input.text().strip() else []
        if is_windows() and not use_wsl:
            cmd = ["tracert"] + opts + [tgt]
        else:
            cmd = ["traceroute"] + opts + [tgt]
        self.start_worker(cmd)

class DigPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("dig：DNS 查詢，可加 +short 顯示簡短答案。")
        h = QtWidgets.QHBoxLayout(); self.short_ck = QtWidgets.QCheckBox("+short"); h.addWidget(self.short_ck); h.addStretch()
        self.options_layout.addLayout(h)
    def on_start_clicked(self):
        t = self.target_edit.text().strip() or "example.com"
        if self.short_ck.isChecked(): self.start_worker(["dig","+short",t])
        else: self.start_worker(["dig",t])

class CurlPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("curl：HTTP(S) 客戶端，檢查 header/status，或模擬表單。")
        f = QtWidgets.QFormLayout()
        self.method = QtWidgets.QComboBox(); self.method.addItems(["GET","HEAD","POST"])
        f.addRow("Method:", self.method)
        self.options_layout.addLayout(f)
    def on_start_clicked(self):
        url = self.target_edit.text().strip()
        if not url: self.output.appendPlainText("[ERROR] 請輸入 URL"); return
        m = self.method.currentText()
        if m=="HEAD": self.start_worker(["curl","-I",url])
        elif m=="POST": self.start_worker(["curl","-X","POST",url])
        else: self.start_worker(["curl","-sS",url])

# Hydra kept similar to earlier polished logic (single/file, http-post handling)
class HydraPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("hydra：暴力破解（請在授權範圍內使用）。User/Pass 可選 Single 或 File（editable）。")
        form = QtWidgets.QFormLayout()
        self.service = QtWidgets.QComboBox(); self.service.addItems(["ssh","ftp","http-get","http-post-form"])
        form.addRow("Service:", self.service)
        umode = QtWidgets.QHBoxLayout()
        self.user_single_rb = QtWidgets.QRadioButton("Single"); self.user_file_rb = QtWidgets.QRadioButton("File")
        self.user_single_rb.setChecked(True); umode.addWidget(self.user_single_rb); umode.addWidget(self.user_file_rb); umode.addStretch()
        form.addRow("User mode:", umode)
        self.user_group = QtWidgets.QButtonGroup(self); self.user_group.addButton(self.user_single_rb); self.user_group.addButton(self.user_file_rb)
        self.user_stack = QtWidgets.QStackedWidget()
        self.user_single = QtWidgets.QLineEdit(); self.user_single.setPlaceholderText("username")
        p0 = QtWidgets.QWidget(); l0 = QtWidgets.QHBoxLayout(p0); l0.addWidget(self.user_single)
        self.user_file = QtWidgets.QLineEdit(); self.user_file.setPlaceholderText("path to user list (editable)")
        self.user_browse = QtWidgets.QPushButton("Browse")
        p1 = QtWidgets.QWidget(); l1 = QtWidgets.QHBoxLayout(p1); l1.addWidget(self.user_file); l1.addWidget(self.user_browse)
        self.user_stack.addWidget(p0); self.user_stack.addWidget(p1)
        form.addRow("User (or file):", self.user_stack)
        pmode = QtWidgets.QHBoxLayout()
        self.pass_single_rb = QtWidgets.QRadioButton("Single"); self.pass_file_rb = QtWidgets.QRadioButton("File")
        self.pass_single_rb.setChecked(True); pmode.addWidget(self.pass_single_rb); pmode.addWidget(self.pass_file_rb); pmode.addStretch()
        form.addRow("Pass mode:", pmode)
        self.pass_group = QtWidgets.QButtonGroup(self); self.pass_group.addButton(self.pass_single_rb); self.pass_group.addButton(self.pass_file_rb)
        self.pass_stack = QtWidgets.QStackedWidget()
        self.pass_single = QtWidgets.QLineEdit(); self.pass_single.setEchoMode(QtWidgets.QLineEdit.Password)
        p0p = QtWidgets.QWidget(); l0p = QtWidgets.QHBoxLayout(p0p); l0p.addWidget(self.pass_single)
        self.pass_file = QtWidgets.QLineEdit(); self.pass_file.setPlaceholderText("path to password list (editable)")
        self.pass_browse = QtWidgets.QPushButton("Browse")
        p1p = QtWidgets.QWidget(); l1p = QtWidgets.QHBoxLayout(p1p); l1p.addWidget(self.pass_file); l1p.addWidget(self.pass_browse)
        self.pass_stack.addWidget(p0p); self.pass_stack.addWidget(p1p)
        form.addRow("Pass (or file):", self.pass_stack)
        self.threads = QtWidgets.QLineEdit("4"); form.addRow("Threads (-t):", self.threads)
        self.http_group = QtWidgets.QWidget()
        self.http_layout = QtWidgets.QFormLayout(self.http_group)
        self.hp_path = QtWidgets.QLineEdit("/doLogin"); self.hp_userfield = QtWidgets.QLineEdit("uid"); self.hp_passfield = QtWidgets.QLineEdit("passw")
        self.hp_extrafield = QtWidgets.QLineEdit(); self.hp_failstr = QtWidgets.QLineEdit("Login Failed")
        self.hp_https_ck = QtWidgets.QCheckBox("Use HTTPS (https-post-form)")
        self.http_layout.addRow("HTTP path:", self.hp_path); self.http_layout.addRow("User field:", self.hp_userfield)
        self.http_layout.addRow("Pass field:", self.hp_passfield); self.http_layout.addRow("Extra params:", self.hp_extrafield)
        self.http_layout.addRow("Failure string:", self.hp_failstr); self.http_layout.addRow("", self.hp_https_ck)
        self.http_group.setVisible(False)
        self.options_layout.addLayout(form); self.options_layout.addWidget(self.http_group)
        # signals
        self.user_single_rb.toggled.connect(lambda v: self.user_stack.setCurrentIndex(0 if v else 1))
        self.pass_single_rb.toggled.connect(lambda v: self.pass_stack.setCurrentIndex(0 if v else 1))
        self.user_browse.clicked.connect(self._choose_user_file); self.pass_browse.clicked.connect(self._choose_pass_file)
        self.service.currentTextChanged.connect(self._on_service_changed)
        self.user_stack.setCurrentIndex(0); self.pass_stack.setCurrentIndex(0); self._on_service_changed(self.service.currentText())

    def _choose_user_file(self):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose user list file")
        if p:
            self.user_file.setText(p); self.user_file_rb.setChecked(True); self.user_stack.setCurrentIndex(1)

    def _choose_pass_file(self):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose password list file")
        if p:
            self.pass_file.setText(p); self.pass_file_rb.setChecked(True); self.pass_stack.setCurrentIndex(1)

    def _convert_path_for_execution(self, path, use_wsl):
        if not use_wsl or not is_windows(): return path
        if len(path) >= 2 and path[1] == ":":
            try:
                p = subprocess.run(["wsl","wslpath","-a", path], capture_output=True, text=True, timeout=2)
                if p.returncode == 0 and p.stdout.strip(): return p.stdout.strip()
            except Exception:
                pass
            drive = path[0].lower(); tail = path[2:].replace("\\","/")
            return f"/mnt/{drive}{tail}"
        return path

    def _on_service_changed(self, svc):
        self.http_group.setVisible(svc == "http-post-form")

    def on_start_clicked(self):
        svc = self.service.currentText(); tgt = self.target_edit.text().strip()
        if not tgt: 
            self.output.appendPlainText("[ERROR] 請輸入 target")
            return
        
        use_wsl = self.use_wsl_ck.isChecked()
        
        # 處理用戶輸入的 User（單一或文件）
        if self.user_single_rb.isChecked():
            u = self.user_single.text().strip()
            if not u: 
                self.output.appendPlainText("[ERROR] User empty")
                return
            user_arg = ["-l", u]
        else:
            ufile = self.user_file.text().strip()
            if not ufile: 
                self.output.appendPlainText("[ERROR] User file 未填")
                return
            if not os.path.exists(ufile): 
                self.output.appendPlainText(f"[WARN] User file 在此系統找不到: {ufile}")
            user_arg = ["-L", self._convert_path_for_execution(ufile, use_wsl)]
        
        # 處理密碼（單一或文件）
        if self.pass_single_rb.isChecked():
            p = self.pass_single.text().strip()
            if not p: 
                self.output.appendPlainText("[ERROR] Password empty")
                return
            pass_arg = ["-p", p]
        else:
            pfile = self.pass_file.text().strip()
            if not pfile: 
                self.output.appendPlainText("[ERROR] Pass file 未填")
                return
            if not os.path.exists(pfile): 
                self.output.appendPlainText(f"[WARN] Pass file 在此系統上找不到: {pfile}")
            pass_arg = ["-P", self._convert_path_for_execution(pfile, use_wsl)]
        
        # 處理執行參數
        threads = self.threads.text().strip() or "4"
        
        # 設定協議與URL格式
        path = self.hp_path.text().strip().lstrip("/")
        ufield = self.hp_userfield.text().strip() or "uid"
        pfield = self.hp_passfield.text().strip() or "passw"
        extra = self.hp_extrafield.text().strip(); fail = self.hp_failstr.text().strip() or "Login Failed"
        
        params = f"{ufield}=^USER^&{pfield}=^PASS^"
        if extra:
            params += extra if extra.startswith("&") else "&" + extra
        
        form = f"/{path}:{params}:{fail}"
        proto = "https-post-form" if self.hp_https_ck.isChecked() else "http-post-form"
        
        cmd = ["hydra"] + user_arg + pass_arg + ["-t", threads, f"{tgt} {proto} \"{form}\""]

        if is_windows() and not command_exists("hydra") and not use_wsl:
            self.output.appendPlainText("[WARN] hydra 未安裝在 Windows；請安裝或改勾 WSL")

        print("cmd 類型:", type(cmd))

        self.start_worker(cmd)

# ---------- main window ----------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Linux Security Tools Suite")
        self.resize(1200,760)
        central = QtWidgets.QWidget(); self.setCentralWidget(central)
        main_h = QtWidgets.QHBoxLayout(central)
        main_h.setContentsMargins(0,8,8,8)

        # left nav - flat
        self.nav = QtWidgets.QListWidget(); self.nav.setFixedWidth(200); self.nav.setSpacing(0); self.nav.setMouseTracking(True)
        self.nav.setFont(QtGui.QFont("Segoe UI",10))
        tools = ["whoami","ls","cat","ping","nc","nmap","traceroute","dig","curl","hydra"]
        for t in tools:
            it = QtWidgets.QListWidgetItem(t); it.setTextAlignment(QtCore.Qt.AlignVCenter)
            self.nav.addItem(it)
        main_h.addWidget(self.nav)

        # content stack
        self.stack = QtWidgets.QStackedWidget(); main_h.addWidget(self.stack,1)
        clsmap = {"whoami":WhoamiPage,"ls":LsPage,"cat":CatPage,"ping":PingPage,"nc":NcPage,"nmap":NmapPage,"traceroute":TraceroutePage,"dig":DigPage,"curl":CurlPage,"hydra":HydraPage}
        self.pages = {}
        for name in tools:
            p = clsmap[name](self); self.pages[name] = p; self.stack.addWidget(p)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex); self.nav.setCurrentRow(0)

        # status bar - encoding + wsl status
        self.status = QtWidgets.QStatusBar(); self.setStatusBar(self.status)
        self.encoding_label = QtWidgets.QLabel("編碼:")
        self.encoding_combo = QtWidgets.QComboBox()
        encs = ["utf-8","cp950","big5","gbk","shift_jis","iso-8859-1","windows-1252","euc-kr","utf-16"]
        self.encoding_combo.addItems(encs); self.encoding_combo.setCurrentText("utf-8"); self.encoding_combo.setFixedWidth(140)
        self.status.addPermanentWidget(self.encoding_label); self.status.addPermanentWidget(self.encoding_combo)
        self.wsl_status_label = QtWidgets.QLabel(); self.wsl_status_label.setFixedWidth(160)
        self.status.addPermanentWidget(self.wsl_status_label)
        self._update_wsl_status(initial=True)
        self.wsl_timer = QtCore.QTimer(self); self.wsl_timer.setInterval(5000); self.wsl_timer.timeout.connect(self._update_wsl_status); self.wsl_timer.start()
        men = self.menuBar(); env = men.addMenu("Env")
        ac = QtWidgets.QAction("Check WSL Now", self); ac.triggered.connect(lambda: self._update_wsl_status(force=True)); env.addAction(ac)
        self.encoding_combo.currentTextChanged.connect(lambda t: self.status.showMessage(f"編碼: {t}",1500))

    def _update_wsl_status(self, initial=False, force=False):
        ok = wsl_available(force=force)
        dot = "●"
        if ok:
            html = f'<span style="color:#2ea84a;font-weight:700">{dot}</span> WSL: Available'
        else:
            html = f'<span style="color:#d9534f;font-weight:700">{dot}</span> WSL: Not available'
        self.wsl_status_label.setText(html)
        if initial:
            self.status.showMessage("WSL 檢查完成", 1200)

# ---------- run ----------
def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet("""
        QMenu {
            background-color: #F9F9F9;
            border: 1px solid #D1D1D6;
        }

        QMenu::item {
            color: #1C1C1E;
            background-color: transparent;
        }

        QMenu::item:selected {
            background-color: #E5F1FF;
        }
                      
        QWidget {
            background-color: #F5F5F7;
            color: #1C1C1E;
            font-family: "FiraCode Nerd Font Mono", sans-serif;
            font-size: 9.5pt;
        }
        QListWidget {
            background-color: #ECECEC;
            border: none;
            padding: 8px;
            outline: 0;
        }
        QListWidget::item {
            padding: 10px 14px;
            border-radius: 4px;
            color: #1C1C1E;
        }
        QListWidget::item:hover {
            background-color: #6eb3ff;
        }
        QListWidget::item:selected {
            background-color: #007AFF;
            color: white;
            font-weight: 600;
        }
        QPushButton {
            background-color: #007AFF;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 6px 12px;
            font-weight: 400;
        }
        QPushButton:hover {
            background-color: #005FCC;
        }
        QLineEdit, QComboBox, QPlainTextEdit {
            background-color: white;
            border: 1px solid #D1D1D6;
            border-radius: 4px;
            padding: 4px 6px;
        }
        QLabel {
            font-weight: 400;
        }
        QStatusBar {
            background-color: #F2F2F2;
            border-top: 1px solid #D1D1D6;
        }
        QScrollBar:vertical {
            border: none;
            background: transparent;
            width: 8px;
            margin: 0px;
        }

        QScrollBar::handle:vertical {
            background: #C6C6C8;
            border-radius: 4px;
            min-height: 20px;
        }

        QScrollBar::handle:vertical:hover {
            background: #A0A0A0;
        }

        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0;
        }

        QScrollBar:horizontal {
            border: none;
            background: transparent;
            height: 8px;
            margin: 0px;
        }

        QScrollBar::handle:horizontal {
            background: #C6C6C8;
            border-radius: 4px;
            min-width: 20px;
        }

        QScrollBar::handle:horizontal:hover {
            background: #A0A0A0;
        }

        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0;
        }
    """)
    win = MainWindow(); win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()