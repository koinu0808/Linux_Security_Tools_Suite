import sys, os, shlex, subprocess, shutil, time, re, threading
from PyQt5 import QtCore, QtGui, QtWidgets
import subprocess, sys
from PyQt5.QtCore import QThread, pyqtSignal
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

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
        ps = (
        "$u = whoami; "
        "$os = (Get-CimInstance Win32_OperatingSystem); "
        "$cpu = (Get-CimInstance Win32_Processor).Name; "
        "$mem = [math]::Round($os.TotalVisibleMemorySize/1MB,2); "
        "$ver = [System.Environment]::OSVersion.VersionString; "
        "Write-Output ('使用者: ' + $u); "
        "Write-Output ('作業系統: ' + $os.Caption); "
        "Write-Output ('版本: ' + $ver); "
        "Write-Output ('CPU: ' + $cpu); "
        "Write-Output ('RAM: ' + $mem + ' GB');"
        )
        return ps
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
        if cmd_list[0] == "whoami":
            linux_cmd = (
                "u=$(id -un 2>/dev/null | tr -d '\\r' | xargs); "
                "if [ -z \"$u\" ]; then u=$(whoami | tr -d '\\r' | xargs); fi; "
                "sys=$(uname -o | tr -d '\\r' | xargs); "
                "ver=$(uname -r | tr -d '\\r' | xargs); "
                "ker=$(uname -s | tr -d '\\r' | xargs); "
                "cpu=$(grep 'model name' /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs); "
                "ram=$(free -h | awk '/Mem:/ {print $2}' | tr -d '\\r' | xargs); "
                "printf '使用者: %s\\n系統: %s\\n版本: %s\\n核心: %s\\nCPU: %s\\nRAM: %s\\n' "
                "\"$u\" \"$sys\" \"$ver\" \"$ker\" \"$cpu\" \"$ram\"; "
                "exit 0"
            )
            return ['wsl', 'bash', '-c', linux_cmd]
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
        # 當 WSL 勾選框變化時，自動通知主視窗切換編碼
        self.use_wsl_ck.toggled.connect(
            lambda v: self.main_window().set_encoding_based_on_wsl(v)
        )
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
        mw.set_encoding_based_on_wsl(use_wsl)
        encoding = mw.encoding_combo.currentText()
        self.output.clear()
        self.output.appendPlainText(f"[START]\n")
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
        self.desc.setText("顯示目前電腦系統資訊")
        self.target_label.hide(); self.target_edit.hide()
        # hide options area entirely
        self.options_scroll.hide()

    def on_start_clicked(self):
        self.start_worker(["whoami"])

class LsPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("列出目錄內容。Options 可填 -l/-la，Target 為路徑或留空。")
        form = QtWidgets.QFormLayout()
        self.opt = QtWidgets.QLineEdit(); self.opt.setPlaceholderText("-l -la")
        form.addRow("Options:", self.opt)
        self.options_layout.addLayout(form)
    def on_start_clicked(self):
        use_wsl = self.use_wsl_ck.isChecked()
        opts = self.opt.text().strip(); path = self.target_edit.text().strip() or "."
        if use_wsl:
            parts = ["wsl","ls"] + (shlex.split(opts) if opts else []) + [path]
        else:
            parts = ["ls"] + (shlex.split(opts) if opts else []) + [path]    
        self.start_worker(parts)

class CatPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("顯示或比對檔案內容，支援自動編碼偵測與 WSL 模式。")

        # --- 隱藏上方 target 區塊，並移除其空白高度 ---
        self.target_label.hide()
        self.target_edit.hide()
        if hasattr(self, 'use_wsl_ck'):
            self.use_wsl_ck.hide()
        # 嘗試縮減原 top layout 的高度
        top_item = self.layout().itemAt(1)
        if top_item and isinstance(top_item, QtWidgets.QLayout):
            top_item.setContentsMargins(0, 0, 0, 0)
            top_item.setSpacing(0)
            for i in range(top_item.count()):
                item = top_item.itemAt(i)
                w = item.widget()
                if w:
                    w.setVisible(False)

        # --- 模式切換 ---
        mode_layout = QtWidgets.QHBoxLayout()
        self.single_mode_rb = QtWidgets.QRadioButton("單檔模式")
        self.diff_mode_rb = QtWidgets.QRadioButton("比對模式")
        self.single_mode_rb.setChecked(True)
        mode_layout.addWidget(self.single_mode_rb)
        mode_layout.addWidget(self.diff_mode_rb)
        mode_layout.addStretch()
        self.options_layout.addLayout(mode_layout)
        self.options_layout.addSpacing(10)

        # --- 單檔模式 ---
        self.single_widget = QtWidgets.QWidget()
        s_form = QtWidgets.QGridLayout(self.single_widget)
        s_form.setContentsMargins(5, 5, 5, 5)
        s_form.setHorizontalSpacing(10)
        s_form.setVerticalSpacing(8)

        self.auto_ck = QtWidgets.QCheckBox("自動判斷編碼")
        self.auto_ck.setChecked(True)
        s_form.addWidget(self.auto_ck, 0, 0, 1, 2)

        self.single_file_edit = QtWidgets.QLineEdit()
        self.single_file_btn = QtWidgets.QPushButton("Browse")
        self.single_file_btn.setFixedWidth(100)
        s_form.addWidget(QtWidgets.QLabel("File:"), 1, 0)
        s_form.addWidget(self.single_file_edit, 1, 1)
        s_form.addWidget(self.single_file_btn, 1, 2)

        # --- 比對模式 ---
        self.diff_widget = QtWidgets.QWidget()
        d_form = QtWidgets.QFormLayout(self.diff_widget)
        self.file1_edit = QtWidgets.QLineEdit()
        self.file2_edit = QtWidgets.QLineEdit()
        self.browse1_btn = QtWidgets.QPushButton("Browse")
        self.browse2_btn = QtWidgets.QPushButton("Browse")
        b1 = QtWidgets.QHBoxLayout(); b1.addWidget(self.file1_edit); b1.addWidget(self.browse1_btn)
        b2 = QtWidgets.QHBoxLayout(); b2.addWidget(self.file2_edit); b2.addWidget(self.browse2_btn)
        d_form.addRow("File1:", b1)
        d_form.addRow("File2:", b2)

        # --- stack 切換區 ---
        self.stack = QtWidgets.QStackedWidget()
        self.stack.addWidget(self.single_widget)
        self.stack.addWidget(self.diff_widget)
        self.options_layout.addWidget(self.stack)

        # --- 事件連接 ---
        self.single_mode_rb.toggled.connect(lambda v: self._toggle_mode(v))
        self.browse1_btn.clicked.connect(lambda: self._choose_file(self.file1_edit))
        self.browse2_btn.clicked.connect(lambda: self._choose_file(self.file2_edit))
        self.single_file_btn.clicked.connect(lambda: self._choose_file(self.single_file_edit))

    def _toggle_mode(self, single_mode):
        """切換單檔/比對模式時調整版面"""
        if single_mode:
            self.stack.setCurrentIndex(0)
            self.stack.setMaximumHeight(100)
        else:
            self.stack.setCurrentIndex(1)
            self.stack.setMaximumHeight(200)

        # ✅ 切換模式時強制清除輸出，避免樣式殘留
        self.output.clear()
        self.output.setPlainText("")  # 重設文字格式狀態

    def _choose_file(self, target_edit):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "選擇檔案")
        if p:
            target_edit.setText(p)

    def on_start_clicked(self):
        use_wsl = self.use_wsl_ck.isChecked()

        # === 單檔模式 ===
        if self.single_mode_rb.isChecked():
            f = self.single_file_edit.text().strip()
            if not f:
                self.output.appendPlainText("[ERROR] 請選擇檔案")
                return

            # ✅ 每次執行時都重設輸出格式
            self.output.clear()
            self.output.setPlainText("")

            if use_wsl:
                self.start_worker(["wsl", "cat", f])
                return

            if os.path.exists(f):
                try:
                    with open(f, "rb") as fh:
                        b = fh.read()
                except Exception as e:
                    self.output.appendPlainText(f"[ERROR] 無法讀取檔案: {e}")
                    return
            else:
                self.start_worker(["cat", f])
                return

            mw = self.main_window()
            enc = mw.encoding_combo.currentText() if mw else "utf-8"
            s = None
            try:
                s = b.decode(enc)
            except Exception:
                if self.auto_ck.isChecked():
                    for e in ("utf-8", "cp950", "big5", "gbk", "utf-16"):
                        try:
                            s = b.decode(e)
                            enc = e
                            break
                        except:
                            s = None
            if s is None:
                s = b.decode(enc, errors="replace")
                self.output.appendPlainText(f"[WARN] decode with {enc} (errors replaced)\n")

            self.output.appendPlainText(s)
            return

        # === 比對模式 ===
        f1 = self.file1_edit.text().strip()
        f2 = self.file2_edit.text().strip()
        if not f1 or not f2:
            self.output.appendPlainText("[ERROR] 請選擇兩個檔案進行比對")
            return
        if not os.path.exists(f1) or not os.path.exists(f2):
            self.output.appendPlainText("[ERROR] 檔案不存在")
            return

        mw = self.main_window()
        enc = mw.encoding_combo.currentText() if mw else "utf-8"

        try:
            with open(f1, "r", encoding=enc, errors="ignore") as a, open(f2, "r", encoding=enc, errors="ignore") as b:
                a_lines = a.readlines()
                b_lines = b.readlines()
        except Exception as e:
            self.output.appendPlainText(f"[ERROR] 無法讀取檔案: {e}")
            return

        import difflib
        diff = list(difflib.unified_diff(a_lines, b_lines, fromfile=f1, tofile=f2, lineterm=""))
        self.output.clear()
        self.output.setPlainText("")  # ✅ 保證每次比對都重設文字格式

        for line in diff:
            if line.startswith("+") and not line.startswith("+++"):
                color = "#2ecc71"  # 新增
                self.output.appendHtml(f"<span style='color:{color}'>{line}</span>")
            elif line.startswith("-") and not line.startswith("---"):
                color = "#e74c3c"  # 刪除
                self.output.appendHtml(f"<span style='color:{color}'>{line}</span>")
            else:
                color = "#95a5a6"  # 保留
                self.output.appendHtml(f"<span style='color:{color}'>{line}</span>")

        self.output.appendPlainText("\n[Finished]")

class PingPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("測試連線品質、延遲 (Count 可設定)。支援範圍 Ping 與 Port 模式。")

        form = QtWidgets.QFormLayout()

        # count
        self.cnt = QtWidgets.QLineEdit("4")
        form.addRow("Count:", self.cnt)

        # port
        self.port_edit = QtWidgets.QLineEdit()
        self.port_edit.setPlaceholderText("輸入 Port (選填)")
        form.addRow("Port:", self.port_edit)

        # 範圍 Ping 勾選框
        self.range_ck = QtWidgets.QCheckBox("範圍 Ping")
        form.addRow("", self.range_ck)

        # 起始與結束 IP 輸入框
        self.range_widget = QtWidgets.QWidget()
        range_layout = QtWidgets.QHBoxLayout(self.range_widget)
        range_layout.setContentsMargins(0, 0, 0, 0)
        self.start_ip = QtWidgets.QLineEdit()
        self.end_ip = QtWidgets.QLineEdit()
        self.start_ip.setPlaceholderText("起始 IP")
        self.end_ip.setPlaceholderText("結束 IP")
        range_layout.addWidget(QtWidgets.QLabel("從"))
        range_layout.addWidget(self.start_ip)
        range_layout.addWidget(QtWidgets.QLabel("到"))
        range_layout.addWidget(self.end_ip)
        self.range_widget.setVisible(False)

        self.options_layout.addLayout(form)
        self.options_layout.addWidget(self.range_widget)

        # 切換範圍模式時顯示/隱藏輸入框
        self.range_ck.toggled.connect(lambda v: self.range_widget.setVisible(v))

    def on_start_clicked(self):
        use_wsl = self.use_wsl_ck.isChecked()
        cnt = self.cnt.text().strip() or "4"
        port = self.port_edit.text().strip()

        if self.range_ck.isChecked():
            # 範圍模式
            start_ip = self.start_ip.text().strip()
            end_ip = self.end_ip.text().strip()
            if not start_ip or not end_ip:
                self.output.appendPlainText("[ERROR] 請輸入起始與結束 IP")
                return
            try:
                start_int = int(ipaddress.IPv4Address(start_ip))
                end_int = int(ipaddress.IPv4Address(end_ip))
            except Exception:
                self.output.appendPlainText("[ERROR] IP 格式錯誤")
                return
            if end_int < start_int:
                self.output.appendPlainText("[ERROR] 結束 IP 應大於起始 IP")
                return
            ip_list = [str(ipaddress.IPv4Address(i)) for i in range(start_int, end_int + 1)]
            self._start_range_ping(ip_list, port, cnt, use_wsl)
        else:
            # 單一 IP
            target = self.target_edit.text().strip() or "8.8.8.8"
            if port:
                self._start_single_port_ping(target, port, cnt, use_wsl)
            else:
                # ✅ 修正：WSL 最終指令需包含 'ping'
                cnt_raw = self.cnt.text().strip()
                try:
                    cnt_num = str(int(''.join(ch for ch in cnt_raw if ch.isdigit())))
                except:
                    cnt_num = "4"

                if use_wsl:
                    # ✅ WSL 版本
                    self.start_worker(["wsl", "ping", "-4", "-c", cnt_num, target])
                else:
                    # ✅ Windows 版本：手動拼出乾淨字串指令，交給 PowerShell -Command 執行
                    cmd_str = f"ping -n {cnt_num} {target}"
                    self.start_worker([cmd_str])

    # --- helper: 實際跑一次 OS ping 並解析 time/ttl ---
    def _run_os_ping_parse(self, ip, cnt, use_wsl):
        """
        執行系統 ping（依 WSL/Windows 自動選），回傳：
          times_ms: List[int] 每次回覆的時間
          ttl_val: Optional[int] 從回覆行解析到的 TTL（以第一個成功值為準，可能為 None）
        """
        if use_wsl:
            cmd = ["wsl", "ping", "-c", str(cnt), ip]
        else:
            cmd = ["ping", "-n", str(cnt), ip]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            out = p.stdout or ""  # 有些系統在 stderr
            lines = out.splitlines()

            times_ms = []
            ttl_val = None

            # 支援 Windows 繁中/英，以及 WSL 英文格式
            # 時間(ms)：可能是 "時間=4ms"、"time=4 ms"、"time<1ms"
            time_pat = re.compile(r"(?:時間|time)\s*=?\s*<?\s*(\d+)\s*ms", re.IGNORECASE)
            # TTL：可能是 "TTL=64"、"ttl=64"
            ttl_pat = re.compile(r"(?:TTL|ttl)\s*=\s*(\d+)", re.IGNORECASE)

            for ln in lines:
                # 解析時間
                mt = time_pat.search(ln)
                if mt:
                    try:
                        times_ms.append(int(mt.group(1)))
                    except:
                        pass
                # 解析 TTL（第一個成功值記錄下來）
                if ttl_val is None:
                    mt2 = ttl_pat.search(ln)
                    if mt2:
                        try:
                            ttl_val = int(mt2.group(1))
                        except:
                            pass

            return times_ms, ttl_val
        except Exception:
            return [], None

    def _start_single_port_ping(self, target, port, cnt, use_wsl):
        """單一 IP + Port 模式：模擬 tcping 行為，多次測試 TCP 連線並輸出延遲"""
        import time
        
        self.output.clear()
        self.output.appendPlainText(f"Ping {target}:{port} (使用 32 位元組的資料):\n")

        times = []
        success_count = 0

        for i in range(int(cnt)):
            start = time.time()
            ok = False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                res = sock.connect_ex((target, int(port)))
                end = time.time()
                sock.close()
                if res == 0:
                    ok = True
            except Exception as e:
                end = time.time()
                ok = False

            duration_ms = int(round((end - start) * 1000))
            if ok:
                success_count += 1
                times.append(duration_ms)
                # 即時輸出這次成功
                self.output.appendPlainText(f"回覆自 {target}:{port}: 位元組=32 時間={duration_ms}ms")
            else:
                # 失敗的話也印出一句失敗
                self.output.appendPlainText(f"連線超時 {target}:{port}")

            QtWidgets.QApplication.processEvents()
            # 可在兩次 probe 間稍微 sleep，以避免瞬間過度擁擠
            time.sleep(0.1)

        # 統計結果
        sent = int(cnt)
        received = success_count
        lost = sent - received
        loss_pct = int(round(lost * 100.0 / sent)) if sent else 0

        self.output.appendPlainText(f"\n{target} 的 Ping 統計資料:")
        self.output.appendPlainText(f"    封包: 已傳送 = {sent}，已收到 = {received}, 已遺失 = {lost} ({loss_pct}% 遺失)，")
        if times:
            self.output.appendPlainText(f"    時間 (毫秒): 最小 = {min(times)}，最大 = {max(times)}，平均 = {int(round(sum(times)/len(times)))}")
        else:
            self.output.appendPlainText("    時間 (毫秒): 無法取得")

        # 最後顯示 port 狀態
        self.output.appendPlainText(f"\n[PORT 狀態] {target}:{port} - {'Open' if received > 0 else 'Closed'}")

    def _start_range_ping(self, ip_list, port, cnt, use_wsl):
        """多線程範圍 Ping / Port 掃描（加入 4 次基底與 loss% 計算）"""
        import re

        self.output.clear()
        self.output.appendPlainText("[多線程範圍 Ping 啟動]\n")
        self.progress.setVisible(True)
        self.progress.setRange(0, len(ip_list))
        self.progress.setValue(0)

        results = {}
        futures = []
        max_workers = min(64, len(ip_list))
        pool = ThreadPoolExecutor(max_workers=max_workers)

        # --- 子任務：每個 IP 的 ping / port 檢測 ---
        def ping_or_port(ip):
            if port:
                # 特定 port：TCP connect
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.8)
                    ok = (sock.connect_ex((ip, int(port))) == 0)
                    sock.close()
                    return ip, ok, 0.0  # port 模式不算 loss%
                except:
                    return ip, False, 0.0
            else:
                # 一般 ping（4次基底）
                if use_wsl:
                    cmd = ["wsl", "ping", "-4", "-c", "4", ip]
                else:
                    cmd = ["ping", "-n", "4", ip]

                try:
                    p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    out = (p.stdout or "").lower()

                    # --- 解析封包資訊 ---
                    if use_wsl:
                        # Linux / WSL 格式：4 packets transmitted, 4 received, 0% packet loss
                        m = re.search(r"(\d+)\s+packets\s+transmitted.*?(\d+)\s+received", out)
                        if m:
                            sent, received = int(m.group(1)), int(m.group(2))
                        else:
                            sent, received = 4, 0
                    else:
                        # Windows 格式：已傳送 = 4，已收到 = 4，已遺失 = 0
                        m = re.search(r"已傳送\s*=\s*(\d+).*?已收到\s*=\s*(\d+).*?已遺失\s*=\s*(\d+)", out)
                        if m:
                            sent, received, lost = int(m.group(1)), int(m.group(2)), int(m.group(3))
                        else:
                            # 英文版 fallback
                            m2 = re.search(r"sent\s*=\s*(\d+).*?received\s*=\s*(\d+).*?lost\s*=\s*(\d+)", out)
                            if m2:
                                sent, received, lost = int(m2.group(1)), int(m2.group(2)), int(m2.group(3))
                            else:
                                sent, received, lost = 4, 0, 4

                    # --- 計算 loss% ---
                    loss_rate = (1 - received / max(sent, 1)) * 100
                    return ip, (received > 0), loss_rate

                except:
                    return ip, False, 100.0

        # --- 建立所有任務 ---
        for ip in ip_list:
            futures.append(pool.submit(ping_or_port, ip))

        completed = 0
        for f in as_completed(futures):
            ip, ok, loss = f.result()
            results[ip] = (ok, loss)
            completed += 1
            self.progress.setValue(completed)

            # --- 即時排序輸出 ---
            sorted_ips = sorted(results.keys(), key=lambda x: tuple(map(int, x.split('.'))))
            self.output.clear()
            for ipx in sorted_ips:
                okx, lossx = results[ipx]
                tag = f"{ipx}:{port}" if port else ipx
                if not okx or lossx >= 100.0:
                    self.output.appendPlainText(f"🔴 [{tag}] Ping Fail")
                else:
                    loss_text = ""
                    if lossx >= 1:
                        # 取 25%,50%,75% 四個級距
                        step = int(round(lossx / 25.0)) * 25
                        if step >= 100: step = 100
                        if step > 0:
                            loss_text = f" [loss {step}%]"
                    self.output.appendPlainText(f"🟢 [{tag}] Ping OK{loss_text}")
            QtWidgets.QApplication.processEvents()

        pool.shutdown(wait=False)
        self.progress.setVisible(False)
        self.output.appendPlainText("\n[Finished]")

class NcPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("連線傳輸測試。若勾選 WSL，執行 WSL 的 nc。")
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
        exe = "wsl nc" if use_wsl else ("nc" if command_exists("nc") else ("ncat" if command_exists("ncat") else "nc"))
        if mode == "connect": self.start_worker([exe, h, p])
        else: self.start_worker([exe, "-l", "-p", p])

class NmapWorker(QThread):
    # 定義信號，用於在任務完成後更新 GUI
    finished_signal = pyqtSignal(str, str)  # 結果: stdout, stderr

    def __init__(self, cmd, parent=None):
        super().__init__(parent)
        self.cmd = cmd

    def run(self):
        # 執行命令
        try:
            process = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()
            # 發送結果到主線程
            self.finished_signal.emit(stdout.decode(), stderr.decode())
        except Exception as e:
            self.finished_signal.emit("", f"[ERROR] 執行命令時出現錯誤: {e}")


class NmapPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.desc.setText("掃描主機/埠。WSL + sudo 支援（會使用 echo PW | sudo -S 執行，注意風險）。")
        
        f = QtWidgets.QFormLayout()
        
        # 設置掃描選項
        self.scan = QtWidgets.QComboBox()
        self.scan.addItems(["-sT (TCP 連線掃描)", "-sS (SYN 掃描)", "-sU (UDP 掃描)", "-sn (Ping 掃描)"])
        
        # 設置端口範圍
        self.ports = QtWidgets.QLineEdit()
        self.ports.setPlaceholderText("1-1024 or 22,80,443")
        
        # 額外參數
        self.extra = QtWidgets.QLineEdit()
        self.extra.setPlaceholderText("-A -Pn -T4")
        
        # WSL sudo 勾選框和密碼輸入框
        self.sudo_ck = QtWidgets.QCheckBox("Use sudo (when using WSL)")
        self.sudo_pass = QtWidgets.QLineEdit()
        self.sudo_pass.setEchoMode(QtWidgets.QLineEdit.Password)
        
        # 將元素加到佈局中
        f.addRow("Scan:", self.scan)
        f.addRow("Ports:", self.ports)
        f.addRow("Extra:", self.extra)
        f.addRow("", self.sudo_ck)
        f.addRow("WSL sudo 密碼:", self.sudo_pass)
        
        self.options_layout.addLayout(f)

    def on_start_clicked(self):
        target = self.target_edit.text().strip()
        if not target:
            self.output.appendPlainText("[ERROR] 請輸入 target")
            return

        # 取得 scan flag（前 3 個字元應該足夠 -sT/-sS/-sU/-sn）
        scan_flag = self.scan.currentText()[0:3]

        # 組 ports & extra
        parts = []
        if self.ports.text().strip():
            parts += ["-p", self.ports.text().strip()]
        if self.extra.text().strip():
            parts += shlex.split(self.extra.text().strip())

        use_wsl = self.use_wsl_ck.isChecked()
        use_sudo = self.sudo_ck.isChecked()
        # 基本 nmap 命令陣列（不含 sudo）
        if not use_wsl:
            cmd_parts = ["nmap", scan_flag] + parts + ["-oN", "-", target]
        else:
            if use_sudo:
                cmd_parts = ["nmap", scan_flag] + parts + ["-oN", "-", target]
            else:
                cmd_parts = ["wsl","nmap", scan_flag] + parts + ["-oN", "-", target]        

        # 如果選擇使用 WSL 並且勾選了 sudo，則處理 sudo 密碼並用 wsl echo 'pw' | sudo -S ...
        if use_wsl and use_sudo:
            pw = self.sudo_pass.text()
            if not pw:
                self.output.appendPlainText("[ERROR] 勾選 Use sudo 但未填密碼")
                return

            # 安全跳脫單引號，避免破壞 shell 字串
            safe_pw = shell_single_quote_escape(pw)

            # 把 cmd_parts 轉成被 shell 正確解析的單行字串（用 shlex.quote）
            # 注意：在 Windows 上我們會 prefix 'wsl '，讓整個管線在 WSL bash 內執行
            nmap_cmd_str = " ".join(shlex.quote(p) for p in cmd_parts)

            # 最終我們要的指令格式（如你要求）
            bash_cmd = f"echo '{safe_pw}' | sudo -S {nmap_cmd_str}"

            # 加上 wsl 前綴，呈現你期望的輸出： wsl echo 'pw' | sudo -S nmap ...
            final_cmd = f"wsl {bash_cmd}"

            # debug（可留可刪）
            print(f"執行的 WSL 命令: {final_cmd}")

            # 使用 start_worker 傳入 single-string list（與你現有程式相容）
            self.start_worker([final_cmd])
            return

        # 否則（沒勾 WSL 或沒勾 sudo）直接執行本地 nmap 命令（list）
        self.start_worker(cmd_parts)
        
class TraceroutePage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("路由追蹤。請在 Options 欄直接輸入完整 traceroute 參數（例如 -4 -d -w 300 -m 30）。")
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
            cmd = ["wsl","traceroute"] + opts + [tgt]
        self.start_worker(cmd)

class DigPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("DNS 查詢，可加 +short 顯示簡短答案。")
        h = QtWidgets.QHBoxLayout(); self.short_ck = QtWidgets.QCheckBox("+short"); h.addWidget(self.short_ck); h.addStretch()
        self.options_layout.addLayout(h)
    def on_start_clicked(self):
        t = self.target_edit.text().strip() or "example.com"
        if self.short_ck.isChecked(): self.start_worker(["wsl","dig","+short",t])
        else: self.start_worker(["wsl","dig",t])

class CurlPage(ToolPageBase):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.desc.setText("請求HTTP(S)，檢查 header/status，或列出HTML。")
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
        self.desc.setText("暴力破解（請在授權範圍內使用）。User/Pass 可選 Single 或 File（editable）。")
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
        if svc == "http-post-form" or svc == "http-get":
            self.http_group.setVisible(True)
        else:
            self.http_group.setVisible(False)

    def on_start_clicked(self):
        svc = self.service.currentText()  # 取得選擇的服務
        tgt = self.target_edit.text().strip()
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
            user_arg = ["-l", u]  # 使用 -l 來指定單一用戶名
        else:
            ufile = self.user_file.text().strip()
            if not ufile: 
                self.output.appendPlainText("[ERROR] User file 未填")
                return
            if not os.path.exists(ufile): 
                self.output.appendPlainText(f"[WARN] User file 在此系統找不到: {ufile}")
            # 確保 WSL 路徑轉換
            user_arg = ["-L", self._convert_path_for_execution(ufile, use_wsl)]  

        # 處理密碼（單一或文件）
        if self.pass_single_rb.isChecked():
            p = self.pass_single.text().strip()
            if not p: 
                self.output.appendPlainText("[ERROR] Password empty")
                return
            pass_arg = ["-p", p]  # 使用 -p 來指定單一密碼
        else:
            pfile = self.pass_file.text().strip()
            if not pfile: 
                self.output.appendPlainText("[ERROR] Pass file 未填")
                return
            if not os.path.exists(pfile): 
                self.output.appendPlainText(f"[WARN] Pass file 在此系統上找不到: {pfile}")
            # 確保 WSL 路徑轉換
            pass_arg = ["-P", self._convert_path_for_execution(pfile, use_wsl)]  

        # 處理執行參數
        threads = self.threads.text().strip() or "4"
        
        # 根據選擇的服務生成不同的命令格式
        if svc == "http-post-form" or svc == "http-get":
            # 處理 http-get-form / http-post-form
            path = self.hp_path.text().strip().lstrip("/")
            ufield = self.hp_userfield.text().strip() or "uid"
            pfield = self.hp_passfield.text().strip() or "passw"
            extra = self.hp_extrafield.text().strip()
            fail = self.hp_failstr.text().strip() or "Login Failed"

            params = f"{ufield}=^USER^&{pfield}=^PASS^"
            if extra:
                params += extra if extra.startswith("&") else "&" + extra

            form = f"/{path}:{params}:{fail}"

            # 根據 service + HTTPS 勾選決定協定
            if svc == "http-post-form":
                proto = "https-post-form" if self.hp_https_ck.isChecked() else "http-post-form"
            elif svc == "http-get":
                proto = "https-get-form" if self.hp_https_ck.isChecked() else "http-get-form"
            else:
                proto = svc  # fallback，理論上不會到這裡

            cmd = ["hydra"] + user_arg + pass_arg + ["-t", threads, f"{tgt} {proto} \"{form}\""]

        elif svc == "ssh":
            # 處理 ssh
            cmd = ["hydra"] + user_arg + pass_arg + ["-t", threads, f"{tgt} ssh"]

        elif svc == "ftp":
            # 處理 ftp
            cmd = ["hydra"] + user_arg + pass_arg + ["-t", threads, f"{tgt} ftp"]

        if use_wsl:
            cmd = ["wsl"] + cmd
        # 輸出命令並開始執行
        print(f"最終命令：{' '.join(cmd)}")
        self.start_worker(cmd)

class SshPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("使用 WSL SSH 連線遠端主機，可輸入命令並即時取得輸出結果。")

        # --- 帳號密碼輸入 ---
        form = QtWidgets.QFormLayout()
        h = QtWidgets.QHBoxLayout()
        self.user_edit = QtWidgets.QLineEdit()
        self.user_edit.setPlaceholderText("username")
        self.pass_edit = QtWidgets.QLineEdit()
        self.pass_edit.setPlaceholderText("password (留空則使用金鑰登入)")
        self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        h.addWidget(self.user_edit)
        h.addWidget(QtWidgets.QLabel("/"))
        h.addWidget(self.pass_edit)
        form.addRow("帳號 / 密碼:", h)

        self.port_edit = QtWidgets.QLineEdit()
        self.port_edit.setPlaceholderText("22 (預設)")
        form.addRow("Port:", self.port_edit)
        self.options_layout.addLayout(form)

        # --- 命令輸入欄 ---
        cmd_bar = QtWidgets.QHBoxLayout()
        self.cmd_edit = QtWidgets.QLineEdit()
        self.cmd_edit.setPlaceholderText("輸入指令（例如：ls、pwd、cat /etc/passwd ...）")
        self.cmd_edit.returnPressed.connect(self._exec_command)
        self.cmd_btn = QtWidgets.QPushButton("執行")
        self.cmd_btn.clicked.connect(self._exec_command)
        cmd_bar.addWidget(self.cmd_edit)
        cmd_bar.addWidget(self.cmd_btn)
        self.layout().addLayout(cmd_bar)

        # --- 輸出區（純輸出） ---
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("SSH 輸出結果將顯示在此")
        self.output.setFont(QtGui.QFont("Consolas", 10))

        self._proc = None
        self._reader_thread = None
        self._connected = False

    def on_start_clicked(self):
        host = self.target_edit.text().strip()
        user = self.user_edit.text().strip()
        pw = self.pass_edit.text().strip()
        port = self.port_edit.text().strip() or "22"

        if not host or not user:
            self.output.appendPlainText("[ERROR] 請輸入主機與帳號")
            return

        self.output.clear()
        self.output.appendPlainText(f"嘗試連線 {user}@{host}:{port} ...\n")

        # --- 組合 SSH 指令 ---
        if pw:
            bash_cmd = (
                f"sshpass -p '{pw}' ssh -tt "
                f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"{user}@{host} -p {port}"
            )
        else:
            bash_cmd = (
                f"ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"{user}@{host} -p {port}"
            )

        cmd = ["wsl", "-e", "bash", "-l", "-c", bash_cmd]

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                bufsize=1
            )
            self._connected = True
            self.output.appendPlainText("✅ SSH 已啟動，可輸入命令或使用上方欄位執行。\n")

            # 啟動非阻塞讀取執行緒
            self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
            self._reader_thread.start()

        except Exception as e:
            self.output.appendPlainText(f"[ERROR] 無法啟動 SSH：{e}")

    def _read_output(self):
        # 移除 ANSI 顏色碼與 OSC 控制序列（含 \x1b]0;... 類型）
        ansi_osc_escape = re.compile(
            r'\x1B\][^\x07]*\x07'  # 抓出 \x1b]0;... \x07 整段
            r'|\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])'  # 抓出顏色控制碼
        )

        if not self._proc:
            return

        prompt_pat = re.compile(r'^[\w\-.]+@[\w\-.]+[:].*[$#]\s*$')
        banner_pat = re.compile(r'^(Welcome|Last login|Linux|Ubuntu|Authorized|Type "help"|Documentation|Support|Management|Expanded Security|Learn more|New release|\s*$)')

        started = False
        for line in iter(self._proc.stdout.readline, ''):
            if not line:
                break

            # 去除控制碼與換行
            clean_line = ansi_osc_escape.sub('', line).rstrip('\r\n')

            # 登入初始階段：過濾空白、banner、prompt、控制碼產生的空字串
            if not started:
                if (
                    clean_line.strip() == "" or
                    banner_pat.match(clean_line) or
                    prompt_pat.match(clean_line)
                ):
                    continue
                started = True

            # 執行過程中：過濾 prompt
            if prompt_pat.match(clean_line):
                continue

            QtCore.QMetaObject.invokeMethod(
                self.output,
                "appendPlainText",
                QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, clean_line)
            )

        self._proc.wait()


    def _exec_command(self):
        if not self._proc or self._proc.poll() is not None:
            return

        cmd = self.cmd_edit.text().strip()
        if not cmd:
            return

        try:
            if not cmd.endswith("\n"):
                cmd += "\n"
            self._proc.stdin.write(cmd)
            self._proc.stdin.flush()
            self.cmd_edit.clear()
        except Exception as e:
            QtCore.QMetaObject.invokeMethod(
                self.output,
                "appendPlainText",
                QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, f"[ERROR] 指令送出失敗: {e}")
            )

    def on_stop_clicked(self):
        if self._proc:
            try:
                self._proc.terminate()
            except:
                pass
        self._connected = False
        self.output.appendPlainText("[SSH 連線結束]")

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
        tools = ["顯示當前裝置資訊","檔案列表","查看文件內容","IP狀態查詢","傳輸測試","埠口掃描","路由追蹤","DNS查詢","網頁原始碼擷取","弱密碼測試","SSH連線"]
        for t in tools:
            it = QtWidgets.QListWidgetItem(t); it.setTextAlignment(QtCore.Qt.AlignVCenter)
            self.nav.addItem(it)
        main_h.addWidget(self.nav)

        # content stack
        self.stack = QtWidgets.QStackedWidget(); main_h.addWidget(self.stack,1)
        clsmap = {"顯示當前裝置資訊":WhoamiPage,"檔案列表":LsPage,"查看文件內容":CatPage,"IP狀態查詢":PingPage,"傳輸測試":NcPage,"埠口掃描":NmapPage,"路由追蹤":TraceroutePage,"DNS查詢":DigPage,"網頁原始碼擷取":CurlPage,"弱密碼測試":HydraPage,"SSH連線": SshPage}
        self.pages = {}
        for name in tools:
            p = clsmap[name](self); self.pages[name] = p; self.stack.addWidget(p)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex); self.nav.setCurrentRow(0)

        # status bar - encoding + wsl status
        self.status = QtWidgets.QStatusBar(); self.setStatusBar(self.status)
        self.encoding_label = QtWidgets.QLabel("編碼:")
        self.encoding_combo = QtWidgets.QComboBox()
        encs = ["utf-8","cp950","big5","gbk","shift_jis","iso-8859-1","windows-1252","euc-kr","utf-16"]
        self.encoding_combo.addItems(encs); self.encoding_combo.setCurrentText("cp950"); self.set_encoding_based_on_wsl(False, initial=True); self.encoding_combo.setFixedWidth(140)
        self.status.addPermanentWidget(self.encoding_label); self.status.addPermanentWidget(self.encoding_combo)
        self.wsl_status_label = QtWidgets.QLabel(); self.wsl_status_label.setFixedWidth(160)
        self.status.addPermanentWidget(self.wsl_status_label)
        self._update_wsl_status(initial=True)
        self.wsl_timer = QtCore.QTimer(self); self.wsl_timer.setInterval(5000); self.wsl_timer.timeout.connect(self._update_wsl_status); self.wsl_timer.start()
        men = self.menuBar(); env = men.addMenu("Env")
        ac = QtWidgets.QAction("Check WSL Now", self); ac.triggered.connect(lambda: self._update_wsl_status(force=True)); env.addAction(ac)
        self.encoding_combo.currentTextChanged.connect(lambda t: self.status.showMessage(f"編碼: {t}",1500))
        self.nav.currentRowChanged.connect(self._sync_encoding_on_page_change)

    def set_encoding_based_on_wsl(self, use_wsl: bool, initial=False):
        """依據是否使用 WSL 自動切換右下角編碼"""
        if use_wsl:
            self.encoding_combo.setCurrentText("utf-8")
            if not initial:
                self.status.showMessage("已自動切換為 UTF-8（WSL 模式）", 2000)
        else:
            self.encoding_combo.setCurrentText("cp950")
            if not initial:
                self.status.showMessage("已自動切換為 CP950（Windows 模式）", 2000)

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

    def _sync_encoding_on_page_change(self, index):
        page = self.stack.widget(index)
        if hasattr(page, "use_wsl_ck"):
            self.set_encoding_based_on_wsl(page.use_wsl_ck.isChecked())

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