import sys
import os
import shlex
import subprocess
import shutil
import time
import re
import threading
import ipaddress
import socket
import difflib
import html
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QThread, pyqtSignal

# ==========================================
#              CONFIG & STYLES
# ==========================================

APP_STYLESHEET = """
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
        font-family: "FiraCode Nerd Font Mono", "Consolas", "Segoe UI", sans-serif;
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
    QPushButton:disabled {
        background-color: #A0A0A0;
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
    QProgressBar {
        border: 1px solid #D1D1D6;
        border-radius: 4px;
        text-align: center;
    }
    QProgressBar::chunk {
        background-color: #007AFF;
    }
    /* Scrollbar styling */
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
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
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
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
"""

# Windows 下隱藏 subprocess 視窗的 hack
if sys.platform.startswith("win"):
    _orig_popen = subprocess.Popen

    def quiet_popen(*args, **kwargs):
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        return _orig_popen(*args, **kwargs)

    subprocess.Popen = quiet_popen

# ==========================================
#              HELPER FUNCTIONS
# ==========================================

_wsl_cache = {"val": None, "ts": 0}
WSL_CACHE_TTL = 3.0

def is_windows():
    return sys.platform.startswith("win")

def wsl_available(force=False):
    global _wsl_cache
    now = time.time()
    if not force and (_wsl_cache["val"] is not None and now - _wsl_cache["ts"] < WSL_CACHE_TTL):
        return _wsl_cache["val"]
    
    val = False
    if not is_windows():
        _wsl_cache.update({"val": False, "ts": now})
        return False
        
    cmds = [["wsl", "wslpath", "/"], ["wsl", "-l"], ["wsl", "echo", "ok"]]
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

def command_exists(cmd):
    return shutil.which(cmd) is not None

def shell_single_quote_escape(s: str):
    return s.replace("'", "'\"'\"'")

def build_powershell_command_str(cmd_list):
    exe = cmd_list[0].lower()
    args = cmd_list[1:]
    def q(s): return s.replace('"', '\\"')
    
    if exe in ("ls", "dir"):
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
        cnt = "4"
        host = args[-1] if args else "8.8.8.8"
        for i, a in enumerate(args):
            if a.startswith("-") and "c" in a:
                if i + 1 < len(args):
                    cnt = args[i + 1]
        return f"ping -n {cnt} {q(host)}"
        
    if exe in ("traceroute", "tracepath"):
        host = args[-1] if args else "8.8.8.8"
        return f"tracert {q(host)}"
        
    if exe in ("dig",):
        host = args[-1] if args else "example.com"
        return f"nslookup {q(host)}"
        
    return " ".join([q(x) for x in cmd_list])

def build_final_command(cmd_list, use_wsl=False):
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
    elif is_windows() and not use_wsl:
        exe = cmd_list[0].lower()
        external = {"nmap", "ncat", "nc", "hydra", "john", "hashid", "tcpdump"}
        if exe in external and command_exists(exe):
            return cmd_list
        ps = build_powershell_command_str(cmd_list)
        return ["powershell", "-NoProfile", "-Command", ps]
    return cmd_list

class AnsiConverter:
    """ ANSI 轉 HTML 處理器 """
    
    def __init__(self):
        self.COLORS = {
            '30': 'black', '31': '#d9534f', '32': '#2ea84a', '33': '#f0ad4e',
            '34': '#007aff', '35': '#9b59b6', '36': '#5bc0de', '37': '#d4d4d4',
            '90': 'gray', '91': '#ff6b6b', '92': '#51cf66', '93': '#fcc419',
            '94': '#339af0', '95': '#cc5de8', '96': '#66d9e8', '97': 'white',
        }
        self.BOLD_COLORS = {
            '30': 'gray', '31': '#ff6b6b', '32': '#51cf66', '33': '#fcc419',
            '34': '#5c9ce6', '35': '#cc5de8', '36': '#66d9e8', '37': 'white',
        }

    def convert(self, text):
        # 1. 移除 Shell 垃圾訊號
        text = re.sub(r'\x1b\[\?2004[hl]', '', text)
        text = re.sub(r'\x1b\[\?1[hl]', '', text)
        text = re.sub(r'\x1b\]0;.*?\x07', '', text)

        # 2. HTML Escape
        text = html.escape(text)

        # 3. 處理 ANSI 顏色碼
        def ansi_sub(match):
            code = match.group(1)
            if code == '0' or code == '00':
                return '</span>'
            
            parts = code.split(';')
            style = []
            fg_color = None
            is_bold = False

            for part in parts:
                if part == '1' or part == '01':
                    is_bold = True
                    style.append('font-weight:bold')
                elif part in self.COLORS:
                    fg_color = part

            if fg_color:
                c_hex = self.BOLD_COLORS.get(fg_color) if is_bold else self.COLORS.get(fg_color)
                style.append(f'color:{c_hex}')
            
            if style:
                return f'<span style="{";".join(style)}">'
            return ''

        text = re.sub(r'\x1b\[([0-9;]*)m', ansi_sub, text)
        
        # 4. 移除其他無法處理的 ANSI 控制碼
        text = re.sub(r'\x1b\[[0-9;?]*[a-zA-Z]', '', text)
        
        # [修正] 這裡不再將 \n 轉為 <br>，交給 SshPage 處理物理換行
        return text

# ==========================================
#              WORKER THREAD
# ==========================================

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
            print("最終命令：", full_cmd)

            if isinstance(full_cmd, list):
                full_cmd = ' '.join(full_cmd)

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

# ==========================================
#              BASE PAGE CLASS
# ==========================================

class ToolPageBase(QtWidgets.QWidget):
    def __init__(self, parent=None):
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
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        self.desc = QtWidgets.QLabel("")
        self.desc.setWordWrap(True)
        self.desc.setFixedHeight(56)
        layout.addWidget(self.desc)

        top_layout = QtWidgets.QHBoxLayout()
        form_layout = QtWidgets.QFormLayout()
        
        self.target_label = QtWidgets.QLabel("Target / Args:")
        self.target_edit = QtWidgets.QLineEdit()
        self.target_edit.setPlaceholderText("Target or arguments")
        form_layout.addRow(self.target_label, self.target_edit)
        top_layout.addLayout(form_layout, 1)

        right_layout = QtWidgets.QVBoxLayout()
        self.use_wsl_ck = QtWidgets.QCheckBox("使用 WSL 執行 (Windows)")
        right_layout.addWidget(self.use_wsl_ck, 0, QtCore.Qt.AlignTop)
        right_layout.addStretch()
        top_layout.addLayout(right_layout)
        
        layout.addLayout(top_layout)

        self.options_box = QtWidgets.QWidget()
        self.options_layout = QtWidgets.QVBoxLayout(self.options_box)
        self.options_layout.setContentsMargins(0, 0, 0, 0)
        
        self.options_scroll = QtWidgets.QScrollArea()
        self.options_scroll.setWidgetResizable(True)
        self.options_scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.options_scroll.setWidget(self.options_box)
        layout.addWidget(self.options_scroll)

        actions = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("Start")
        self.stop_btn = QtWidgets.QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        
        self.use_wsl_ck.toggled.connect(
            lambda v: self.main_window().set_encoding_based_on_wsl(v)
        )
        
        actions.addWidget(self.start_btn)
        actions.addWidget(self.stop_btn)
        actions.addStretch()
        layout.addLayout(actions)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setVisible(False)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(18)
        layout.addWidget(self.progress)

        self.output = QtWidgets.QPlainTextEdit()
        self.output.setReadOnly(True)
        font = QtGui.QFont("Consolas" if is_windows() else "Monospace", 10)
        self.output.setFont(font)
        layout.addWidget(self.output, 1)

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
            exe = cmd_list[0].lower() if isinstance(cmd_list, list) else cmd_list.split()[0].lower()
            if exe in {"nmap", "hydra", "john", "tcpdump", "hashid", "ncat", "nc", "gobuster"} and not command_exists(exe):
                self.output.appendPlainText(f"[WARN] 系統找不到 {exe}；請安裝或改勾 WSL")
                
        self.progress.setVisible(True)
        self.progress.setRange(0, 100)
        self.progress.setValue(50)
        
        self.worker = CmdWorker(cmd_list, encoding=encoding, use_wsl=use_wsl)
        self.thread = QtCore.QThread()
        self.worker.moveToThread(self.thread)
        self.worker.output_line.connect(self.output.appendPlainText)
        self.worker.finished.connect(self._on_finished)
        self.thread.started.connect(self.worker.run)
        self.thread.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def _on_finished(self):
        self.output.appendPlainText("\n[Finished]")
        self.progress.setValue(100)
        self.progress.setVisible(False)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        if self.thread:
            self.thread.quit()
            self.thread.wait()
            self.thread = None
            self.worker = None

    def on_stop_clicked(self):
        if self.worker:
            self.worker.stop()
            self.output.appendPlainText("[Stopping...]")
            self.stop_btn.setEnabled(False)

    def on_start_clicked(self):
        raise NotImplementedError

# ==========================================
#              TOOL PAGES
# ==========================================

class WhoamiPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("顯示目前電腦系統資訊")
        self.target_label.hide()
        self.target_edit.hide()
        self.options_scroll.hide()
        
    def on_start_clicked(self):
        self.start_worker(["whoami"])

class LsPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("列出目錄內容。Options 可填 -l/-la，Target 為路徑或留空。")
        form = QtWidgets.QFormLayout()
        self.opt = QtWidgets.QLineEdit()
        self.opt.setPlaceholderText("-l -la")
        form.addRow("Options:", self.opt)
        self.options_layout.addLayout(form)
        
    def on_start_clicked(self):
        use_wsl = self.use_wsl_ck.isChecked()
        opts = self.opt.text().strip()
        path = self.target_edit.text().strip() or "."
        
        parts = ["ls"] + (shlex.split(opts) if opts else []) + [path]
        if use_wsl:
            parts.insert(0, "wsl")
            
        self.start_worker(parts)

class CatPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("顯示或比對檔案內容，支援自動編碼偵測與 WSL 模式。")
        self.target_label.hide()
        self.target_edit.hide()
        
        if hasattr(self, 'use_wsl_ck'):
            self.use_wsl_ck.hide()
            
        top_item = self.layout().itemAt(1)
        if top_item and isinstance(top_item, QtWidgets.QLayout):
            top_item.setContentsMargins(0, 0, 0, 0)
            top_item.setSpacing(0)
            for i in range(top_item.count()):
                item = top_item.itemAt(i)
                w = item.widget()
                if w: w.setVisible(False)

        mode_layout = QtWidgets.QHBoxLayout()
        self.single_mode_rb = QtWidgets.QRadioButton("單檔模式")
        self.diff_mode_rb = QtWidgets.QRadioButton("比對模式")
        self.single_mode_rb.setChecked(True)
        mode_layout.addWidget(self.single_mode_rb)
        mode_layout.addWidget(self.diff_mode_rb)
        mode_layout.addStretch()
        self.options_layout.addLayout(mode_layout)
        self.options_layout.addSpacing(10)

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

        self.diff_widget = QtWidgets.QWidget()
        d_form = QtWidgets.QFormLayout(self.diff_widget)
        self.file1_edit = QtWidgets.QLineEdit()
        self.file2_edit = QtWidgets.QLineEdit()
        self.browse1_btn = QtWidgets.QPushButton("Browse")
        self.browse2_btn = QtWidgets.QPushButton("Browse")
        
        b1 = QtWidgets.QHBoxLayout()
        b1.addWidget(self.file1_edit)
        b1.addWidget(self.browse1_btn)
        
        b2 = QtWidgets.QHBoxLayout()
        b2.addWidget(self.file2_edit)
        b2.addWidget(self.browse2_btn)
        
        d_form.addRow("File1:", b1)
        d_form.addRow("File2:", b2)

        self.stack = QtWidgets.QStackedWidget()
        self.stack.addWidget(self.single_widget)
        self.stack.addWidget(self.diff_widget)
        self.options_layout.addWidget(self.stack)

        self.single_mode_rb.toggled.connect(lambda v: self._toggle_mode(v))
        self.browse1_btn.clicked.connect(lambda: self._choose_file(self.file1_edit))
        self.browse2_btn.clicked.connect(lambda: self._choose_file(self.file2_edit))
        self.single_file_btn.clicked.connect(lambda: self._choose_file(self.single_file_edit))

    def _toggle_mode(self, single_mode):
        if single_mode:
            self.stack.setCurrentIndex(0)
            self.stack.setMaximumHeight(100)
        else:
            self.stack.setCurrentIndex(1)
            self.stack.setMaximumHeight(200)
        self.output.clear()
        self.output.setPlainText("")

    def _choose_file(self, target_edit):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "選擇檔案")
        if p:
            target_edit.setText(p)

    def on_start_clicked(self):
        use_wsl = self.use_wsl_ck.isChecked()
        
        if self.single_mode_rb.isChecked():
            f = self.single_file_edit.text().strip()
            if not f:
                self.output.appendPlainText("[ERROR] 請選擇檔案")
                return
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
            
        diff = list(difflib.unified_diff(a_lines, b_lines, fromfile=f1, tofile=f2, lineterm=""))
        self.output.clear()
        self.output.setPlainText("")
        
        for line in diff:
            if line.startswith("+") and not line.startswith("+++"):
                color = "#2ecc71"
                self.output.appendHtml(f"<span style='color:{color}'>{line}</span>")
            elif line.startswith("-") and not line.startswith("---"):
                color = "#e74c3c"
                self.output.appendHtml(f"<span style='color:{color}'>{line}</span>")
            else:
                color = "#95a5a6"
                self.output.appendHtml(f"<span style='color:{color}'>{line}</span>")
        self.output.appendPlainText("\n[Finished]")

class PingPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("測試連線品質、延遲 (Count 可設定)。支援範圍 Ping 與 Port 模式。")
        form = QtWidgets.QFormLayout()
        self.cnt = QtWidgets.QLineEdit("4")
        form.addRow("Count:", self.cnt)
        
        self.port_edit = QtWidgets.QLineEdit()
        self.port_edit.setPlaceholderText("輸入 Port (選填)")
        form.addRow("Port:", self.port_edit)
        
        self.range_ck = QtWidgets.QCheckBox("範圍 Ping")
        form.addRow("", self.range_ck)
        
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
        
        self.range_ck.toggled.connect(lambda v: self.range_widget.setVisible(v))

    def on_start_clicked(self):
        use_wsl = self.use_wsl_ck.isChecked()
        cnt = self.cnt.text().strip() or "4"
        port = self.port_edit.text().strip()
        
        if self.range_ck.isChecked():
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
            target = self.target_edit.text().strip() or "8.8.8.8"
            if port:
                self._start_single_port_ping(target, port, cnt, use_wsl)
            else:
                cnt_raw = self.cnt.text().strip()
                try:
                    cnt_num = str(int(''.join(ch for ch in cnt_raw if ch.isdigit())))
                except:
                    cnt_num = "4"
                if use_wsl:
                    self.start_worker(["wsl", "ping", "-4", "-c", cnt_num, target])
                else:
                    cmd_str = f"ping -n {cnt_num} {target}"
                    self.start_worker([cmd_str])

    def _start_single_port_ping(self, target, port, cnt, use_wsl):
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
            except Exception:
                end = time.time()
                ok = False
                
            duration_ms = int(round((end - start) * 1000))
            if ok:
                success_count += 1
                times.append(duration_ms)
                self.output.appendPlainText(f"回覆自 {target}:{port}: 位元組=32 時間={duration_ms}ms")
            else:
                self.output.appendPlainText(f"連線超時 {target}:{port}")
                
            QtWidgets.QApplication.processEvents()
            time.sleep(0.1)
            
        sent = int(cnt)
        received = success_count
        lost = sent - received
        loss_pct = int(round(lost * 100.0 / sent)) if sent else 0
        
        self.output.appendPlainText(f"\n{target} 的 Ping 統計資料:")
        self.output.appendPlainText(f"    封包: 已傳送 = {sent}，已收到 = {received}, 已遺失 = {lost} ({loss_pct}% 遺失)，")
        if times:
            avg_time = int(round(sum(times) / len(times)))
            self.output.appendPlainText(f"    時間 (毫秒): 最小 = {min(times)}，最大 = {max(times)}，平均 = {avg_time}")
        else:
            self.output.appendPlainText("    時間 (毫秒): 無法取得")
        self.output.appendPlainText(f"\n[PORT 狀態] {target}:{port} - {'Open' if received > 0 else 'Closed'}")

    def _start_range_ping(self, ip_list, port, cnt, use_wsl):
        self.output.clear()
        self.output.appendPlainText("[多線程範圍 Ping 啟動]\n")
        self.progress.setVisible(True)
        self.progress.setRange(0, len(ip_list))
        self.progress.setValue(0)
        
        results = {}
        futures = []
        max_workers = min(64, len(ip_list))
        pool = ThreadPoolExecutor(max_workers=max_workers)
        
        def ping_or_port(ip):
            if port:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.8)
                    ok = (sock.connect_ex((ip, int(port))) == 0)
                    sock.close()
                    return ip, ok, 0.0
                except:
                    return ip, False, 0.0
            else:
                if use_wsl:
                    cmd = ["wsl", "ping", "-4", "-c", "4", ip]
                else:
                    cmd = ["ping", "-n", "4", ip]
                try:
                    p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    out = (p.stdout or "").lower()
                    if use_wsl:
                        m = re.search(r"(\d+)\s+packets\s+transmitted.*?(\d+)\s+received", out)
                        if m:
                            sent, received = int(m.group(1)), int(m.group(2))
                        else:
                            sent, received = 4, 0
                    else:
                        m = re.search(r"已傳送\s*=\s*(\d+).*?已收到\s*=\s*(\d+).*?已遺失\s*=\s*(\d+)", out)
                        if m:
                            sent, received, lost = int(m.group(1)), int(m.group(2)), int(m.group(3))
                        else:
                            m2 = re.search(r"sent\s*=\s*(\d+).*?received\s*=\s*(\d+).*?lost\s*=\s*(\d+)", out)
                            if m2:
                                sent, received, lost = int(m2.group(1)), int(m2.group(2)), int(m2.group(3))
                            else:
                                sent, received, lost = 4, 0, 4
                    loss_rate = (1 - received / max(sent, 1)) * 100
                    return ip, (received > 0), loss_rate
                except:
                    return ip, False, 100.0

        for ip in ip_list:
            futures.append(pool.submit(ping_or_port, ip))
            
        completed = 0
        for f in as_completed(futures):
            ip, ok, loss = f.result()
            results[ip] = (ok, loss)
            completed += 1
            self.progress.setValue(completed)
            
            # Sort output by IP
            sorted_ips = sorted(results.keys(), key=lambda x: tuple(map(int, x.split('.'))))
            self.output.clear()
            
            for ipx in sorted_ips:
                okx, lossx = results[ipx]
                tag = f"{ipx}:{port}" if port else ipx
                
                red_dot = "<span style='color:#FF3B30'>●</span>"
                green_dot = "<span style='color:#28CD41'>●</span>"

                if not okx or lossx >= 100.0:
                    self.output.appendHtml(f"{red_dot} [{tag}] Ping Fail")
                else:
                    loss_text = ""
                    if lossx >= 1:
                        step = int(round(lossx / 25.0)) * 25
                        if step >= 100: step = 100
                        if step > 0:
                            loss_text = f" [loss {step}%]"
                    self.output.appendHtml(f"{green_dot} [{tag}] Ping OK{loss_text}")
            QtWidgets.QApplication.processEvents()
            
        pool.shutdown(wait=False)
        self.progress.setVisible(False)
        self.output.appendPlainText("\n[Finished]")

class NcPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("連線傳輸測試。若勾選 WSL，執行 WSL 的 nc。")
        self.target_label.hide()
        self.target_edit.hide()
        
        f = QtWidgets.QFormLayout()
        self.mode = QtWidgets.QComboBox()
        self.mode.addItems(["connect", "listen"])
        
        self.host = QtWidgets.QLineEdit("127.0.0.1")
        self.port = QtWidgets.QLineEdit()
        
        f.addRow("Mode:", self.mode)
        f.addRow("Host:", self.host)
        f.addRow("Port:", self.port)
        self.options_layout.addLayout(f)
        
    def on_start_clicked(self):
        mode = self.mode.currentText()
        h = self.host.text().strip() or "127.0.0.1"
        p = self.port.text().strip()
        
        if not p:
            self.output.appendPlainText("[ERROR] 請輸入 port")
            return
            
        use_wsl = self.use_wsl_ck.isChecked()
        exe = "wsl nc" if use_wsl else ("nc" if command_exists("nc") else ("ncat" if command_exists("ncat") else "nc"))
        
        if mode == "connect":
            self.start_worker([exe, h, p])
        else:
            self.start_worker([exe, "-l", "-p", p])

class NmapPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("掃描主機/埠。WSL + sudo 支援（會使用 echo PW | sudo -S 執行，注意風險）。")
        f = QtWidgets.QFormLayout()
        
        self.scan = QtWidgets.QComboBox()
        self.scan.addItems(["-sT (TCP 連線掃描)", "-sS (SYN 掃描)", "-sU (UDP 掃描)", "-sn (Ping 掃描)"])
        
        self.ports = QtWidgets.QLineEdit()
        self.ports.setPlaceholderText("1-1024 or 22,80,443")
        
        self.extra = QtWidgets.QLineEdit()
        self.extra.setPlaceholderText("-A -Pn -T4")
        
        self.sudo_ck = QtWidgets.QCheckBox("Use sudo (when using WSL)")
        self.sudo_pass = QtWidgets.QLineEdit()
        self.sudo_pass.setEchoMode(QtWidgets.QLineEdit.Password)
        
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
            
        scan_flag = self.scan.currentText()[0:3]
        parts = []
        if self.ports.text().strip():
            parts += ["-p", self.ports.text().strip()]
        if self.extra.text().strip():
            parts += shlex.split(self.extra.text().strip())
            
        use_wsl = self.use_wsl_ck.isChecked()
        use_sudo = self.sudo_ck.isChecked()
        
        if not use_wsl:
            cmd_parts = ["nmap", scan_flag] + parts + ["-oN", "-", target]
        else:
            if use_sudo:
                cmd_parts = ["nmap", scan_flag] + parts + ["-oN", "-", target]
            else:
                cmd_parts = ["wsl", "nmap", scan_flag] + parts + ["-oN", "-", target]
                
        if use_wsl and use_sudo:
            pw = self.sudo_pass.text()
            if not pw:
                self.output.appendPlainText("[ERROR] 勾選 Use sudo 但未填密碼")
                return
            safe_pw = shell_single_quote_escape(pw)
            nmap_cmd_str = " ".join(shlex.quote(p) for p in cmd_parts)
            bash_cmd = f"echo '{safe_pw}' | sudo -S {nmap_cmd_str}"
            final_cmd = f"wsl {bash_cmd}"
            print(f"執行的 WSL 命令: {final_cmd}")
            self.start_worker([final_cmd])
            return
            
        self.start_worker(cmd_parts)

class TraceroutePage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("路由追蹤。請在 Options 欄直接輸入完整 traceroute 參數（例如 -4 -d -w 300 -m 30）。")
        form = QtWidgets.QFormLayout()
        self.opts_input = QtWidgets.QLineEdit()
        self.opts_input.setPlaceholderText("輸入 traceroute 參數，例如: -4 -d -w 300 -m 30")
        form.addRow("Options:", self.opts_input)
        self.options_layout.addLayout(form)
        
    def on_start_clicked(self):
        tgt = self.target_edit.text().strip()
        if not tgt:
            self.output.appendPlainText("[ERROR] 請輸入 target")
            return
            
        use_wsl = self.use_wsl_ck.isChecked()
        opts = shlex.split(self.opts_input.text().strip()) if self.opts_input.text().strip() else []
        
        if is_windows() and not use_wsl:
            cmd = ["tracert"] + opts + [tgt]
        else:
            cmd = ["wsl", "traceroute"] + opts + [tgt]
        self.start_worker(cmd)

class DigPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("DNS 查詢，可加 +short 顯示簡短答案。")
        h = QtWidgets.QHBoxLayout()
        self.short_ck = QtWidgets.QCheckBox("+short")
        h.addWidget(self.short_ck)
        h.addStretch()
        self.options_layout.addLayout(h)
        
    def on_start_clicked(self):
        t = self.target_edit.text().strip() or "example.com"
        if self.short_ck.isChecked():
            self.start_worker(["wsl", "dig", "+short", t])
        else:
            self.start_worker(["wsl", "dig", t])

class CurlPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("請求HTTP(S)，檢查 header/status，或列出HTML。")
        f = QtWidgets.QFormLayout()
        self.method = QtWidgets.QComboBox()
        self.method.addItems(["GET", "HEAD", "POST"])
        f.addRow("Method:", self.method)
        self.options_layout.addLayout(f)
        
    def on_start_clicked(self):
        url = self.target_edit.text().strip()
        if not url:
            self.output.appendPlainText("[ERROR] 請輸入 URL")
            return
        m = self.method.currentText()
        if m == "HEAD":
            self.start_worker(["curl", "-I", url])
        elif m == "POST":
            self.start_worker(["curl", "-X", "POST", url])
        else:
            self.start_worker(["curl", "-sS", url])

class HydraPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("暴力破解（請在授權範圍內使用）。User/Pass 可選 Single 或 File（editable）。")
        form = QtWidgets.QFormLayout()
        
        self.service = QtWidgets.QComboBox()
        self.service.addItems(["ssh", "ftp", "http-get", "http-post-form"])
        form.addRow("Service:", self.service)
        
        # User Mode
        umode = QtWidgets.QHBoxLayout()
        self.user_single_rb = QtWidgets.QRadioButton("Single")
        self.user_file_rb = QtWidgets.QRadioButton("File")
        self.user_single_rb.setChecked(True)
        umode.addWidget(self.user_single_rb)
        umode.addWidget(self.user_file_rb)
        umode.addStretch()
        form.addRow("User mode:", umode)
        
        self.user_group = QtWidgets.QButtonGroup(self)
        self.user_group.addButton(self.user_single_rb)
        self.user_group.addButton(self.user_file_rb)
        self.user_stack = QtWidgets.QStackedWidget()
        
        self.user_single = QtWidgets.QLineEdit()
        self.user_single.setPlaceholderText("username")
        p0 = QtWidgets.QWidget(); l0 = QtWidgets.QHBoxLayout(p0); l0.addWidget(self.user_single)
        
        self.user_file = QtWidgets.QLineEdit()
        self.user_file.setPlaceholderText("path to user list (editable)")
        self.user_browse = QtWidgets.QPushButton("Browse")
        p1 = QtWidgets.QWidget(); l1 = QtWidgets.QHBoxLayout(p1); l1.addWidget(self.user_file); l1.addWidget(self.user_browse)
        
        self.user_stack.addWidget(p0)
        self.user_stack.addWidget(p1)
        form.addRow("User (or file):", self.user_stack)
        
        # Password Mode
        pmode = QtWidgets.QHBoxLayout()
        self.pass_single_rb = QtWidgets.QRadioButton("Single")
        self.pass_file_rb = QtWidgets.QRadioButton("File")
        self.pass_single_rb.setChecked(True)
        pmode.addWidget(self.pass_single_rb)
        pmode.addWidget(self.pass_file_rb)
        pmode.addStretch()
        form.addRow("Pass mode:", pmode)
        
        self.pass_group = QtWidgets.QButtonGroup(self)
        self.pass_group.addButton(self.pass_single_rb)
        self.pass_group.addButton(self.pass_file_rb)
        self.pass_stack = QtWidgets.QStackedWidget()
        
        self.pass_single = QtWidgets.QLineEdit()
        self.pass_single.setEchoMode(QtWidgets.QLineEdit.Password)
        p0p = QtWidgets.QWidget(); l0p = QtWidgets.QHBoxLayout(p0p); l0p.addWidget(self.pass_single)
        
        self.pass_file = QtWidgets.QLineEdit()
        self.pass_file.setPlaceholderText("path to password list (editable)")
        self.pass_browse = QtWidgets.QPushButton("Browse")
        p1p = QtWidgets.QWidget(); l1p = QtWidgets.QHBoxLayout(p1p); l1p.addWidget(self.pass_file); l1p.addWidget(self.pass_browse)
        
        self.pass_stack.addWidget(p0p)
        self.pass_stack.addWidget(p1p)
        form.addRow("Pass (or file):", self.pass_stack)
        
        self.threads = QtWidgets.QLineEdit("4")
        form.addRow("Threads (-t):", self.threads)
        
        # HTTP specific options
        self.http_group = QtWidgets.QWidget()
        self.http_layout = QtWidgets.QFormLayout(self.http_group)
        self.hp_path = QtWidgets.QLineEdit("/doLogin")
        self.hp_userfield = QtWidgets.QLineEdit("uid")
        self.hp_passfield = QtWidgets.QLineEdit("passw")
        self.hp_extrafield = QtWidgets.QLineEdit()
        self.hp_failstr = QtWidgets.QLineEdit("Login Failed")
        self.hp_https_ck = QtWidgets.QCheckBox("Use HTTPS (https-post-form)")
        
        self.http_layout.addRow("HTTP path:", self.hp_path)
        self.http_layout.addRow("User field:", self.hp_userfield)
        self.http_layout.addRow("Pass field:", self.hp_passfield)
        self.http_layout.addRow("Extra params:", self.hp_extrafield)
        self.http_layout.addRow("Failure string:", self.hp_failstr)
        self.http_layout.addRow("", self.hp_https_ck)
        self.http_group.setVisible(False)
        
        self.options_layout.addLayout(form)
        self.options_layout.addWidget(self.http_group)
        
        # Connections
        self.user_single_rb.toggled.connect(lambda v: self.user_stack.setCurrentIndex(0 if v else 1))
        self.pass_single_rb.toggled.connect(lambda v: self.pass_stack.setCurrentIndex(0 if v else 1))
        self.user_browse.clicked.connect(self._choose_user_file)
        self.pass_browse.clicked.connect(self._choose_pass_file)
        self.service.currentTextChanged.connect(self._on_service_changed)
        
        self.user_stack.setCurrentIndex(0)
        self.pass_stack.setCurrentIndex(0)
        self._on_service_changed(self.service.currentText())

    def _choose_user_file(self):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose user list file")
        if p:
            self.user_file.setText(p)
            self.user_file_rb.setChecked(True)
            self.user_stack.setCurrentIndex(1)

    def _choose_pass_file(self):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose password list file")
        if p:
            self.pass_file.setText(p)
            self.pass_file_rb.setChecked(True)
            self.pass_stack.setCurrentIndex(1)

    def _convert_path_for_execution(self, path, use_wsl):
        if not use_wsl or not is_windows():
            return path
        if len(path) >= 2 and path[1] == ":":
            try:
                p = subprocess.run(["wsl", "wslpath", "-a", path], capture_output=True, text=True, timeout=2)
                if p.returncode == 0 and p.stdout.strip():
                    return p.stdout.strip()
            except Exception:
                pass
            drive = path[0].lower()
            tail = path[2:].replace("\\", "/")
            return f"/mnt/{drive}{tail}"
        return path

    def _on_service_changed(self, svc):
        if svc in ("http-post-form", "http-get"):
            self.http_group.setVisible(True)
        else:
            self.http_group.setVisible(False)

    def on_start_clicked(self):
        svc = self.service.currentText()
        tgt = self.target_edit.text().strip()
        if not tgt:
            self.output.appendPlainText("[ERROR] 請輸入 target")
            return
            
        use_wsl = self.use_wsl_ck.isChecked()
        
        # User Argument
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
            
        # Password Argument
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
            
        threads = self.threads.text().strip() or "4"
        cmd = []
        
        if svc in ("http-post-form", "http-get"):
            path = self.hp_path.text().strip().lstrip("/")
            ufield = self.hp_userfield.text().strip() or "uid"
            pfield = self.hp_passfield.text().strip() or "passw"
            extra = self.hp_extrafield.text().strip()
            fail = self.hp_failstr.text().strip() or "Login Failed"
            params = f"{ufield}=^USER^&{pfield}=^PASS^"
            if extra:
                params += extra if extra.startswith("&") else "&" + extra
            form = f"/{path}:{params}:{fail}"
            
            if svc == "http-post-form":
                proto = "https-post-form" if self.hp_https_ck.isChecked() else "http-post-form"
            elif svc == "http-get":
                proto = "https-get-form" if self.hp_https_ck.isChecked() else "http-get-form"
            else:
                proto = svc
                
            cmd = ["hydra"] + user_arg + pass_arg + ["-t", threads, f"{tgt} {proto} \"{form}\""]
        elif svc == "ssh":
            cmd = ["hydra"] + user_arg + pass_arg + ["-t", threads, f"{tgt} ssh"]
        elif svc == "ftp":
            cmd = ["hydra"] + user_arg + pass_arg + ["-t", threads, f"{tgt} ftp"]
            
        if use_wsl:
            cmd = ["wsl"] + cmd
            
        print(f"最終命令：{' '.join(cmd)}")
        self.start_worker(cmd)

class SshPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("互動式 SSH 終端機")
        self.ansi_converter = AnsiConverter()

        # SSH Settings Form
        form = QtWidgets.QFormLayout()
        form.setLabelAlignment(QtCore.Qt.AlignRight)

        self.user_edit = QtWidgets.QLineEdit("")
        self.user_edit.setPlaceholderText("預設 root、ubuntu、ec2-user...")
        form.addRow("Username:", self.user_edit)

        # Auth Method
        auth_box = QtWidgets.QGroupBox("登入方式")
        auth_layout = QtWidgets.QHBoxLayout(auth_box)
        self.pass_rb = QtWidgets.QRadioButton("密碼登入")
        self.key_rb = QtWidgets.QRadioButton("金鑰登入")
        self.pass_rb.setChecked(True)
        auth_layout.addWidget(self.pass_rb)
        auth_layout.addWidget(self.key_rb)
        auth_layout.addStretch()
        form.addRow(auth_box)

        # Password Widget
        self.pass_widget = QtWidgets.QWidget()
        p_lay = QtWidgets.QHBoxLayout(self.pass_widget)
        p_lay.setContentsMargins(0, 4, 0, 4)
        self.pass_edit = QtWidgets.QLineEdit()
        self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        p_lay.addWidget(QtWidgets.QLabel("Password:"))
        p_lay.addWidget(self.pass_edit, 1)
        form.addRow(self.pass_widget)

        # Key Widget
        self.key_widget = QtWidgets.QWidget()
        self.key_widget.setVisible(False)
        k_lay = QtWidgets.QGridLayout(self.key_widget)
        self.key_edit = QtWidgets.QLineEdit()
        self.key_browse = QtWidgets.QPushButton("Browse")
        self.passphrase_edit = QtWidgets.QLineEdit()
        self.passphrase_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        k_lay.addWidget(QtWidgets.QLabel("Private Key:"), 0, 0)
        k_lay.addWidget(self.key_edit, 0, 1)
        k_lay.addWidget(self.key_browse, 0, 2)
        k_lay.addWidget(QtWidgets.QLabel("Key Password:"), 1, 0)
        k_lay.addWidget(self.passphrase_edit, 1, 1, 1, 2)
        form.addRow(self.key_widget)

        self.port_edit = QtWidgets.QLineEdit("22")
        self.port_edit.setFixedWidth(80)
        form.addRow("Port:", self.port_edit)

        self.options_layout.addLayout(form)

        # Output Styles
        self.output.setReadOnly(True)
        self.output.setFont(QtGui.QFont("Consolas", 11))
        self.output.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                selection-background-color: #264f78;
                line-height: 1.2;
            }
        """)

        # Command Input
        self.input = QtWidgets.QLineEdit()
        self.input.setPlaceholderText("輸入指令... 按 Enter 執行")
        self.layout().addWidget(self.input)

        # State
        self._proc = None
        self._connected = False
        self._history = []
        self._history_index = -1

        # Connections
        self.pass_rb.toggled.connect(lambda c: self.pass_widget.setVisible(c))
        self.key_rb.toggled.connect(lambda c: self.key_widget.setVisible(c))
        self.key_browse.clicked.connect(self._browse_key)
        self.input.returnPressed.connect(self._send_command)
        self.input.installEventFilter(self)

    def _browse_key(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "選擇私鑰檔案", "", "All Files (*)")
        if path:
            self.key_edit.setText(path)

    def eventFilter(self, obj, event):
        if obj == self.input and event.type() == QtCore.QEvent.KeyPress:
            key = event.key()
            mod = event.modifiers()

            # =========================================================
            # [新增] 智慧 Ctrl+C 處理
            # =========================================================
            if key == QtCore.Qt.Key_C and (mod & QtCore.Qt.ControlModifier):
                # 情況 1: 如果你在輸入框裡「選取了文字」
                # -> 我們什麼都不做 (return False)，讓系統執行預設的「複製」動作
                if self.input.hasSelectedText():
                    return False
                
                # 情況 2: 如果沒有選字 -> 發送 SIGINT (中斷訊號) 給 SSH
                if self._connected and self._proc:
                    try:
                        # 發送 ASCII \x03 (End of Text)，這就是終端機裡的 Ctrl+C
                        self._proc.stdin.write(b'\x03')
                        self._proc.stdin.flush()
                    except Exception:
                        pass
                    return True # 攔截事件，避免在輸入框打出奇怪的字元

            # =========================================================
            # 原本的歷史紀錄功能 (保持不變)
            # =========================================================
            if key == QtCore.Qt.Key_Up:
                self._history_prev()
                return True
            if key == QtCore.Qt.Key_Down:
                self._history_next()
                return True
                
        return super().eventFilter(obj, event)

    def _send_command(self):
        if not self._connected or not self._proc:
            return
        line = self.input.text() 
        
        if not self._history or (self._history and self._history[-1] != line):
            self._history.append(line)
        self._history_index = len(self._history)

        try:
            self._proc.stdin.write((line + "\n").encode())
            self._proc.stdin.flush()
        except Exception:
            self.output.appendPlainText("[ERROR] 指令無法送出 (連線已中斷)")
            self._connected = False

        self.input.clear()

    def _history_prev(self):
        if self._history_index <= 0:
            return
        self._history_index -= 1
        self.input.setText(self._history[self._history_index])

    def _history_next(self):
        if self._history_index >= len(self._history):
            self.input.clear()
            return
        self._history_index += 1
        if self._history_index == len(self._history):
            self.input.clear()
        else:
            self.input.setText(self._history[self._history_index])

    def _start_reader(self):
        def reader():
            while self._connected and self._proc:
                try:
                    # 使用 read(4096) 避免 peek 錯誤並提高效能
                    data = self._proc.stdout.read(4096)
                    if not data:
                        break
                    
                    text = data.decode("utf-8", errors="replace")
                    
                    QtCore.QMetaObject.invokeMethod(
                        self, 
                        "_append_html_safe", 
                        QtCore.Qt.QueuedConnection,
                        QtCore.Q_ARG(str, text)
                    )
                except Exception as e:
                    print(f"Reader error: {e}")
                    break
            self._connected = False
            QtCore.QMetaObject.invokeMethod(
                self.output,
                "appendPlainText",
                QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, "\n[!] 連線已中斷")
            )

        threading.Thread(target=reader, daemon=True).start()

    @QtCore.pyqtSlot(str)
    def _append_html_safe(self, raw_text):
        cursor = self.output.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)

        # 1. 統一將 \r\n 轉為 \n
        raw_text = raw_text.replace('\r\n', '\n')

        # 2. [關鍵邏輯] 使用正則表達式分割 \n 與 \r
        # 這樣我們可以精準控制何時「換段落」何時「刪除行」
        parts = re.split(r'(\n|\r)', raw_text)

        for part in parts:
            if part == '\n':
                # 遇到換行：插入真正的 "Block" (段落)
                # 這樣之前的內容就安全了，不會被 StartOfBlock 刪除
                cursor.insertBlock()
            elif part == '\r':
                # 遇到回車：回到當前 Block 的開頭並刪除
                # 因為前面已經用 insertBlock 保護了歷史紀錄，這裡只會刪到當前行
                cursor.movePosition(QtGui.QTextCursor.StartOfBlock, QtGui.QTextCursor.KeepAnchor)
                cursor.removeSelectedText()
            else:
                if part:
                    html_content = self.ansi_converter.convert(part)
                    cursor.insertHtml(html_content)

        self.output.setTextCursor(cursor)
        self.output.ensureCursorVisible()

    def on_start_clicked(self):
        host = self.target_edit.text().strip()
        user = self.user_edit.text().strip() or "root"
        port = self.port_edit.text().strip() or "22"

        self.output.clear()
        self.output.appendPlainText(f"[*] 正在連線 {user}@{host}:{port} ...")

        use_wsl = self.use_wsl_ck.isChecked()
        cmd = ["ssh", "-tt", "-p", port, "-o", "StrictHostKeyChecking=no", f"{user}@{host}"]

        if self.key_rb.isChecked():
            key = self.key_edit.text().strip()
            if key:
                cmd.insert(1, "-i")
                cmd.insert(2, key)
        else:
            pw = self.pass_edit.text().strip()
            if not pw:
                self.output.appendPlainText("[ERROR] 密碼不能為空！")
                return
            cmd = [
                "env", f"SSHPASS={pw}",
                "sshpass", "-e",
                "ssh", "-tt",
                "-p", port,
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                f"{user}@{host}"
            ]

        if use_wsl:
            cmd = ["wsl"] + cmd

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0, 
                universal_newlines=False
            )
            self._connected = True
            self._start_reader()
        except Exception as e:
            self.output.appendPlainText(f"[ERROR] {e}")

    def on_stop_clicked(self):
        self._connected = False
        if self._proc:
            try:
                self._proc.terminate()
            except:
                pass
            self._proc = None
        self.output.appendPlainText("[!] 已中斷連線")

# ==========================================
#       GOBUSTER 專用 ANSI 轉換器
# ==========================================
# ==========================================
#       GOBUSTER 專用 ANSI 轉換器
# ==========================================
class GobusterAnsiConverter:
    def __init__(self):
        self.fg_colors = {
            '30': 'black', '31': '#d9534f', '32': '#2ea84a', '33': '#f0ad4e',
            '34': '#007aff', '35': '#9b59b6', '36': '#5bc0de', '37': '#d4d4d4',
            '90': 'gray', '91': '#ff6b6b', '92': '#51cf66', '93': '#fcc419',
            '94': '#339af0', '95': '#cc5de8', '96': '#66d9e8', '97': 'white',
        }

    def convert(self, text):
        text = html.escape(text)
        def ansi_sub(match):
            code = match.group(1)
            if not code or code == '0':
                return '</span>'
            parts = code.split(';')
            style = []
            for part in parts:
                if part == '1':
                    style.append('font-weight:bold')
                elif part in self.fg_colors:
                    style.append(f'color:{self.fg_colors[part]}')
            if style:
                return f'<span style="{";".join(style)}">'
            return ''
        text = re.sub(r'\x1b\[([0-9;]*)m', ansi_sub, text)
        text = re.sub(r'\x1b\[[0-9;?]*[a-zA-Z]', '', text)
        return text

# ==========================================
#              GOBUSTER PAGE (完美 CMD 版)
# ==========================================
# ==========================================
#              GOBUSTER PAGE (完美 CMD 版)
# ==========================================
class GobusterPage(ToolPageBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.desc.setText("列出目標網頁資料夾、文件 (CMD 模擬模式)")
        
        self.ansi_converter = GobusterAnsiConverter()
        
        form = QtWidgets.QFormLayout()

        # -w Wordlist
        word_h = QtWidgets.QHBoxLayout()
        self.wordlist_edit = QtWidgets.QLineEdit()
        self.wordlist_edit.setPlaceholderText("例如: /usr/share/wordlists/dirb/common.txt")
        self.wordlist_btn = QtWidgets.QPushButton("Browse")
        word_h.addWidget(self.wordlist_edit)
        word_h.addWidget(self.wordlist_btn)
        form.addRow("-w Wordlist*:", word_h)
        self._last_line_was_progress = False

        # -t Threads
        self.threads_edit = QtWidgets.QLineEdit("10")
        form.addRow("-t Threads:", self.threads_edit)

        # -x Extensions
        self.ext_edit = QtWidgets.QLineEdit()
        self.ext_edit.setPlaceholderText("例如: php,html,txt")
        form.addRow("-x Extensions:", self.ext_edit)

        # -o Output
        out_h = QtWidgets.QHBoxLayout()
        self.output_edit = QtWidgets.QLineEdit()
        self.output_edit.setPlaceholderText("儲存結果檔案 (可選)")
        self.output_btn = QtWidgets.QPushButton("Browse")
        out_h.addWidget(self.output_edit)
        out_h.addWidget(self.output_btn)
        form.addRow("-o Output:", out_h)

        # -s Status
        self.status_edit = QtWidgets.QLineEdit()
        self.status_edit.setPlaceholderText("預設: 200,204,301,302,307,403,500")
        form.addRow("-s Status:", self.status_edit)

        # Options
        self.options_edit = QtWidgets.QLineEdit()
        self.options_edit.setPlaceholderText("其他參數, e.g. -k --timeout 10s")
        form.addRow("Options:", self.options_edit)

        self.options_layout.addLayout(form)

        # [樣式還原] 使用 SSH Page 的深灰色風格
        self.output.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: Consolas, "Courier New", monospace;
                font-size: 10pt;
                border: 1px solid #333;
            }
        """)

        self.wordlist_btn.clicked.connect(self._browse_wordlist)
        self.output_btn.clicked.connect(self._browse_output)

    def _browse_wordlist(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "選擇字典檔", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self.wordlist_edit.setText(path)

    def _browse_output(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "儲存結果", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self.output_edit.setText(path)

    def _convert_path_for_wsl(self, path):
        # 這裡不管 checkbox，只要路徑轉換需要依賴 WSL 環境就執行
        if not is_windows():
            return path
        try:
            result = subprocess.run(["wsl", "wslpath", "-a", path], capture_output=True, text=True, timeout=1)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except:
            pass
        if len(path) >= 2 and path[1] == ":":
            drive = path[0].lower()
            tail = path[2:].replace("\\", "/")
            return f"/mnt/{drive}{tail}"
        return path

    def _quote_if_needed(self, s):
        if ' ' in s:
            return f'"{s}"'
        return s

    def _on_finished(self):
        cursor = self.output.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        
        # [修改] 確保之前有空一行
        if self.output.document().characterCount() > 0:
            cursor.insertBlock() # 換行
            cursor.insertBlock() # 再換一行 (製造空行效果)
            
        # [修改] [Finished] 改為純白色
        cursor.insertHtml('<span style="color:#FFFFFF; font-weight:bold">[Finished]</span>')
        self.output.ensureCursorVisible()

        # 恢復按鈕狀態
        self.progress.setVisible(False)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        if self.thread:
            self.thread.quit()
            self.thread.wait()
            self.thread = None
            self.worker = None

    def on_output_line(self, raw_line):
        import re

        # 1. 前置清理
        if not raw_line: return
        clean_line = raw_line.replace('\x1b[2K', '')
        if not clean_line.strip(): return

        # 2. 準備游標
        cursor = self.output.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        
        # 3. 【防誤刪機制】
        cursor.select(QtGui.QTextCursor.BlockUnderCursor)
        last_line_text = cursor.selectedText()
        
        if "Progress:" in last_line_text:
            cursor.removeSelectedText()
        else:
            cursor.clearSelection() 
        
        # 4. 【資訊分離】
        results = re.findall(r"(\/[^\s]+\s+\(Status:\s+\d+\))", clean_line)
        progress_matches = re.findall(r"(Progress:.*?\))", clean_line)
        latest_progress = progress_matches[-1] if progress_matches else None
        
        # 5. 【寫入順序】
        
        # --- A. 寫入結果 ---
        for res in results:
            if cursor.positionInBlock() > 0:
                cursor.insertBlock()
            
            # 上色保持原樣 (狀態碼顏色)
            if "200" in res: html = f'<span style="color:#2ea84a">{res}</span>'
            elif "301" in res: html = f'<span style="color:#f0ad4e">{res}</span>'
            elif "403" in res: html = f'<span style="color:#d9534f">{res}</span>'
            else: html = res
            
            cursor.insertHtml(html)
            cursor.insertBlock() 

        # --- B. 寫入進度 ---
        if latest_progress:
            if cursor.positionInBlock() > 0:
                cursor.insertBlock()
                
            # [修改] Progress 改為純白色
            cursor.insertHtml(f'<span style="color:#FFFFFF">{latest_progress}</span>')

        self.output.ensureCursorVisible()

    def start_worker(self, cmd_list):
        mw = self.main_window()
        if not mw: return

        # 強制使用 UTF-8 編碼 (因為我們會強制走 WSL)
        mw.set_encoding_based_on_wsl(True)
        encoding = "utf-8"

        self.output.clear()
        
        # [修改] [START] 改為純白色
        # 我們不印出指令，只印出標籤
        self.output.appendHtml('<span style="color:#FFFFFF; font-weight:bold">[START]</span><br>')

        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        
        # [關鍵修改] 這裡強制傳入 use_wsl=True !!!
        # 這樣 CmdWorker 就不會去加 powershell 的前綴，解決指令被汙染的問題
        self.worker = CmdWorker(cmd_list, encoding=encoding, use_wsl=True)
        
        self.thread = QtCore.QThread()
        self.worker.moveToThread(self.thread)

        self.worker.output_line.connect(self.on_output_line)
        self.worker.finished.connect(self._on_finished)
        self.thread.started.connect(self.worker.run)
        self.thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def on_start_clicked(self):
        target = self.target_edit.text().strip()
        wordlist = self.wordlist_edit.text().strip()

        if not target:
            self.output.appendPlainText("[ERROR] 請輸入 Target URL")
            return
        if not wordlist:
            self.output.appendPlainText("[ERROR] 請選擇 Wordlist")
            return

        wordlist_path = self._convert_path_for_wsl(wordlist)
        output_path = self.output_edit.text().strip()
        if output_path:
            output_path = self._convert_path_for_wsl(output_path)

        # 這裡我們手動組裝 wsl 指令
        cmd = ["wsl", "gobuster"] 
        
        cmd.extend(["-u", self._quote_if_needed(target)])
        cmd.extend(["-w", self._quote_if_needed(wordlist_path)])

        if self.threads_edit.text().strip():
            cmd.extend(["-t", self.threads_edit.text().strip()])
            
        if self.ext_edit.text().strip():
            cmd.extend(["-x", self._quote_if_needed(self.ext_edit.text().strip())])
        
        if output_path:
            cmd.extend(["-o", self._quote_if_needed(output_path)])
            
        if self.status_edit.text().strip():
            cmd.extend(["-s", self.status_edit.text().strip()])

        extra_raw = self.options_edit.text().strip()
        if extra_raw:
            import shlex
            for part in shlex.split(extra_raw):
                cmd.append(self._quote_if_needed(part))
        
        self.start_worker(cmd)

# ==========================================
#              MAIN WINDOW
# ==========================================

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Linux Security Tools Suite")
        self.resize(1200, 760)
        
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        
        main_layout = QtWidgets.QHBoxLayout(central)
        main_layout.setContentsMargins(0, 8, 8, 8)

        # Navigation Bar
        self.nav = QtWidgets.QListWidget()
        self.nav.setFixedWidth(200)
        self.nav.setSpacing(0)
        self.nav.setMouseTracking(True)
        self.nav.setFont(QtGui.QFont("Segoe UI", 10))
        
        tools = [
            "顯示當前裝置資訊", "檔案列表", "查看文件內容", "IP狀態查詢", "傳輸測試",
            "埠口掃描", "路由追蹤", "DNS查詢", "網頁原始碼擷取", "弱密碼測試", "SSH連線", "列出網頁文件"
        ]
        
        for t in tools:
            it = QtWidgets.QListWidgetItem(t)
            it.setTextAlignment(QtCore.Qt.AlignVCenter)
            self.nav.addItem(it)
        main_layout.addWidget(self.nav)

        # Page Stack
        self.stack = QtWidgets.QStackedWidget()
        main_layout.addWidget(self.stack, 1)
        
        clsmap = {
            "顯示當前裝置資訊": WhoamiPage,
            "檔案列表": LsPage,
            "查看文件內容": CatPage,
            "IP狀態查詢": PingPage,
            "傳輸測試": NcPage,
            "埠口掃描": NmapPage,
            "路由追蹤": TraceroutePage,
            "DNS查詢": DigPage,
            "網頁原始碼擷取": CurlPage,
            "弱密碼測試": HydraPage,
            "SSH連線": SshPage,
            "列出網頁文件": GobusterPage
        }
        
        self.pages = {}
        for name in tools:
            p = clsmap[name](self)
            self.pages[name] = p
            self.stack.addWidget(p)
            
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)

        # Status Bar
        self.status = QtWidgets.QStatusBar()
        self.setStatusBar(self.status)
        
        self.encoding_label = QtWidgets.QLabel("編碼:")
        self.encoding_combo = QtWidgets.QComboBox()
        encs = ["utf-8", "cp950", "big5", "gbk", "shift_jis", "iso-8859-1", "windows-1252", "euc-kr", "utf-16"]
        self.encoding_combo.addItems(encs)
        self.encoding_combo.setCurrentText("cp950")
        self.encoding_combo.setFixedWidth(140)
        
        self.set_encoding_based_on_wsl(False, initial=True)
        
        self.status.addPermanentWidget(self.encoding_label)
        self.status.addPermanentWidget(self.encoding_combo)
        
        self.wsl_status_label = QtWidgets.QLabel()
        self.wsl_status_label.setFixedWidth(160)
        self.status.addPermanentWidget(self.wsl_status_label)
        
        self._update_wsl_status(initial=True)
        
        self.wsl_timer = QtCore.QTimer(self)
        self.wsl_timer.setInterval(5000)
        self.wsl_timer.timeout.connect(self._update_wsl_status)
        self.wsl_timer.start()
        
        # Menu
        menubar = self.menuBar()
        env_menu = menubar.addMenu("Env")
        ac = QtWidgets.QAction("Check WSL Now", self)
        ac.triggered.connect(lambda: self._update_wsl_status(force=True))
        env_menu.addAction(ac)
        
        # Events
        self.encoding_combo.currentTextChanged.connect(lambda t: self.status.showMessage(f"編碼: {t}", 1500))
        self.nav.currentRowChanged.connect(self._sync_encoding_on_page_change)

    def set_encoding_based_on_wsl(self, use_wsl: bool, initial=False):
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

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(APP_STYLESHEET)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()