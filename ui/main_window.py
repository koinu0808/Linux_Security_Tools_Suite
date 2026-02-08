# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, QtWidgets
from urllib.parse import urlparse
import shlex
import subprocess

from core.env import wsl_available, is_windows, build_final_command
from tools.original_pages import (
    WhatWebPage, SslCertPage, LsPage, CatPage, PingPage, NcPage, NmapPage, TraceroutePage,
    DigPage, CurlPage, HydraPage, SshPage, GobusterPage, ExifToolPage, ReportPage,
)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Linux Security Tools Suite')
        self.resize(1360, 820)

        self._pages = {}
        self.settings = QtCore.QSettings('LSTS', 'LinuxSecurityToolsSuite')
        self._theme = self.settings.value('theme', 'light')
        self._build_style()
        self._build_layout()
        self._build_tools_pages()

        self._update_wsl_status(initial=True, force=True)
        self.wsl_timer = QtCore.QTimer(self)
        self.wsl_timer.setInterval(5000)
        self.wsl_timer.timeout.connect(self._update_wsl_status)
        self.wsl_timer.start()

    def _build_style(self):
        self._dark_qss = '''
        QMainWindow { background:#0f1217; }
        QWidget { color:#E6EDF3; font-family: Segoe UI, Arial; font-size: 10.5pt; background: transparent; }
        QLabel, QRadioButton, QCheckBox, QGroupBox { background: transparent; }
        QFrame { background: transparent; }
        QTabWidget::pane { border: 1px solid #2a2f3a; background:#10141b; }
        QScrollArea { background:#0c1016; border:1px solid #2a2f3a; border-radius:6px; }
        QScrollArea QWidget { background: transparent; }
        QTabBar::tab { background:#141a22; padding:8px 12px; border:1px solid #2a2f3a; border-bottom:none; margin-right:4px; }
        QTabBar::tab:selected { background:#1b2330; font-weight:600; }
        QSplitter::handle { background:#2a2f3a; }
        QLineEdit, QPlainTextEdit { background:#0c1016; border:1px solid #2a2f3a; border-radius:6px; padding:6px; }
        QPlainTextEdit { font-family: Consolas, ui-monospace, monospace; font-size: 10pt; }
        QPushButton { background:#2563eb; border:1px solid #1d4ed8; border-radius:8px; padding:8px 12px; font-weight:600; }
        QPushButton:hover { background:#1d4ed8; }
        QPushButton:disabled { background:#334155; }
        
        QPushButton[variant="primary"] { background:#2563eb; color:#ffffff; border:1px solid #1d4ed8; border-radius:8px; padding:8px 12px; font-weight:600; }
        QPushButton[variant="primary"]:hover { background:#1d4ed8; }
        QPushButton[variant="primary"]:pressed { background:#1f4faf; }
        QPushButton[variant="primary"]:disabled { background:#94a3b8; border-color:#94a3b8; color:#ffffff; }
QPushButton#themeBtn { padding:4px 14px; }
        QComboBox { background:#0c1016; border:1px solid #2a2f3a; border-radius:6px; padding:6px; }
        QComboBox QAbstractItemView { background:#0c1016; border:1px solid #2a2f3a; selection-background-color:#1d4ed8; }
        QHeaderView::section { background:#141a22; border:1px solid #2a2f3a; padding:6px; }
        QTableWidget { background:#0c1016; border:1px solid #2a2f3a; gridline-color:#1f2530; }
        QTreeWidget { background:#0c1016; border:1px solid #2a2f3a; }
        QStatusBar { background:#0f1217; border-top:1px solid #2a2f3a; }
        QStatusBar::item { border: none; }
        
        QScrollBar:vertical { width: 10px; margin: 2px; background: transparent; }
        QScrollBar::handle:vertical { min-height: 24px; border-radius: 5px; background: rgba(0,0,0,0.25); }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
        QScrollBar:horizontal { height: 10px; margin: 2px; background: transparent; }
        QScrollBar::handle:horizontal { min-width: 24px; border-radius: 5px; background: rgba(0,0,0,0.25); }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }
        QComboBox::drop-down { border: none; width: 26px; }
        QComboBox::down-arrow { image: none; border: none; width: 0px; height: 0px; }
    '''

        self._light_qss = '''
        QMainWindow { background:#f4f6fb; }
        QWidget { color:#111827; font-family: Segoe UI, Arial; font-size: 10.5pt; background:#f4f6fb; }
        QLabel, QRadioButton, QCheckBox, QGroupBox { background: transparent; }
        QFrame { background: transparent; }

        QTabWidget { background:#f4f6fb; }
        QTabWidget::pane { border: 1px solid #cfd6e4; background:#ffffff; }
        QTabBar { background:#f4f6fb; }
        QTabBar::tab { background:#eef2ff; padding:8px 12px; border:1px solid #cfd6e4; border-bottom:none; margin-right:4px; }
        QTabBar::tab:selected { background:#ffffff; font-weight:600; }

        QScrollArea { background:#ffffff; border:1px solid #cfd6e4; border-radius:6px; }
        QScrollArea QWidget { background: transparent; }

        QSplitter::handle { background:#cfd6e4; }

        QLineEdit, QPlainTextEdit { background:#ffffff; border:1px solid #cfd6e4; border-radius:6px; padding:6px; }
        QPlainTextEdit { font-family: Consolas, ui-monospace, monospace; font-size: 10pt; }

        QPushButton { background:#2563eb; color:#ffffff; border:1px solid #1d4ed8; border-radius:8px; padding:8px 12px; font-weight:600; }
        QPushButton:hover { background:#1d4ed8; }
        QPushButton:disabled { background:#94a3b8; }
        
        QPushButton[variant="primary"] { background:#2563eb; color:#ffffff; border:1px solid #1d4ed8; border-radius:8px; padding:8px 12px; font-weight:600; }
        QPushButton[variant="primary"]:hover { background:#1d4ed8; }
        QPushButton[variant="primary"]:pressed { background:#1f4faf; }
        QPushButton[variant="primary"]:disabled { background:#94a3b8; border-color:#94a3b8; color:#ffffff; }
QPushButton#themeBtn { padding:4px 14px; }

        QComboBox { background:#ffffff; border:1px solid #cfd6e4; border-radius:6px; padding:6px; }
        QComboBox QAbstractItemView { background:#ffffff; border:1px solid #cfd6e4; selection-background-color:#bfdbfe; }

        QHeaderView::section { background:#eef2ff; border:1px solid #cfd6e4; padding:6px; }
        QTableWidget { background:#ffffff; border:1px solid #cfd6e4; gridline-color:#e5e7eb; }
        QTreeWidget { background:#ffffff; border:1px solid #cfd6e4; }

        QStatusBar { background:#f4f6fb; border-top:1px solid #cfd6e4; }
        QStatusBar::item { border: none; }
        
        QScrollBar:vertical { width: 10px; margin: 2px; background: transparent; }
        QScrollBar::handle:vertical { min-height: 24px; border-radius: 5px; background: rgba(0,0,0,0.25); }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
        QScrollBar:horizontal { height: 10px; margin: 2px; background: transparent; }
        QScrollBar::handle:horizontal { min-width: 24px; border-radius: 5px; background: rgba(0,0,0,0.25); }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }
        QComboBox::drop-down { border: none; width: 26px; }
        QComboBox::down-arrow { image: none; border: none; width: 0px; height: 0px; }
    '''

        self._apply_theme(self._theme)

    def _apply_theme(self, theme: str):
        self._theme = 'light' if theme == 'light' else 'dark'
        self.setStyleSheet(self._light_qss if self._theme == 'light' else self._dark_qss)
        try:
            if hasattr(self, 'theme_btn'):
                self.theme_btn.setText('Dark' if self._theme == 'light' else 'Light')
        except Exception:
            pass

    def _build_layout(self):
        central = QtWidgets.QWidget(); self.setCentralWidget(central)
        root = QtWidgets.QVBoxLayout(central)
        root.setContentsMargins(10,10,10,10)
        root.setSpacing(10)

        main_split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        root.addWidget(main_split, 1)

        left_tabs = QtWidgets.QTabWidget(); left_tabs.setMinimumWidth(400)
        main_split.addWidget(left_tabs)

        self.tools_tree = QtWidgets.QTreeWidget(); self.tools_tree.setHeaderLabels(['Tools'])
        self.tools_tree.itemSelectionChanged.connect(self._on_tool_selected)
        left_tabs.addTab(self.tools_tree, 'Tools')

        tgt_wrap = QtWidgets.QWidget(); tgt_l = QtWidgets.QVBoxLayout(tgt_wrap)
        tgt_l.setContentsMargins(8,8,8,8); tgt_l.setSpacing(8)
        row = QtWidgets.QHBoxLayout()
        self.target_input = QtWidgets.QLineEdit(); self.target_input.setPlaceholderText('domain / IP / URL')
        self.btn_add_target = QtWidgets.QPushButton('Add')
        self.btn_add_target.clicked.connect(self._add_target)
        row.addWidget(self.target_input, 1)
        row.addWidget(self.btn_add_target)
        tgt_l.addLayout(row)
        self.targets_tree = QtWidgets.QTreeWidget(); self.targets_tree.setHeaderLabels(['Targets'])
        self.targets_tree.itemSelectionChanged.connect(self._on_target_selected)
        self.targets_tree.itemClicked.connect(self._on_target_clicked)
        tgt_l.addWidget(self.targets_tree, 1)
        left_tabs.addTab(tgt_wrap, 'Targets')

        self.hist = QtWidgets.QTableWidget(0,4)
        self.hist.setHorizontalHeaderLabels(['Time','Tool','Target','Status'])
        self.hist.horizontalHeader().setStretchLastSection(True)
        self.hist.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.hist.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.hist.itemSelectionChanged.connect(self._on_history_selected)
        left_tabs.addTab(self.hist, 'History')

        right_split = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        main_split.addWidget(right_split)
        main_split.setStretchFactor(1, 1)

        self.work_tabs = QtWidgets.QTabWidget()
        right_split.addWidget(self.work_tabs)

        self.tools_stack = QtWidgets.QStackedWidget()
        self.work_tabs.addTab(self.tools_stack, 'Workspace')

        self.cmd_runner = self._build_cmd_runner()
        self.work_tabs.addTab(self.cmd_runner, 'Cmd Runner')

        advw = QtWidgets.QWidget(); advl = QtWidgets.QVBoxLayout(advw)
        adv_tabs = QtWidgets.QTabWidget()
        adv_tabs.addTab(CurlPage(self), 'HTTP Client')
        adv_tabs.addTab(SslCertPage(self), 'TLS')
        from tools.original_pages import HeadersPage
        adv_tabs.addTab(HeadersPage(self), 'Headers')
        advl.addWidget(adv_tabs)
        self.work_tabs.addTab(advw, 'Advanced')

        self.result = QtWidgets.QPlainTextEdit(); self.result.setReadOnly(True)
        right_split.addWidget(self.result)
        right_split.setStretchFactor(0, 3)
        right_split.setStretchFactor(1, 2)

        self.status = QtWidgets.QStatusBar(); self.setStatusBar(self.status)

        # Theme toggle
        self.theme_btn = QtWidgets.QPushButton('Light')
        self.theme_btn.setObjectName('themeBtn')
        self.theme_btn.setFixedHeight(26)
        self.theme_btn.setFixedWidth(120)
        self.theme_btn.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        self.theme_btn.clicked.connect(self._toggle_theme)

        self._sb_spacer = QtWidgets.QWidget()
        self._sb_spacer.setFixedWidth(10)

        self.encoding_label = QtWidgets.QLabel('編碼:')
        self.encoding_combo = QtWidgets.QComboBox(); self.encoding_combo.addItems(['utf-8','cp950','big5','gbk','shift_jis','iso-8859-1','windows-1252','euc-kr','utf-16'])
        self.encoding_combo.setCurrentText('utf-8'); self.encoding_combo.setFixedWidth(140)
        self.wsl_status_label = QtWidgets.QLabel(); self.wsl_status_label.setFixedWidth(170)

        self.status.addPermanentWidget(self.theme_btn)
        self.status.addPermanentWidget(self._sb_spacer)
        self.status.addPermanentWidget(self.encoding_label)
        self.status.addPermanentWidget(self.encoding_combo)
        self.status.addPermanentWidget(self.wsl_status_label)

    def _toggle_theme(self):
        new_theme = 'dark' if self._theme == 'light' else 'light'
        self._apply_theme(new_theme)
        try:
            self.settings.setValue('theme', self._theme)
        except Exception:
            pass


    def set_encoding_based_on_wsl(self, use_wsl: bool, initial=False):
        if use_wsl:
            self.encoding_combo.setCurrentText('utf-8')
        else:
            self.encoding_combo.setCurrentText('utf-8')

    def _update_wsl_status(self, initial=False, force=False):
        ok = wsl_available(force=force)
        dot = '●'
        color = '#2ea84a' if ok else '#d9534f'
        self.wsl_status_label.setText(f'<span style="color:{color};font-weight:700">{dot}</span> WSL: ' + ('Available' if ok else 'Not available'))

    def _build_tools_pages(self):
        cats = {
            '資訊蒐集 / 指紋': [('顯示目標裝置資訊', WhatWebPage),('SSL/TLS 憑證檢查', SslCertPage),('網頁原始碼擷取', CurlPage)],
            '網路 / 診斷': [('IP狀態查詢', PingPage),('路由追蹤', TraceroutePage),('DNS查詢', DigPage)],
            '掃描 / 枚舉': [('埠口掃描', NmapPage),('列出網頁文件', GobusterPage)],
            '檔案 / 取證': [('檔案列表', LsPage),('查看文件內容', CatPage),('掃描檔案/圖片隱藏資訊', ExifToolPage)],
            '連線 / 互動': [('傳輸測試', NcPage),('SSH連線', SshPage)],
            '攻擊測試（需授權）': [('弱密碼測試', HydraPage)],
            '報告': [('一鍵生成報告', ReportPage)],
        }

        self.tools_tree.clear()
        while self.tools_stack.count():
            w = self.tools_stack.widget(0)
            self.tools_stack.removeWidget(w)
            if w: w.deleteLater()
        self._pages.clear()

        for cat, items in cats.items():
            parent = QtWidgets.QTreeWidgetItem([cat]); parent.setExpanded(True)
            self.tools_tree.addTopLevelItem(parent)
            for name, cls in items:
                child = QtWidgets.QTreeWidgetItem([name])
                child.setData(0, QtCore.Qt.UserRole, name)
                parent.addChild(child)
                page = cls(self)
                page.tool_name = name
                self.tools_stack.addWidget(page)
                self._pages[name] = page

        # expand all + select first
        try:
            self.tools_tree.expandAll()
        except Exception:
            pass
        self.tools_tree.setCurrentItem(self.tools_tree.topLevelItem(0).child(0))

    def _on_tool_selected(self):
        items = self.tools_tree.selectedItems()
        if not items:
            return
        name = items[0].data(0, QtCore.Qt.UserRole)
        if not name:
            return
        page = self._pages.get(name)
        if page:
            self.tools_stack.setCurrentWidget(page)
            self.work_tabs.setCurrentIndex(0)

    
    def _add_target(self):
        raw = (self.target_input.text() or '').strip()
        if not raw:
            return

        display = raw.strip().rstrip('/')

        # Normalize http(s) URL to scheme://host[:port]
        if display.startswith('http://') or display.startswith('https://'):
            try:
                u = urlparse(display)
                if u.scheme and u.netloc:
                    display = f"{u.scheme}://{u.netloc}"
            except Exception:
                pass
        else:
            display = display.split('/')[0]

        # avoid exact duplicates only
        for i in range(self.targets_tree.topLevelItemCount()):
            it = self.targets_tree.topLevelItem(i)
            if it and it.text(0) == display:
                self.targets_tree.setCurrentItem(it)
                return

        it = QtWidgets.QTreeWidgetItem([display])
        it.setData(0, QtCore.Qt.UserRole, display)
        self.targets_tree.insertTopLevelItem(0, it)
        self.targets_tree.setCurrentItem(it)
        self.target_input.clear()




    def _on_target_clicked(self, item, column=0):
        # Ensure clicking an already-selected target still applies it to current tool target input.
        try:
            raw = item.data(0, QtCore.Qt.UserRole) or item.text(0)
        except Exception:
            return
        w = self.tools_stack.currentWidget()
        if w and hasattr(w, 'target_edit'):
            try:
                w.target_edit.setText(str(raw))
            except Exception:
                pass

    def _on_target_selected(self):
        items = self.targets_tree.selectedItems()
        if not items:
            return
        raw = items[0].data(0, QtCore.Qt.UserRole) or items[0].text(0)
        w = self.tools_stack.currentWidget()
        if w and hasattr(w, 'target_edit'):
            try:
                w.target_edit.setText(str(raw))
            except Exception:
                pass

    def add_history(self, tool: str, target: str, ok: bool, output: str):
        self.hist.insertRow(0)
        vals = [QtCore.QDateTime.currentDateTime().toString('yyyy-MM-dd HH:mm:ss'), tool, target, 'OK' if ok else 'ERR']
        for c,v in enumerate(vals):
            cell = QtWidgets.QTableWidgetItem(str(v))
            if c == 3:
                cell.setForeground(QtGui.QBrush(QtGui.QColor('#28CD41' if ok else '#FF3B30')))
            self.hist.setItem(0,c,cell)
        self.hist.item(0,0).setData(QtCore.Qt.UserRole, output)
        self.hist.resizeColumnsToContents()
        self.result.setPlainText(output)

    def _on_history_selected(self):
        sel = self.hist.selectedItems()
        if not sel:
            return
        row = sel[0].row()
        it = self.hist.item(row,0)
        if not it:
            return
        out = it.data(QtCore.Qt.UserRole) or ''
        self.result.setPlainText(out)

    def _build_cmd_runner(self):
        w = QtWidgets.QWidget(); lay = QtWidgets.QVBoxLayout(w)
        lay.setContentsMargins(10,10,10,10)
        row = QtWidgets.QHBoxLayout()
        self.cmd_use_wsl = QtWidgets.QCheckBox('Use WSL')
        self.cmd_use_wsl.setChecked(bool(wsl_available()))
        if is_windows() and not wsl_available():
            self.cmd_use_wsl.setEnabled(False)
        self.cmd_line = QtWidgets.QLineEdit(); self.cmd_line.setPlaceholderText('輸入命令，例如: nmap -F example.com')
        btn = QtWidgets.QPushButton('Run')
        row.addWidget(self.cmd_use_wsl)
        row.addWidget(self.cmd_line, 1)
        row.addWidget(btn)
        lay.addLayout(row)
        self.cmd_out = QtWidgets.QPlainTextEdit(); self.cmd_out.setReadOnly(True)
        lay.addWidget(self.cmd_out, 1)

        def run_now():
            line = (self.cmd_line.text() or '').strip()
            if not line:
                return
            try:
                parts = shlex.split(line)
            except Exception:
                parts = line.split()
            cmd = build_final_command(parts, use_wsl=self.cmd_use_wsl.isChecked())
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
                out = (p.stdout or '') + ('\n' + p.stderr if p.stderr else '')
                self.cmd_out.setPlainText(out)
                self.add_history('Cmd', line, p.returncode == 0, out)
            except Exception as e:
                msg = f'[ERROR] {e}'
                self.cmd_out.setPlainText(msg)
                self.add_history('Cmd', line, False, msg)

        btn.clicked.connect(run_now)
        self.cmd_line.returnPressed.connect(run_now)
        return w