# -*- coding: utf-8 -*-

from tools.original_pages import ToolPageBase


def _toolpage_on_finished_with_history(self, rc: int = 0):
    try:
        self.output.appendPlainText("\n[Finished]")
        self.progress.setVisible(False)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        if self.thread:
            self.thread.quit(); self.thread.wait()
            self.thread = None
            self.worker = None
    except Exception:
        pass

    try:
        mw = self.main_window()
        if mw and hasattr(mw, 'add_history'):
            name = getattr(self, 'tool_name', self.__class__.__name__)
            tgt = ''
            if hasattr(self, 'target_edit') and self.target_edit.isVisible():
                tgt = self.target_edit.text().strip()
            if not tgt and hasattr(self, 'single_file_edit'):
                tgt = self.single_file_edit.text().strip()
            out = self.output.toPlainText()
            mw.add_history(name, tgt, int(rc) == 0, out)
    except Exception:
        pass


def install():
    ToolPageBase._on_finished = _toolpage_on_finished_with_history
