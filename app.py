# -*- coding: utf-8 -*-

import sys
from PyQt5 import QtWidgets

from ui.main_window import MainWindow
from tools.hook import install


def main():
    app = QtWidgets.QApplication(sys.argv)
    install()
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
