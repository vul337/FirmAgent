dependencies_loaded = True
failed_dependency = ''
try:
    import sys
    import idapro
    from PyQt5.QtCore import QRunnable, pyqtSlot, Qt
    from env import *
    from view.main import MainWindow
    from model.manager import Manager
    from PyQt5.QtWidgets import (
        QApplication,
        QFileDialog,
    )
except ImportError as e:
    dependencies_loaded = False  # Set flag if a dependency fails
    failed_dependency = e.name   # Store the name of the missing dependency
    if not dependencies_loaded:
        print(f"IDA Feeds ({__file__}) cannot start, requires {failed_dependency}.\n")
        sys.exit(1)

class AppMainWindow(MainWindow):
    def __init__(self):
        super().__init__()

        self.idb_path = None

    def load_idb(self):
        self.wait_dialog.show()
        QApplication.processEvents()
        if idapro.open_database(self.idb_path, True):
            print(f"Failed opening {self.idb_path}")
            sys.exit(1)
        self.wait_dialog.hide()

    def select_idb(self, idb=IDB_PATH):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        # options |= QFileDialog.DontUseNativeDialog
        self.idb_path, _ = QFileDialog.getOpenFileName(self,
                                                       "Open binary file...",
                                                       idb,
                                                       "IDA Files (*.i64);;All Files (*)",
                                                       options=options)

        if not self.idb_path:
            print("Please select a binary file.")
            sys.exit(1)

if __name__ == '__main__':
    SYS_INTERPRETER_PATH = sys.executable
    idapro.enable_console_messages(True)
    app = QApplication(sys.argv)
    view = AppMainWindow()
    mgr = Manager(PORTS, IDB_PATH, view, True)

    view.select_idb()
    view.load_idb()
    mgr.populate_model()
    view.show()

    app.exec_()

    idapro.close_database()
