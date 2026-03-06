import ida_kernwin
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QCursor, QPalette, QIcon
from PyQt5.QtWidgets import QLabel, QDialog, QDialogButtonBox
from PyQt5.QtWidgets import QMainWindow, QGroupBox, QProgressBar, \
    QAbstractItemView, QMenu, QAction, QHBoxLayout, QApplication
from PyQt5.QtWidgets import QTreeView, QWidget, QVBoxLayout, QPushButton, QSizePolicy, QHeaderView, \
    QLineEdit, QMessageBox, QStyle

default_style_sheet = ("""
            QGroupBox {
                border-radius: 5px;
            }
            QLineEdit {
                border-radius: 5px;
            }
        """)

class PleaseWaitDialog(QMessageBox):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Loading binary")
        self.setText("Auto-analysis in progress, please wait...")
        self.setStandardButtons(QMessageBox.NoButton)
        self.setWindowFlags(self.windowFlags() | Qt.FramelessWindowHint)
        self.setModal(True)
        self.setAttribute(Qt.WA_DeleteOnClose)

class ProgressDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Progress")
        self.setFixedSize(300, 150)
        self.setWindowFlag(Qt.WindowCloseButtonHint, False)
        self.setWindowFlag(Qt.WindowMinimizeButtonHint, False)
        self.setWindowFlag(Qt.WindowStaysOnTopHint, True)

        # Layout
        layout = QVBoxLayout(self)

        # Label
        self.label = QLabel("Processing, please wait...")
        layout.addWidget(self.label)

        # Progress Bar
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)

        self.setLayout(layout)

    def accept(self):
        self.close()
        self.label.setText("Processing, please wait...")

class SignaturesTreeView(QWidget):
    def __init__(self):
        super().__init__()


        # Set up the QTreeView
        self.treeView = QTreeView(self)
        self.treeView.setSelectionMode(QAbstractItemView.ExtendedSelection)
        # Set the header resize mode
        self.header = self.treeView.header()
        self.header.setSectionResizeMode(QHeaderView.Interactive)
        self.header.resizeSections(QHeaderView.Stretch)

        # Enable custom context menu
        self.context_menu = QMenu(self)
        self.open_action = QAction("Open signatures folder", self)
        self.analysis_action = QAction("Run multi-core analysis", self)
        self.apply_action = QAction("Apply signatures", self)
        self.cancel_action = QAction("Close", self)
        self.context_menu.addAction(self.open_action)
        self.context_menu.addSeparator()
        self.context_menu.addAction(self.analysis_action)
        self.context_menu.addAction(self.apply_action)
        # self.context_menu.addSeparator()
        # self.context_menu.addAction(self.cancel_action)

        self.treeView.setContextMenuPolicy(Qt.CustomContextMenu)
        self.treeView.setSortingEnabled(True)


        # Set up the layout
        layout = QVBoxLayout(self)
        layout.addWidget(self.treeView)
        self.setLayout(layout)


class MainWindow(QMainWindow):
    WINDOW_TITLE = "IDA Signature Tools"

    def __init__(self):
        super().__init__()

        self.setWindowTitle(self.WINDOW_TITLE)

        self.wait_dialog = PleaseWaitDialog()
        self.progress_dialog = ProgressDialog(parent=self)
        self.button_open = QPushButton("Open signatures folder")
        self.button_open.setDefault(True)
        self.button_close = QPushButton("Close")
        self.button_analysis = QPushButton("Run multi-core analysis")
        self.button_analysis.setDisabled(True)
        self.button_apply = QPushButton("Apply signatures")
        self.button_apply.setDisabled(True)

        self.button_open.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.button_close.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.button_analysis.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.button_apply.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        self.download_label = QLabel('Download more signatures packs from <a href="https://my.hex-rays.io">my.hex-rays.com</a>')
        palette = self.download_label.palette()
        palette.setColor(QPalette.WindowText, palette.color(QPalette.Link))
        self.download_label.setPalette(palette)
        self.download_label.setAlignment(Qt.AlignCenter)
        self.download_label.setOpenExternalLinks(True)
        self.download_label.setDisabled(True)
        self.download_label.hide()

        self.regex_input = QLineEdit()
        self.regex_input.setStyleSheet("""
            QLineEdit {
                border-radius: 4px;
            }
        """)
        self.regex_input.setMinimumWidth(200)
        self.regex_input.setPlaceholderText("Filter by regex")

        self.top_hbox = QHBoxLayout()
        self.top_hbox.addWidget(self.button_open)
        self.top_hbox.addWidget(self.regex_input)
        self.top_hbox.addStretch()
        self.top_hbox.addWidget(self.button_analysis)
        self.top_hbox.addWidget(self.button_apply)

        self.bottom_hbox = QHBoxLayout()
        # self.bottom_hbox.addSpacing(20)
        # self.bottom_hbox.addWidget(self.button_close)
        self.bottom_hbox.addStretch()
        self.bottom_hbox.addWidget(self.download_label)
        self.vbox = QVBoxLayout()

        self.tree_view = SignaturesTreeView()

        self.top_widget = QWidget()
        self.top_widget.setLayout(self.top_hbox)

        self.center_label = QLabel('No signature found. Click \"Open signatures folder\" to import signatures.')
        self.center_label.setAlignment(Qt.AlignCenter)
        self.center_label.setAutoFillBackground(True)
        self.center_label.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.center_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.bottom_widget = QWidget()
        self.bottom_widget.setLayout(self.bottom_hbox)

        self.main_vbox = QVBoxLayout()
        self.main_vbox.addWidget(self.top_widget)
        self.main_vbox.addWidget(self.center_label)
        # self.main_vbox.addWidget(self.tree_view)
        self.main_vbox.addWidget(self.bottom_widget)

        self.details_group = QGroupBox("")
        self.details_group.setLayout(self.main_vbox)
        self.details_group.setStyleSheet(default_style_sheet)

        self.vbox.addWidget(self.details_group)

        self.central_widget = QWidget()
        self.central_widget.setLayout(self.vbox)

        self.setCentralWidget(self.central_widget)
        self.resize_and_center()

    def showEvent(self, event):
        super().showEvent(event)
        self.button_open.setFocus()

    def resize_and_center(self):
        # Get the current cursor position (where the mouse is located)
        cursor_pos = QCursor.pos()

        # Get the screen where the cursor is located
        screen = QApplication.screenAt(cursor_pos)
        screen_geometry = screen.availableGeometry()

        # Calculate the size: 2/3 of the screen width and height
        width = screen_geometry.width() * 2 // 3
        height = screen_geometry.height() * 2 // 3

        # Set the size of the main window
        self.resize(width, height)

        # Calculate the position to center the window on the current screen
        left = screen_geometry.left() + (screen_geometry.width() - width) // 2
        top = screen_geometry.top() + (screen_geometry.height() - height) // 2

        # Move the window to the calculated position
        self.move(left, top)

class IdaPluginForm(ida_kernwin.PluginForm):
    def __init__(self):
        super(IdaPluginForm, self).__init__()
        self.parent = None
        self.visible = False
        self.prepare()

    def prepare(self):
        self.wait_dialog = PleaseWaitDialog()
        self.progress_dialog = ProgressDialog(parent=self.parent)
        self.button_open = QPushButton("Open signatures folder")
        self.button_open.setDefault(True)
        self.button_close = QPushButton("Close")
        self.button_analysis = QPushButton("Run multi-core analysis")
        self.button_analysis.setDisabled(True)
        self.button_apply = QPushButton("Apply signatures")
        self.button_apply.setDisabled(True)

        self.button_open.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.button_close.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.button_analysis.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.button_apply.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        self.download_label = QLabel(
            'Download more signatures packs from <a href="https://my.hex-rays.io">my.hex-rays.com</a>')
        palette = self.download_label.palette()
        palette.setColor(QPalette.WindowText, palette.color(QPalette.Link))
        self.download_label.setPalette(palette)
        self.download_label.setAlignment(Qt.AlignCenter)
        self.download_label.setOpenExternalLinks(True)
        self.download_label.setDisabled(True)
        self.download_label.hide()

        self.regex_input = QLineEdit()
        self.regex_input.setStyleSheet("""
            QLineEdit {
                border-radius: 4px;
            }
        """)
        self.regex_input.setMinimumWidth(200)
        self.regex_input.setPlaceholderText("Filter by regex")

        self.top_hbox = QHBoxLayout()
        self.top_hbox.addWidget(self.button_open)
        self.top_hbox.addWidget(self.regex_input)
        self.top_hbox.addStretch()
        self.top_hbox.addWidget(self.button_analysis)
        self.top_hbox.addWidget(self.button_apply)

        self.bottom_hbox = QHBoxLayout()
        # self.bottom_hbox.addSpacing(20)
        # self.bottom_hbox.addWidget(self.button_close)
        self.bottom_hbox.addStretch()
        self.bottom_hbox.addWidget(self.download_label)
        self.vbox = QVBoxLayout()

        self.tree_view = SignaturesTreeView()

        self.top_widget = QWidget()
        self.top_widget.setLayout(self.top_hbox)

        self.center_label = QLabel('No signature found. Click \"Open signatures folder\" to import signatures.')
        self.center_label.setAlignment(Qt.AlignCenter)
        self.center_label.setAutoFillBackground(True)
        self.center_label.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.center_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.bottom_widget = QWidget()
        self.bottom_widget.setLayout(self.bottom_hbox)

        self.main_vbox = QVBoxLayout()
        self.main_vbox.addWidget(self.top_widget)
        self.main_vbox.addWidget(self.center_label)
        # self.main_vbox.addWidget(self.tree_view)
        self.main_vbox.addWidget(self.bottom_widget)

        self.details_group = QGroupBox("")
        self.details_group.setLayout(self.main_vbox)
        self.details_group.setStyleSheet(default_style_sheet)

        self.vbox.addWidget(self.details_group)

        # self.central_widget = QWidget()
        # self.central_widget.setLayout(self.vbox)

    def OnCreate(self, form):
        """
        Called when the form is created.
        This is where we create and set up the widget and its layout.
        """
        # Get the QWidget for the form
        self.parent = self.FormToPyQtWidget(form)
        self.prepare()
        self.parent.setLayout(self.main_vbox)

    def Show(self, caption):
        """
        Override the Show method to make the form visible again if it was hidden.
        """
        if not self.visible:
            # Show the form if it's not visible
            ida_kernwin.PluginForm.Show(self, caption, options = ida_kernwin.PluginForm.WOPN_TAB)
            self.visible = True
        else:
            # If it's already hidden, just show it again
            self.parent.show()

    def Close(self):
        """
        Hides the form when closing (instead of actually closing/destroying it).
        """
        if self.visible:
            self.OnClose(self)
        else:
            ida_kernwin.msg("The form is already hidden.\n")

    def populate_form(self):
        # self.parent.setWindowTitle(self.WINDOW_TITLE)
        self.parent.setCentralWidget(self.central_widget)
        # self.resize_and_center()
