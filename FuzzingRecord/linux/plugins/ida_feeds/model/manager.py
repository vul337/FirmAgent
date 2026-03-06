import os
import shutil
import subprocess
from collections import Counter
from enum import Enum
from itertools import cycle
from time import sleep
import platform

import idc
import rpyc.utils.classic
from PyQt5.QtCore import *
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import *

import env
from core.client import RpcClient
from core.idahelper import IDA
from env import *  # SERVER_PY, CACHE_DIR, SYS_INTERPRETER_PATH
from model.filter import CustomFilterProxyModel
from view.main import MainWindow

sysenv = os.environ.copy()
# Allow IDALIB to load when running the plugin
sysenv["IDA_IS_INTERACTIVE"] = "0"
sysenv["IDA_NO_HISTORY"] = "1"

def start_process(port):
    # process = subprocess.Popen([sys.executable, SERVER_PY, str(port)], stdout=sys.stdout, stderr=sys.stderr)
    process = None
    try:
        if platform.system() == "Windows":
            process = subprocess.Popen([SYS_INTERPRETER_PATH, SERVER_PY, str(port)], env=sysenv, creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            process = subprocess.Popen([SYS_INTERPRETER_PATH, SERVER_PY, str(port)], env=sysenv)
    except Exception as e:
        print(e)
    return process


class WorkerSignals(QObject):
    auto_started = pyqtSignal()
    auto_finished = pyqtSignal()
    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object, object, bool)
    progress = pyqtSignal(int)


'''
RpcPipe
'''


class RpcPipe(QRunnable):
    def __init__(self, port, host='localhost'):
        super(RpcPipe, self).__init__()

        self.host = host
        self.port = port
        self.server = None
        self.client = None
        self.sig_list = []
        self.signals = WorkerSignals()
        self.dir = os.path.join(CACHE_DIR, 'procs', f'{self.port}')
        self.idb = os.path.join(self.dir, os.path.basename(idc.get_idb_path()))

    def start(self):
        self.server = start_process(str(self.port))
        self.client = RpcClient(self.host, self.port)
        sleep(1)  # TODO: add retries handling
        self.client.connect(os.path.join(self.dir, f'ida.log'))
        return self

    def stop(self):
        self.client.disconnect()
        self.server.wait()

    def prepare(self):
        try:
            if not os.path.exists(self.dir):
                os.makedirs(self.dir)
            val = env.disable_history()
            IDA.save_idb_copy(self.idb)
            env.revert_history(val)
        except Exception as e:
            print(e)
            pass

    @pyqtSlot()
    def run(self):
        try:
            self.start()
            result = self.client.request("open_database", self.idb)
            i = 0
            for item in self.sig_list:
                path = item["path"]
                row = item["row"]
                self.client.request("create_undo")
                result = self.client.request("apply_signature", path)
                value = rpyc.utils.classic.obtain(result)
                self.signals.result.emit(value, row, True)
                self.client.request("perform_undo")
                i += 1
                self.signals.progress.emit(1)

            self.client.request("close_database")
            self.stop()
        except Exception as e:
            print(e)
        else:
            pass
        finally:
            self.signals.finished.emit()

    def process(self, thread_pool, sig_list):
        self.sig_list = sig_list
        thread_pool.start(self)

    def cleanup(self):
        try:
            shutil.rmtree(self.dir)
        except Exception as e:
            pass


class SignatureItemState(Enum):
    NONE = (0, "None")
    VERIFIED = (1, "Verified")
    APPLIED = (2, "Applied")

    @property
    def value_int(self):
        return self.value[0]

    @property
    def description(self):
        return self.value[1]

    @classmethod
    def from_value(cls, value):
        for member in cls:
            if member.value_int == value:
                return member
        return cls.NONE


'''
Manager
'''


class Manager:
    def __init__(self, ports, idb, view: MainWindow, lib_available: bool):
        self.ports = ports
        self.idb = idb
        self.lib_available = lib_available
        self.view = view
        self.signals = WorkerSignals()
        self.thread_pool = QThreadPool.globalInstance()
        self.thread_pool.setMaxThreadCount(len(ports))
        self.clean_cache()
        self.job_completed_units = 0
        self.job_total_units = 0
        self.state_counter = Counter({item_state: 0 for item_state in SignatureItemState})

        # Set up model
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(['File', 'Library name', '# Matches', 'State'])

        # Set up the sorting filter proxy model
        self.proxy_model = CustomFilterProxyModel()
        self.proxy_model.setSourceModel(self.model)
        self.view.tree_view.treeView.setModel(self.proxy_model)

        self.connect_callbacks()

    def set_item_state(self, item, row_state: SignatureItemState = SignatureItemState.NONE):
        font = item.font()
        if row_state == SignatureItemState.VERIFIED:
            font.setItalic(True)
            font.setBold(False)
            item.setFont(font)
        if row_state == SignatureItemState.APPLIED:
            font.setItalic(False)
            font.setBold(True)
            item.setFont(font)

    def set_row_state(self, row, row_state: SignatureItemState = SignatureItemState.NONE):
        cols = self.model.columnCount()
        for col in range(cols):
            item = self.get_item_from_source(row, col)
            self.set_item_state(item, row_state)

    def set_row_list_state(self, row: [], row_state: SignatureItemState = SignatureItemState.NONE):
        for item in row:
            self.set_row_state(item, row_state)

    def add_row(self, root, file_path, file_name, matches, state: SignatureItemState = SignatureItemState.NONE):
        columns = []

        item = QStandardItem(f'{file_name} ({root})')
        item.setData(file_path, Qt.UserRole)
        columns.append(item)

        item = QStandardItem(f'{IDA.get_sig_name(file_path)}')
        columns.append(item)

        item = QStandardItem(matches)
        if matches > -1:
            item.setData(matches, Qt.UserRole)
            item.setText(str(matches))
        else:
            item.setData(-1, Qt.UserRole)
            item.setText('')
        columns.append(item)

        item = QStandardItem(state.description)
        item.setData(state.value_int, Qt.UserRole)
        columns.append(item)

        for item in columns:
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
        self.model.appendRow(columns)
        self.set_row_list_state(columns, state)

    def add_items(self, folder_path):
        applied = IDA.get_applied_sigs()
        for root, dirs, files in os.walk(folder_path):
            for file_name in files:
                if file_name.endswith('.sig'):
                    file_path = os.path.join(root, file_name)
                    # file_size = os.path.getsize(file_path) / 1024  # Size in KB
                    result = next((i for i, sig in enumerate(applied) if sig[0] == file_path), None)
                    if result:
                        self.add_row(root, file_path, file_name, applied[result][2], SignatureItemState.APPLIED)
                    else:
                        self.add_row(root, file_path, file_name, -1, SignatureItemState.NONE)

    def connect_callbacks(self):
        self.view.regex_input.editingFinished.connect(self.filter_items)
        self.view.tree_view.open_action.triggered.connect(self.open_directory_dialog)
        self.view.tree_view.analysis_action.triggered.connect(self.on_click_analyze)
        self.view.tree_view.apply_action.triggered.connect(self.on_click_apply)
        # self.view.tree_view.cancel_action.triggered.connect(self.view.close)
        self.view.button_open.clicked.connect(self.open_directory_dialog)
        # self.view.button_close.clicked.connect(self.view.close)
        self.view.button_analysis.clicked.connect(self.on_click_analyze)
        self.view.button_apply.clicked.connect(self.on_click_apply)
        self.view.tree_view.treeView.customContextMenuRequested.connect(self.open_context_menu)
        self.view.tree_view.treeView.selectionModel().selectionChanged.connect(self.on_selection_changed)
        self.model.dataChanged.connect(self.on_data_changed)

    def set_actions_state(self):
        selected_states = []
        selected_indexes = self.view.tree_view.treeView.selectionModel().selectedIndexes()
        for index in selected_indexes:
            if index.column() == 0:
                row_state = self.get_row_state(index)
                if row_state is not None:
                    selected_states.append(SignatureItemState.from_value(row_state))

        self.state_counter = Counter({item_state: 0 for item_state in SignatureItemState})
        self.state_counter.update(selected_states)

        self.view.tree_view.analysis_action.setEnabled(self.lib_available)
        self.view.tree_view.apply_action.setEnabled(True)
        self.view.button_analysis.setEnabled(self.lib_available)
        self.view.button_apply.setEnabled(True)
        if self.state_counter[SignatureItemState.NONE] == 0:
            self.view.tree_view.analysis_action.setDisabled(True)
            self.view.button_analysis.setDisabled(True)
            if self.state_counter[SignatureItemState.VERIFIED] == 0:
                self.view.tree_view.apply_action.setDisabled(True)
                self.view.button_apply.setDisabled(True)

        self.view.button_analysis.setText(f'Run multi-core analysis ({self.state_counter[SignatureItemState.NONE]})')
        self.view.button_apply.setText(f'Apply signatures ({self.state_counter[SignatureItemState.NONE] + self.state_counter[SignatureItemState.VERIFIED]})')

    def on_data_changed(self, tl, br, ro):
        self.set_actions_state()

    def on_selection_changed(self, selected, deselected):
        self.set_actions_state()

    def open_context_menu(self, position):
        # index = self.treeView.indexAt(position)
        self.set_actions_state()
        self.view.tree_view.context_menu.exec_(self.view.tree_view.treeView.viewport().mapToGlobal(position))

    def on_applied_result(self, matches, row):
        self.update_results(row, matches, [], SignatureItemState.APPLIED)

    def on_verified_result(self, result, row):
        self.update_results(row, result["matches"], result["matched_functions"], SignatureItemState.VERIFIED)

    def on_progress(self, value):
        self.job_completed_units += 1
        val = self.job_completed_units
        self.view.progress_dialog.progress_bar.setValue(val)
        if val >= self.job_total_units:
            self.view.progress_dialog.label.setText(f"Done analysing {val} signatures")
            self.view.progress_dialog.hide()
            self.view.tree_view.treeView.sortByColumn(3, Qt.DescendingOrder)
            self.view.tree_view.treeView.sortByColumn(2, Qt.DescendingOrder)

    def filter_items(self):
        pattern = self.view.regex_input.text()
        self.proxy_model.setFilterRegularExpression(QRegularExpression(pattern))

    def get_row_state(self, index):
        if index.column() == 0:
            source_index = self.proxy_model.mapToSource(index)
            if source_index.isValid():
                state_index = source_index.siblingAtColumn(3)
                return self.model.data(state_index, Qt.UserRole)

        return None

    def get_selected_items(self, allow_state: []):
        sig_rows = []
        selected_indexes = self.view.tree_view.treeView.selectionModel().selectedIndexes()
        for index in selected_indexes:
            if index.column() == 0:
                source_index = self.proxy_model.mapToSource(index)
                if source_index.isValid():
                    source_data = self.model.data(source_index, Qt.UserRole)
                    if self.get_row_state(index) in allow_state:
                        sig_rows.append({'path': source_data, 'row': source_index})

        return sig_rows

    def on_click_apply(self):
        items = self.get_selected_items([SignatureItemState.NONE.value_int, SignatureItemState.VERIFIED.value_int])
        results = IDA.apply_sig_list(items)
        for result in results:
            self.on_applied_result(result[1], result[2])

    def get_item_from_proxy(self, row, column):
        proxy_index = self.proxy_model.index(row, column)
        source_index = self.proxy_model.mapToSource(proxy_index)
        return self.model.itemFromIndex(source_index)

    def get_item_from_source(self, index, column):
        row = index.row()
        item_index = self.model.index(row, column)
        return self.model.itemFromIndex(item_index)

    def update_results(self, row, total_matches, func_matches, row_state: SignatureItemState = None):
        self.set_row_state(row, row_state)
        item_sig = self.get_item_from_source(row, 0)
        for fun_match in func_matches:
            fun_item = QStandardItem(fun_match)
            fun_item.setSelectable(False)
            fun_item.setEditable(False)
            item_sig.appendRow(fun_item)

        self.get_item_from_source(row, 2).setData(int(total_matches), Qt.UserRole)
        self.get_item_from_source(row, 2).setData(str(total_matches), Qt.DisplayRole)
        self.get_item_from_source(row, 3).setData(row_state.value_int, Qt.UserRole)
        self.get_item_from_source(row, 3).setData(row_state.description, Qt.DisplayRole)

    def on_click_analyze(self):
        sig_rows = self.get_selected_items([SignatureItemState.NONE.value_int])
        if len(sig_rows) != 0:
            self.process(sig_rows)

    def on_local_line_text_changed(self, text):
        pass

    def populate_model(self, directory = IDA.get_ida_sig_dir()):
        self.model.removeRows(0, self.model.rowCount())  # Clear the model
        self.add_items(directory)
        self.view.tree_view.treeView.sortByColumn(2, Qt.DescendingOrder)
        self.view.tree_view.treeView.sortByColumn(3, Qt.DescendingOrder)
        self.view.tree_view.header.resizeSections(QHeaderView.ResizeToContents)
        self.view.tree_view.treeView.expandAll()  # Expand all groups

        if self.view.center_label is not None:
            self.view.main_vbox.removeWidget(self.view.center_label)
            self.view.center_label.deleteLater()
            self.view.center_label = None
        self.view.main_vbox.insertWidget(1, self.view.tree_view)

    def open_directory_dialog(self):
        if type(self.view.parent) is QWidget:
            parent=self.view.parent
        else:
            parent=self.view

        directory = QFileDialog.getExistingDirectory(parent=parent, caption="Select Directory", directory=IDA.get_ida_sig_dir())
        if directory:
            self.populate_model(directory)

    def clean_cache(self):
        try:
            shutil.rmtree(CACHE_DIR)
        except Exception as e:
            pass

    def process(self, signatures):

        def split_list(lst, n):
            # Initialize the sublists as empty lists
            slists = [[] for _ in range(n)]
            # Distribute items across the sublists
            for i, item in enumerate(lst):
                slists[i % n].append(item)

            return slists

        sig_lists = split_list(signatures, len(self.ports))
        combined = list(zip(cycle(self.ports), sig_lists))
        self.job_total_units = len(signatures)
        self.job_completed_units = 0
        self.view.progress_dialog.progress_bar.setValue(0)
        self.view.progress_dialog.progress_bar.setMaximum(self.job_total_units)
        self.view.progress_dialog.show()
        try:
            for port, sig_sublist in combined:
                if len(sig_sublist) > 0:
                    rpc_pipe = RpcPipe(port)
                    # keep 'prepare' on the main thread
                    rpc_pipe.cleanup()
                    rpc_pipe.prepare()
                    rpc_pipe.signals.result.connect(self.on_verified_result, Qt.QueuedConnection)
                    rpc_pipe.signals.progress.connect(self.on_progress, Qt.QueuedConnection)
                    rpc_pipe.process(thread_pool=self.thread_pool, sig_list=sig_sublist)
        except Exception as e:
            self.view.progress_dialog.hide()
