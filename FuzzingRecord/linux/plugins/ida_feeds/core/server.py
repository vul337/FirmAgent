import os
import sys
import signal
import rpyc
import idapro
from idahelper import IDA as wrapper
from rpyc.utils.server import OneShotServer


def disable_history():
    try:
        if "IDA_NO_HISTORY" in os.environ:
            value = os.environ["IDA_NO_HISTORY"]
            os.environ["IDA_NO_HISTORY"] = "1"
            return value
        else:
            os.environ["IDA_NO_HISTORY"] = "1"
            return None
    except:
        pass

def revert_history(value):
    try:
        if value is not None:
            if "IDA_NO_HISTORY" in os.environ:
                os.environ["IDA_NO_HISTORY"] = value
        else:
            os.environ.pop("IDA_NO_HISTORY")
    except:
        pass

class FeedsService(rpyc.Service):
    def on_connect(self, conn):
        sys.stdout.write = conn.root.stdout_write
        sys.stderr.write = conn.root.stderr_write
        print(f"Client connected to worker on port {self.port}")

    def on_disconnect(self, conn):
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

    def exposed_open_database(self, path):
        val = disable_history()
        result = idapro.open_database(path, True)
        revert_history(val)
        return result

    def exposed_close_database(self):
        val = disable_history()
        idapro.close_database(False)
        revert_history(val)

    def exposed_apply_signature(self, path):
        val = disable_history()
        result = wrapper.apply_sig_file(path)
        revert_history(val)
        return result

    def exposed_create_undo(self):
        val = disable_history()
        wrapper.create_undo()
        revert_history(val)

    def exposed_perform_undo(self):
        val = disable_history()
        wrapper.perform_undo()
        revert_history(val)

def signal_handler(sig, frame):
    print("Shutting down...")
    server.close()


if __name__ == "__main__":
    idapro.enable_console_messages(True)
    port = int(sys.argv[1])

    print(f"Started new server on port {port}")

    service = FeedsService()
    service.port = port

    server = OneShotServer(service, port=port, protocol_config={"sync_request_timeout": 240, "allow_pickle": True})

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    val = disable_history()
    server.start()
    revert_history(val)
