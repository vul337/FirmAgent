import rpyc
import sys


class ClientService(rpyc.Service):
    def exposed_stdout_write(self, data):
        sys.stdout.write(data)

    def exposed_stderr_write(self, data):
        sys.stderr.write(data)


class LoggerClientService(rpyc.Service):
    def __init__(self, log_file):
        super().__init__()
        self.log_file = open(log_file, "a")  # Open the file in append mode

    def exposed_stdout_write(self, data):
        self.log_file.write(data)
        self.log_file.flush()  # Ensure the output is flushed immediately

    def exposed_stderr_write(self, data):
        self.log_file.write(data)
        self.log_file.flush()  # Ensure the error output is flushed immediately

    def on_disconnect(self, conn):
        self.log_file.close()  # Close the file when the connection is closed

    def __del__(self):
        self.log_file.close()

class RpcClient(object):
    def __init__(self, host="localhost", port=None):
        self.host = host
        self.port = port
        self.conn = None

    def connect(self, log_file=None):
        self.conn = rpyc.connect(host=self.host,
                                 port=self.port,
                                 service=LoggerClientService(log_file),
                                 config={"sync_request_timeout": 240})

    def disconnect(self):
        self.conn.close()

    def request(self, method_name: str, *args, **kwargs):
        method = getattr(self.conn.root, method_name)
        response = method(*args, **kwargs)
        return response
