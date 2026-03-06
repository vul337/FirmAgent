import os
import sys
import platform
from pathlib import Path

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


def get_user_config_path():
    system = platform.system()

    if system == "Windows":
        # On Windows, use the %APPDATA%\Hex-Rays\IDA Pro directory
        config_dir = Path(os.getenv('APPDATA')) / "Hex-Rays" / "IDA Pro"
    else:
        # On macOS and Linux, use ~/.idapro
        config_dir = Path.home() / ".idapro"
    return config_dir


PLUGIN_DIR = Path(__file__).resolve().parent
CACHE_DIR = os.path.join(get_user_config_path(), '.cache')
SERVER_PY = os.path.join(PLUGIN_DIR, 'core', 'server.py')
IDB_PATH = ''

# get the right python interpreter path
# first check sys.executable (set under venv and standalone execution)
interpfn = os.path.basename(sys.executable) if sys.executable else ''
if interpfn.startswith("python"): #python[.exe] or python3
   SYS_INTERPRETER_PATH = sys.executable
else:
    # IDAPython sets sys.executable to ida[.exe]
    # so look in base_exec_prefix
    platform_str = platform.system()
    if platform_str == "Windows":
        SYS_INTERPRETER_PATH = os.path.join(sys.base_exec_prefix, 'python')
    elif platform_str == "Linux":
        SYS_INTERPRETER_PATH = os.path.join(sys.base_exec_prefix, 'bin', 'python3')
    elif platform_str == "Darwin":
        SYS_INTERPRETER_PATH = os.path.join(sys.base_exec_prefix, 'bin', 'python3')
    else:
        raise ImportError(f"Unknown platform {platform_str}")

PORT_START = 12345
PORT_END = PORT_START + os.cpu_count()
PORTS = [str(i) for i in range(PORT_START, PORT_END)]
