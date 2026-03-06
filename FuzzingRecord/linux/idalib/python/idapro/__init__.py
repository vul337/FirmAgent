from __future__ import annotations
import sys
import platform
from pathlib import Path
import ctypes
import os
from .config import get_ida_install_dir

def find_file(name, path):
    """Internal method used for recursively find a file in a folder"""
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)
    return None

# get the right filename based on platform
platform_str = platform.system()

if platform_str == "Windows":
    name = "idalib.dll"
elif platform_str == "Linux":
    name = "libidalib.so"
elif platform_str == "Darwin":
    name = "libidalib.dylib"
else:
    raise ImportError(f"Unknown platform {platform_str}")

# Get the ida-install-dir setting
root_dir = get_ida_install_dir()

if platform_str == "Windows":
    # IDA kernel and modules may need dependencies in its root dir (e.g. clp64.dll)
    # tell Windows loader where they can be found
    # NB: for AddDllDirectory() be effective for indirectly loaded DLLs,
    # SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_USER_DIRS) has to be called first
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    SetDefaultDllDirectories = getattr(kernel32, "SetDefaultDllDirectories")
    if SetDefaultDllDirectories:
        from  ctypes.wintypes import DWORD, BOOL
        SetDefaultDllDirectories.argtypes = [DWORD]
        SetDefaultDllDirectories.restype = BOOL
        LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400
        if SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_USER_DIRS):
            # finally, add IDA's directory for dependencies
            os.add_dll_directory(root_dir)
    else:
        os.environ['PATH'] = root_dir + os.pathsep + os.environ.get('PATH', '')

idalib_path = find_file(name=name, path=root_dir)
if idalib_path is None:
    raise ImportError(f"Could not find {name} in {root_dir}. Please make sure you have an IDA version 9.0 or newer and run py-activate-idalib.py utility shipped with it in order to activate this module.")

if "IDA_IS_INTERACTIVE" in os.environ:
    if os.environ["IDA_IS_INTERACTIVE"] == "1":
        raise ImportError("The IDA library can only be run in a separate process and cannot be loaded within IDA itself.")

# load the library and initialize the kernel
try:
    libida = ctypes.cdll.LoadLibrary(idalib_path)
except Exception as e:
    raise ImportError(f"Failed loading IDA library file {idalib_path}, exception {e}\n")

try:
    error_description = None
    init_code = libida.init_library(0, None)
    if init_code != 0:
        error_description = f"init_library error code {init_code}"
except Exception as e:
    error_description = f"exception {e}"

if error_description != None:
    raise ImportError(f"Failed to initialize IDA library, {error_description}, check logging for additional information\n")

sys.path.append(str(Path(idalib_path).parent / "python/lib-dynload"))
sys.path.append(str(Path(idalib_path).parent / "python"))

def open_database(file_name:str, run_auto_analysis)->int:
    """Open the database specified in file_path argument
    NOTE: All library functions must be called from the same thread that initialized the library
    The library is single-threaded, and performing database operations from a different thread
    than the initialization thread may lead to undefined behavior"""
    return libida.open_database(file_name.encode(), run_auto_analysis)

def close_database(save = True)->None:
    """Close the current database"""
    libida.close_database(save)

def make_signatures(only_pat = False)->bool:
    """Generate .sig and .pat files for the current database"""
    return libida.make_signatures(only_pat)

def enable_console_messages(enable:bool)->None:
    """Enable console messages, they are disabled by default"""
    libida.enable_console_messages(enable)

def set_screen_ea(screen_ea: "ea_t")->None:
    """Set screen ea, let the user specify the current screen ea
    subsequent calls to get_screen_ea will return this value"""
    libida.set_screen_ea.argtypes = [ctypes.c_uint64]
    libida.set_screen_ea(screen_ea)

def get_library_version()->tuple[int, int, int] | None:
    """Get IDA library version, return minor, major build in case of success, None if fails"""
    major = ctypes.c_int()
    minor = ctypes.c_int()
    build = ctypes.c_int()

    libida.get_library_version.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)]
    libida.get_library_version.restype = ctypes.c_bool
    success = libida.get_library_version(ctypes.byref(major), ctypes.byref(minor), ctypes.byref(build))

    if success:
        return major.value, minor.value, build.value
    else:
        return None
