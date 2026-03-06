r"""
This is the first header included in the IDA project.

It defines the most common types, functions and data. Also, it tries to make
system dependent definitions.

The following preprocessor macros are used in the project (the list may be
incomplete)

Platform must be specified as one of:

__NT__ - MS Windows (all platforms)
__LINUX__ - Linux
__MAC__ - MAC OS X

__EA64__ - 64-bit address size (sizeof(ea_t)==8)
__X86__ - 32-bit debug servers (sizeof(void*)==4)
__X64__ - x64 processor (sizeof(void*)==8) default
__PPC__ - PowerPC
__ARM__ - ARM"""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_pro
else:
    import _ida_pro

try:
    import builtins as __builtin__
except ImportError:
    import __builtin__

def _swig_repr(self):
    try:
        strthis = "proxy of " + self.this.__repr__()
    except __builtin__.Exception:
        strthis = ""
    return "<%s.%s; %s >" % (self.__class__.__module__, self.__class__.__name__, strthis,)


def _swig_setattr_nondynamic_instance_variable(set):
    def set_instance_attr(self, name, value):
        if name == "this":
            set(self, name, value)
        elif name == "thisown":
            self.this.own(value)
        elif hasattr(self, name) and isinstance(getattr(type(self), name), property):
            set(self, name, value)
        else:
            raise AttributeError("You cannot add instance attributes to %s" % self)
    return set_instance_attr


def _swig_setattr_nondynamic_class_variable(set):
    def set_class_attr(cls, name, value):
        if hasattr(cls, name) and not isinstance(getattr(cls, name), property):
            set(cls, name, value)
        else:
            raise AttributeError("You cannot add class attributes to %s" % cls)
    return set_class_attr


def _swig_add_metaclass(metaclass):
    """Class decorator for adding a metaclass to a SWIG wrapped class - a slimmed down version of six.add_metaclass"""
    def wrapper(cls):
        return metaclass(cls.__name__, cls.__bases__, cls.__dict__.copy())
    return wrapper


class _SwigNonDynamicMeta(type):
    """Meta class to enforce nondynamic attributes (no new attributes) for a class"""
    __setattr__ = _swig_setattr_nondynamic_class_variable(type.__setattr__)


import weakref

SWIG_PYTHON_LEGACY_BOOL = _ida_pro.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

BADDIFF = _ida_pro.BADDIFF

IDA_SDK_VERSION = _ida_pro.IDA_SDK_VERSION
r"""
IDA SDK v9.0.
"""

BADMEMSIZE = _ida_pro.BADMEMSIZE

_CRT_DECLARE_NONSTDC_NAMES = _ida_pro._CRT_DECLARE_NONSTDC_NAMES

MAXSTR = _ida_pro.MAXSTR
r"""
maximum string size
"""

__MF__ = _ida_pro.__MF__
r"""
byte sex of our platform (Most significant byte First). 0: little endian (Intel
80x86). 1: big endian (PowerPC).
"""


def qatoll(nptr: "char const *") -> "int64":
    r"""
    qatoll(nptr) -> int64

    @param nptr: char const *
    """
    return _ida_pro.qatoll(nptr)
FMT_64 = _ida_pro.FMT_64

FMT_Z = _ida_pro.FMT_Z

FMT_ZX = _ida_pro.FMT_ZX

FMT_ZS = _ida_pro.FMT_ZS

FMT_EA = _ida_pro.FMT_EA


def qexit(code: "int") -> "void":
    r"""
    qexit(code)
    Call qatexit functions, shut down UI and kernel, and exit.

    @param code: (C++: int) exit code
    """
    return _ida_pro.qexit(code)

def log2ceil(d64: "uint64") -> "int":
    r"""
    log2ceil(d64) -> int
    calculate ceil(log2(d64)) or floor(log2(d64)), it returns 0 if d64 == 0

    @param d64: (C++: uint64)
    """
    return _ida_pro.log2ceil(d64)

def log2floor(d64: "uint64") -> "int":
    r"""
    log2floor(d64) -> int

    @param d64: uint64
    """
    return _ida_pro.log2floor(d64)

def extend_sign(v: "uint64", nbytes: "int", sign_extend: "bool") -> "uint64":
    r"""
    extend_sign(v, nbytes, sign_extend) -> uint64
    Sign-, or zero-extend the value 'v' to occupy 64 bits. The value 'v' is
    considered to be of size 'nbytes'.

    @param v: (C++: uint64)
    @param nbytes: (C++: int)
    @param sign_extend: (C++: bool)
    """
    return _ida_pro.extend_sign(v, nbytes, sign_extend)

def readbytes(h: "int", res: "uint32 *", size: "int", mf: "bool") -> "int":
    r"""
    readbytes(h, res, size, mf) -> int
    Read at most 4 bytes from file.

    @param h: (C++: int) file handle
    @param res: (C++: uint32 *) value read from file
    @param size: (C++: int) size of value in bytes (1,2,4)
    @param mf: (C++: bool) is MSB first?
    @return: 0 on success, nonzero otherwise
    """
    return _ida_pro.readbytes(h, res, size, mf)

def writebytes(h: "int", l: "uint32", size: "int", mf: "bool") -> "int":
    r"""
    writebytes(h, l, size, mf) -> int
    Write at most 4 bytes to file.

    @param h: (C++: int) file handle
    @param l: (C++: uint32) value to write
    @param size: (C++: int) size of value in bytes (1,2,4)
    @param mf: (C++: bool) is MSB first?
    @return: 0 on success, nonzero otherwise
    """
    return _ida_pro.writebytes(h, l, size, mf)

def reloc_value(value: "void *", size: "int", delta: "adiff_t", mf: "bool") -> "void":
    r"""
    reloc_value(value, size, delta, mf)

    @param value: void *
    @param size: int
    @param delta: adiff_t
    @param mf: bool
    """
    return _ida_pro.reloc_value(value, size, delta, mf)

def qvector_reserve(vec: "void *", old: "void *", cnt: "size_t", elsize: "size_t") -> "void *":
    r"""
    qvector_reserve(vec, old, cnt, elsize) -> void *
    Change capacity of given qvector.

    @param vec: (C++: void *) a pointer to a qvector
    @param old: (C++: void *) a pointer to the qvector's array
    @param cnt: (C++: size_t) number of elements to reserve
    @param elsize: (C++: size_t) size of each element
    @return: a pointer to the newly allocated array
    """
    return _ida_pro.qvector_reserve(vec, old, cnt, elsize)
class qrefcnt_obj_t(object):
    r"""
    Proxy of C++ qrefcnt_obj_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined - class is abstract")
    __repr__ = _swig_repr
    refcnt: "int" = property(_ida_pro.qrefcnt_obj_t_refcnt_get, _ida_pro.qrefcnt_obj_t_refcnt_set, doc=r"""refcnt""")
    r"""
    counter
    """

    def release(self) -> "void":
        r"""
        release(self)
        Call destructor. We use release() instead of operator delete() to maintain
        binary compatibility with all compilers (vc and gcc use different vtable layouts
        for operator delete)
        """
        return _ida_pro.qrefcnt_obj_t_release(self)
    __swig_destroy__ = _ida_pro.delete_qrefcnt_obj_t

# Register qrefcnt_obj_t in _ida_pro:
_ida_pro.qrefcnt_obj_t_swigregister(qrefcnt_obj_t)

def relocate_relobj(_relobj: "relobj_t *", ea: "ea_t", mf: "bool") -> "bool":
    r"""
    relocate_relobj(_relobj, ea, mf) -> bool

    @param _relobj: relobj_t *
    @param ea: ea_t
    @param mf: bool
    """
    return _ida_pro.relocate_relobj(_relobj, ea, mf)
IDBDEC_ESCAPE = _ida_pro.IDBDEC_ESCAPE
r"""
convert non-printable characters to C escapes (
, \xNN, \uNNNN)
"""

CP_BOM = _ida_pro.CP_BOM

UTF8_BOM = _ida_pro.UTF8_BOM

UTF16LE_BOM = _ida_pro.UTF16LE_BOM

UTF16BE_BOM = _ida_pro.UTF16BE_BOM

UTF32LE_BOM = _ida_pro.UTF32LE_BOM

UTF32BE_BOM = _ida_pro.UTF32BE_BOM

CP_ELLIPSIS = _ida_pro.CP_ELLIPSIS

UTF8_ELLIPSIS = _ida_pro.UTF8_ELLIPSIS

CP_REPLCHAR = _ida_pro.CP_REPLCHAR

UTF8_REPLCHAR = _ida_pro.UTF8_REPLCHAR

MAX_UTF8_SEQ_LEN = _ida_pro.MAX_UTF8_SEQ_LEN


def is_cvt64() -> "bool":
    r"""
    is_cvt64() -> bool
    is IDA converting IDB into I64?
    """
    return _ida_pro.is_cvt64()
CEF_RETERR = _ida_pro.CEF_RETERR

ENC_WIN1252 = _ida_pro.ENC_WIN1252

ENC_UTF8 = _ida_pro.ENC_UTF8

ENC_MUTF8 = _ida_pro.ENC_MUTF8

ENC_UTF16 = _ida_pro.ENC_UTF16

ENC_UTF16LE = _ida_pro.ENC_UTF16LE

ENC_UTF16BE = _ida_pro.ENC_UTF16BE

ENC_UTF32 = _ida_pro.ENC_UTF32

ENC_UTF32LE = _ida_pro.ENC_UTF32LE

ENC_UTF32BE = _ida_pro.ENC_UTF32BE

CP_UTF8 = _ida_pro.CP_UTF8

CP_UTF16 = _ida_pro.CP_UTF16
r"""
UTF-16 codepage.
"""

SUBSTCHAR = _ida_pro.SUBSTCHAR
r"""
default char, used if a char cannot be represented in a codepage
"""

class channel_redir_t(object):
    r"""
    Proxy of C++ channel_redir_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    fd: "int" = property(_ida_pro.channel_redir_t_fd_get, _ida_pro.channel_redir_t_fd_set, doc=r"""fd""")
    r"""
    channel number
    """
    file: "qstring" = property(_ida_pro.channel_redir_t_file_get, _ida_pro.channel_redir_t_file_set, doc=r"""file""")
    r"""
    file name to redirect to/from. if empty, the channel must be closed.
    """
    flags: "int" = property(_ida_pro.channel_redir_t_flags_get, _ida_pro.channel_redir_t_flags_set, doc=r"""flags""")
    r"""
    i/o redirection flags
    """

    def is_input(self) -> "bool":
        r"""
        is_input(self) -> bool
        """
        return _ida_pro.channel_redir_t_is_input(self)

    def is_output(self) -> "bool":
        r"""
        is_output(self) -> bool
        """
        return _ida_pro.channel_redir_t_is_output(self)

    def is_append(self) -> "bool":
        r"""
        is_append(self) -> bool
        """
        return _ida_pro.channel_redir_t_is_append(self)

    def is_quoted(self) -> "bool":
        r"""
        is_quoted(self) -> bool
        """
        return _ida_pro.channel_redir_t_is_quoted(self)
    start: "int" = property(_ida_pro.channel_redir_t_start_get, _ida_pro.channel_redir_t_start_set, doc=r"""start""")
    r"""
    begin of the redirection string in the command line
    """
    length: "int" = property(_ida_pro.channel_redir_t_length_get, _ida_pro.channel_redir_t_length_set, doc=r"""length""")
    r"""
    length of the redirection string in the command line
    """

    def __init__(self):
        r"""
        __init__(self) -> channel_redir_t
        """
        _ida_pro.channel_redir_t_swiginit(self, _ida_pro.new_channel_redir_t())
    __swig_destroy__ = _ida_pro.delete_channel_redir_t

# Register channel_redir_t in _ida_pro:
_ida_pro.channel_redir_t_swigregister(channel_redir_t)
IOREDIR_INPUT = _ida_pro.IOREDIR_INPUT
r"""
input redirection
"""

IOREDIR_OUTPUT = _ida_pro.IOREDIR_OUTPUT
r"""
output redirection
"""

IOREDIR_APPEND = _ida_pro.IOREDIR_APPEND
r"""
append, do not overwrite the output file
"""

IOREDIR_QUOTED = _ida_pro.IOREDIR_QUOTED
r"""
the file name was quoted
"""



def quote_cmdline_arg(arg: "qstring *") -> "bool":
    r"""
    quote_cmdline_arg(arg) -> bool
    Quote a command line argument if it contains escape characters. For example, *.c
    will be converted into "*.c" because * may be inadvertently expanded by the
    shell

    @param arg: (C++: qstring *)
    @return: true: modified 'arg'
    """
    return _ida_pro.quote_cmdline_arg(arg)
class plugin_options_t(object):
    r"""
    Proxy of C++ plugin_options_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def erase(self, name: "char const *") -> "bool":
        r"""
        erase(self, name) -> bool

        @param name: char const *
        """
        return _ida_pro.plugin_options_t_erase(self, name)

    def __init__(self):
        r"""
        __init__(self) -> plugin_options_t
        """
        _ida_pro.plugin_options_t_swiginit(self, _ida_pro.new_plugin_options_t())
    __swig_destroy__ = _ida_pro.delete_plugin_options_t

# Register plugin_options_t in _ida_pro:
_ida_pro.plugin_options_t_swigregister(plugin_options_t)
class instant_dbgopts_t(object):
    r"""
    Proxy of C++ instant_dbgopts_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    debmod: "qstring" = property(_ida_pro.instant_dbgopts_t_debmod_get, _ida_pro.instant_dbgopts_t_debmod_set, doc=r"""debmod""")
    r"""
    name of debugger module
    """
    env: "qstring" = property(_ida_pro.instant_dbgopts_t_env_get, _ida_pro.instant_dbgopts_t_env_set, doc=r"""env""")
    r"""
    config variables for debmod. example: DEFAULT_CPU=13;MAXPACKETSIZE=-1
    """
    host: "qstring" = property(_ida_pro.instant_dbgopts_t_host_get, _ida_pro.instant_dbgopts_t_host_set, doc=r"""host""")
    r"""
    remote hostname (if remote debugging)
    """
    _pass: "qstring" = property(_ida_pro.instant_dbgopts_t__pass_get, _ida_pro.instant_dbgopts_t__pass_set, doc=r"""_pass""")
    port: "int" = property(_ida_pro.instant_dbgopts_t_port_get, _ida_pro.instant_dbgopts_t_port_set, doc=r"""port""")
    r"""
    port number for the remote debugger server
    """
    pid: "int" = property(_ida_pro.instant_dbgopts_t_pid_get, _ida_pro.instant_dbgopts_t_pid_set, doc=r"""pid""")
    r"""
    process to attach to (-1: ask the user)
    """
    event_id: "int" = property(_ida_pro.instant_dbgopts_t_event_id_get, _ida_pro.instant_dbgopts_t_event_id_set, doc=r"""event_id""")
    r"""
    event to trigger upon attaching
    """
    attach: "bool" = property(_ida_pro.instant_dbgopts_t_attach_get, _ida_pro.instant_dbgopts_t_attach_set, doc=r"""attach""")
    r"""
    should attach to a process?
    """

    def __init__(self):
        r"""
        __init__(self) -> instant_dbgopts_t
        """
        _ida_pro.instant_dbgopts_t_swiginit(self, _ida_pro.new_instant_dbgopts_t())
    __swig_destroy__ = _ida_pro.delete_instant_dbgopts_t

# Register instant_dbgopts_t in _ida_pro:
_ida_pro.instant_dbgopts_t_swigregister(instant_dbgopts_t)

def parse_dbgopts(ido: "instant_dbgopts_t", r_switch: "char const *") -> "bool":
    r"""
    parse_dbgopts(ido, r_switch) -> bool
    Parse the -r command line switch (for instant debugging). r_switch points to the
    value of the -r switch. Example: win32@localhost+

    @param ido: (C++: struct instant_dbgopts_t *) instant_dbgopts_t *
    @param r_switch: (C++: const char *) char const *
    @return: true-ok, false-parse error
    """
    return _ida_pro.parse_dbgopts(ido, r_switch)
QWCONTINUED = _ida_pro.QWCONTINUED

QWNOHANG = _ida_pro.QWNOHANG


def check_process_exit(handle: "void *", exit_code: "int *", msecs: "int"=-1) -> "int":
    r"""
    check_process_exit(handle, exit_code, msecs=-1) -> int
    Check whether process has terminated or not.

    @param handle: (C++: void *) process handle to wait for
    @param exit_code: (C++: int *) pointer to the buffer for the exit code
    @param msecs: how long to wait. special values:
    * 0: do not wait
    * 1 or -1: wait infinitely
    * other values: timeout in milliseconds
    @retval 0: process has exited, and the exit code is available. if *exit_code <
               0: the process was killed with a signal -*exit_code
    @retval 1: process has not exited yet
    @retval -1: error happened, see error code for winerr() in *exit_code
    """
    return _ida_pro.check_process_exit(handle, exit_code, msecs)
TCT_UNKNOWN = _ida_pro.TCT_UNKNOWN

TCT_OWNER = _ida_pro.TCT_OWNER

TCT_NOT_OWNER = _ida_pro.TCT_NOT_OWNER


def is_control_tty(fd: "int") -> "enum tty_control_t":
    r"""
    is_control_tty(fd) -> enum tty_control_t
    Check if the current process is the owner of the TTY specified by 'fd'
    (typically an opened descriptor to /dev/tty).

    @param fd: (C++: int)
    """
    return _ida_pro.is_control_tty(fd)

def qdetach_tty() -> "void":
    r"""
    qdetach_tty()
    If the current terminal is the controlling terminal of the calling process, give
    up this controlling terminal.
    @note: The current terminal is supposed to be /dev/tty
    """
    return _ida_pro.qdetach_tty()

def qcontrol_tty() -> "void":
    r"""
    qcontrol_tty()
    Make the current terminal the controlling terminal of the calling process.
    @note: The current terminal is supposed to be /dev/tty
    """
    return _ida_pro.qcontrol_tty()
class __qthread_t(object):
    r"""
    Proxy of C++ __qthread_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> __qthread_t
        """
        _ida_pro.__qthread_t_swiginit(self, _ida_pro.new___qthread_t())
    __swig_destroy__ = _ida_pro.delete___qthread_t

# Register __qthread_t in _ida_pro:
_ida_pro.__qthread_t_swigregister(__qthread_t)

def qthread_equal(q1: "__qthread_t", q2: "__qthread_t") -> "bool":
    r"""
    qthread_equal(q1, q2) -> bool
    Are two threads equal?

    @param q1: (C++: qthread_t)
    @param q2: (C++: qthread_t)
    """
    return _ida_pro.qthread_equal(q1, q2)

def is_main_thread() -> "bool":
    r"""
    is_main_thread() -> bool
    Are we running in the main thread?
    """
    return _ida_pro.is_main_thread()
class __qsemaphore_t(object):
    r"""
    Proxy of C++ __qsemaphore_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> __qsemaphore_t
        """
        _ida_pro.__qsemaphore_t_swiginit(self, _ida_pro.new___qsemaphore_t())
    __swig_destroy__ = _ida_pro.delete___qsemaphore_t

# Register __qsemaphore_t in _ida_pro:
_ida_pro.__qsemaphore_t_swigregister(__qsemaphore_t)
class __qmutex_t(object):
    r"""
    Proxy of C++ __qmutex_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> __qmutex_t
        """
        _ida_pro.__qmutex_t_swiginit(self, _ida_pro.new___qmutex_t())
    __swig_destroy__ = _ida_pro.delete___qmutex_t

# Register __qmutex_t in _ida_pro:
_ida_pro.__qmutex_t_swigregister(__qmutex_t)
class qmutex_locker_t(object):
    r"""
    Proxy of C++ qmutex_locker_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, _lock: "__qmutex_t"):
        r"""
        __init__(self, _lock) -> qmutex_locker_t

        @param _lock: qmutex_t
        """
        _ida_pro.qmutex_locker_t_swiginit(self, _ida_pro.new_qmutex_locker_t(_lock))
    __swig_destroy__ = _ida_pro.delete_qmutex_locker_t

# Register qmutex_locker_t in _ida_pro:
_ida_pro.qmutex_locker_t_swigregister(qmutex_locker_t)

def get_login_name() -> "qstring *":
    r"""
    get_login_name() -> str
    Get the user name for the current desktop session

    @return: success
    """
    return _ida_pro.get_login_name()
class intvec_t(object):
    r"""
    Proxy of C++ qvector< int > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> intvec_t
        __init__(self, x) -> intvec_t

        @param x: qvector< int > const &
        """
        _ida_pro.intvec_t_swiginit(self, _ida_pro.new_intvec_t(*args))
    __swig_destroy__ = _ida_pro.delete_intvec_t

    def push_back(self, *args) -> "int &":
        r"""
        push_back(self, x)

        @param x: int const &

        push_back(self) -> int &
        """
        return _ida_pro.intvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_pro.intvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_pro.intvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_pro.intvec_t_empty(self)

    def at(self, _idx: "size_t") -> "int const &":
        r"""
        at(self, _idx) -> int const &

        @param _idx: size_t
        """
        return _ida_pro.intvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_pro.intvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_pro.intvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: int const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_pro.intvec_t_resize(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_pro.intvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_pro.intvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_pro.intvec_t_truncate(self)

    def swap(self, r: "intvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< int > &
        """
        return _ida_pro.intvec_t_swap(self, r)

    def extract(self) -> "int *":
        r"""
        extract(self) -> int *
        """
        return _ida_pro.intvec_t_extract(self)

    def inject(self, s: "int *", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: int *
        @param len: size_t
        """
        return _ida_pro.intvec_t_inject(self, s, len)

    def __eq__(self, r: "intvec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< int > const &
        """
        return _ida_pro.intvec_t___eq__(self, r)

    def __ne__(self, r: "intvec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< int > const &
        """
        return _ida_pro.intvec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< int >::const_iterator":
        r"""
        begin(self) -> qvector< int >::iterator
        begin(self) -> qvector< int >::const_iterator
        """
        return _ida_pro.intvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< int >::const_iterator":
        r"""
        end(self) -> qvector< int >::iterator
        end(self) -> qvector< int >::const_iterator
        """
        return _ida_pro.intvec_t_end(self, *args)

    def insert(self, it: "qvector< int >::iterator", x: "int const &") -> "qvector< int >::iterator":
        r"""
        insert(self, it, x) -> qvector< int >::iterator

        @param it: qvector< int >::iterator
        @param x: int const &
        """
        return _ida_pro.intvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< int >::iterator":
        r"""
        erase(self, it) -> qvector< int >::iterator

        @param it: qvector< int >::iterator

        erase(self, first, last) -> qvector< int >::iterator

        @param first: qvector< int >::iterator
        @param last: qvector< int >::iterator
        """
        return _ida_pro.intvec_t_erase(self, *args)

    def find(self, *args) -> "qvector< int >::const_iterator":
        r"""
        find(self, x) -> qvector< int >::iterator

        @param x: int const &

        find(self, x) -> qvector< int >::const_iterator

        @param x: int const &
        """
        return _ida_pro.intvec_t_find(self, *args)

    def has(self, x: "int const &") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: int const &
        """
        return _ida_pro.intvec_t_has(self, x)

    def add_unique(self, x: "int const &") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: int const &
        """
        return _ida_pro.intvec_t_add_unique(self, x)

    def _del(self, x: "int const &") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: int const &

        """
        return _ida_pro.intvec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_pro.intvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "int const &":
        r"""
        __getitem__(self, i) -> int const &

        @param i: size_t
        """
        return _ida_pro.intvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "int const &") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: int const &
        """
        return _ida_pro.intvec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register intvec_t in _ida_pro:
_ida_pro.intvec_t_swigregister(intvec_t)
cvar = _ida_pro.cvar
NULL_PIPE_HANDLE = cvar.NULL_PIPE_HANDLE

class uintvec_t(object):
    r"""
    Proxy of C++ qvector< unsigned int > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> uintvec_t
        __init__(self, x) -> uintvec_t

        @param x: qvector< unsigned int > const &
        """
        _ida_pro.uintvec_t_swiginit(self, _ida_pro.new_uintvec_t(*args))
    __swig_destroy__ = _ida_pro.delete_uintvec_t

    def push_back(self, *args) -> "unsigned int &":
        r"""
        push_back(self, x)

        @param x: unsigned int const &

        push_back(self) -> unsigned int &
        """
        return _ida_pro.uintvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_pro.uintvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_pro.uintvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_pro.uintvec_t_empty(self)

    def at(self, _idx: "size_t") -> "unsigned int const &":
        r"""
        at(self, _idx) -> unsigned int const &

        @param _idx: size_t
        """
        return _ida_pro.uintvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_pro.uintvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_pro.uintvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: unsigned int const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_pro.uintvec_t_resize(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_pro.uintvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_pro.uintvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_pro.uintvec_t_truncate(self)

    def swap(self, r: "uintvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< unsigned int > &
        """
        return _ida_pro.uintvec_t_swap(self, r)

    def extract(self) -> "unsigned int *":
        r"""
        extract(self) -> unsigned int *
        """
        return _ida_pro.uintvec_t_extract(self)

    def inject(self, s: "unsigned int *", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: unsigned int *
        @param len: size_t
        """
        return _ida_pro.uintvec_t_inject(self, s, len)

    def __eq__(self, r: "uintvec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< unsigned int > const &
        """
        return _ida_pro.uintvec_t___eq__(self, r)

    def __ne__(self, r: "uintvec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< unsigned int > const &
        """
        return _ida_pro.uintvec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< unsigned int >::const_iterator":
        r"""
        begin(self) -> qvector< unsigned int >::iterator
        begin(self) -> qvector< unsigned int >::const_iterator
        """
        return _ida_pro.uintvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< unsigned int >::const_iterator":
        r"""
        end(self) -> qvector< unsigned int >::iterator
        end(self) -> qvector< unsigned int >::const_iterator
        """
        return _ida_pro.uintvec_t_end(self, *args)

    def insert(self, it: "qvector< unsigned int >::iterator", x: "unsigned int const &") -> "qvector< unsigned int >::iterator":
        r"""
        insert(self, it, x) -> qvector< unsigned int >::iterator

        @param it: qvector< unsigned int >::iterator
        @param x: unsigned int const &
        """
        return _ida_pro.uintvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< unsigned int >::iterator":
        r"""
        erase(self, it) -> qvector< unsigned int >::iterator

        @param it: qvector< unsigned int >::iterator

        erase(self, first, last) -> qvector< unsigned int >::iterator

        @param first: qvector< unsigned int >::iterator
        @param last: qvector< unsigned int >::iterator
        """
        return _ida_pro.uintvec_t_erase(self, *args)

    def find(self, *args) -> "qvector< unsigned int >::const_iterator":
        r"""
        find(self, x) -> qvector< unsigned int >::iterator

        @param x: unsigned int const &

        find(self, x) -> qvector< unsigned int >::const_iterator

        @param x: unsigned int const &
        """
        return _ida_pro.uintvec_t_find(self, *args)

    def has(self, x: "unsigned int const &") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: unsigned int const &
        """
        return _ida_pro.uintvec_t_has(self, x)

    def add_unique(self, x: "unsigned int const &") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: unsigned int const &
        """
        return _ida_pro.uintvec_t_add_unique(self, x)

    def _del(self, x: "unsigned int const &") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: unsigned int const &

        """
        return _ida_pro.uintvec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_pro.uintvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "unsigned int const &":
        r"""
        __getitem__(self, i) -> unsigned int const &

        @param i: size_t
        """
        return _ida_pro.uintvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "unsigned int const &") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: unsigned int const &
        """
        return _ida_pro.uintvec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register uintvec_t in _ida_pro:
_ida_pro.uintvec_t_swigregister(uintvec_t)
class int64vec_t(object):
    r"""
    Proxy of C++ qvector< long long > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> int64vec_t
        __init__(self, x) -> int64vec_t

        @param x: qvector< long long > const &
        """
        _ida_pro.int64vec_t_swiginit(self, _ida_pro.new_int64vec_t(*args))
    __swig_destroy__ = _ida_pro.delete_int64vec_t

    def push_back(self, *args) -> "long long &":
        r"""
        push_back(self, x)

        @param x: long long const &

        push_back(self) -> long long &
        """
        return _ida_pro.int64vec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_pro.int64vec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_pro.int64vec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_pro.int64vec_t_empty(self)

    def at(self, _idx: "size_t") -> "long long const &":
        r"""
        at(self, _idx) -> long long const &

        @param _idx: size_t
        """
        return _ida_pro.int64vec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_pro.int64vec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_pro.int64vec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: long long const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_pro.int64vec_t_resize(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_pro.int64vec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_pro.int64vec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_pro.int64vec_t_truncate(self)

    def swap(self, r: "int64vec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< long long > &
        """
        return _ida_pro.int64vec_t_swap(self, r)

    def extract(self) -> "long long *":
        r"""
        extract(self) -> long long *
        """
        return _ida_pro.int64vec_t_extract(self)

    def inject(self, s: "long long *", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: long long *
        @param len: size_t
        """
        return _ida_pro.int64vec_t_inject(self, s, len)

    def __eq__(self, r: "int64vec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< long long > const &
        """
        return _ida_pro.int64vec_t___eq__(self, r)

    def __ne__(self, r: "int64vec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< long long > const &
        """
        return _ida_pro.int64vec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< long long >::const_iterator":
        r"""
        begin(self) -> qvector< long long >::iterator
        begin(self) -> qvector< long long >::const_iterator
        """
        return _ida_pro.int64vec_t_begin(self, *args)

    def end(self, *args) -> "qvector< long long >::const_iterator":
        r"""
        end(self) -> qvector< long long >::iterator
        end(self) -> qvector< long long >::const_iterator
        """
        return _ida_pro.int64vec_t_end(self, *args)

    def insert(self, it: "qvector< long long >::iterator", x: "long long const &") -> "qvector< long long >::iterator":
        r"""
        insert(self, it, x) -> qvector< long long >::iterator

        @param it: qvector< long long >::iterator
        @param x: long long const &
        """
        return _ida_pro.int64vec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< long long >::iterator":
        r"""
        erase(self, it) -> qvector< long long >::iterator

        @param it: qvector< long long >::iterator

        erase(self, first, last) -> qvector< long long >::iterator

        @param first: qvector< long long >::iterator
        @param last: qvector< long long >::iterator
        """
        return _ida_pro.int64vec_t_erase(self, *args)

    def find(self, *args) -> "qvector< long long >::const_iterator":
        r"""
        find(self, x) -> qvector< long long >::iterator

        @param x: long long const &

        find(self, x) -> qvector< long long >::const_iterator

        @param x: long long const &
        """
        return _ida_pro.int64vec_t_find(self, *args)

    def has(self, x: "long long const &") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: long long const &
        """
        return _ida_pro.int64vec_t_has(self, x)

    def add_unique(self, x: "long long const &") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: long long const &
        """
        return _ida_pro.int64vec_t_add_unique(self, x)

    def _del(self, x: "long long const &") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: long long const &

        """
        return _ida_pro.int64vec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_pro.int64vec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "long long const &":
        r"""
        __getitem__(self, i) -> long long const &

        @param i: size_t
        """
        return _ida_pro.int64vec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "long long const &") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: long long const &
        """
        return _ida_pro.int64vec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register int64vec_t in _ida_pro:
_ida_pro.int64vec_t_swigregister(int64vec_t)
class uint64vec_t(object):
    r"""
    Proxy of C++ qvector< unsigned long long > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> uint64vec_t
        __init__(self, x) -> uint64vec_t

        @param x: qvector< unsigned long long > const &
        """
        _ida_pro.uint64vec_t_swiginit(self, _ida_pro.new_uint64vec_t(*args))
    __swig_destroy__ = _ida_pro.delete_uint64vec_t

    def push_back(self, *args) -> "unsigned long long &":
        r"""
        push_back(self, x)

        @param x: unsigned long long const &

        push_back(self) -> unsigned long long &
        """
        return _ida_pro.uint64vec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_pro.uint64vec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_pro.uint64vec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_pro.uint64vec_t_empty(self)

    def at(self, _idx: "size_t") -> "unsigned long long const &":
        r"""
        at(self, _idx) -> unsigned long long const &

        @param _idx: size_t
        """
        return _ida_pro.uint64vec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_pro.uint64vec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_pro.uint64vec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: unsigned long long const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_pro.uint64vec_t_resize(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_pro.uint64vec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_pro.uint64vec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_pro.uint64vec_t_truncate(self)

    def swap(self, r: "uint64vec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< unsigned long long > &
        """
        return _ida_pro.uint64vec_t_swap(self, r)

    def extract(self) -> "unsigned long long *":
        r"""
        extract(self) -> unsigned long long *
        """
        return _ida_pro.uint64vec_t_extract(self)

    def inject(self, s: "unsigned long long *", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: unsigned long long *
        @param len: size_t
        """
        return _ida_pro.uint64vec_t_inject(self, s, len)

    def __eq__(self, r: "uint64vec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< unsigned long long > const &
        """
        return _ida_pro.uint64vec_t___eq__(self, r)

    def __ne__(self, r: "uint64vec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< unsigned long long > const &
        """
        return _ida_pro.uint64vec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< unsigned long long >::const_iterator":
        r"""
        begin(self) -> qvector< unsigned long long >::iterator
        begin(self) -> qvector< unsigned long long >::const_iterator
        """
        return _ida_pro.uint64vec_t_begin(self, *args)

    def end(self, *args) -> "qvector< unsigned long long >::const_iterator":
        r"""
        end(self) -> qvector< unsigned long long >::iterator
        end(self) -> qvector< unsigned long long >::const_iterator
        """
        return _ida_pro.uint64vec_t_end(self, *args)

    def insert(self, it: "qvector< unsigned long long >::iterator", x: "unsigned long long const &") -> "qvector< unsigned long long >::iterator":
        r"""
        insert(self, it, x) -> qvector< unsigned long long >::iterator

        @param it: qvector< unsigned long long >::iterator
        @param x: unsigned long long const &
        """
        return _ida_pro.uint64vec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< unsigned long long >::iterator":
        r"""
        erase(self, it) -> qvector< unsigned long long >::iterator

        @param it: qvector< unsigned long long >::iterator

        erase(self, first, last) -> qvector< unsigned long long >::iterator

        @param first: qvector< unsigned long long >::iterator
        @param last: qvector< unsigned long long >::iterator
        """
        return _ida_pro.uint64vec_t_erase(self, *args)

    def find(self, *args) -> "qvector< unsigned long long >::const_iterator":
        r"""
        find(self, x) -> qvector< unsigned long long >::iterator

        @param x: unsigned long long const &

        find(self, x) -> qvector< unsigned long long >::const_iterator

        @param x: unsigned long long const &
        """
        return _ida_pro.uint64vec_t_find(self, *args)

    def has(self, x: "unsigned long long const &") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: unsigned long long const &
        """
        return _ida_pro.uint64vec_t_has(self, x)

    def add_unique(self, x: "unsigned long long const &") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: unsigned long long const &
        """
        return _ida_pro.uint64vec_t_add_unique(self, x)

    def _del(self, x: "unsigned long long const &") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: unsigned long long const &

        """
        return _ida_pro.uint64vec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_pro.uint64vec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "unsigned long long const &":
        r"""
        __getitem__(self, i) -> unsigned long long const &

        @param i: size_t
        """
        return _ida_pro.uint64vec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "unsigned long long const &") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: unsigned long long const &
        """
        return _ida_pro.uint64vec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register uint64vec_t in _ida_pro:
_ida_pro.uint64vec_t_swigregister(uint64vec_t)
class boolvec_t(object):
    r"""
    Proxy of C++ qvector< bool > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> boolvec_t
        __init__(self, x) -> boolvec_t

        @param x: qvector< bool > const &
        """
        _ida_pro.boolvec_t_swiginit(self, _ida_pro.new_boolvec_t(*args))
    __swig_destroy__ = _ida_pro.delete_boolvec_t

    def push_back(self, *args) -> "bool &":
        r"""
        push_back(self, x)

        @param x: bool const &

        push_back(self) -> bool &
        """
        return _ida_pro.boolvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_pro.boolvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_pro.boolvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_pro.boolvec_t_empty(self)

    def at(self, _idx: "size_t") -> "bool const &":
        r"""
        at(self, _idx) -> bool const &

        @param _idx: size_t
        """
        return _ida_pro.boolvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_pro.boolvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_pro.boolvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: bool const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_pro.boolvec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=bool())

        @param x: bool const &
        """
        return _ida_pro.boolvec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_pro.boolvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_pro.boolvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_pro.boolvec_t_truncate(self)

    def swap(self, r: "boolvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< bool > &
        """
        return _ida_pro.boolvec_t_swap(self, r)

    def extract(self) -> "bool *":
        r"""
        extract(self) -> bool *
        """
        return _ida_pro.boolvec_t_extract(self)

    def inject(self, s: "bool *", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: bool *
        @param len: size_t
        """
        return _ida_pro.boolvec_t_inject(self, s, len)

    def __eq__(self, r: "boolvec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< bool > const &
        """
        return _ida_pro.boolvec_t___eq__(self, r)

    def __ne__(self, r: "boolvec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< bool > const &
        """
        return _ida_pro.boolvec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< bool >::const_iterator":
        r"""
        begin(self) -> qvector< bool >::iterator
        begin(self) -> qvector< bool >::const_iterator
        """
        return _ida_pro.boolvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< bool >::const_iterator":
        r"""
        end(self) -> qvector< bool >::iterator
        end(self) -> qvector< bool >::const_iterator
        """
        return _ida_pro.boolvec_t_end(self, *args)

    def insert(self, it: "qvector< bool >::iterator", x: "bool const &") -> "qvector< bool >::iterator":
        r"""
        insert(self, it, x) -> qvector< bool >::iterator

        @param it: qvector< bool >::iterator
        @param x: bool const &
        """
        return _ida_pro.boolvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< bool >::iterator":
        r"""
        erase(self, it) -> qvector< bool >::iterator

        @param it: qvector< bool >::iterator

        erase(self, first, last) -> qvector< bool >::iterator

        @param first: qvector< bool >::iterator
        @param last: qvector< bool >::iterator
        """
        return _ida_pro.boolvec_t_erase(self, *args)

    def find(self, *args) -> "qvector< bool >::const_iterator":
        r"""
        find(self, x) -> qvector< bool >::iterator

        @param x: bool const &

        find(self, x) -> qvector< bool >::const_iterator

        @param x: bool const &
        """
        return _ida_pro.boolvec_t_find(self, *args)

    def has(self, x: "bool const &") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: bool const &
        """
        return _ida_pro.boolvec_t_has(self, x)

    def add_unique(self, x: "bool const &") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: bool const &
        """
        return _ida_pro.boolvec_t_add_unique(self, x)

    def _del(self, x: "bool const &") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: bool const &

        """
        return _ida_pro.boolvec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_pro.boolvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "bool const &":
        r"""
        __getitem__(self, i) -> bool const &

        @param i: size_t
        """
        return _ida_pro.boolvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "bool const &") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: bool const &
        """
        return _ida_pro.boolvec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register boolvec_t in _ida_pro:
_ida_pro.boolvec_t_swigregister(boolvec_t)
class strvec_t(object):
    r"""
    Proxy of C++ qvector< simpleline_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> strvec_t
        __init__(self, x) -> strvec_t

        @param x: qvector< simpleline_t > const &
        """
        _ida_pro.strvec_t_swiginit(self, _ida_pro.new_strvec_t(*args))
    __swig_destroy__ = _ida_pro.delete_strvec_t

    def push_back(self, *args) -> "simpleline_t &":
        r"""
        push_back(self, x)

        @param x: simpleline_t const &

        push_back(self) -> simpleline_t &
        """
        return _ida_pro.strvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_pro.strvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_pro.strvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_pro.strvec_t_empty(self)

    def at(self, _idx: "size_t") -> "simpleline_t const &":
        r"""
        at(self, _idx) -> simpleline_t const &

        @param _idx: size_t
        """
        return _ida_pro.strvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_pro.strvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_pro.strvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: simpleline_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_pro.strvec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=simpleline_t())

        @param x: simpleline_t const &
        """
        return _ida_pro.strvec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_pro.strvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_pro.strvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_pro.strvec_t_truncate(self)

    def swap(self, r: "strvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< simpleline_t > &
        """
        return _ida_pro.strvec_t_swap(self, r)

    def extract(self) -> "simpleline_t *":
        r"""
        extract(self) -> simpleline_t *
        """
        return _ida_pro.strvec_t_extract(self)

    def inject(self, s: "simpleline_t *", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: simpleline_t *
        @param len: size_t
        """
        return _ida_pro.strvec_t_inject(self, s, len)

    def begin(self, *args) -> "qvector< simpleline_t >::const_iterator":
        r"""
        begin(self) -> qvector< simpleline_t >::iterator
        begin(self) -> qvector< simpleline_t >::const_iterator
        """
        return _ida_pro.strvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< simpleline_t >::const_iterator":
        r"""
        end(self) -> qvector< simpleline_t >::iterator
        end(self) -> qvector< simpleline_t >::const_iterator
        """
        return _ida_pro.strvec_t_end(self, *args)

    def insert(self, it: "qvector< simpleline_t >::iterator", x: "simpleline_t const &") -> "qvector< simpleline_t >::iterator":
        r"""
        insert(self, it, x) -> qvector< simpleline_t >::iterator

        @param it: qvector< simpleline_t >::iterator
        @param x: simpleline_t const &
        """
        return _ida_pro.strvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< simpleline_t >::iterator":
        r"""
        erase(self, it) -> qvector< simpleline_t >::iterator

        @param it: qvector< simpleline_t >::iterator

        erase(self, first, last) -> qvector< simpleline_t >::iterator

        @param first: qvector< simpleline_t >::iterator
        @param last: qvector< simpleline_t >::iterator
        """
        return _ida_pro.strvec_t_erase(self, *args)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_pro.strvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "simpleline_t const &":
        r"""
        __getitem__(self, i) -> simpleline_t const &

        @param i: size_t
        """
        return _ida_pro.strvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "simpleline_t const &") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: simpleline_t const &
        """
        return _ida_pro.strvec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register strvec_t in _ida_pro:
_ida_pro.strvec_t_swigregister(strvec_t)
class sizevec_t(object):
    r"""
    Proxy of C++ qvector< size_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> sizevec_t
        __init__(self, x) -> sizevec_t

        @param x: qvector< size_t > const &
        """
        _ida_pro.sizevec_t_swiginit(self, _ida_pro.new_sizevec_t(*args))
    __swig_destroy__ = _ida_pro.delete_sizevec_t

    def push_back(self, *args) -> "size_t &":
        r"""
        push_back(self, x)

        @param x: size_t const &

        push_back(self) -> size_t &
        """
        return _ida_pro.sizevec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_pro.sizevec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_pro.sizevec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_pro.sizevec_t_empty(self)

    def at(self, _idx: "size_t") -> "size_t const &":
        r"""
        at(self, _idx) -> size_t const &

        @param _idx: size_t
        """
        return _ida_pro.sizevec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_pro.sizevec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_pro.sizevec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: size_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_pro.sizevec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=size_t())

        @param x: size_t const &
        """
        return _ida_pro.sizevec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_pro.sizevec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_pro.sizevec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_pro.sizevec_t_truncate(self)

    def swap(self, r: "sizevec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< size_t > &
        """
        return _ida_pro.sizevec_t_swap(self, r)

    def extract(self) -> "size_t *":
        r"""
        extract(self) -> size_t *
        """
        return _ida_pro.sizevec_t_extract(self)

    def inject(self, s: "size_t *", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: size_t *
        @param len: size_t
        """
        return _ida_pro.sizevec_t_inject(self, s, len)

    def __eq__(self, r: "sizevec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< size_t > const &
        """
        return _ida_pro.sizevec_t___eq__(self, r)

    def __ne__(self, r: "sizevec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< size_t > const &
        """
        return _ida_pro.sizevec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< size_t >::const_iterator":
        r"""
        begin(self) -> qvector< size_t >::iterator
        begin(self) -> qvector< size_t >::const_iterator
        """
        return _ida_pro.sizevec_t_begin(self, *args)

    def end(self, *args) -> "qvector< size_t >::const_iterator":
        r"""
        end(self) -> qvector< size_t >::iterator
        end(self) -> qvector< size_t >::const_iterator
        """
        return _ida_pro.sizevec_t_end(self, *args)

    def insert(self, it: "qvector< size_t >::iterator", x: "size_t const &") -> "qvector< size_t >::iterator":
        r"""
        insert(self, it, x) -> qvector< size_t >::iterator

        @param it: qvector< size_t >::iterator
        @param x: size_t const &
        """
        return _ida_pro.sizevec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< size_t >::iterator":
        r"""
        erase(self, it) -> qvector< size_t >::iterator

        @param it: qvector< size_t >::iterator

        erase(self, first, last) -> qvector< size_t >::iterator

        @param first: qvector< size_t >::iterator
        @param last: qvector< size_t >::iterator
        """
        return _ida_pro.sizevec_t_erase(self, *args)

    def find(self, *args) -> "qvector< size_t >::const_iterator":
        r"""
        find(self, x) -> qvector< size_t >::iterator

        @param x: size_t const &

        find(self, x) -> qvector< size_t >::const_iterator

        @param x: size_t const &
        """
        return _ida_pro.sizevec_t_find(self, *args)

    def has(self, x: "size_t const &") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: size_t const &
        """
        return _ida_pro.sizevec_t_has(self, x)

    def add_unique(self, x: "size_t const &") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: size_t const &
        """
        return _ida_pro.sizevec_t_add_unique(self, x)

    def _del(self, x: "size_t const &") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: size_t const &

        """
        return _ida_pro.sizevec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_pro.sizevec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "size_t const &":
        r"""
        __getitem__(self, i) -> size_t const &

        @param i: size_t
        """
        return _ida_pro.sizevec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "size_t const &") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: size_t const &
        """
        return _ida_pro.sizevec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register sizevec_t in _ida_pro:
_ida_pro.sizevec_t_swigregister(sizevec_t)

def qstrvec_t_create() -> "PyObject *":
    r"""
    qstrvec_t_create() -> PyObject *
    """
    return _ida_pro.qstrvec_t_create()

def qstrvec_t_destroy(py_obj: "PyObject *") -> "bool":
    r"""
    qstrvec_t_destroy(py_obj) -> bool

    @param py_obj: PyObject *
    """
    return _ida_pro.qstrvec_t_destroy(py_obj)

def qstrvec_t_get_clink(_self: "PyObject *") -> "qstrvec_t *":
    r"""
    qstrvec_t_get_clink(_self) -> qstrvec_t *

    @param self: PyObject *
    """
    return _ida_pro.qstrvec_t_get_clink(_self)

def qstrvec_t_get_clink_ptr(_self: "PyObject *") -> "PyObject *":
    r"""
    qstrvec_t_get_clink_ptr(_self) -> PyObject *

    @param self: PyObject *
    """
    return _ida_pro.qstrvec_t_get_clink_ptr(_self)

def qstrvec_t_assign(_self: "PyObject *", other: "PyObject *") -> "bool":
    r"""
    qstrvec_t_assign(_self, other) -> bool

    @param self: PyObject *
    @param other: PyObject *
    """
    return _ida_pro.qstrvec_t_assign(_self, other)

def qstrvec_t_addressof(_self: "PyObject *", idx: "size_t") -> "PyObject *":
    r"""
    qstrvec_t_addressof(_self, idx) -> PyObject *

    @param self: PyObject *
    @param idx: size_t
    """
    return _ida_pro.qstrvec_t_addressof(_self, idx)

def qstrvec_t_set(_self: "PyObject *", idx: "size_t", s: "char const *") -> "bool":
    r"""
    qstrvec_t_set(_self, idx, s) -> bool

    @param self: PyObject *
    @param idx: size_t
    @param s: char const *
    """
    return _ida_pro.qstrvec_t_set(_self, idx, s)

def qstrvec_t_from_list(_self: "PyObject *", py_list: "PyObject *") -> "bool":
    r"""
    qstrvec_t_from_list(_self, py_list) -> bool

    @param self: PyObject *
    @param py_list: PyObject *
    """
    return _ida_pro.qstrvec_t_from_list(_self, py_list)

def qstrvec_t_size(_self: "PyObject *") -> "size_t":
    r"""
    qstrvec_t_size(_self) -> size_t

    @param self: PyObject *
    """
    return _ida_pro.qstrvec_t_size(_self)

def qstrvec_t_get(_self: "PyObject *", idx: "size_t") -> "PyObject *":
    r"""
    qstrvec_t_get(_self, idx) -> PyObject *

    @param self: PyObject *
    @param idx: size_t
    """
    return _ida_pro.qstrvec_t_get(_self, idx)

def qstrvec_t_add(_self: "PyObject *", s: "char const *") -> "bool":
    r"""
    qstrvec_t_add(_self, s) -> bool

    @param self: PyObject *
    @param s: char const *
    """
    return _ida_pro.qstrvec_t_add(_self, s)

def qstrvec_t_clear(_self: "PyObject *", qclear: "bool") -> "bool":
    r"""
    qstrvec_t_clear(_self, qclear) -> bool

    @param self: PyObject *
    @param qclear: bool
    """
    return _ida_pro.qstrvec_t_clear(_self, qclear)

def qstrvec_t_insert(_self: "PyObject *", idx: "size_t", s: "char const *") -> "bool":
    r"""
    qstrvec_t_insert(_self, idx, s) -> bool

    @param self: PyObject *
    @param idx: size_t
    @param s: char const *
    """
    return _ida_pro.qstrvec_t_insert(_self, idx, s)

def qstrvec_t_remove(_self: "PyObject *", idx: "size_t") -> "bool":
    r"""
    qstrvec_t_remove(_self, idx) -> bool

    @param self: PyObject *
    @param idx: size_t
    """
    return _ida_pro.qstrvec_t_remove(_self, idx)

def str2user(str: "char const *") -> "PyObject *":
    r"""
    str2user(str) -> str or None
    Insert C-style escape characters to string

    @param str: char const *
    @return: new string with escape characters inserted
    """
    return _ida_pro.str2user(str)
class uchar_array(object):
    r"""
    Proxy of C++ uchar_array class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, nelements: "size_t"):
        r"""
        __init__(self, nelements) -> uchar_array

        @param nelements: size_t
        """
        _ida_pro.uchar_array_swiginit(self, _ida_pro.new_uchar_array(nelements))
    __swig_destroy__ = _ida_pro.delete_uchar_array

    def __getitem__(self, index: "size_t") -> "uchar":
        r"""
        __getitem__(self, index) -> uchar

        @param index: size_t
        """
        return _ida_pro.uchar_array___getitem__(self, index)

    def __setitem__(self, index: "size_t", value: "uchar") -> "void":
        r"""
        __setitem__(self, index, value)

        @param index: size_t
        @param value: uchar
        """
        return _ida_pro.uchar_array___setitem__(self, index, value)

    def cast(self) -> "uchar *":
        r"""
        cast(self) -> uchar *
        """
        return _ida_pro.uchar_array_cast(self)

    @staticmethod
    def frompointer(t: "uchar *") -> "uchar_array *":
        r"""
        frompointer(t) -> uchar_array

        @param t: uchar *
        """
        return _ida_pro.uchar_array_frompointer(t)

# Register uchar_array in _ida_pro:
_ida_pro.uchar_array_swigregister(uchar_array)
class tid_array(object):
    r"""
    Proxy of C++ tid_array class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, nelements: "size_t"):
        r"""
        __init__(self, nelements) -> tid_array

        @param nelements: size_t
        """
        _ida_pro.tid_array_swiginit(self, _ida_pro.new_tid_array(nelements))
    __swig_destroy__ = _ida_pro.delete_tid_array

    def __getitem__(self, index: "size_t") -> "tid_t":
        r"""
        __getitem__(self, index) -> tid_t

        @param index: size_t
        """
        return _ida_pro.tid_array___getitem__(self, index)

    def __setitem__(self, index: "size_t", value: "tid_t") -> "void":
        r"""
        __setitem__(self, index, value)

        @param index: size_t
        @param value: tid_t
        """
        return _ida_pro.tid_array___setitem__(self, index, value)

    def cast(self) -> "tid_t *":
        r"""
        cast(self) -> tid_t *
        """
        return _ida_pro.tid_array_cast(self)

    @staticmethod
    def frompointer(t: "tid_t *") -> "tid_array *":
        r"""
        frompointer(t) -> tid_array

        @param t: tid_t *
        """
        return _ida_pro.tid_array_frompointer(t)

# Register tid_array in _ida_pro:
_ida_pro.tid_array_swigregister(tid_array)
class ea_array(object):
    r"""
    Proxy of C++ ea_array class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, nelements: "size_t"):
        r"""
        __init__(self, nelements) -> ea_array

        @param nelements: size_t
        """
        _ida_pro.ea_array_swiginit(self, _ida_pro.new_ea_array(nelements))
    __swig_destroy__ = _ida_pro.delete_ea_array

    def __getitem__(self, index: "size_t") -> "ea_t":
        r"""
        __getitem__(self, index) -> ea_t

        @param index: size_t
        """
        return _ida_pro.ea_array___getitem__(self, index)

    def __setitem__(self, index: "size_t", value: "ea_t") -> "void":
        r"""
        __setitem__(self, index, value)

        @param index: size_t
        @param value: ea_t
        """
        return _ida_pro.ea_array___setitem__(self, index, value)

    def cast(self) -> "ea_t *":
        r"""
        cast(self) -> ea_t *
        """
        return _ida_pro.ea_array_cast(self)

    @staticmethod
    def frompointer(t: "ea_t *") -> "ea_array *":
        r"""
        frompointer(t) -> ea_array

        @param t: ea_t *
        """
        return _ida_pro.ea_array_frompointer(t)

# Register ea_array in _ida_pro:
_ida_pro.ea_array_swigregister(ea_array)
class sel_array(object):
    r"""
    Proxy of C++ sel_array class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, nelements: "size_t"):
        r"""
        __init__(self, nelements) -> sel_array

        @param nelements: size_t
        """
        _ida_pro.sel_array_swiginit(self, _ida_pro.new_sel_array(nelements))
    __swig_destroy__ = _ida_pro.delete_sel_array

    def __getitem__(self, index: "size_t") -> "sel_t":
        r"""
        __getitem__(self, index) -> sel_t

        @param index: size_t
        """
        return _ida_pro.sel_array___getitem__(self, index)

    def __setitem__(self, index: "size_t", value: "sel_t") -> "void":
        r"""
        __setitem__(self, index, value)

        @param index: size_t
        @param value: sel_t
        """
        return _ida_pro.sel_array___setitem__(self, index, value)

    def cast(self) -> "sel_t *":
        r"""
        cast(self) -> sel_t *
        """
        return _ida_pro.sel_array_cast(self)

    @staticmethod
    def frompointer(t: "sel_t *") -> "sel_array *":
        r"""
        frompointer(t) -> sel_array

        @param t: sel_t *
        """
        return _ida_pro.sel_array_frompointer(t)

# Register sel_array in _ida_pro:
_ida_pro.sel_array_swigregister(sel_array)
class uval_array(object):
    r"""
    Proxy of C++ uval_array class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, nelements: "size_t"):
        r"""
        __init__(self, nelements) -> uval_array

        @param nelements: size_t
        """
        _ida_pro.uval_array_swiginit(self, _ida_pro.new_uval_array(nelements))
    __swig_destroy__ = _ida_pro.delete_uval_array

    def __getitem__(self, index: "size_t") -> "uval_t":
        r"""
        __getitem__(self, index) -> uval_t

        @param index: size_t
        """
        return _ida_pro.uval_array___getitem__(self, index)

    def __setitem__(self, index: "size_t", value: "uval_t") -> "void":
        r"""
        __setitem__(self, index, value)

        @param index: size_t
        @param value: uval_t
        """
        return _ida_pro.uval_array___setitem__(self, index, value)

    def cast(self) -> "uval_t *":
        r"""
        cast(self) -> uval_t *
        """
        return _ida_pro.uval_array_cast(self)

    @staticmethod
    def frompointer(t: "uval_t *") -> "uval_array *":
        r"""
        frompointer(t) -> uval_array

        @param t: uval_t *
        """
        return _ida_pro.uval_array_frompointer(t)

# Register uval_array in _ida_pro:
_ida_pro.uval_array_swigregister(uval_array)
class uchar_pointer(object):
    r"""
    Proxy of C++ uchar_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> uchar_pointer
        """
        _ida_pro.uchar_pointer_swiginit(self, _ida_pro.new_uchar_pointer())
    __swig_destroy__ = _ida_pro.delete_uchar_pointer

    def assign(self, value: "uchar") -> "void":
        r"""
        assign(self, value)

        @param value: uchar
        """
        return _ida_pro.uchar_pointer_assign(self, value)

    def value(self) -> "uchar":
        r"""
        value(self) -> uchar
        """
        return _ida_pro.uchar_pointer_value(self)

    def cast(self) -> "uchar *":
        r"""
        cast(self) -> uchar *
        """
        return _ida_pro.uchar_pointer_cast(self)

    @staticmethod
    def frompointer(t: "uchar *") -> "uchar_pointer *":
        r"""
        frompointer(t) -> uchar_pointer

        @param t: uchar *
        """
        return _ida_pro.uchar_pointer_frompointer(t)

# Register uchar_pointer in _ida_pro:
_ida_pro.uchar_pointer_swigregister(uchar_pointer)
class ushort_pointer(object):
    r"""
    Proxy of C++ ushort_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> ushort_pointer
        """
        _ida_pro.ushort_pointer_swiginit(self, _ida_pro.new_ushort_pointer())
    __swig_destroy__ = _ida_pro.delete_ushort_pointer

    def assign(self, value: "ushort") -> "void":
        r"""
        assign(self, value)

        @param value: ushort
        """
        return _ida_pro.ushort_pointer_assign(self, value)

    def value(self) -> "ushort":
        r"""
        value(self) -> ushort
        """
        return _ida_pro.ushort_pointer_value(self)

    def cast(self) -> "ushort *":
        r"""
        cast(self) -> ushort *
        """
        return _ida_pro.ushort_pointer_cast(self)

    @staticmethod
    def frompointer(t: "ushort *") -> "ushort_pointer *":
        r"""
        frompointer(t) -> ushort_pointer

        @param t: ushort *
        """
        return _ida_pro.ushort_pointer_frompointer(t)

# Register ushort_pointer in _ida_pro:
_ida_pro.ushort_pointer_swigregister(ushort_pointer)
class uint_pointer(object):
    r"""
    Proxy of C++ uint_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> uint_pointer
        """
        _ida_pro.uint_pointer_swiginit(self, _ida_pro.new_uint_pointer())
    __swig_destroy__ = _ida_pro.delete_uint_pointer

    def assign(self, value: "uint") -> "void":
        r"""
        assign(self, value)

        @param value: uint
        """
        return _ida_pro.uint_pointer_assign(self, value)

    def value(self) -> "uint":
        r"""
        value(self) -> uint
        """
        return _ida_pro.uint_pointer_value(self)

    def cast(self) -> "uint *":
        r"""
        cast(self) -> uint *
        """
        return _ida_pro.uint_pointer_cast(self)

    @staticmethod
    def frompointer(t: "uint *") -> "uint_pointer *":
        r"""
        frompointer(t) -> uint_pointer

        @param t: uint *
        """
        return _ida_pro.uint_pointer_frompointer(t)

# Register uint_pointer in _ida_pro:
_ida_pro.uint_pointer_swigregister(uint_pointer)
class sint8_pointer(object):
    r"""
    Proxy of C++ sint8_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> sint8_pointer
        """
        _ida_pro.sint8_pointer_swiginit(self, _ida_pro.new_sint8_pointer())
    __swig_destroy__ = _ida_pro.delete_sint8_pointer

    def assign(self, value: "sint8") -> "void":
        r"""
        assign(self, value)

        @param value: sint8
        """
        return _ida_pro.sint8_pointer_assign(self, value)

    def value(self) -> "sint8":
        r"""
        value(self) -> sint8
        """
        return _ida_pro.sint8_pointer_value(self)

    def cast(self) -> "sint8 *":
        r"""
        cast(self) -> sint8 *
        """
        return _ida_pro.sint8_pointer_cast(self)

    @staticmethod
    def frompointer(t: "sint8 *") -> "sint8_pointer *":
        r"""
        frompointer(t) -> sint8_pointer

        @param t: sint8 *
        """
        return _ida_pro.sint8_pointer_frompointer(t)

# Register sint8_pointer in _ida_pro:
_ida_pro.sint8_pointer_swigregister(sint8_pointer)
class int8_pointer(object):
    r"""
    Proxy of C++ int8_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> int8_pointer
        """
        _ida_pro.int8_pointer_swiginit(self, _ida_pro.new_int8_pointer())
    __swig_destroy__ = _ida_pro.delete_int8_pointer

    def assign(self, value: "int8") -> "void":
        r"""
        assign(self, value)

        @param value: int8
        """
        return _ida_pro.int8_pointer_assign(self, value)

    def value(self) -> "int8":
        r"""
        value(self) -> int8
        """
        return _ida_pro.int8_pointer_value(self)

    def cast(self) -> "int8 *":
        r"""
        cast(self) -> int8 *
        """
        return _ida_pro.int8_pointer_cast(self)

    @staticmethod
    def frompointer(t: "int8 *") -> "int8_pointer *":
        r"""
        frompointer(t) -> int8_pointer

        @param t: int8 *
        """
        return _ida_pro.int8_pointer_frompointer(t)

# Register int8_pointer in _ida_pro:
_ida_pro.int8_pointer_swigregister(int8_pointer)
class uint8_pointer(object):
    r"""
    Proxy of C++ uint8_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> uint8_pointer
        """
        _ida_pro.uint8_pointer_swiginit(self, _ida_pro.new_uint8_pointer())
    __swig_destroy__ = _ida_pro.delete_uint8_pointer

    def assign(self, value: "uint8") -> "void":
        r"""
        assign(self, value)

        @param value: uint8
        """
        return _ida_pro.uint8_pointer_assign(self, value)

    def value(self) -> "uint8":
        r"""
        value(self) -> uint8
        """
        return _ida_pro.uint8_pointer_value(self)

    def cast(self) -> "uint8 *":
        r"""
        cast(self) -> uint8 *
        """
        return _ida_pro.uint8_pointer_cast(self)

    @staticmethod
    def frompointer(t: "uint8 *") -> "uint8_pointer *":
        r"""
        frompointer(t) -> uint8_pointer

        @param t: uint8 *
        """
        return _ida_pro.uint8_pointer_frompointer(t)

# Register uint8_pointer in _ida_pro:
_ida_pro.uint8_pointer_swigregister(uint8_pointer)
class int16_pointer(object):
    r"""
    Proxy of C++ int16_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> int16_pointer
        """
        _ida_pro.int16_pointer_swiginit(self, _ida_pro.new_int16_pointer())
    __swig_destroy__ = _ida_pro.delete_int16_pointer

    def assign(self, value: "int16") -> "void":
        r"""
        assign(self, value)

        @param value: int16
        """
        return _ida_pro.int16_pointer_assign(self, value)

    def value(self) -> "int16":
        r"""
        value(self) -> int16
        """
        return _ida_pro.int16_pointer_value(self)

    def cast(self) -> "int16 *":
        r"""
        cast(self) -> int16 *
        """
        return _ida_pro.int16_pointer_cast(self)

    @staticmethod
    def frompointer(t: "int16 *") -> "int16_pointer *":
        r"""
        frompointer(t) -> int16_pointer

        @param t: int16 *
        """
        return _ida_pro.int16_pointer_frompointer(t)

# Register int16_pointer in _ida_pro:
_ida_pro.int16_pointer_swigregister(int16_pointer)
class uint16_pointer(object):
    r"""
    Proxy of C++ uint16_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> uint16_pointer
        """
        _ida_pro.uint16_pointer_swiginit(self, _ida_pro.new_uint16_pointer())
    __swig_destroy__ = _ida_pro.delete_uint16_pointer

    def assign(self, value: "uint16") -> "void":
        r"""
        assign(self, value)

        @param value: uint16
        """
        return _ida_pro.uint16_pointer_assign(self, value)

    def value(self) -> "uint16":
        r"""
        value(self) -> uint16
        """
        return _ida_pro.uint16_pointer_value(self)

    def cast(self) -> "uint16 *":
        r"""
        cast(self) -> uint16 *
        """
        return _ida_pro.uint16_pointer_cast(self)

    @staticmethod
    def frompointer(t: "uint16 *") -> "uint16_pointer *":
        r"""
        frompointer(t) -> uint16_pointer

        @param t: uint16 *
        """
        return _ida_pro.uint16_pointer_frompointer(t)

# Register uint16_pointer in _ida_pro:
_ida_pro.uint16_pointer_swigregister(uint16_pointer)
class int32_pointer(object):
    r"""
    Proxy of C++ int32_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> int32_pointer
        """
        _ida_pro.int32_pointer_swiginit(self, _ida_pro.new_int32_pointer())
    __swig_destroy__ = _ida_pro.delete_int32_pointer

    def assign(self, value: "int32") -> "void":
        r"""
        assign(self, value)

        @param value: int32
        """
        return _ida_pro.int32_pointer_assign(self, value)

    def value(self) -> "int32":
        r"""
        value(self) -> int32
        """
        return _ida_pro.int32_pointer_value(self)

    def cast(self) -> "int32 *":
        r"""
        cast(self) -> int32 *
        """
        return _ida_pro.int32_pointer_cast(self)

    @staticmethod
    def frompointer(t: "int32 *") -> "int32_pointer *":
        r"""
        frompointer(t) -> int32_pointer

        @param t: int32 *
        """
        return _ida_pro.int32_pointer_frompointer(t)

# Register int32_pointer in _ida_pro:
_ida_pro.int32_pointer_swigregister(int32_pointer)
class uint32_pointer(object):
    r"""
    Proxy of C++ uint32_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> uint32_pointer
        """
        _ida_pro.uint32_pointer_swiginit(self, _ida_pro.new_uint32_pointer())
    __swig_destroy__ = _ida_pro.delete_uint32_pointer

    def assign(self, value: "uint32") -> "void":
        r"""
        assign(self, value)

        @param value: uint32
        """
        return _ida_pro.uint32_pointer_assign(self, value)

    def value(self) -> "uint32":
        r"""
        value(self) -> uint32
        """
        return _ida_pro.uint32_pointer_value(self)

    def cast(self) -> "uint32 *":
        r"""
        cast(self) -> uint32 *
        """
        return _ida_pro.uint32_pointer_cast(self)

    @staticmethod
    def frompointer(t: "uint32 *") -> "uint32_pointer *":
        r"""
        frompointer(t) -> uint32_pointer

        @param t: uint32 *
        """
        return _ida_pro.uint32_pointer_frompointer(t)

# Register uint32_pointer in _ida_pro:
_ida_pro.uint32_pointer_swigregister(uint32_pointer)
class int64_pointer(object):
    r"""
    Proxy of C++ int64_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> int64_pointer
        """
        _ida_pro.int64_pointer_swiginit(self, _ida_pro.new_int64_pointer())
    __swig_destroy__ = _ida_pro.delete_int64_pointer

    def assign(self, value: "int64") -> "void":
        r"""
        assign(self, value)

        @param value: int64
        """
        return _ida_pro.int64_pointer_assign(self, value)

    def value(self) -> "int64":
        r"""
        value(self) -> int64
        """
        return _ida_pro.int64_pointer_value(self)

    def cast(self) -> "int64 *":
        r"""
        cast(self) -> int64 *
        """
        return _ida_pro.int64_pointer_cast(self)

    @staticmethod
    def frompointer(t: "int64 *") -> "int64_pointer *":
        r"""
        frompointer(t) -> int64_pointer

        @param t: int64 *
        """
        return _ida_pro.int64_pointer_frompointer(t)

# Register int64_pointer in _ida_pro:
_ida_pro.int64_pointer_swigregister(int64_pointer)
class uint64_pointer(object):
    r"""
    Proxy of C++ uint64_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> uint64_pointer
        """
        _ida_pro.uint64_pointer_swiginit(self, _ida_pro.new_uint64_pointer())
    __swig_destroy__ = _ida_pro.delete_uint64_pointer

    def assign(self, value: "uint64") -> "void":
        r"""
        assign(self, value)

        @param value: uint64
        """
        return _ida_pro.uint64_pointer_assign(self, value)

    def value(self) -> "uint64":
        r"""
        value(self) -> uint64
        """
        return _ida_pro.uint64_pointer_value(self)

    def cast(self) -> "uint64 *":
        r"""
        cast(self) -> uint64 *
        """
        return _ida_pro.uint64_pointer_cast(self)

    @staticmethod
    def frompointer(t: "uint64 *") -> "uint64_pointer *":
        r"""
        frompointer(t) -> uint64_pointer

        @param t: uint64 *
        """
        return _ida_pro.uint64_pointer_frompointer(t)

# Register uint64_pointer in _ida_pro:
_ida_pro.uint64_pointer_swigregister(uint64_pointer)
class ssize_pointer(object):
    r"""
    Proxy of C++ ssize_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> ssize_pointer
        """
        _ida_pro.ssize_pointer_swiginit(self, _ida_pro.new_ssize_pointer())
    __swig_destroy__ = _ida_pro.delete_ssize_pointer

    def assign(self, value: "ssize_t") -> "void":
        r"""
        assign(self, value)

        @param value: ssize_t
        """
        return _ida_pro.ssize_pointer_assign(self, value)

    def value(self) -> "ssize_t":
        r"""
        value(self) -> ssize_t
        """
        return _ida_pro.ssize_pointer_value(self)

    def cast(self) -> "ssize_t *":
        r"""
        cast(self) -> ssize_t *
        """
        return _ida_pro.ssize_pointer_cast(self)

    @staticmethod
    def frompointer(t: "ssize_t *") -> "ssize_pointer *":
        r"""
        frompointer(t) -> ssize_pointer

        @param t: ssize_t *
        """
        return _ida_pro.ssize_pointer_frompointer(t)

# Register ssize_pointer in _ida_pro:
_ida_pro.ssize_pointer_swigregister(ssize_pointer)
class bool_pointer(object):
    r"""
    Proxy of C++ bool_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> bool_pointer
        """
        _ida_pro.bool_pointer_swiginit(self, _ida_pro.new_bool_pointer())
    __swig_destroy__ = _ida_pro.delete_bool_pointer

    def assign(self, value: "bool") -> "void":
        r"""
        assign(self, value)

        @param value: bool
        """
        return _ida_pro.bool_pointer_assign(self, value)

    def value(self) -> "bool":
        r"""
        value(self) -> bool
        """
        return _ida_pro.bool_pointer_value(self)

    def cast(self) -> "bool *":
        r"""
        cast(self) -> bool *
        """
        return _ida_pro.bool_pointer_cast(self)

    @staticmethod
    def frompointer(t: "bool *") -> "bool_pointer *":
        r"""
        frompointer(t) -> bool_pointer

        @param t: bool *
        """
        return _ida_pro.bool_pointer_frompointer(t)

# Register bool_pointer in _ida_pro:
_ida_pro.bool_pointer_swigregister(bool_pointer)
class char_pointer(object):
    r"""
    Proxy of C++ char_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> char_pointer
        """
        _ida_pro.char_pointer_swiginit(self, _ida_pro.new_char_pointer())
    __swig_destroy__ = _ida_pro.delete_char_pointer

    def assign(self, value: "char") -> "void":
        r"""
        assign(self, value)

        @param value: char
        """
        return _ida_pro.char_pointer_assign(self, value)

    def value(self) -> "char":
        r"""
        value(self) -> char
        """
        return _ida_pro.char_pointer_value(self)

    def cast(self) -> "char *":
        r"""
        cast(self) -> char *
        """
        return _ida_pro.char_pointer_cast(self)

    @staticmethod
    def frompointer(t: "char *") -> "char_pointer *":
        r"""
        frompointer(t) -> char_pointer

        @param t: char *
        """
        return _ida_pro.char_pointer_frompointer(t)

# Register char_pointer in _ida_pro:
_ida_pro.char_pointer_swigregister(char_pointer)
class short_pointer(object):
    r"""
    Proxy of C++ short_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> short_pointer
        """
        _ida_pro.short_pointer_swiginit(self, _ida_pro.new_short_pointer())
    __swig_destroy__ = _ida_pro.delete_short_pointer

    def assign(self, value: "short") -> "void":
        r"""
        assign(self, value)

        @param value: short
        """
        return _ida_pro.short_pointer_assign(self, value)

    def value(self) -> "short":
        r"""
        value(self) -> short
        """
        return _ida_pro.short_pointer_value(self)

    def cast(self) -> "short *":
        r"""
        cast(self) -> short *
        """
        return _ida_pro.short_pointer_cast(self)

    @staticmethod
    def frompointer(t: "short *") -> "short_pointer *":
        r"""
        frompointer(t) -> short_pointer

        @param t: short *
        """
        return _ida_pro.short_pointer_frompointer(t)

# Register short_pointer in _ida_pro:
_ida_pro.short_pointer_swigregister(short_pointer)
class int_pointer(object):
    r"""
    Proxy of C++ int_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> int_pointer
        """
        _ida_pro.int_pointer_swiginit(self, _ida_pro.new_int_pointer())
    __swig_destroy__ = _ida_pro.delete_int_pointer

    def assign(self, value: "int") -> "void":
        r"""
        assign(self, value)

        @param value: int
        """
        return _ida_pro.int_pointer_assign(self, value)

    def value(self) -> "int":
        r"""
        value(self) -> int
        """
        return _ida_pro.int_pointer_value(self)

    def cast(self) -> "int *":
        r"""
        cast(self) -> int *
        """
        return _ida_pro.int_pointer_cast(self)

    @staticmethod
    def frompointer(t: "int *") -> "int_pointer *":
        r"""
        frompointer(t) -> int_pointer

        @param t: int *
        """
        return _ida_pro.int_pointer_frompointer(t)

# Register int_pointer in _ida_pro:
_ida_pro.int_pointer_swigregister(int_pointer)
class ea_pointer(object):
    r"""
    Proxy of C++ ea_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> ea_pointer
        """
        _ida_pro.ea_pointer_swiginit(self, _ida_pro.new_ea_pointer())
    __swig_destroy__ = _ida_pro.delete_ea_pointer

    def assign(self, value: "ea_t") -> "void":
        r"""
        assign(self, value)

        @param value: ea_t
        """
        return _ida_pro.ea_pointer_assign(self, value)

    def value(self) -> "ea_t":
        r"""
        value(self) -> ea_t
        """
        return _ida_pro.ea_pointer_value(self)

    def cast(self) -> "ea_t *":
        r"""
        cast(self) -> ea_t *
        """
        return _ida_pro.ea_pointer_cast(self)

    @staticmethod
    def frompointer(t: "ea_t *") -> "ea_pointer *":
        r"""
        frompointer(t) -> ea_pointer

        @param t: ea_t *
        """
        return _ida_pro.ea_pointer_frompointer(t)

# Register ea_pointer in _ida_pro:
_ida_pro.ea_pointer_swigregister(ea_pointer)
class sel_pointer(object):
    r"""
    Proxy of C++ sel_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> sel_pointer
        """
        _ida_pro.sel_pointer_swiginit(self, _ida_pro.new_sel_pointer())
    __swig_destroy__ = _ida_pro.delete_sel_pointer

    def assign(self, value: "sel_t") -> "void":
        r"""
        assign(self, value)

        @param value: sel_t
        """
        return _ida_pro.sel_pointer_assign(self, value)

    def value(self) -> "sel_t":
        r"""
        value(self) -> sel_t
        """
        return _ida_pro.sel_pointer_value(self)

    def cast(self) -> "sel_t *":
        r"""
        cast(self) -> sel_t *
        """
        return _ida_pro.sel_pointer_cast(self)

    @staticmethod
    def frompointer(t: "sel_t *") -> "sel_pointer *":
        r"""
        frompointer(t) -> sel_pointer

        @param t: sel_t *
        """
        return _ida_pro.sel_pointer_frompointer(t)

# Register sel_pointer in _ida_pro:
_ida_pro.sel_pointer_swigregister(sel_pointer)
class asize_pointer(object):
    r"""
    Proxy of C++ asize_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> asize_pointer
        """
        _ida_pro.asize_pointer_swiginit(self, _ida_pro.new_asize_pointer())
    __swig_destroy__ = _ida_pro.delete_asize_pointer

    def assign(self, value: "asize_t") -> "void":
        r"""
        assign(self, value)

        @param value: asize_t
        """
        return _ida_pro.asize_pointer_assign(self, value)

    def value(self) -> "asize_t":
        r"""
        value(self) -> asize_t
        """
        return _ida_pro.asize_pointer_value(self)

    def cast(self) -> "asize_t *":
        r"""
        cast(self) -> asize_t *
        """
        return _ida_pro.asize_pointer_cast(self)

    @staticmethod
    def frompointer(t: "asize_t *") -> "asize_pointer *":
        r"""
        frompointer(t) -> asize_pointer

        @param t: asize_t *
        """
        return _ida_pro.asize_pointer_frompointer(t)

# Register asize_pointer in _ida_pro:
_ida_pro.asize_pointer_swigregister(asize_pointer)
class adiff_pointer(object):
    r"""
    Proxy of C++ adiff_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> adiff_pointer
        """
        _ida_pro.adiff_pointer_swiginit(self, _ida_pro.new_adiff_pointer())
    __swig_destroy__ = _ida_pro.delete_adiff_pointer

    def assign(self, value: "adiff_t") -> "void":
        r"""
        assign(self, value)

        @param value: adiff_t
        """
        return _ida_pro.adiff_pointer_assign(self, value)

    def value(self) -> "adiff_t":
        r"""
        value(self) -> adiff_t
        """
        return _ida_pro.adiff_pointer_value(self)

    def cast(self) -> "adiff_t *":
        r"""
        cast(self) -> adiff_t *
        """
        return _ida_pro.adiff_pointer_cast(self)

    @staticmethod
    def frompointer(t: "adiff_t *") -> "adiff_pointer *":
        r"""
        frompointer(t) -> adiff_pointer

        @param t: adiff_t *
        """
        return _ida_pro.adiff_pointer_frompointer(t)

# Register adiff_pointer in _ida_pro:
_ida_pro.adiff_pointer_swigregister(adiff_pointer)
class uval_pointer(object):
    r"""
    Proxy of C++ uval_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> uval_pointer
        """
        _ida_pro.uval_pointer_swiginit(self, _ida_pro.new_uval_pointer())
    __swig_destroy__ = _ida_pro.delete_uval_pointer

    def assign(self, value: "uval_t") -> "void":
        r"""
        assign(self, value)

        @param value: uval_t
        """
        return _ida_pro.uval_pointer_assign(self, value)

    def value(self) -> "uval_t":
        r"""
        value(self) -> uval_t
        """
        return _ida_pro.uval_pointer_value(self)

    def cast(self) -> "uval_t *":
        r"""
        cast(self) -> uval_t *
        """
        return _ida_pro.uval_pointer_cast(self)

    @staticmethod
    def frompointer(t: "uval_t *") -> "uval_pointer *":
        r"""
        frompointer(t) -> uval_pointer

        @param t: uval_t *
        """
        return _ida_pro.uval_pointer_frompointer(t)

# Register uval_pointer in _ida_pro:
_ida_pro.uval_pointer_swigregister(uval_pointer)
class sval_pointer(object):
    r"""
    Proxy of C++ sval_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> sval_pointer
        """
        _ida_pro.sval_pointer_swiginit(self, _ida_pro.new_sval_pointer())
    __swig_destroy__ = _ida_pro.delete_sval_pointer

    def assign(self, value: "sval_t") -> "void":
        r"""
        assign(self, value)

        @param value: sval_t
        """
        return _ida_pro.sval_pointer_assign(self, value)

    def value(self) -> "sval_t":
        r"""
        value(self) -> sval_t
        """
        return _ida_pro.sval_pointer_value(self)

    def cast(self) -> "sval_t *":
        r"""
        cast(self) -> sval_t *
        """
        return _ida_pro.sval_pointer_cast(self)

    @staticmethod
    def frompointer(t: "sval_t *") -> "sval_pointer *":
        r"""
        frompointer(t) -> sval_pointer

        @param t: sval_t *
        """
        return _ida_pro.sval_pointer_frompointer(t)

# Register sval_pointer in _ida_pro:
_ida_pro.sval_pointer_swigregister(sval_pointer)
class ea32_pointer(object):
    r"""
    Proxy of C++ ea32_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> ea32_pointer
        """
        _ida_pro.ea32_pointer_swiginit(self, _ida_pro.new_ea32_pointer())
    __swig_destroy__ = _ida_pro.delete_ea32_pointer

    def assign(self, value: "ea32_t") -> "void":
        r"""
        assign(self, value)

        @param value: ea32_t
        """
        return _ida_pro.ea32_pointer_assign(self, value)

    def value(self) -> "ea32_t":
        r"""
        value(self) -> ea32_t
        """
        return _ida_pro.ea32_pointer_value(self)

    def cast(self) -> "ea32_t *":
        r"""
        cast(self) -> ea32_t *
        """
        return _ida_pro.ea32_pointer_cast(self)

    @staticmethod
    def frompointer(t: "ea32_t *") -> "ea32_pointer *":
        r"""
        frompointer(t) -> ea32_pointer

        @param t: ea32_t *
        """
        return _ida_pro.ea32_pointer_frompointer(t)

# Register ea32_pointer in _ida_pro:
_ida_pro.ea32_pointer_swigregister(ea32_pointer)
class ea64_pointer(object):
    r"""
    Proxy of C++ ea64_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> ea64_pointer
        """
        _ida_pro.ea64_pointer_swiginit(self, _ida_pro.new_ea64_pointer())
    __swig_destroy__ = _ida_pro.delete_ea64_pointer

    def assign(self, value: "ea64_t") -> "void":
        r"""
        assign(self, value)

        @param value: ea64_t
        """
        return _ida_pro.ea64_pointer_assign(self, value)

    def value(self) -> "ea64_t":
        r"""
        value(self) -> ea64_t
        """
        return _ida_pro.ea64_pointer_value(self)

    def cast(self) -> "ea64_t *":
        r"""
        cast(self) -> ea64_t *
        """
        return _ida_pro.ea64_pointer_cast(self)

    @staticmethod
    def frompointer(t: "ea64_t *") -> "ea64_pointer *":
        r"""
        frompointer(t) -> ea64_pointer

        @param t: ea64_t *
        """
        return _ida_pro.ea64_pointer_frompointer(t)

# Register ea64_pointer in _ida_pro:
_ida_pro.ea64_pointer_swigregister(ea64_pointer)
class flags_pointer(object):
    r"""
    Proxy of C++ flags_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> flags_pointer
        """
        _ida_pro.flags_pointer_swiginit(self, _ida_pro.new_flags_pointer())
    __swig_destroy__ = _ida_pro.delete_flags_pointer

    def assign(self, value: "flags_t") -> "void":
        r"""
        assign(self, value)

        @param value: flags_t
        """
        return _ida_pro.flags_pointer_assign(self, value)

    def value(self) -> "flags_t":
        r"""
        value(self) -> flags_t
        """
        return _ida_pro.flags_pointer_value(self)

    def cast(self) -> "flags_t *":
        r"""
        cast(self) -> flags_t *
        """
        return _ida_pro.flags_pointer_cast(self)

    @staticmethod
    def frompointer(t: "flags_t *") -> "flags_pointer *":
        r"""
        frompointer(t) -> flags_pointer

        @param t: flags_t *
        """
        return _ida_pro.flags_pointer_frompointer(t)

# Register flags_pointer in _ida_pro:
_ida_pro.flags_pointer_swigregister(flags_pointer)
class flags64_pointer(object):
    r"""
    Proxy of C++ flags64_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> flags64_pointer
        """
        _ida_pro.flags64_pointer_swiginit(self, _ida_pro.new_flags64_pointer())
    __swig_destroy__ = _ida_pro.delete_flags64_pointer

    def assign(self, value: "flags64_t") -> "void":
        r"""
        assign(self, value)

        @param value: flags64_t
        """
        return _ida_pro.flags64_pointer_assign(self, value)

    def value(self) -> "flags64_t":
        r"""
        value(self) -> flags64_t
        """
        return _ida_pro.flags64_pointer_value(self)

    def cast(self) -> "flags64_t *":
        r"""
        cast(self) -> flags64_t *
        """
        return _ida_pro.flags64_pointer_cast(self)

    @staticmethod
    def frompointer(t: "flags64_t *") -> "flags64_pointer *":
        r"""
        frompointer(t) -> flags64_pointer

        @param t: flags64_t *
        """
        return _ida_pro.flags64_pointer_frompointer(t)

# Register flags64_pointer in _ida_pro:
_ida_pro.flags64_pointer_swigregister(flags64_pointer)
class tid_pointer(object):
    r"""
    Proxy of C++ tid_pointer class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> tid_pointer
        """
        _ida_pro.tid_pointer_swiginit(self, _ida_pro.new_tid_pointer())
    __swig_destroy__ = _ida_pro.delete_tid_pointer

    def assign(self, value: "tid_t") -> "void":
        r"""
        assign(self, value)

        @param value: tid_t
        """
        return _ida_pro.tid_pointer_assign(self, value)

    def value(self) -> "tid_t":
        r"""
        value(self) -> tid_t
        """
        return _ida_pro.tid_pointer_value(self)

    def cast(self) -> "tid_t *":
        r"""
        cast(self) -> tid_t *
        """
        return _ida_pro.tid_pointer_cast(self)

    @staticmethod
    def frompointer(t: "tid_t *") -> "tid_pointer *":
        r"""
        frompointer(t) -> tid_pointer

        @param t: tid_t *
        """
        return _ida_pro.tid_pointer_frompointer(t)

# Register tid_pointer in _ida_pro:
_ida_pro.tid_pointer_swigregister(tid_pointer)

#<pycode(py_pro)>
import ida_idaapi

longlongvec_t = int64vec_t
ulonglongvec_t = uint64vec_t

if ida_idaapi.__EA64__:
    svalvec_t = int64vec_t
    uvalvec_t = uint64vec_t
else:
    svalvec_t = intvec_t
    uvalvec_t = uintvec_t
eavec_t = uvalvec_t

ida_idaapi._listify_types(
        intvec_t,
        uintvec_t,
        int64vec_t,
        uint64vec_t,
        boolvec_t,
        strvec_t)

# -----------------------------------------------------------------------
# qstrvec_t clinked object
class _qstrvec_t(ida_idaapi.py_clinked_object_t):
    """
    WARNING: It is very unlikely an IDAPython user should ever, ever
    have to use this type. It should only be used for IDAPython internals.

    For example, in py_askusingform.py, we ctypes-expose to the IDA
    kernel & UI a qstrvec instance, in case a DropdownListControl is
    constructed.
    That's because that's what ask_form expects, and we have no
    choice but to make a DropdownListControl hold a qstrvec_t.
    This is, afaict, the only situation where a Python
    _qstrvec_t is required.
    """

    def __init__(self, items=None):
        ida_idaapi.py_clinked_object_t.__init__(self)
# Populate the list if needed
        if items:
            self.from_list(items)

    def _create_clink(self):
        return _ida_pro.qstrvec_t_create()

    def _del_clink(self, lnk):
        return _ida_pro.qstrvec_t_destroy(lnk)

    def _get_clink_ptr(self):
        return _ida_pro.qstrvec_t_get_clink_ptr(self)

    def assign(self, other):
        """Copies the contents of 'other' to 'self'"""
        return _ida_pro.qstrvec_t_assign(self, other)

    def __setitem__(self, idx, s):
        """Sets string at the given index"""
        return _ida_pro.qstrvec_t_set(self, idx, s)

    def __getitem__(self, idx):
        """Gets the string at the given index"""
        return _ida_pro.qstrvec_t_get(self, idx)

    def __get_size(self):
        return _ida_pro.qstrvec_t_size(self)

    size = property(__get_size)
    """Returns the count of elements"""

    def addressof(self, idx):
        """Returns the address (as number) of the qstring at the given index"""
        return _ida_pro.qstrvec_t_addressof(self, idx)

    def add(self, s):
        """Add a string to the vector"""
        return _ida_pro.qstrvec_t_add(self, s)

    def from_list(self, lst):
        """Populates the vector from a Python string list"""
        return _ida_pro.qstrvec_t_from_list(self, lst)

    def clear(self, qclear=False):
        """
        Clears all strings from the vector.
        @param qclear: Just reset the size but do not actually free the memory
        """
        return _ida_pro.qstrvec_t_clear(self, qclear)

    def insert(self, idx, s):
        """Insert a string into the vector"""
        return _ida_pro.qstrvec_t_insert(self, idx, s)

    def remove(self, idx):
        """Removes a string from the vector"""
        return _ida_pro.qstrvec_t_remove(self, idx)

#</pycode(py_pro)>



