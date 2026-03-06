r"""
Routines to manipulate function stack frames, stack variables, register
variables and local labels.

The frame is represented as a structure:
+------------------------------------------------+
  | function arguments                             |
  +------------------------------------------------+
  | return address (isn't stored in func_t)        |
  +------------------------------------------------+
  | saved registers (SI, DI, etc - func_t::frregs) |
  +------------------------------------------------+ <- typical BP
  |                                                |  |
  |                                                |  | func_t::fpd
  |                                                |  |
  |                                                | <- real BP
  | local variables (func_t::frsize)               |
  |                                                |
  |                                                |
  +------------------------------------------------+ <- SP

To access the structure of a function frame, use:
* tinfo_t::get_func_frame(const func_t *pfn) (the preferred way)
* get_func_frame(tinfo_t *out, const func_t *pfn)"""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_frame
else:
    import _ida_frame

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

SWIG_PYTHON_LEGACY_BOOL = _ida_frame.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

import ida_range
class xreflist_t(object):
    r"""
    Proxy of C++ qvector< xreflist_entry_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> xreflist_t
        __init__(self, x) -> xreflist_t

        @param x: qvector< xreflist_entry_t > const &
        """
        _ida_frame.xreflist_t_swiginit(self, _ida_frame.new_xreflist_t(*args))
    __swig_destroy__ = _ida_frame.delete_xreflist_t

    def push_back(self, *args) -> "xreflist_entry_t &":
        r"""
        push_back(self, x)

        @param x: xreflist_entry_t const &

        push_back(self) -> xreflist_entry_t
        """
        return _ida_frame.xreflist_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_frame.xreflist_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_frame.xreflist_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_frame.xreflist_t_empty(self)

    def at(self, _idx: "size_t") -> "xreflist_entry_t const &":
        r"""
        at(self, _idx) -> xreflist_entry_t

        @param _idx: size_t
        """
        return _ida_frame.xreflist_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_frame.xreflist_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_frame.xreflist_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: xreflist_entry_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_frame.xreflist_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=xreflist_entry_t())

        @param x: xreflist_entry_t const &
        """
        return _ida_frame.xreflist_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_frame.xreflist_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_frame.xreflist_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_frame.xreflist_t_truncate(self)

    def swap(self, r: "xreflist_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< xreflist_entry_t > &
        """
        return _ida_frame.xreflist_t_swap(self, r)

    def extract(self) -> "xreflist_entry_t *":
        r"""
        extract(self) -> xreflist_entry_t
        """
        return _ida_frame.xreflist_t_extract(self)

    def inject(self, s: "xreflist_entry_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: xreflist_entry_t *
        @param len: size_t
        """
        return _ida_frame.xreflist_t_inject(self, s, len)

    def __eq__(self, r: "xreflist_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< xreflist_entry_t > const &
        """
        return _ida_frame.xreflist_t___eq__(self, r)

    def __ne__(self, r: "xreflist_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< xreflist_entry_t > const &
        """
        return _ida_frame.xreflist_t___ne__(self, r)

    def begin(self, *args) -> "qvector< xreflist_entry_t >::const_iterator":
        r"""
        begin(self) -> xreflist_entry_t
        """
        return _ida_frame.xreflist_t_begin(self, *args)

    def end(self, *args) -> "qvector< xreflist_entry_t >::const_iterator":
        r"""
        end(self) -> xreflist_entry_t
        """
        return _ida_frame.xreflist_t_end(self, *args)

    def insert(self, it: "xreflist_entry_t", x: "xreflist_entry_t") -> "qvector< xreflist_entry_t >::iterator":
        r"""
        insert(self, it, x) -> xreflist_entry_t

        @param it: qvector< xreflist_entry_t >::iterator
        @param x: xreflist_entry_t const &
        """
        return _ida_frame.xreflist_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< xreflist_entry_t >::iterator":
        r"""
        erase(self, it) -> xreflist_entry_t

        @param it: qvector< xreflist_entry_t >::iterator

        erase(self, first, last) -> xreflist_entry_t

        @param first: qvector< xreflist_entry_t >::iterator
        @param last: qvector< xreflist_entry_t >::iterator
        """
        return _ida_frame.xreflist_t_erase(self, *args)

    def find(self, *args) -> "qvector< xreflist_entry_t >::const_iterator":
        r"""
        find(self, x) -> xreflist_entry_t

        @param x: xreflist_entry_t const &

        """
        return _ida_frame.xreflist_t_find(self, *args)

    def has(self, x: "xreflist_entry_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: xreflist_entry_t const &
        """
        return _ida_frame.xreflist_t_has(self, x)

    def add_unique(self, x: "xreflist_entry_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: xreflist_entry_t const &
        """
        return _ida_frame.xreflist_t_add_unique(self, x)

    def _del(self, x: "xreflist_entry_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: xreflist_entry_t const &

        """
        return _ida_frame.xreflist_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_frame.xreflist_t___len__(self)

    def __getitem__(self, i: "size_t") -> "xreflist_entry_t const &":
        r"""
        __getitem__(self, i) -> xreflist_entry_t

        @param i: size_t
        """
        return _ida_frame.xreflist_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "xreflist_entry_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: xreflist_entry_t const &
        """
        return _ida_frame.xreflist_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register xreflist_t in _ida_frame:
_ida_frame.xreflist_t_swigregister(xreflist_t)

def is_funcarg_off(pfn: "func_t const *", frameoff: "uval_t") -> "bool":
    r"""
    is_funcarg_off(pfn, frameoff) -> bool

    @param pfn: func_t const *
    @param frameoff: uval_t
    """
    return _ida_frame.is_funcarg_off(pfn, frameoff)

def lvar_off(pfn: "func_t const *", frameoff: "uval_t") -> "sval_t":
    r"""
    lvar_off(pfn, frameoff) -> sval_t

    @param pfn: func_t const *
    @param frameoff: uval_t
    """
    return _ida_frame.lvar_off(pfn, frameoff)
FRAME_UDM_NAME_R = _ida_frame.FRAME_UDM_NAME_R

FRAME_UDM_NAME_S = _ida_frame.FRAME_UDM_NAME_S

class stkpnt_t(object):
    r"""
    Proxy of C++ stkpnt_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ea: "ea_t" = property(_ida_frame.stkpnt_t_ea_get, _ida_frame.stkpnt_t_ea_set, doc=r"""ea""")
    spd: "sval_t" = property(_ida_frame.stkpnt_t_spd_get, _ida_frame.stkpnt_t_spd_set, doc=r"""spd""")

    def __eq__(self, r: "stkpnt_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: stkpnt_t const &
        """
        return _ida_frame.stkpnt_t___eq__(self, r)

    def __ne__(self, r: "stkpnt_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: stkpnt_t const &
        """
        return _ida_frame.stkpnt_t___ne__(self, r)

    def __lt__(self, r: "stkpnt_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: stkpnt_t const &
        """
        return _ida_frame.stkpnt_t___lt__(self, r)

    def __gt__(self, r: "stkpnt_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: stkpnt_t const &
        """
        return _ida_frame.stkpnt_t___gt__(self, r)

    def __le__(self, r: "stkpnt_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: stkpnt_t const &
        """
        return _ida_frame.stkpnt_t___le__(self, r)

    def __ge__(self, r: "stkpnt_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: stkpnt_t const &
        """
        return _ida_frame.stkpnt_t___ge__(self, r)

    def compare(self, r: "stkpnt_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: stkpnt_t const &
        """
        return _ida_frame.stkpnt_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> stkpnt_t
        """
        _ida_frame.stkpnt_t_swiginit(self, _ida_frame.new_stkpnt_t())
    __swig_destroy__ = _ida_frame.delete_stkpnt_t

# Register stkpnt_t in _ida_frame:
_ida_frame.stkpnt_t_swigregister(stkpnt_t)
class stkpnts_t(object):
    r"""
    Proxy of C++ stkpnts_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __eq__(self, r: "stkpnts_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: stkpnts_t const &
        """
        return _ida_frame.stkpnts_t___eq__(self, r)

    def __ne__(self, r: "stkpnts_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: stkpnts_t const &
        """
        return _ida_frame.stkpnts_t___ne__(self, r)

    def __lt__(self, r: "stkpnts_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: stkpnts_t const &
        """
        return _ida_frame.stkpnts_t___lt__(self, r)

    def __gt__(self, r: "stkpnts_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: stkpnts_t const &
        """
        return _ida_frame.stkpnts_t___gt__(self, r)

    def __le__(self, r: "stkpnts_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: stkpnts_t const &
        """
        return _ida_frame.stkpnts_t___le__(self, r)

    def __ge__(self, r: "stkpnts_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: stkpnts_t const &
        """
        return _ida_frame.stkpnts_t___ge__(self, r)

    def compare(self, r: "stkpnts_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: stkpnts_t const &
        """
        return _ida_frame.stkpnts_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> stkpnts_t
        """
        _ida_frame.stkpnts_t_swiginit(self, _ida_frame.new_stkpnts_t())
    __swig_destroy__ = _ida_frame.delete_stkpnts_t

# Register stkpnts_t in _ida_frame:
_ida_frame.stkpnts_t_swigregister(stkpnts_t)

def add_frame(pfn: "func_t *", frsize: "sval_t", frregs: "ushort", argsize: "asize_t") -> "bool":
    r"""
    add_frame(pfn, frsize, frregs, argsize) -> bool
    Add function frame.

    @param pfn: (C++: func_t *) pointer to function structure
    @param frsize: (C++: sval_t) size of function local variables
    @param frregs: (C++: ushort) size of saved registers
    @param argsize: (C++: asize_t) size of function arguments range which will be purged upon
                    return. this parameter is used for __stdcall and __pascal
                    calling conventions. for other calling conventions please pass
                    0.
    @retval 1: ok
    @retval 0: failed (no function, frame already exists)
    """
    return _ida_frame.add_frame(pfn, frsize, frregs, argsize)

def del_frame(pfn: "func_t *") -> "bool":
    r"""
    del_frame(pfn) -> bool
    Delete a function frame.

    @param pfn: (C++: func_t *) pointer to function structure
    @return: success
    """
    return _ida_frame.del_frame(pfn)

def set_frame_size(pfn: "func_t *", frsize: "asize_t", frregs: "ushort", argsize: "asize_t") -> "bool":
    r"""
    set_frame_size(pfn, frsize, frregs, argsize) -> bool
    Set size of function frame. Note: The returned size may not include all stack
    arguments. It does so only for __stdcall and __fastcall calling conventions. To
    get the entire frame size for all cases use frame.get_func_frame(pfn).get_size()

    @param pfn: (C++: func_t *) pointer to function structure
    @param frsize: (C++: asize_t) size of function local variables
    @param frregs: (C++: ushort) size of saved registers
    @param argsize: (C++: asize_t) size of function arguments that will be purged from the stack
                    upon return
    @return: success
    """
    return _ida_frame.set_frame_size(pfn, frsize, frregs, argsize)

def get_frame_size(pfn: "func_t const *") -> "asize_t":
    r"""
    get_frame_size(pfn) -> asize_t
    Get full size of a function frame. This function takes into account size of
    local variables + size of saved registers + size of return address + number of
    purged bytes. The purged bytes correspond to the arguments of the functions with
    __stdcall and __fastcall calling conventions.

    @param pfn: (C++: const func_t *) pointer to function structure, may be nullptr
    @return: size of frame in bytes or zero
    """
    return _ida_frame.get_frame_size(pfn)

def get_frame_retsize(pfn: "func_t const *") -> "int":
    r"""
    get_frame_retsize(pfn) -> int
    Get size of function return address.

    @param pfn: (C++: const func_t *) pointer to function structure, can't be nullptr
    """
    return _ida_frame.get_frame_retsize(pfn)
FPC_ARGS = _ida_frame.FPC_ARGS

FPC_RETADDR = _ida_frame.FPC_RETADDR

FPC_SAVREGS = _ida_frame.FPC_SAVREGS

FPC_LVARS = _ida_frame.FPC_LVARS


def get_frame_part(range: "range_t", pfn: "func_t const *", part: "frame_part_t") -> "void":
    r"""
    get_frame_part(range, pfn, part)
    Get offsets of the frame part in the frame.

    @param range: (C++: range_t *) pointer to the output buffer with the frame part
                  start/end(exclusive) offsets, can't be nullptr
    @param pfn: (C++: const func_t *) pointer to function structure, can't be nullptr
    @param part: (C++: frame_part_t) frame part
    """
    return _ida_frame.get_frame_part(range, pfn, part)

def frame_off_args(pfn: "func_t const *") -> "ea_t":
    r"""
    frame_off_args(pfn) -> ea_t
    Get starting address of arguments section.

    @param pfn: (C++: const func_t *) func_t const *
    """
    return _ida_frame.frame_off_args(pfn)

def frame_off_retaddr(pfn: "func_t const *") -> "ea_t":
    r"""
    frame_off_retaddr(pfn) -> ea_t
    Get starting address of return address section.

    @param pfn: (C++: const func_t *) func_t const *
    """
    return _ida_frame.frame_off_retaddr(pfn)

def frame_off_savregs(pfn: "func_t const *") -> "ea_t":
    r"""
    frame_off_savregs(pfn) -> ea_t
    Get starting address of saved registers section.

    @param pfn: (C++: const func_t *) func_t const *
    """
    return _ida_frame.frame_off_savregs(pfn)

def frame_off_lvars(pfn: "func_t const *") -> "ea_t":
    r"""
    frame_off_lvars(pfn) -> ea_t
    Get start address of local variables section.

    @param pfn: (C++: const func_t *) func_t const *
    """
    return _ida_frame.frame_off_lvars(pfn)

def get_func_frame(out: "tinfo_t", pfn: "func_t const *") -> "bool":
    r"""
    get_func_frame(out, pfn) -> bool

    @param out: tinfo_t *
    @param pfn: func_t const *
    """
    return _ida_frame.get_func_frame(out, pfn)

def soff_to_fpoff(pfn: "func_t *", soff: "uval_t") -> "sval_t":
    r"""
    soff_to_fpoff(pfn, soff) -> sval_t
    Convert struct offsets into fp-relative offsets. This function converts the
    offsets inside the udt_type_data_t object into the frame pointer offsets (for
    example, EBP-relative).

    @param pfn: (C++: func_t *)
    @param soff: (C++: uval_t)
    """
    return _ida_frame.soff_to_fpoff(pfn, soff)

def update_fpd(pfn: "func_t *", fpd: "asize_t") -> "bool":
    r"""
    update_fpd(pfn, fpd) -> bool
    Update frame pointer delta.

    @param pfn: (C++: func_t *) pointer to function structure
    @param fpd: (C++: asize_t) new fpd value. cannot be bigger than the local variable range size.
    @return: success
    """
    return _ida_frame.update_fpd(pfn, fpd)

def set_purged(ea: "ea_t", nbytes: "int", override_old_value: "bool") -> "bool":
    r"""
    set_purged(ea, nbytes, override_old_value) -> bool
    Set the number of purged bytes for a function or data item (funcptr). This
    function will update the database and plan to reanalyze items referencing the
    specified address. It works only for processors with PR_PURGING bit in 16 and 32
    bit modes.

    @param ea: (C++: ea_t) address of the function of item
    @param nbytes: (C++: int) number of purged bytes
    @param override_old_value: (C++: bool) may overwrite old information about purged bytes
    @return: success
    """
    return _ida_frame.set_purged(ea, nbytes, override_old_value)
STKVAR_VALID_SIZE = _ida_frame.STKVAR_VALID_SIZE
r"""
x.dtyp contains correct variable type (for insns like 'lea' this bit must be
off). In general, dr_O references do not allow to determine the variable size
"""


def define_stkvar(pfn: "func_t *", name: "char const *", off: "sval_t", tif: "tinfo_t", repr: "value_repr_t"=None) -> "bool":
    r"""
    define_stkvar(pfn, name, off, tif, repr=None) -> bool
    Define/redefine a stack variable.

    @param pfn: (C++: func_t *) pointer to function
    @param name: (C++: const char *) variable name, nullptr means autogenerate a name
    @param off: (C++: sval_t) offset of the stack variable in the frame. negative values denote
                local variables, positive - function arguments.
    @param tif: (C++: const tinfo_t &) variable type
    @param repr: (C++: const struct value_repr_t *) variable representation
    @return: success
    """
    return _ida_frame.define_stkvar(pfn, name, off, tif, repr)

def add_frame_member(pfn: "func_t const *", name: "char const *", offset: "uval_t", tif: "tinfo_t", repr: "value_repr_t"=None, etf_flags: "uint"=0) -> "bool":
    r"""
    add_frame_member(pfn, name, offset, tif, repr=None, etf_flags=0) -> bool
    Add member to the frame type

    @param pfn: (C++: const func_t *) pointer to function
    @param name: (C++: const char *) variable name, nullptr means autogenerate a name
    @param offset: (C++: uval_t) member offset in the frame structure, in bytes
    @param tif: (C++: const tinfo_t &) variable type
    @param repr: (C++: const struct value_repr_t *) variable representation
    @param etf_flags: (C++: uint)
    @see: type changing flags
    @return: success
    """
    return _ida_frame.add_frame_member(pfn, name, offset, tif, repr, etf_flags)

def is_anonymous_member_name(name: "char const *") -> "bool":
    r"""
    is_anonymous_member_name(name) -> bool
    Is member name prefixed with "anonymous"?

    @param name: (C++: const char *) char const *
    """
    return _ida_frame.is_anonymous_member_name(name)

def is_dummy_member_name(name: "char const *") -> "bool":
    r"""
    is_dummy_member_name(name) -> bool
    Is member name an auto-generated name?

    @param name: (C++: const char *) char const *
    """
    return _ida_frame.is_dummy_member_name(name)

def is_special_frame_member(tid: "tid_t") -> "bool":
    r"""
    is_special_frame_member(tid) -> bool
    Is stkvar with TID the return address slot or the saved registers slot ?

    @param tid: (C++: tid_t) frame member type id return address or saved registers member?
    """
    return _ida_frame.is_special_frame_member(tid)

def set_frame_member_type(pfn: "func_t const *", offset: "uval_t", tif: "tinfo_t", repr: "value_repr_t"=None, etf_flags: "uint"=0) -> "bool":
    r"""
    set_frame_member_type(pfn, offset, tif, repr=None, etf_flags=0) -> bool
    Change type of the frame member

    @param pfn: (C++: const func_t *) pointer to function
    @param offset: (C++: uval_t) member offset in the frame structure, in bytes
    @param tif: (C++: const tinfo_t &) variable type
    @param repr: (C++: const struct value_repr_t *) variable representation
    @param etf_flags: (C++: uint)
    @see: type changing flags
    @return: success
    """
    return _ida_frame.set_frame_member_type(pfn, offset, tif, repr, etf_flags)

def delete_frame_members(pfn: "func_t const *", start_offset: "uval_t", end_offset: "uval_t") -> "bool":
    r"""
    delete_frame_members(pfn, start_offset, end_offset) -> bool
    Delete frame members

    @param pfn: (C++: const func_t *) pointer to function
    @param start_offset: (C++: uval_t) member offset to start deletion from, in bytes
    @param end_offset: (C++: uval_t) member offset which not included in the deletion, in bytes
    @return: success
    """
    return _ida_frame.delete_frame_members(pfn, start_offset, end_offset)

def build_stkvar_name(pfn: "func_t const *", v: "sval_t") -> "qstring *":
    r"""
    build_stkvar_name(pfn, v) -> str
    Build automatic stack variable name.

    @param pfn: (C++: const func_t *) pointer to function (can't be nullptr!)
    @param v: (C++: sval_t) value of variable offset
    @return: length of stack variable name or -1
    """
    return _ida_frame.build_stkvar_name(pfn, v)

def calc_stkvar_struc_offset(pfn: "func_t *", insn: "insn_t const &", n: "int") -> "ea_t":
    r"""
    calc_stkvar_struc_offset(pfn, insn, n) -> ea_t
    Calculate offset of stack variable in the frame structure.

    @param pfn: (C++: func_t *) pointer to function (cannot be nullptr)
    @param insn: (C++: const insn_t &) the instruction
    @param n: (C++: int) 0..UA_MAXOP-1 operand number -1 if error, return BADADDR
    @return: BADADDR if some error (issue a warning if stack frame is bad)
    """
    return _ida_frame.calc_stkvar_struc_offset(pfn, insn, n)

def calc_frame_offset(pfn: "func_t *", off: "sval_t", insn: "insn_t const *"=None, op: "op_t const *"=None) -> "sval_t":
    r"""
    calc_frame_offset(pfn, off, insn=None, op=None) -> sval_t
    Calculate the offset of stack variable in the frame.

    @param pfn: (C++: func_t *) pointer to function (cannot be nullptr)
    @param off: (C++: sval_t) the offset relative to stack pointer or frame pointer
    @param insn: (C++: const insn_t *) the instruction
    @param op: (C++: const op_t *) the operand
    @return: the offset in the frame
    """
    return _ida_frame.calc_frame_offset(pfn, off, insn, op)

def free_regvar(v: "regvar_t") -> "void":
    r"""
    free_regvar(v)

    @param v: regvar_t *
    """
    return _ida_frame.free_regvar(v)
class regvar_t(ida_range.range_t):
    r"""
    Proxy of C++ regvar_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    canon: "char *" = property(_ida_frame.regvar_t_canon_get, _ida_frame.regvar_t_canon_set, doc=r"""canon""")
    r"""
    canonical register name (case-insensitive)
    """
    user: "char *" = property(_ida_frame.regvar_t_user_get, _ida_frame.regvar_t_user_set, doc=r"""user""")
    r"""
    user-defined register name
    """
    cmt: "char *" = property(_ida_frame.regvar_t_cmt_get, _ida_frame.regvar_t_cmt_set, doc=r"""cmt""")
    r"""
    comment to appear near definition
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> regvar_t
        __init__(self, r) -> regvar_t

        @param r: regvar_t const &
        """
        _ida_frame.regvar_t_swiginit(self, _ida_frame.new_regvar_t(*args))
    __swig_destroy__ = _ida_frame.delete_regvar_t

    def swap(self, r: "regvar_t") -> "void":
        r"""
        swap(self, r)

        @param r: regvar_t &
        """
        return _ida_frame.regvar_t_swap(self, r)

# Register regvar_t in _ida_frame:
_ida_frame.regvar_t_swigregister(regvar_t)

def add_regvar(pfn: "func_t *", ea1: "ea_t", ea2: "ea_t", canon: "char const *", user: "char const *", cmt: "char const *") -> "int":
    r"""
    add_regvar(pfn, ea1, ea2, canon, user, cmt) -> int
    Define a register variable.

    @param pfn: (C++: func_t *) function in which the definition will be created
    @param ea1: (C++: ea_t) ,ea2: range of addresses within the function where the definition will
                    be used
    @param canon: (C++: const char *) name of a general register
    @param canon: (C++: const char *) name of a general register
    @param user: (C++: const char *) user-defined name for the register
    @param cmt: (C++: const char *) comment for the definition
    @return: Register variable error codes
    """
    return _ida_frame.add_regvar(pfn, ea1, ea2, canon, user, cmt)
REGVAR_ERROR_OK = _ida_frame.REGVAR_ERROR_OK
r"""
all ok
"""

REGVAR_ERROR_ARG = _ida_frame.REGVAR_ERROR_ARG
r"""
function arguments are bad
"""

REGVAR_ERROR_RANGE = _ida_frame.REGVAR_ERROR_RANGE
r"""
the definition range is bad
"""

REGVAR_ERROR_NAME = _ida_frame.REGVAR_ERROR_NAME
r"""
the provided name(s) can't be accepted
"""


def find_regvar(*args) -> "regvar_t *":
    r"""
    find_regvar(pfn, ea1, ea2, canon, user) -> regvar_t
    Find a register variable definition.

    @param pfn: (C++: func_t *) function in question
    @param ea1: ea_t
    @param canon: (C++: const char *) name of a general register
    @param canon: (C++: const char *) name of a general register
    @param user: char const *

    @return: nullptr-not found, otherwise ptr to regvar_t
    find_regvar(pfn, ea, canon) -> regvar_t

    @param pfn: func_t *
    @param ea: ea_t
    @param canon: char const *
    """
    return _ida_frame.find_regvar(*args)

def has_regvar(pfn: "func_t *", ea: "ea_t") -> "bool":
    r"""
    has_regvar(pfn, ea) -> bool
    Is there a register variable definition?

    @param pfn: (C++: func_t *) function in question
    @param ea: (C++: ea_t) current address
    """
    return _ida_frame.has_regvar(pfn, ea)

def rename_regvar(pfn: "func_t *", v: "regvar_t", user: "char const *") -> "int":
    r"""
    rename_regvar(pfn, v, user) -> int
    Rename a register variable.

    @param pfn: (C++: func_t *) function in question
    @param v: (C++: regvar_t *) variable to rename
    @param user: (C++: const char *) new user-defined name for the register
    @return: Register variable error codes
    """
    return _ida_frame.rename_regvar(pfn, v, user)

def set_regvar_cmt(pfn: "func_t *", v: "regvar_t", cmt: "char const *") -> "int":
    r"""
    set_regvar_cmt(pfn, v, cmt) -> int
    Set comment for a register variable.

    @param pfn: (C++: func_t *) function in question
    @param v: (C++: regvar_t *) variable to rename
    @param cmt: (C++: const char *) new comment
    @return: Register variable error codes
    """
    return _ida_frame.set_regvar_cmt(pfn, v, cmt)

def del_regvar(pfn: "func_t *", ea1: "ea_t", ea2: "ea_t", canon: "char const *") -> "int":
    r"""
    del_regvar(pfn, ea1, ea2, canon) -> int
    Delete a register variable definition.

    @param pfn: (C++: func_t *) function in question
    @param ea1: (C++: ea_t) ,ea2: range of addresses within the function where the definition
                    holds
    @param canon: (C++: const char *) name of a general register
    @param canon: (C++: const char *) name of a general register
    @return: Register variable error codes
    """
    return _ida_frame.del_regvar(pfn, ea1, ea2, canon)

def add_auto_stkpnt(pfn: "func_t *", ea: "ea_t", delta: "sval_t") -> "bool":
    r"""
    add_auto_stkpnt(pfn, ea, delta) -> bool
    Add automatic SP register change point.

    @param pfn: (C++: func_t *) pointer to the function. may be nullptr.
    @param ea: (C++: ea_t) linear address where SP changes. usually this is the end of the
               instruction which modifies the stack pointer ( insn_t::ea+
               insn_t::size)
    @param delta: (C++: sval_t) difference between old and new values of SP
    @return: success
    """
    return _ida_frame.add_auto_stkpnt(pfn, ea, delta)

def add_user_stkpnt(ea: "ea_t", delta: "sval_t") -> "bool":
    r"""
    add_user_stkpnt(ea, delta) -> bool
    Add user-defined SP register change point.

    @param ea: (C++: ea_t) linear address where SP changes
    @param delta: (C++: sval_t) difference between old and new values of SP
    @return: success
    """
    return _ida_frame.add_user_stkpnt(ea, delta)

def del_stkpnt(pfn: "func_t *", ea: "ea_t") -> "bool":
    r"""
    del_stkpnt(pfn, ea) -> bool
    Delete SP register change point.

    @param pfn: (C++: func_t *) pointer to the function. may be nullptr.
    @param ea: (C++: ea_t) linear address
    @return: success
    """
    return _ida_frame.del_stkpnt(pfn, ea)

def get_spd(pfn: "func_t *", ea: "ea_t") -> "sval_t":
    r"""
    get_spd(pfn, ea) -> sval_t
    Get difference between the initial and current values of ESP.

    @param pfn: (C++: func_t *) pointer to the function. may be nullptr.
    @param ea: (C++: ea_t) linear address of the instruction
    @return: 0 or the difference, usually a negative number. returns the sp-diff
             before executing the instruction.
    """
    return _ida_frame.get_spd(pfn, ea)

def get_effective_spd(pfn: "func_t *", ea: "ea_t") -> "sval_t":
    r"""
    get_effective_spd(pfn, ea) -> sval_t
    Get effective difference between the initial and current values of ESP. This
    function returns the sp-diff used by the instruction. The difference between
    get_spd() and get_effective_spd() is present only for instructions like "pop
    [esp+N]": they modify sp and use the modified value.

    @param pfn: (C++: func_t *) pointer to the function. may be nullptr.
    @param ea: (C++: ea_t) linear address
    @return: 0 or the difference, usually a negative number
    """
    return _ida_frame.get_effective_spd(pfn, ea)

def get_sp_delta(pfn: "func_t *", ea: "ea_t") -> "sval_t":
    r"""
    get_sp_delta(pfn, ea) -> sval_t
    Get modification of SP made at the specified location

    @param pfn: (C++: func_t *) pointer to the function. may be nullptr.
    @param ea: (C++: ea_t) linear address
    @return: 0 if the specified location doesn't contain a SP change point.
             otherwise return delta of SP modification.
    """
    return _ida_frame.get_sp_delta(pfn, ea)

def set_auto_spd(pfn: "func_t *", ea: "ea_t", new_spd: "sval_t") -> "bool":
    r"""
    set_auto_spd(pfn, ea, new_spd) -> bool
    Add such an automatic SP register change point so that at EA the new cumulative
    SP delta (that is, the difference between the initial and current values of SP)
    would be equal to NEW_SPD.

    @param pfn: (C++: func_t *) pointer to the function. may be nullptr.
    @param ea: (C++: ea_t) linear address of the instruction
    @param new_spd: (C++: sval_t) new value of the cumulative SP delta
    @return: success
    """
    return _ida_frame.set_auto_spd(pfn, ea, new_spd)

def recalc_spd(cur_ea: "ea_t") -> "bool":
    r"""
    recalc_spd(cur_ea) -> bool
    Recalculate SP delta for an instruction that stops execution. The next
    instruction is not reached from the current instruction. We need to recalculate
    SP for the next instruction.

    This function will create a new automatic SP register change point if necessary.
    It should be called from the emulator (emu.cpp) when auto_state == AU_USED if
    the current instruction doesn't pass the execution flow to the next instruction.

    @param cur_ea: (C++: ea_t) linear address of the current instruction
    @retval 1: new stkpnt is added
    @retval 0: nothing is changed
    """
    return _ida_frame.recalc_spd(cur_ea)

def recalc_spd_for_basic_block(pfn: "func_t *", cur_ea: "ea_t") -> "bool":
    r"""
    recalc_spd_for_basic_block(pfn, cur_ea) -> bool
    Recalculate SP delta for the current instruction. The typical code snippet to
    calculate SP delta in a proc module is:

    if ( may_trace_sp() && pfn != nullptr )
      if ( !recalc_spd_for_basic_block(pfn, insn.ea) )
        trace_sp(pfn, insn);

    where trace_sp() is a typical name for a function that emulates the SP change of
    an instruction.

    @param pfn: (C++: func_t *) pointer to the function
    @param cur_ea: (C++: ea_t) linear address of the current instruction
    @retval true: the cumulative SP delta is set
    @retval false: the instruction at CUR_EA passes flow to the next instruction. SP
                   delta must be set as a result of emulating the current
                   instruction.
    """
    return _ida_frame.recalc_spd_for_basic_block(pfn, cur_ea)
class xreflist_entry_t(object):
    r"""
    Proxy of C++ xreflist_entry_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ea: "ea_t" = property(_ida_frame.xreflist_entry_t_ea_get, _ida_frame.xreflist_entry_t_ea_set, doc=r"""ea""")
    r"""
    Location of the insn referencing the stack frame member.
    """
    opnum: "uchar" = property(_ida_frame.xreflist_entry_t_opnum_get, _ida_frame.xreflist_entry_t_opnum_set, doc=r"""opnum""")
    r"""
    Number of the operand of that instruction.
    """
    type: "uchar" = property(_ida_frame.xreflist_entry_t_type_get, _ida_frame.xreflist_entry_t_type_set, doc=r"""type""")
    r"""
    The type of xref (cref_t & dref_t)
    """

    def __eq__(self, r: "xreflist_entry_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: xreflist_entry_t const &
        """
        return _ida_frame.xreflist_entry_t___eq__(self, r)

    def __ne__(self, r: "xreflist_entry_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: xreflist_entry_t const &
        """
        return _ida_frame.xreflist_entry_t___ne__(self, r)

    def __lt__(self, r: "xreflist_entry_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: xreflist_entry_t const &
        """
        return _ida_frame.xreflist_entry_t___lt__(self, r)

    def __gt__(self, r: "xreflist_entry_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: xreflist_entry_t const &
        """
        return _ida_frame.xreflist_entry_t___gt__(self, r)

    def __le__(self, r: "xreflist_entry_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: xreflist_entry_t const &
        """
        return _ida_frame.xreflist_entry_t___le__(self, r)

    def __ge__(self, r: "xreflist_entry_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: xreflist_entry_t const &
        """
        return _ida_frame.xreflist_entry_t___ge__(self, r)

    def compare(self, r: "xreflist_entry_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: xreflist_entry_t const &
        """
        return _ida_frame.xreflist_entry_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> xreflist_entry_t
        """
        _ida_frame.xreflist_entry_t_swiginit(self, _ida_frame.new_xreflist_entry_t())
    __swig_destroy__ = _ida_frame.delete_xreflist_entry_t

# Register xreflist_entry_t in _ida_frame:
_ida_frame.xreflist_entry_t_swigregister(xreflist_entry_t)

def build_stkvar_xrefs(out: "xreflist_t", pfn: "func_t *", start_offset: "uval_t", end_offset: "uval_t") -> "void":
    r"""
    build_stkvar_xrefs(out, pfn, start_offset, end_offset)
    Fill 'out' with a list of all the xrefs made from function 'pfn' to specified
    range of the pfn's stack frame.

    @param out: (C++: xreflist_t *) the list of xrefs to fill.
    @param pfn: (C++: func_t *) the function to scan.
    @param start_offset: (C++: uval_t) start frame structure offset, in bytes
    @param end_offset: (C++: uval_t) end frame structure offset, in bytes
    """
    return _ida_frame.build_stkvar_xrefs(out, pfn, start_offset, end_offset)


