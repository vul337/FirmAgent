r"""
Definitions of various information kept in netnodes.

Each address in the program has a corresponding netnode: netnode(ea).

If we have no information about an address, the corresponding netnode is not
created. Otherwise we will create a netnode and save information in it. All
variable length information (names, comments, offset information, etc) is stored
in the netnode.

Don't forget that some information is already stored in the flags (bytes.hpp)

@warning: Many of the functions in this file are very low level (they are marked
          as low level functions). Use them only if you can't find higher level
          function to set/get/del information.netnode."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_nalt
else:
    import _ida_nalt

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

SWIG_PYTHON_LEGACY_BOOL = _ida_nalt.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

class custom_data_type_ids_fids_array(object):
    r"""
    Proxy of C++ wrapped_array_t< int16,8 > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    data: "short (&)[8]" = property(_ida_nalt.custom_data_type_ids_fids_array_data_get, doc=r"""data""")

    def __init__(self, data: "short (&)[8]"):
        r"""
        __init__(self, data) -> custom_data_type_ids_fids_array

        @param data: short (&)[8]
        """
        _ida_nalt.custom_data_type_ids_fids_array_swiginit(self, _ida_nalt.new_custom_data_type_ids_fids_array(data))

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_nalt.custom_data_type_ids_fids_array___len__(self)

    def __getitem__(self, i: "size_t") -> "short const &":
        r"""
        __getitem__(self, i) -> short const &

        @param i: size_t
        """
        return _ida_nalt.custom_data_type_ids_fids_array___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "short const &") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: short const &
        """
        return _ida_nalt.custom_data_type_ids_fids_array___setitem__(self, i, v)

    def _get_bytes(self) -> "bytevec_t":
        r"""_get_bytes(self) -> bytevec_t"""
        return _ida_nalt.custom_data_type_ids_fids_array__get_bytes(self)

    def _set_bytes(self, bts: "bytevec_t const &") -> "void":
        r"""
        _set_bytes(self, bts)

        Parameters
        ----------
        bts: bytevec_t const &

        """
        return _ida_nalt.custom_data_type_ids_fids_array__set_bytes(self, bts)

    __iter__ = ida_idaapi._bounded_getitem_iterator
    bytes = property(_get_bytes, _set_bytes)

    __swig_destroy__ = _ida_nalt.delete_custom_data_type_ids_fids_array

# Register custom_data_type_ids_fids_array in _ida_nalt:
_ida_nalt.custom_data_type_ids_fids_array_swigregister(custom_data_type_ids_fids_array)
class strpath_ids_array(object):
    r"""
    Proxy of C++ wrapped_array_t< tid_t,32 > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    data: "unsigned long long (&)[32]" = property(_ida_nalt.strpath_ids_array_data_get, doc=r"""data""")

    def __init__(self, data: "unsigned long long (&)[32]"):
        r"""
        __init__(self, data) -> strpath_ids_array

        @param data: unsigned long long (&)[32]
        """
        _ida_nalt.strpath_ids_array_swiginit(self, _ida_nalt.new_strpath_ids_array(data))

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_nalt.strpath_ids_array___len__(self)

    def __getitem__(self, i: "size_t") -> "unsigned long long const &":
        r"""
        __getitem__(self, i) -> unsigned long long const &

        @param i: size_t
        """
        return _ida_nalt.strpath_ids_array___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "unsigned long long const &") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: unsigned long long const &
        """
        return _ida_nalt.strpath_ids_array___setitem__(self, i, v)

    def _get_bytes(self) -> "bytevec_t":
        r"""_get_bytes(self) -> bytevec_t"""
        return _ida_nalt.strpath_ids_array__get_bytes(self)

    def _set_bytes(self, bts: "bytevec_t const &") -> "void":
        r"""
        _set_bytes(self, bts)

        Parameters
        ----------
        bts: bytevec_t const &

        """
        return _ida_nalt.strpath_ids_array__set_bytes(self, bts)

    __iter__ = ida_idaapi._bounded_getitem_iterator
    bytes = property(_get_bytes, _set_bytes)

    __swig_destroy__ = _ida_nalt.delete_strpath_ids_array

# Register strpath_ids_array in _ida_nalt:
_ida_nalt.strpath_ids_array_swigregister(strpath_ids_array)
NALT_SWITCH = _ida_nalt.NALT_SWITCH
r"""
switch idiom address (used at jump targets)
"""

NALT_STRUCT = _ida_nalt.NALT_STRUCT
r"""
struct id
"""

NALT_AFLAGS = _ida_nalt.NALT_AFLAGS
r"""
additional flags for an item
"""

NALT_LINNUM = _ida_nalt.NALT_LINNUM
r"""
source line number
"""

NALT_ABSBASE = _ida_nalt.NALT_ABSBASE
r"""
absolute segment location
"""

NALT_ENUM0 = _ida_nalt.NALT_ENUM0
r"""
enum id for the first operand
"""

NALT_ENUM1 = _ida_nalt.NALT_ENUM1
r"""
enum id for the second operand
"""

NALT_PURGE = _ida_nalt.NALT_PURGE
r"""
number of bytes purged from the stack when a function is called indirectly
"""

NALT_STRTYPE = _ida_nalt.NALT_STRTYPE
r"""
type of string item
"""

NALT_ALIGN = _ida_nalt.NALT_ALIGN
r"""
alignment value if the item is FF_ALIGN (should by equal to power of 2)
"""

NALT_COLOR = _ida_nalt.NALT_COLOR
r"""
instruction/data background color
"""

NSUP_CMT = _ida_nalt.NSUP_CMT
r"""
regular comment
"""

NSUP_REPCMT = _ida_nalt.NSUP_REPCMT
r"""
repeatable comment
"""

NSUP_FOP1 = _ida_nalt.NSUP_FOP1
r"""
forced operand 1
"""

NSUP_FOP2 = _ida_nalt.NSUP_FOP2
r"""
forced operand 2
"""

NSUP_JINFO = _ida_nalt.NSUP_JINFO
r"""
jump table info
"""

NSUP_ARRAY = _ida_nalt.NSUP_ARRAY
r"""
array parameters
"""

NSUP_OMFGRP = _ida_nalt.NSUP_OMFGRP
r"""
OMF: group of segments (not used anymore)
"""

NSUP_FOP3 = _ida_nalt.NSUP_FOP3
r"""
forced operand 3
"""

NSUP_SWITCH = _ida_nalt.NSUP_SWITCH
r"""
switch information
"""

NSUP_REF0 = _ida_nalt.NSUP_REF0
r"""
complex reference information for operand 1
"""

NSUP_REF1 = _ida_nalt.NSUP_REF1
r"""
complex reference information for operand 2
"""

NSUP_REF2 = _ida_nalt.NSUP_REF2
r"""
complex reference information for operand 3
"""

NSUP_OREF0 = _ida_nalt.NSUP_OREF0
r"""
outer complex reference information for operand 1
"""

NSUP_OREF1 = _ida_nalt.NSUP_OREF1
r"""
outer complex reference information for operand 2
"""

NSUP_OREF2 = _ida_nalt.NSUP_OREF2
r"""
outer complex reference information for operand 3
"""

NSUP_STROFF0 = _ida_nalt.NSUP_STROFF0
r"""
stroff: struct path for the first operand
"""

NSUP_STROFF1 = _ida_nalt.NSUP_STROFF1
r"""
stroff: struct path for the second operand
"""

NSUP_SEGTRANS = _ida_nalt.NSUP_SEGTRANS
r"""
segment translations
"""

NSUP_FOP4 = _ida_nalt.NSUP_FOP4
r"""
forced operand 4
"""

NSUP_FOP5 = _ida_nalt.NSUP_FOP5
r"""
forced operand 5
"""

NSUP_FOP6 = _ida_nalt.NSUP_FOP6
r"""
forced operand 6
"""

NSUP_REF3 = _ida_nalt.NSUP_REF3
r"""
complex reference information for operand 4
"""

NSUP_REF4 = _ida_nalt.NSUP_REF4
r"""
complex reference information for operand 5
"""

NSUP_REF5 = _ida_nalt.NSUP_REF5
r"""
complex reference information for operand 6
"""

NSUP_OREF3 = _ida_nalt.NSUP_OREF3
r"""
outer complex reference information for operand 4
"""

NSUP_OREF4 = _ida_nalt.NSUP_OREF4
r"""
outer complex reference information for operand 5
"""

NSUP_OREF5 = _ida_nalt.NSUP_OREF5
r"""
outer complex reference information for operand 6
"""

NSUP_XREFPOS = _ida_nalt.NSUP_XREFPOS
r"""
saved xref address and type in the xrefs window
"""

NSUP_CUSTDT = _ida_nalt.NSUP_CUSTDT
r"""
custom data type id
"""

NSUP_GROUPS = _ida_nalt.NSUP_GROUPS
r"""
SEG_GRP: pack_dd encoded list of selectors.
"""

NSUP_ARGEAS = _ida_nalt.NSUP_ARGEAS
r"""
instructions that initialize call arguments
"""

NSUP_FOP7 = _ida_nalt.NSUP_FOP7
r"""
forced operand 7
"""

NSUP_FOP8 = _ida_nalt.NSUP_FOP8
r"""
forced operand 8
"""

NSUP_REF6 = _ida_nalt.NSUP_REF6
r"""
complex reference information for operand 7
"""

NSUP_REF7 = _ida_nalt.NSUP_REF7
r"""
complex reference information for operand 8
"""

NSUP_OREF6 = _ida_nalt.NSUP_OREF6
r"""
outer complex reference information for operand 7
"""

NSUP_OREF7 = _ida_nalt.NSUP_OREF7
r"""
outer complex reference information for operand 8
"""

NSUP_EX_FLAGS = _ida_nalt.NSUP_EX_FLAGS
r"""
Extended flags.
"""

NSUP_POINTS = _ida_nalt.NSUP_POINTS
r"""
SP change points blob (see funcs.cpp). values NSUP_POINTS..NSUP_POINTS+0x1000
are reserved
"""

NSUP_MANUAL = _ida_nalt.NSUP_MANUAL
r"""
manual instruction. values NSUP_MANUAL..NSUP_MANUAL+0x1000 are reserved
"""

NSUP_TYPEINFO = _ida_nalt.NSUP_TYPEINFO
r"""
type information. values NSUP_TYPEINFO..NSUP_TYPEINFO+0x1000 are reserved
"""

NSUP_REGVAR = _ida_nalt.NSUP_REGVAR
r"""
register variables. values NSUP_REGVAR..NSUP_REGVAR+0x1000 are reserved
"""

NSUP_LLABEL = _ida_nalt.NSUP_LLABEL
r"""
local labels. values NSUP_LLABEL..NSUP_LLABEL+0x1000 are reserved
"""

NSUP_REGARG = _ida_nalt.NSUP_REGARG
r"""
register argument type/name descriptions values NSUP_REGARG..NSUP_REGARG+0x1000
are reserved
"""

NSUP_FTAILS = _ida_nalt.NSUP_FTAILS
r"""
function tails or tail referers values NSUP_FTAILS..NSUP_FTAILS+0x1000 are
reserved
"""

NSUP_GROUP = _ida_nalt.NSUP_GROUP
r"""
graph group information values NSUP_GROUP..NSUP_GROUP+0x1000 are reserved
"""

NSUP_OPTYPES = _ida_nalt.NSUP_OPTYPES
r"""
operand type information. values NSUP_OPTYPES..NSUP_OPTYPES+0x100000 are
reserved
"""

NSUP_ORIGFMD = _ida_nalt.NSUP_ORIGFMD
r"""
function metadata before lumina information was applied values
NSUP_ORIGFMD..NSUP_ORIGFMD+0x1000 are reserved
"""

NSUP_FRAME = _ida_nalt.NSUP_FRAME
r"""
function frame type values NSUP_FRAME..NSUP_FRAME+0x10000 are reserved
"""

NALT_CREF_TO = _ida_nalt.NALT_CREF_TO
r"""
code xref to, idx: target address
"""

NALT_CREF_FROM = _ida_nalt.NALT_CREF_FROM
r"""
code xref from, idx: source address
"""

NALT_DREF_TO = _ida_nalt.NALT_DREF_TO
r"""
data xref to, idx: target address
"""

NALT_DREF_FROM = _ida_nalt.NALT_DREF_FROM
r"""
data xref from, idx: source address
"""

NSUP_GR_INFO = _ida_nalt.NSUP_GR_INFO
r"""
group node info: color, ea, text
"""

NALT_GR_LAYX = _ida_nalt.NALT_GR_LAYX
r"""
group layout ptrs, hash: md5 of 'belongs'
"""

NSUP_GR_LAYT = _ida_nalt.NSUP_GR_LAYT
r"""
group layouts, idx: layout pointer
"""

PATCH_TAG = _ida_nalt.PATCH_TAG
r"""
Patch netnode tag.
"""

IDB_DESKTOPS_NODE_NAME = _ida_nalt.IDB_DESKTOPS_NODE_NAME
r"""
hash indexed by desktop name with dekstop netnode
"""

IDB_DESKTOPS_TAG = _ida_nalt.IDB_DESKTOPS_TAG
r"""
tag to store desktop blob & timestamp
"""


def ea2node(ea: "ea_t") -> "nodeidx_t":
    r"""
    ea2node(ea) -> nodeidx_t
    Get netnode for the specified address.

    @param ea: (C++: ea_t)
    """
    return _ida_nalt.ea2node(ea)

def node2ea(ndx: "nodeidx_t") -> "ea_t":
    r"""
    node2ea(ndx) -> ea_t

    @param ndx: nodeidx_t
    """
    return _ida_nalt.node2ea(ndx)

def end_ea2node(ea: "ea_t") -> "nodeidx_t":
    r"""
    end_ea2node(ea) -> nodeidx_t

    @param ea: ea_t
    """
    return _ida_nalt.end_ea2node(ea)

def getnode(ea: "ea_t") -> "netnode":
    r"""
    getnode(ea) -> netnode

    @param ea: ea_t
    """
    return _ida_nalt.getnode(ea)

def get_strid(ea: "ea_t") -> "tid_t":
    r"""
    get_strid(ea) -> tid_t

    @param ea: ea_t
    """
    return _ida_nalt.get_strid(ea)
AFL_LINNUM = _ida_nalt.AFL_LINNUM
r"""
has line number info
"""

AFL_USERSP = _ida_nalt.AFL_USERSP
r"""
user-defined SP value
"""

AFL_PUBNAM = _ida_nalt.AFL_PUBNAM
r"""
name is public (inter-file linkage)
"""

AFL_WEAKNAM = _ida_nalt.AFL_WEAKNAM
r"""
name is weak
"""

AFL_HIDDEN = _ida_nalt.AFL_HIDDEN
r"""
the item is hidden completely
"""

AFL_MANUAL = _ida_nalt.AFL_MANUAL
r"""
the instruction/data is specified by the user
"""

AFL_NOBRD = _ida_nalt.AFL_NOBRD
r"""
the code/data border is hidden
"""

AFL_ZSTROFF = _ida_nalt.AFL_ZSTROFF
r"""
display struct field name at 0 offset when displaying an offset. example:
offset somestruct.field_0  if this flag is clear, then
offset somestruct
"""

AFL_BNOT0 = _ida_nalt.AFL_BNOT0
r"""
the 1st operand is bitwise negated
"""

AFL_BNOT1 = _ida_nalt.AFL_BNOT1
r"""
the 2nd operand is bitwise negated
"""

AFL_LIB = _ida_nalt.AFL_LIB
r"""
item from the standard library. low level flag, is used to set FUNC_LIB of
func_t
"""

AFL_TI = _ida_nalt.AFL_TI
r"""
has typeinfo? (NSUP_TYPEINFO); used only for addresses, not for member_t
"""

AFL_TI0 = _ida_nalt.AFL_TI0
r"""
has typeinfo for operand 0? (NSUP_OPTYPES)
"""

AFL_TI1 = _ida_nalt.AFL_TI1
r"""
has typeinfo for operand 1? (NSUP_OPTYPES+1)
"""

AFL_LNAME = _ida_nalt.AFL_LNAME
r"""
has local name too (FF_NAME should be set)
"""

AFL_TILCMT = _ida_nalt.AFL_TILCMT
r"""
has type comment? (such a comment may be changed by IDA)
"""

AFL_LZERO0 = _ida_nalt.AFL_LZERO0
r"""
toggle leading zeroes for the 1st operand
"""

AFL_LZERO1 = _ida_nalt.AFL_LZERO1
r"""
toggle leading zeroes for the 2nd operand
"""

AFL_COLORED = _ida_nalt.AFL_COLORED
r"""
has user defined instruction color?
"""

AFL_TERSESTR = _ida_nalt.AFL_TERSESTR
r"""
terse structure variable display?
"""

AFL_SIGN0 = _ida_nalt.AFL_SIGN0
r"""
code: toggle sign of the 1st operand
"""

AFL_SIGN1 = _ida_nalt.AFL_SIGN1
r"""
code: toggle sign of the 2nd operand
"""

AFL_NORET = _ida_nalt.AFL_NORET
r"""
for imported function pointers: doesn't return. this flag can also be used for
any instruction which halts or finishes the program execution
"""

AFL_FIXEDSPD = _ida_nalt.AFL_FIXEDSPD
r"""
sp delta value is fixed by analysis. should not be modified by modules
"""

AFL_ALIGNFLOW = _ida_nalt.AFL_ALIGNFLOW
r"""
the previous insn was created for alignment purposes only
"""

AFL_USERTI = _ida_nalt.AFL_USERTI
r"""
the type information is definitive. (comes from the user or type library) if not
set see AFL_TYPE_GUESSED
"""

AFL_RETFP = _ida_nalt.AFL_RETFP
r"""
function returns a floating point value
"""

AFL_USEMODSP = _ida_nalt.AFL_USEMODSP
r"""
insn modifes SP and uses the modified value; example: pop [rsp+N]
"""

AFL_NOTCODE = _ida_nalt.AFL_NOTCODE
r"""
autoanalysis should not create code here
"""

AFL_NOTPROC = _ida_nalt.AFL_NOTPROC
r"""
autoanalysis should not create proc here
"""

AFL_TYPE_GUESSED = _ida_nalt.AFL_TYPE_GUESSED
r"""
who guessed the type information?
"""

AFL_IDA_GUESSED = _ida_nalt.AFL_IDA_GUESSED
r"""
the type is guessed by IDA
"""

AFL_HR_GUESSED_FUNC = _ida_nalt.AFL_HR_GUESSED_FUNC
r"""
the function type is guessed by the decompiler
"""

AFL_HR_GUESSED_DATA = _ida_nalt.AFL_HR_GUESSED_DATA
r"""
the data type is guessed by the decompiler
"""

AFL_HR_DETERMINED = _ida_nalt.AFL_HR_DETERMINED
r"""
the type is definitely guessed by the decompiler
"""


def set_aflags(ea: "ea_t", flags: "aflags_t") -> "void":
    r"""
    set_aflags(ea, flags)

    @param ea: ea_t
    @param flags: aflags_t
    """
    return _ida_nalt.set_aflags(ea, flags)

def upd_abits(ea: "ea_t", clr_bits: "aflags_t", set_bits: "aflags_t") -> "void":
    r"""
    upd_abits(ea, clr_bits, set_bits)

    @param ea: ea_t
    @param clr_bits: aflags_t
    @param set_bits: aflags_t
    """
    return _ida_nalt.upd_abits(ea, clr_bits, set_bits)

def set_abits(ea: "ea_t", bits: "aflags_t") -> "void":
    r"""
    set_abits(ea, bits)

    @param ea: ea_t
    @param bits: aflags_t
    """
    return _ida_nalt.set_abits(ea, bits)

def clr_abits(ea: "ea_t", bits: "aflags_t") -> "void":
    r"""
    clr_abits(ea, bits)

    @param ea: ea_t
    @param bits: aflags_t
    """
    return _ida_nalt.clr_abits(ea, bits)

def get_aflags(ea: "ea_t") -> "aflags_t":
    r"""
    get_aflags(ea) -> aflags_t

    @param ea: ea_t
    """
    return _ida_nalt.get_aflags(ea)

def del_aflags(ea: "ea_t") -> "void":
    r"""
    del_aflags(ea)

    @param ea: ea_t
    """
    return _ida_nalt.del_aflags(ea)

def has_aflag_linnum(flags: "aflags_t") -> "bool":
    r"""
    has_aflag_linnum(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.has_aflag_linnum(flags)

def is_aflag_usersp(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_usersp(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_usersp(flags)

def is_aflag_public_name(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_public_name(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_public_name(flags)

def is_aflag_weak_name(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_weak_name(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_weak_name(flags)

def is_aflag_hidden_item(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_hidden_item(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_hidden_item(flags)

def is_aflag_manual_insn(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_manual_insn(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_manual_insn(flags)

def is_aflag_hidden_border(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_hidden_border(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_hidden_border(flags)

def is_aflag_zstroff(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_zstroff(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_zstroff(flags)

def is_aflag__bnot0(flags: "aflags_t") -> "bool":
    r"""
    is_aflag__bnot0(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag__bnot0(flags)

def is_aflag__bnot1(flags: "aflags_t") -> "bool":
    r"""
    is_aflag__bnot1(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag__bnot1(flags)

def is_aflag_libitem(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_libitem(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_libitem(flags)

def has_aflag_ti(flags: "aflags_t") -> "bool":
    r"""
    has_aflag_ti(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.has_aflag_ti(flags)

def has_aflag_ti0(flags: "aflags_t") -> "bool":
    r"""
    has_aflag_ti0(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.has_aflag_ti0(flags)

def has_aflag_ti1(flags: "aflags_t") -> "bool":
    r"""
    has_aflag_ti1(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.has_aflag_ti1(flags)

def has_aflag_lname(flags: "aflags_t") -> "bool":
    r"""
    has_aflag_lname(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.has_aflag_lname(flags)

def is_aflag_tilcmt(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_tilcmt(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_tilcmt(flags)

def is_aflag_lzero0(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_lzero0(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_lzero0(flags)

def is_aflag_lzero1(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_lzero1(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_lzero1(flags)

def is_aflag_colored_item(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_colored_item(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_colored_item(flags)

def is_aflag_terse_struc(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_terse_struc(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_terse_struc(flags)

def is_aflag__invsign0(flags: "aflags_t") -> "bool":
    r"""
    is_aflag__invsign0(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag__invsign0(flags)

def is_aflag__invsign1(flags: "aflags_t") -> "bool":
    r"""
    is_aflag__invsign1(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag__invsign1(flags)

def is_aflag_noret(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_noret(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_noret(flags)

def is_aflag_fixed_spd(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_fixed_spd(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_fixed_spd(flags)

def is_aflag_align_flow(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_align_flow(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_align_flow(flags)

def is_aflag_userti(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_userti(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_userti(flags)

def is_aflag_retfp(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_retfp(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_retfp(flags)

def uses_aflag_modsp(flags: "aflags_t") -> "bool":
    r"""
    uses_aflag_modsp(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.uses_aflag_modsp(flags)

def is_aflag_notcode(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_notcode(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_notcode(flags)

def is_aflag_notproc(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_notproc(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_notproc(flags)

def is_aflag_type_guessed_by_ida(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_type_guessed_by_ida(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_type_guessed_by_ida(flags)

def is_aflag_func_guessed_by_hexrays(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_func_guessed_by_hexrays(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_func_guessed_by_hexrays(flags)

def is_aflag_data_guessed_by_hexrays(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_data_guessed_by_hexrays(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_data_guessed_by_hexrays(flags)

def is_aflag_type_determined_by_hexrays(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_type_determined_by_hexrays(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_type_determined_by_hexrays(flags)

def is_aflag_type_guessed_by_hexrays(flags: "aflags_t") -> "bool":
    r"""
    is_aflag_type_guessed_by_hexrays(flags) -> bool

    @param flags: aflags_t
    """
    return _ida_nalt.is_aflag_type_guessed_by_hexrays(flags)

def is_hidden_item(ea: "ea_t") -> "bool":
    r"""
    is_hidden_item(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_hidden_item(ea)

def hide_item(ea: "ea_t") -> "void":
    r"""
    hide_item(ea)

    @param ea: ea_t
    """
    return _ida_nalt.hide_item(ea)

def unhide_item(ea: "ea_t") -> "void":
    r"""
    unhide_item(ea)

    @param ea: ea_t
    """
    return _ida_nalt.unhide_item(ea)

def is_hidden_border(ea: "ea_t") -> "bool":
    r"""
    is_hidden_border(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_hidden_border(ea)

def hide_border(ea: "ea_t") -> "void":
    r"""
    hide_border(ea)

    @param ea: ea_t
    """
    return _ida_nalt.hide_border(ea)

def unhide_border(ea: "ea_t") -> "void":
    r"""
    unhide_border(ea)

    @param ea: ea_t
    """
    return _ida_nalt.unhide_border(ea)

def uses_modsp(ea: "ea_t") -> "bool":
    r"""
    uses_modsp(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.uses_modsp(ea)

def set_usemodsp(ea: "ea_t") -> "void":
    r"""
    set_usemodsp(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_usemodsp(ea)

def clr_usemodsp(ea: "ea_t") -> "void":
    r"""
    clr_usemodsp(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_usemodsp(ea)

def is_zstroff(ea: "ea_t") -> "bool":
    r"""
    is_zstroff(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_zstroff(ea)

def set_zstroff(ea: "ea_t") -> "void":
    r"""
    set_zstroff(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_zstroff(ea)

def clr_zstroff(ea: "ea_t") -> "void":
    r"""
    clr_zstroff(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_zstroff(ea)

def is__bnot0(ea: "ea_t") -> "bool":
    r"""
    is__bnot0(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is__bnot0(ea)

def set__bnot0(ea: "ea_t") -> "void":
    r"""
    set__bnot0(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set__bnot0(ea)

def clr__bnot0(ea: "ea_t") -> "void":
    r"""
    clr__bnot0(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr__bnot0(ea)

def is__bnot1(ea: "ea_t") -> "bool":
    r"""
    is__bnot1(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is__bnot1(ea)

def set__bnot1(ea: "ea_t") -> "void":
    r"""
    set__bnot1(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set__bnot1(ea)

def clr__bnot1(ea: "ea_t") -> "void":
    r"""
    clr__bnot1(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr__bnot1(ea)

def is_libitem(ea: "ea_t") -> "bool":
    r"""
    is_libitem(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_libitem(ea)

def set_libitem(ea: "ea_t") -> "void":
    r"""
    set_libitem(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_libitem(ea)

def clr_libitem(ea: "ea_t") -> "void":
    r"""
    clr_libitem(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_libitem(ea)

def has_ti(ea: "ea_t") -> "bool":
    r"""
    has_ti(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.has_ti(ea)

def set_has_ti(ea: "ea_t") -> "void":
    r"""
    set_has_ti(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_has_ti(ea)

def clr_has_ti(ea: "ea_t") -> "void":
    r"""
    clr_has_ti(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_has_ti(ea)

def has_ti0(ea: "ea_t") -> "bool":
    r"""
    has_ti0(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.has_ti0(ea)

def set_has_ti0(ea: "ea_t") -> "void":
    r"""
    set_has_ti0(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_has_ti0(ea)

def clr_has_ti0(ea: "ea_t") -> "void":
    r"""
    clr_has_ti0(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_has_ti0(ea)

def has_ti1(ea: "ea_t") -> "bool":
    r"""
    has_ti1(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.has_ti1(ea)

def set_has_ti1(ea: "ea_t") -> "void":
    r"""
    set_has_ti1(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_has_ti1(ea)

def clr_has_ti1(ea: "ea_t") -> "void":
    r"""
    clr_has_ti1(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_has_ti1(ea)

def has_lname(ea: "ea_t") -> "bool":
    r"""
    has_lname(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.has_lname(ea)

def set_has_lname(ea: "ea_t") -> "void":
    r"""
    set_has_lname(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_has_lname(ea)

def clr_has_lname(ea: "ea_t") -> "void":
    r"""
    clr_has_lname(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_has_lname(ea)

def is_tilcmt(ea: "ea_t") -> "bool":
    r"""
    is_tilcmt(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_tilcmt(ea)

def set_tilcmt(ea: "ea_t") -> "void":
    r"""
    set_tilcmt(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_tilcmt(ea)

def clr_tilcmt(ea: "ea_t") -> "void":
    r"""
    clr_tilcmt(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_tilcmt(ea)

def is_usersp(ea: "ea_t") -> "bool":
    r"""
    is_usersp(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_usersp(ea)

def set_usersp(ea: "ea_t") -> "void":
    r"""
    set_usersp(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_usersp(ea)

def clr_usersp(ea: "ea_t") -> "void":
    r"""
    clr_usersp(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_usersp(ea)

def is_lzero0(ea: "ea_t") -> "bool":
    r"""
    is_lzero0(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_lzero0(ea)

def set_lzero0(ea: "ea_t") -> "void":
    r"""
    set_lzero0(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_lzero0(ea)

def clr_lzero0(ea: "ea_t") -> "void":
    r"""
    clr_lzero0(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_lzero0(ea)

def is_lzero1(ea: "ea_t") -> "bool":
    r"""
    is_lzero1(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_lzero1(ea)

def set_lzero1(ea: "ea_t") -> "void":
    r"""
    set_lzero1(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_lzero1(ea)

def clr_lzero1(ea: "ea_t") -> "void":
    r"""
    clr_lzero1(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_lzero1(ea)

def is_colored_item(ea: "ea_t") -> "bool":
    r"""
    is_colored_item(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_colored_item(ea)

def set_colored_item(ea: "ea_t") -> "void":
    r"""
    set_colored_item(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_colored_item(ea)

def clr_colored_item(ea: "ea_t") -> "void":
    r"""
    clr_colored_item(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_colored_item(ea)

def is_terse_struc(ea: "ea_t") -> "bool":
    r"""
    is_terse_struc(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_terse_struc(ea)

def set_terse_struc(ea: "ea_t") -> "void":
    r"""
    set_terse_struc(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_terse_struc(ea)

def clr_terse_struc(ea: "ea_t") -> "void":
    r"""
    clr_terse_struc(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_terse_struc(ea)

def is__invsign0(ea: "ea_t") -> "bool":
    r"""
    is__invsign0(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is__invsign0(ea)

def set__invsign0(ea: "ea_t") -> "void":
    r"""
    set__invsign0(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set__invsign0(ea)

def clr__invsign0(ea: "ea_t") -> "void":
    r"""
    clr__invsign0(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr__invsign0(ea)

def is__invsign1(ea: "ea_t") -> "bool":
    r"""
    is__invsign1(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is__invsign1(ea)

def set__invsign1(ea: "ea_t") -> "void":
    r"""
    set__invsign1(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set__invsign1(ea)

def clr__invsign1(ea: "ea_t") -> "void":
    r"""
    clr__invsign1(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr__invsign1(ea)

def is_noret(ea: "ea_t") -> "bool":
    r"""
    is_noret(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_noret(ea)

def set_noret(ea: "ea_t") -> "void":
    r"""
    set_noret(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_noret(ea)

def clr_noret(ea: "ea_t") -> "void":
    r"""
    clr_noret(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_noret(ea)

def is_fixed_spd(ea: "ea_t") -> "bool":
    r"""
    is_fixed_spd(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_fixed_spd(ea)

def set_fixed_spd(ea: "ea_t") -> "void":
    r"""
    set_fixed_spd(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_fixed_spd(ea)

def clr_fixed_spd(ea: "ea_t") -> "void":
    r"""
    clr_fixed_spd(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_fixed_spd(ea)

def is_align_flow(ea: "ea_t") -> "bool":
    r"""
    is_align_flow(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_align_flow(ea)

def set_align_flow(ea: "ea_t") -> "void":
    r"""
    set_align_flow(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_align_flow(ea)

def clr_align_flow(ea: "ea_t") -> "void":
    r"""
    clr_align_flow(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_align_flow(ea)

def is_userti(ea: "ea_t") -> "bool":
    r"""
    is_userti(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_userti(ea)

def set_userti(ea: "ea_t") -> "void":
    r"""
    set_userti(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_userti(ea)

def clr_userti(ea: "ea_t") -> "void":
    r"""
    clr_userti(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_userti(ea)

def is_retfp(ea: "ea_t") -> "bool":
    r"""
    is_retfp(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_retfp(ea)

def set_retfp(ea: "ea_t") -> "void":
    r"""
    set_retfp(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_retfp(ea)

def clr_retfp(ea: "ea_t") -> "void":
    r"""
    clr_retfp(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_retfp(ea)

def is_notproc(ea: "ea_t") -> "bool":
    r"""
    is_notproc(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_notproc(ea)

def set_notproc(ea: "ea_t") -> "void":
    r"""
    set_notproc(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_notproc(ea)

def clr_notproc(ea: "ea_t") -> "void":
    r"""
    clr_notproc(ea)

    @param ea: ea_t
    """
    return _ida_nalt.clr_notproc(ea)

def is_type_guessed_by_ida(ea: "ea_t") -> "bool":
    r"""
    is_type_guessed_by_ida(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_type_guessed_by_ida(ea)

def is_func_guessed_by_hexrays(ea: "ea_t") -> "bool":
    r"""
    is_func_guessed_by_hexrays(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_func_guessed_by_hexrays(ea)

def is_data_guessed_by_hexrays(ea: "ea_t") -> "bool":
    r"""
    is_data_guessed_by_hexrays(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_data_guessed_by_hexrays(ea)

def is_type_determined_by_hexrays(ea: "ea_t") -> "bool":
    r"""
    is_type_determined_by_hexrays(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_type_determined_by_hexrays(ea)

def is_type_guessed_by_hexrays(ea: "ea_t") -> "bool":
    r"""
    is_type_guessed_by_hexrays(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.is_type_guessed_by_hexrays(ea)

def set_type_guessed_by_ida(ea: "ea_t") -> "void":
    r"""
    set_type_guessed_by_ida(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_type_guessed_by_ida(ea)

def set_func_guessed_by_hexrays(ea: "ea_t") -> "void":
    r"""
    set_func_guessed_by_hexrays(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_func_guessed_by_hexrays(ea)

def set_data_guessed_by_hexrays(ea: "ea_t") -> "void":
    r"""
    set_data_guessed_by_hexrays(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_data_guessed_by_hexrays(ea)

def set_type_determined_by_hexrays(ea: "ea_t") -> "void":
    r"""
    set_type_determined_by_hexrays(ea)

    @param ea: ea_t
    """
    return _ida_nalt.set_type_determined_by_hexrays(ea)

def set_notcode(ea: "ea_t") -> "void":
    r"""
    set_notcode(ea)
    Mark address so that it cannot be converted to instruction.

    @param ea: (C++: ea_t)
    """
    return _ida_nalt.set_notcode(ea)

def clr_notcode(ea: "ea_t") -> "void":
    r"""
    clr_notcode(ea)
    Clear not-code mark.

    @param ea: (C++: ea_t)
    """
    return _ida_nalt.clr_notcode(ea)

def is_notcode(ea: "ea_t") -> "bool":
    r"""
    is_notcode(ea) -> bool
    Is the address marked as not-code?

    @param ea: (C++: ea_t)
    """
    return _ida_nalt.is_notcode(ea)

def set_visible_item(ea: "ea_t", visible: "bool") -> "void":
    r"""
    set_visible_item(ea, visible)
    Change visibility of item at given ea.

    @param ea: (C++: ea_t)
    @param visible: (C++: bool)
    """
    return _ida_nalt.set_visible_item(ea, visible)

def is_visible_item(ea: "ea_t") -> "bool":
    r"""
    is_visible_item(ea) -> bool
    Test visibility of item at given ea.

    @param ea: (C++: ea_t)
    """
    return _ida_nalt.is_visible_item(ea)

def is_finally_visible_item(ea: "ea_t") -> "bool":
    r"""
    is_finally_visible_item(ea) -> bool
    Is instruction visible?

    @param ea: (C++: ea_t)
    """
    return _ida_nalt.is_finally_visible_item(ea)

def set_source_linnum(ea: "ea_t", lnnum: "uval_t") -> "void":
    r"""
    set_source_linnum(ea, lnnum)

    @param ea: ea_t
    @param lnnum: uval_t
    """
    return _ida_nalt.set_source_linnum(ea, lnnum)

def get_source_linnum(ea: "ea_t") -> "uval_t":
    r"""
    get_source_linnum(ea) -> uval_t

    @param ea: ea_t
    """
    return _ida_nalt.get_source_linnum(ea)

def del_source_linnum(ea: "ea_t") -> "void":
    r"""
    del_source_linnum(ea)

    @param ea: ea_t
    """
    return _ida_nalt.del_source_linnum(ea)

def get_absbase(ea: "ea_t") -> "ea_t":
    r"""
    get_absbase(ea) -> ea_t

    @param ea: ea_t
    """
    return _ida_nalt.get_absbase(ea)

def set_absbase(ea: "ea_t", x: "ea_t") -> "void":
    r"""
    set_absbase(ea, x)

    @param ea: ea_t
    @param x: ea_t
    """
    return _ida_nalt.set_absbase(ea, x)

def del_absbase(ea: "ea_t") -> "void":
    r"""
    del_absbase(ea)

    @param ea: ea_t
    """
    return _ida_nalt.del_absbase(ea)

def get_ind_purged(ea: "ea_t") -> "ea_t":
    r"""
    get_ind_purged(ea) -> ea_t

    @param ea: ea_t
    """
    return _ida_nalt.get_ind_purged(ea)

def del_ind_purged(ea: "ea_t") -> "void":
    r"""
    del_ind_purged(ea)

    @param ea: ea_t
    """
    return _ida_nalt.del_ind_purged(ea)

def get_str_type(ea: "ea_t") -> "uint32":
    r"""
    get_str_type(ea) -> uint32

    @param ea: ea_t
    """
    return _ida_nalt.get_str_type(ea)

def set_str_type(ea: "ea_t", x: "uint32") -> "void":
    r"""
    set_str_type(ea, x)

    @param ea: ea_t
    @param x: uint32
    """
    return _ida_nalt.set_str_type(ea, x)

def del_str_type(ea: "ea_t") -> "void":
    r"""
    del_str_type(ea)

    @param ea: ea_t
    """
    return _ida_nalt.del_str_type(ea)
STRWIDTH_1B = _ida_nalt.STRWIDTH_1B

STRWIDTH_2B = _ida_nalt.STRWIDTH_2B

STRWIDTH_4B = _ida_nalt.STRWIDTH_4B

STRWIDTH_MASK = _ida_nalt.STRWIDTH_MASK

STRLYT_TERMCHR = _ida_nalt.STRLYT_TERMCHR

STRLYT_PASCAL1 = _ida_nalt.STRLYT_PASCAL1

STRLYT_PASCAL2 = _ida_nalt.STRLYT_PASCAL2

STRLYT_PASCAL4 = _ida_nalt.STRLYT_PASCAL4

STRLYT_MASK = _ida_nalt.STRLYT_MASK

STRLYT_SHIFT = _ida_nalt.STRLYT_SHIFT

STRTYPE_TERMCHR = _ida_nalt.STRTYPE_TERMCHR
r"""
C-style string.
"""

STRTYPE_C = _ida_nalt.STRTYPE_C
r"""
Zero-terminated 16bit chars.
"""

STRTYPE_C_16 = _ida_nalt.STRTYPE_C_16
r"""
Zero-terminated 32bit chars.
"""

STRTYPE_C_32 = _ida_nalt.STRTYPE_C_32
r"""
Pascal-style, one-byte length prefix.
"""

STRTYPE_PASCAL = _ida_nalt.STRTYPE_PASCAL
r"""
Pascal-style, 16bit chars, one-byte length prefix.
"""

STRTYPE_PASCAL_16 = _ida_nalt.STRTYPE_PASCAL_16
r"""
Pascal-style, 32bit chars, one-byte length prefix.
"""

STRTYPE_PASCAL_32 = _ida_nalt.STRTYPE_PASCAL_32
r"""
Pascal-style, two-byte length prefix.
"""

STRTYPE_LEN2 = _ida_nalt.STRTYPE_LEN2
r"""
Pascal-style, 16bit chars, two-byte length prefix.
"""

STRTYPE_LEN2_16 = _ida_nalt.STRTYPE_LEN2_16
r"""
Pascal-style, 32bit chars, two-byte length prefix.
"""

STRTYPE_LEN2_32 = _ida_nalt.STRTYPE_LEN2_32
r"""
Pascal-style, four-byte length prefix.
"""

STRTYPE_LEN4 = _ida_nalt.STRTYPE_LEN4
r"""
Pascal-style, 16bit chars, four-byte length prefix.
"""

STRTYPE_LEN4_16 = _ida_nalt.STRTYPE_LEN4_16
r"""
Pascal-style, 32bit chars, four-byte length prefix.
"""

STRTYPE_LEN4_32 = _ida_nalt.STRTYPE_LEN4_32


def get_str_type_code(strtype: "int32") -> "uchar":
    r"""
    get_str_type_code(strtype) -> uchar

    @param strtype: int32
    """
    return _ida_nalt.get_str_type_code(strtype)

def get_str_term1(strtype: "int32") -> "char":
    r"""
    get_str_term1(strtype) -> char

    @param strtype: int32
    """
    return _ida_nalt.get_str_term1(strtype)

def get_str_term2(strtype: "int32") -> "char":
    r"""
    get_str_term2(strtype) -> char

    @param strtype: int32
    """
    return _ida_nalt.get_str_term2(strtype)

def get_str_encoding_idx(strtype: "int32") -> "uchar":
    r"""
    get_str_encoding_idx(strtype) -> uchar
    Get index of the string encoding for this string.

    @param strtype: (C++: int32)
    """
    return _ida_nalt.get_str_encoding_idx(strtype)

def set_str_encoding_idx(strtype: "int32", encoding_idx: "int") -> "int32":
    r"""
    set_str_encoding_idx(strtype, encoding_idx) -> int32
    Set index of the string encoding in the string type.

    @param strtype: (C++: int32)
    @param encoding_idx: (C++: int)
    """
    return _ida_nalt.set_str_encoding_idx(strtype, encoding_idx)

def make_str_type(type_code: "uchar", encoding_idx: "int", term1: "uchar"=0, term2: "uchar"=0) -> "int32":
    r"""
    make_str_type(type_code, encoding_idx, term1=0, term2=0) -> int32
    Get string type for a string in the given encoding.

    @param type_code: (C++: uchar)
    @param encoding_idx: (C++: int)
    @param term1: (C++: uchar)
    @param term2: (C++: uchar)
    """
    return _ida_nalt.make_str_type(type_code, encoding_idx, term1, term2)

def is_pascal(strtype: "int32") -> "bool":
    r"""
    is_pascal(strtype) -> bool

    @param strtype: int32
    """
    return _ida_nalt.is_pascal(strtype)

def get_str_type_prefix_length(strtype: "int32") -> "size_t":
    r"""
    get_str_type_prefix_length(strtype) -> size_t

    @param strtype: int32
    """
    return _ida_nalt.get_str_type_prefix_length(strtype)
STRENC_DEFAULT = _ida_nalt.STRENC_DEFAULT
r"""
use default encoding for this type (see get_default_encoding_idx())
"""

STRENC_NONE = _ida_nalt.STRENC_NONE
r"""
force no-conversion encoding
"""


def get_alignment(ea: "ea_t") -> "uint32":
    r"""
    get_alignment(ea) -> uint32

    @param ea: ea_t
    """
    return _ida_nalt.get_alignment(ea)

def set_alignment(ea: "ea_t", x: "uint32") -> "void":
    r"""
    set_alignment(ea, x)

    @param ea: ea_t
    @param x: uint32
    """
    return _ida_nalt.set_alignment(ea, x)

def del_alignment(ea: "ea_t") -> "void":
    r"""
    del_alignment(ea)

    @param ea: ea_t
    """
    return _ida_nalt.del_alignment(ea)

def set_item_color(ea: "ea_t", color: "bgcolor_t") -> "void":
    r"""
    set_item_color(ea, color)

    @param ea: ea_t
    @param color: bgcolor_t
    """
    return _ida_nalt.set_item_color(ea, color)

def get_item_color(ea: "ea_t") -> "bgcolor_t":
    r"""
    get_item_color(ea) -> bgcolor_t

    @param ea: ea_t
    """
    return _ida_nalt.get_item_color(ea)

def del_item_color(ea: "ea_t") -> "bool":
    r"""
    del_item_color(ea) -> bool

    @param ea: ea_t
    """
    return _ida_nalt.del_item_color(ea)
class array_parameters_t(object):
    r"""
    Proxy of C++ array_parameters_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    flags: "int32" = property(_ida_nalt.array_parameters_t_flags_get, _ida_nalt.array_parameters_t_flags_set, doc=r"""flags""")
    lineitems: "int32" = property(_ida_nalt.array_parameters_t_lineitems_get, _ida_nalt.array_parameters_t_lineitems_set, doc=r"""lineitems""")
    r"""
    number of items on a line
    """
    alignment: "int32" = property(_ida_nalt.array_parameters_t_alignment_get, _ida_nalt.array_parameters_t_alignment_set, doc=r"""alignment""")
    r"""
    -1 - don't align. 0 - align automatically. else item width
    """

    def __init__(self, _f: "int32"=0x00000001, _l: "int32"=0, _a: "int32"=-1):
        r"""
        __init__(self, _f=0x00000001, _l=0, _a=-1) -> array_parameters_t

        @param _f: int32
        @param _l: int32
        @param _a: int32
        """
        _ida_nalt.array_parameters_t_swiginit(self, _ida_nalt.new_array_parameters_t(_f, _l, _a))

    def is_default(self) -> "bool":
        r"""
        is_default(self) -> bool
        """
        return _ida_nalt.array_parameters_t_is_default(self)
    __swig_destroy__ = _ida_nalt.delete_array_parameters_t

# Register array_parameters_t in _ida_nalt:
_ida_nalt.array_parameters_t_swigregister(array_parameters_t)
AP_ALLOWDUPS = _ida_nalt.AP_ALLOWDUPS
r"""
use 'dup' construct
"""

AP_SIGNED = _ida_nalt.AP_SIGNED
r"""
treats numbers as signed
"""

AP_INDEX = _ida_nalt.AP_INDEX
r"""
display array element indexes as comments
"""

AP_ARRAY = _ida_nalt.AP_ARRAY
r"""
create as array (this flag is not stored in database)
"""

AP_IDXBASEMASK = _ida_nalt.AP_IDXBASEMASK
r"""
mask for number base of the indexes
"""

AP_IDXDEC = _ida_nalt.AP_IDXDEC
r"""
display indexes in decimal
"""

AP_IDXHEX = _ida_nalt.AP_IDXHEX
r"""
display indexes in hex
"""

AP_IDXOCT = _ida_nalt.AP_IDXOCT
r"""
display indexes in octal
"""

AP_IDXBIN = _ida_nalt.AP_IDXBIN
r"""
display indexes in binary
"""



def get_array_parameters(out: "array_parameters_t", ea: "ea_t") -> "ssize_t":
    r"""
    get_array_parameters(out, ea) -> ssize_t

    @param out: array_parameters_t *
    @param ea: ea_t
    """
    return _ida_nalt.get_array_parameters(out, ea)

def set_array_parameters(ea: "ea_t", _in: "array_parameters_t") -> "void":
    r"""
    set_array_parameters(ea, _in)

    @param ea: ea_t
    @param in: array_parameters_t const *
    """
    return _ida_nalt.set_array_parameters(ea, _in)

def del_array_parameters(ea: "ea_t") -> "void":
    r"""
    del_array_parameters(ea)

    @param ea: ea_t
    """
    return _ida_nalt.del_array_parameters(ea)
class switch_info_t(object):
    r"""
    Proxy of C++ switch_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    flags: "uint32" = property(_ida_nalt.switch_info_t_flags_get, _ida_nalt.switch_info_t_flags_set, doc=r"""flags""")
    r"""
    Switch info flags
    """

    def get_shift(self) -> "int":
        r"""
        get_shift(self) -> int
        See SWI_SHIFT_MASK. possible answers: 0..3.
        """
        return _ida_nalt.switch_info_t_get_shift(self)

    def set_shift(self, shift: "int") -> "void":
        r"""
        set_shift(self, shift)
        See SWI_SHIFT_MASK.

        @param shift: (C++: int)
        """
        return _ida_nalt.switch_info_t_set_shift(self, shift)

    def get_jtable_element_size(self) -> "int":
        r"""
        get_jtable_element_size(self) -> int
        """
        return _ida_nalt.switch_info_t_get_jtable_element_size(self)

    def set_jtable_element_size(self, size: "int") -> "void":
        r"""
        set_jtable_element_size(self, size)

        @param size: int
        """
        return _ida_nalt.switch_info_t_set_jtable_element_size(self, size)

    def get_vtable_element_size(self) -> "int":
        r"""
        get_vtable_element_size(self) -> int
        """
        return _ida_nalt.switch_info_t_get_vtable_element_size(self)

    def set_vtable_element_size(self, size: "int") -> "void":
        r"""
        set_vtable_element_size(self, size)

        @param size: int
        """
        return _ida_nalt.switch_info_t_set_vtable_element_size(self, size)

    def has_default(self) -> "bool":
        r"""
        has_default(self) -> bool
        """
        return _ida_nalt.switch_info_t_has_default(self)

    def has_elbase(self) -> "bool":
        r"""
        has_elbase(self) -> bool
        """
        return _ida_nalt.switch_info_t_has_elbase(self)

    def is_sparse(self) -> "bool":
        r"""
        is_sparse(self) -> bool
        """
        return _ida_nalt.switch_info_t_is_sparse(self)

    def is_custom(self) -> "bool":
        r"""
        is_custom(self) -> bool
        """
        return _ida_nalt.switch_info_t_is_custom(self)

    def is_indirect(self) -> "bool":
        r"""
        is_indirect(self) -> bool
        """
        return _ida_nalt.switch_info_t_is_indirect(self)

    def is_subtract(self) -> "bool":
        r"""
        is_subtract(self) -> bool
        """
        return _ida_nalt.switch_info_t_is_subtract(self)

    def is_nolowcase(self) -> "bool":
        r"""
        is_nolowcase(self) -> bool
        """
        return _ida_nalt.switch_info_t_is_nolowcase(self)

    def use_std_table(self) -> "bool":
        r"""
        use_std_table(self) -> bool
        """
        return _ida_nalt.switch_info_t_use_std_table(self)

    def is_user_defined(self) -> "bool":
        r"""
        is_user_defined(self) -> bool
        """
        return _ida_nalt.switch_info_t_is_user_defined(self)
    ncases: "ushort" = property(_ida_nalt.switch_info_t_ncases_get, _ida_nalt.switch_info_t_ncases_set, doc=r"""ncases""")
    r"""
    number of cases (excluding default)
    """
    jumps: "ea_t" = property(_ida_nalt.switch_info_t_jumps_get, _ida_nalt.switch_info_t_jumps_set, doc=r"""jumps""")
    r"""
    jump table start address
    """
    values: "ea_t" = property(_ida_nalt.switch_info_t_values_get, _ida_nalt.switch_info_t_values_set, doc=r"""values""")
    r"""
    values table address (if SWI_SPARSE is set)
    """
    lowcase: "uval_t" = property(_ida_nalt.switch_info_t_lowcase_get, _ida_nalt.switch_info_t_lowcase_set, doc=r"""lowcase""")
    r"""
    the lowest value in cases
    """
    defjump: "ea_t" = property(_ida_nalt.switch_info_t_defjump_get, _ida_nalt.switch_info_t_defjump_set, doc=r"""defjump""")
    r"""
    default jump address (BADADDR if no default case)
    """
    startea: "ea_t" = property(_ida_nalt.switch_info_t_startea_get, _ida_nalt.switch_info_t_startea_set, doc=r"""startea""")
    r"""
    start of the switch idiom
    """
    jcases: "int" = property(_ida_nalt.switch_info_t_jcases_get, _ida_nalt.switch_info_t_jcases_set, doc=r"""jcases""")
    r"""
    number of entries in the jump table (SWI_INDIRECT)
    """
    ind_lowcase: "sval_t" = property(_ida_nalt.switch_info_t_ind_lowcase_get, _ida_nalt.switch_info_t_ind_lowcase_set, doc=r"""ind_lowcase""")

    def get_lowcase(self) -> "sval_t":
        r"""
        get_lowcase(self) -> sval_t
        """
        return _ida_nalt.switch_info_t_get_lowcase(self)
    elbase: "ea_t" = property(_ida_nalt.switch_info_t_elbase_get, _ida_nalt.switch_info_t_elbase_set, doc=r"""elbase""")
    r"""
    element base
    """
    regnum: "int" = property(_ida_nalt.switch_info_t_regnum_get, _ida_nalt.switch_info_t_regnum_set, doc=r"""regnum""")
    r"""
    the switch expression as a value of the REGNUM register before the instruction
    at EXPR_EA. -1 means 'unknown'
    """
    regdtype: "op_dtype_t" = property(_ida_nalt.switch_info_t_regdtype_get, _ida_nalt.switch_info_t_regdtype_set, doc=r"""regdtype""")
    r"""
    size of the switch expression register as dtype
    """

    def get_jtable_size(self) -> "int":
        r"""
        get_jtable_size(self) -> int
        """
        return _ida_nalt.switch_info_t_get_jtable_size(self)

    def set_jtable_size(self, size: "int") -> "void":
        r"""
        set_jtable_size(self, size)

        @param size: int
        """
        return _ida_nalt.switch_info_t_set_jtable_size(self, size)

    def set_elbase(self, base: "ea_t") -> "void":
        r"""
        set_elbase(self, base)

        @param base: ea_t
        """
        return _ida_nalt.switch_info_t_set_elbase(self, base)

    def set_expr(self, r: "int", dt: "op_dtype_t") -> "void":
        r"""
        set_expr(self, r, dt)

        @param r: int
        @param dt: op_dtype_t
        """
        return _ida_nalt.switch_info_t_set_expr(self, r, dt)

    def get_jrange_vrange(self, jrange: "range_t"=None, vrange: "range_t"=None) -> "bool":
        r"""
        get_jrange_vrange(self, jrange=None, vrange=None) -> bool
        get separate parts of the switch

        @param jrange: (C++: range_t *)
        @param vrange: (C++: range_t *)
        """
        return _ida_nalt.switch_info_t_get_jrange_vrange(self, jrange, vrange)
    custom: "uval_t" = property(_ida_nalt.switch_info_t_custom_get, _ida_nalt.switch_info_t_custom_set, doc=r"""custom""")
    r"""
    information for custom tables (filled and used by modules)
    """
    SWITCH_INFO_VERSION = _ida_nalt.switch_info_t_SWITCH_INFO_VERSION
    

    def get_version(self) -> "int":
        r"""
        get_version(self) -> int
        """
        return _ida_nalt.switch_info_t_get_version(self)
    expr_ea: "ea_t" = property(_ida_nalt.switch_info_t_expr_ea_get, _ida_nalt.switch_info_t_expr_ea_set, doc=r"""expr_ea""")
    r"""
    the address before that the switch expression is in REGNUM. If BADADDR, then the
    first insn marked as IM_SWITCH after STARTEA is used.
    """
    marks: "eavec_t" = property(_ida_nalt.switch_info_t_marks_get, _ida_nalt.switch_info_t_marks_set, doc=r"""marks""")
    r"""
    the insns marked as IM_SWITCH. They are used to delete the switch.
    """

    def __init__(self):
        r"""
        __init__(self) -> switch_info_t
        """
        _ida_nalt.switch_info_t_swiginit(self, _ida_nalt.new_switch_info_t())

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_nalt.switch_info_t_clear(self)

    def assign(self, other: "switch_info_t") -> "void":
        r"""
        assign(self, other)

        @param other: switch_info_t const &
        """
        return _ida_nalt.switch_info_t_assign(self, other)

    def _get_values_lowcase(self) -> "ea_t":
        r"""_get_values_lowcase(self) -> ea_t"""
        return _ida_nalt.switch_info_t__get_values_lowcase(self)

    def _set_values_lowcase(self, values: "ea_t") -> "void":
        r"""
        _set_values_lowcase(self, values)

        Parameters
        ----------
        values: ea_t

        """
        return _ida_nalt.switch_info_t__set_values_lowcase(self, values)

    values = property(_get_values_lowcase, _set_values_lowcase)
    lowcase = property(_get_values_lowcase, _set_values_lowcase)

    __swig_destroy__ = _ida_nalt.delete_switch_info_t

# Register switch_info_t in _ida_nalt:
_ida_nalt.switch_info_t_swigregister(switch_info_t)
SWI_SPARSE = _ida_nalt.SWI_SPARSE
r"""
sparse switch (value table present), otherwise lowcase present
"""

SWI_V32 = _ida_nalt.SWI_V32
r"""
32-bit values in table
"""

SWI_J32 = _ida_nalt.SWI_J32
r"""
32-bit jump offsets
"""

SWI_VSPLIT = _ida_nalt.SWI_VSPLIT
r"""
value table is split (only for 32-bit values)
"""

SWI_USER = _ida_nalt.SWI_USER
r"""
user specified switch (starting from version 2)
"""

SWI_DEF_IN_TBL = _ida_nalt.SWI_DEF_IN_TBL
r"""
default case is an entry in the jump table. This flag is applicable in 2 cases:
* The sparse indirect switch (i.e. a switch with a values table) {jump table
size} == {value table size} + 1. The default case entry is the last one in the
table (or the first one in the case of an inversed jump table).
* The switch with insns in the jump table. The default case entry is before the
first entry of the table.
See also the find_defjump_from_table() helper function.
"""

SWI_JMP_INV = _ida_nalt.SWI_JMP_INV
r"""
jumptable is inversed. (last entry is for first entry in values table)
"""

SWI_SHIFT_MASK = _ida_nalt.SWI_SHIFT_MASK
r"""
use formula (element<<shift) + elbase to find jump targets
"""

SWI_ELBASE = _ida_nalt.SWI_ELBASE
r"""
elbase is present (otherwise the base of the switch segment will be used)
"""

SWI_JSIZE = _ida_nalt.SWI_JSIZE
r"""
jump offset expansion bit
"""

SWI_VSIZE = _ida_nalt.SWI_VSIZE
r"""
value table element size expansion bit
"""

SWI_SEPARATE = _ida_nalt.SWI_SEPARATE
r"""
create an array of individual elements (otherwise separate items)
"""

SWI_SIGNED = _ida_nalt.SWI_SIGNED
r"""
jump table entries are signed
"""

SWI_CUSTOM = _ida_nalt.SWI_CUSTOM
r"""
custom jump table. processor_t::create_switch_xrefs will be called to create
code xrefs for the table. Custom jump table must be created by the module (see
also SWI_STDTBL)
"""

SWI_INDIRECT = _ida_nalt.SWI_INDIRECT
r"""
value table elements are used as indexes into the jump table (for sparse
switches)
"""

SWI_SUBTRACT = _ida_nalt.SWI_SUBTRACT
r"""
table values are subtracted from the elbase instead of being added
"""

SWI_HXNOLOWCASE = _ida_nalt.SWI_HXNOLOWCASE
r"""
lowcase value should not be used by the decompiler (internal flag)
"""

SWI_STDTBL = _ida_nalt.SWI_STDTBL
r"""
custom jump table with standard table formatting. ATM IDA doesn't use SWI_CUSTOM
for switches with standard table formatting. So this flag can be considered as
obsolete.
"""

SWI_DEFRET = _ida_nalt.SWI_DEFRET
r"""
return in the default case (defjump==BADADDR)
"""

SWI_SELFREL = _ida_nalt.SWI_SELFREL
r"""
jump address is relative to the element not to ELBASE
"""

SWI_JMPINSN = _ida_nalt.SWI_JMPINSN
r"""
jump table entries are insns. For such entries SHIFT has a different meaning. It
denotes the number of insns in the entry. For example, 0 - the entry contains
the jump to the case, 1 - the entry contains one insn like a 'mov' and jump to
the end of case, and so on.
"""

SWI_VERSION = _ida_nalt.SWI_VERSION
r"""
the structure contains the VERSION member
"""



def get_switch_info(out: "switch_info_t", ea: "ea_t") -> "ssize_t":
    r"""
    get_switch_info(out, ea) -> ssize_t

    @param out: switch_info_t *
    @param ea: ea_t
    """
    return _ida_nalt.get_switch_info(out, ea)

def set_switch_info(ea: "ea_t", _in: "switch_info_t") -> "void":
    r"""
    set_switch_info(ea, _in)

    @param ea: ea_t
    @param in: switch_info_t const &
    """
    return _ida_nalt.set_switch_info(ea, _in)

def del_switch_info(ea: "ea_t") -> "void":
    r"""
    del_switch_info(ea)

    @param ea: ea_t
    """
    return _ida_nalt.del_switch_info(ea)

def get_switch_parent(ea: "ea_t") -> "ea_t":
    r"""
    get_switch_parent(ea) -> ea_t

    @param ea: ea_t
    """
    return _ida_nalt.get_switch_parent(ea)

def set_switch_parent(ea: "ea_t", x: "ea_t") -> "void":
    r"""
    set_switch_parent(ea, x)

    @param ea: ea_t
    @param x: ea_t
    """
    return _ida_nalt.set_switch_parent(ea, x)

def del_switch_parent(ea: "ea_t") -> "void":
    r"""
    del_switch_parent(ea)

    @param ea: ea_t
    """
    return _ida_nalt.del_switch_parent(ea)
class custom_data_type_ids_t(object):
    r"""
    Proxy of C++ custom_data_type_ids_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    dtid: "int16" = property(_ida_nalt.custom_data_type_ids_t_dtid_get, _ida_nalt.custom_data_type_ids_t_dtid_set, doc=r"""dtid""")
    r"""
    data type id
    """
    fids: "int16 [8]" = property(_ida_nalt.custom_data_type_ids_t_fids_get, _ida_nalt.custom_data_type_ids_t_fids_set, doc=r"""fids""")
    r"""
    data format ids
    """

    def set(self, tid: "tid_t") -> "void":
        r"""
        set(self, tid)

        @param tid: tid_t
        """
        return _ida_nalt.custom_data_type_ids_t_set(self, tid)

    def get_dtid(self) -> "tid_t":
        r"""
        get_dtid(self) -> tid_t
        """
        return _ida_nalt.custom_data_type_ids_t_get_dtid(self)

    def __getFids(self) -> "wrapped_array_t< int16,8 >":
        r"""
        __getFids(self) -> custom_data_type_ids_fids_array
        """
        return _ida_nalt.custom_data_type_ids_t___getFids(self)

    fids = property(__getFids)


    def __init__(self):
        r"""
        __init__(self) -> custom_data_type_ids_t
        """
        _ida_nalt.custom_data_type_ids_t_swiginit(self, _ida_nalt.new_custom_data_type_ids_t())
    __swig_destroy__ = _ida_nalt.delete_custom_data_type_ids_t

# Register custom_data_type_ids_t in _ida_nalt:
_ida_nalt.custom_data_type_ids_t_swigregister(custom_data_type_ids_t)

def get_custom_data_type_ids(cdis: "custom_data_type_ids_t", ea: "ea_t") -> "int":
    r"""
    get_custom_data_type_ids(cdis, ea) -> int

    @param cdis: custom_data_type_ids_t *
    @param ea: ea_t
    """
    return _ida_nalt.get_custom_data_type_ids(cdis, ea)

def set_custom_data_type_ids(ea: "ea_t", cdis: "custom_data_type_ids_t") -> "void":
    r"""
    set_custom_data_type_ids(ea, cdis)

    @param ea: ea_t
    @param cdis: custom_data_type_ids_t const *
    """
    return _ida_nalt.set_custom_data_type_ids(ea, cdis)

def del_custom_data_type_ids(ea: "ea_t") -> "void":
    r"""
    del_custom_data_type_ids(ea)

    @param ea: ea_t
    """
    return _ida_nalt.del_custom_data_type_ids(ea)

def is_reftype_target_optional(type: "reftype_t") -> "bool":
    r"""
    is_reftype_target_optional(type) -> bool
    Can the target be calculated using operand value?

    @param type: (C++: reftype_t)
    """
    return _ida_nalt.is_reftype_target_optional(type)

def get_reftype_by_size(size: "size_t") -> "reftype_t":
    r"""
    get_reftype_by_size(size) -> reftype_t
    Get REF_... constant from size Supported sizes: 1,2,4,8,16 For other sizes
    returns reftype_t(-1)

    @param size: (C++: size_t)
    """
    return _ida_nalt.get_reftype_by_size(size)
class refinfo_t(object):
    r"""
    Proxy of C++ refinfo_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    target: "ea_t" = property(_ida_nalt.refinfo_t_target_get, _ida_nalt.refinfo_t_target_set, doc=r"""target""")
    r"""
    reference target (BADADDR-none)
    """
    base: "ea_t" = property(_ida_nalt.refinfo_t_base_get, _ida_nalt.refinfo_t_base_set, doc=r"""base""")
    r"""
    base of reference (may be BADADDR)
    """
    tdelta: "adiff_t" = property(_ida_nalt.refinfo_t_tdelta_get, _ida_nalt.refinfo_t_tdelta_set, doc=r"""tdelta""")
    r"""
    offset from the target
    """
    flags: "uint32" = property(_ida_nalt.refinfo_t_flags_get, _ida_nalt.refinfo_t_flags_set, doc=r"""flags""")
    r"""
    Reference info flags
    """

    def type(self) -> "reftype_t":
        r"""
        type(self) -> reftype_t
        """
        return _ida_nalt.refinfo_t_type(self)

    def is_target_optional(self) -> "bool":
        r"""
        is_target_optional(self) -> bool
        < is_reftype_target_optional()
        """
        return _ida_nalt.refinfo_t_is_target_optional(self)

    def no_base_xref(self) -> "bool":
        r"""
        no_base_xref(self) -> bool
        """
        return _ida_nalt.refinfo_t_no_base_xref(self)

    def is_pastend(self) -> "bool":
        r"""
        is_pastend(self) -> bool
        """
        return _ida_nalt.refinfo_t_is_pastend(self)

    def is_rvaoff(self) -> "bool":
        r"""
        is_rvaoff(self) -> bool
        """
        return _ida_nalt.refinfo_t_is_rvaoff(self)

    def is_custom(self) -> "bool":
        r"""
        is_custom(self) -> bool
        """
        return _ida_nalt.refinfo_t_is_custom(self)

    def is_subtract(self) -> "bool":
        r"""
        is_subtract(self) -> bool
        """
        return _ida_nalt.refinfo_t_is_subtract(self)

    def is_signed(self) -> "bool":
        r"""
        is_signed(self) -> bool
        """
        return _ida_nalt.refinfo_t_is_signed(self)

    def is_no_zeros(self) -> "bool":
        r"""
        is_no_zeros(self) -> bool
        """
        return _ida_nalt.refinfo_t_is_no_zeros(self)

    def is_no_ones(self) -> "bool":
        r"""
        is_no_ones(self) -> bool
        """
        return _ida_nalt.refinfo_t_is_no_ones(self)

    def is_selfref(self) -> "bool":
        r"""
        is_selfref(self) -> bool
        """
        return _ida_nalt.refinfo_t_is_selfref(self)

    def set_type(self, rt: "reftype_t") -> "void":
        r"""
        set_type(self, rt)

        @param rt: reftype_t
        """
        return _ida_nalt.refinfo_t_set_type(self, rt)

    def init(self, *args) -> "void":
        r"""
        init(self, reft_and_flags, _base=0, _target=BADADDR, _tdelta=0)

        @param reft_and_flags: uint32
        @param _base: ea_t
        @param _target: ea_t
        @param _tdelta: adiff_t
        """
        return _ida_nalt.refinfo_t_init(self, *args)

    def __init__(self):
        r"""
        __init__(self) -> refinfo_t
        """
        _ida_nalt.refinfo_t_swiginit(self, _ida_nalt.new_refinfo_t())
    __swig_destroy__ = _ida_nalt.delete_refinfo_t

# Register refinfo_t in _ida_nalt:
_ida_nalt.refinfo_t_swigregister(refinfo_t)
cvar = _ida_nalt.cvar
V695_REF_OFF8 = cvar.V695_REF_OFF8
r"""
reserved
"""
REF_OFF16 = cvar.REF_OFF16
r"""
16bit full offset
"""
REF_OFF32 = cvar.REF_OFF32
r"""
32bit full offset
"""
REF_LOW8 = cvar.REF_LOW8
r"""
low 8bits of 16bit offset
"""
REF_LOW16 = cvar.REF_LOW16
r"""
low 16bits of 32bit offset
"""
REF_HIGH8 = cvar.REF_HIGH8
r"""
high 8bits of 16bit offset
"""
REF_HIGH16 = cvar.REF_HIGH16
r"""
high 16bits of 32bit offset
"""
V695_REF_VHIGH = cvar.V695_REF_VHIGH
r"""
obsolete
"""
V695_REF_VLOW = cvar.V695_REF_VLOW
r"""
obsolete
"""
REF_OFF64 = cvar.REF_OFF64
r"""
64bit full offset
"""
REF_OFF8 = cvar.REF_OFF8
r"""
8bit full offset
"""
REF_LAST = cvar.REF_LAST
REFINFO_TYPE = _ida_nalt.REFINFO_TYPE
r"""
reference type (reftype_t), or custom reference ID if REFINFO_CUSTOM set
"""

REFINFO_RVAOFF = _ida_nalt.REFINFO_RVAOFF
r"""
based reference (rva); refinfo_t::base will be forced to get_imagebase(); such a
reference is displayed with the asm_t::a_rva keyword
"""

REFINFO_PASTEND = _ida_nalt.REFINFO_PASTEND
r"""
reference past an item; it may point to an nonexistent address; do not destroy
alignment dirs
"""

REFINFO_CUSTOM = _ida_nalt.REFINFO_CUSTOM
r"""
a custom reference. see custom_refinfo_handler_t. the id of the custom refinfo
is stored under the REFINFO_TYPE mask.
"""

REFINFO_NOBASE = _ida_nalt.REFINFO_NOBASE
r"""
don't create the base xref; implies that the base can be any value. nb: base
xrefs are created only if the offset base points to the middle of a segment
"""

REFINFO_SUBTRACT = _ida_nalt.REFINFO_SUBTRACT
r"""
the reference value is subtracted from the base value instead of (as usual)
being added to it
"""

REFINFO_SIGNEDOP = _ida_nalt.REFINFO_SIGNEDOP
r"""
the operand value is sign-extended (only supported for REF_OFF8/16/32/64)
"""

REFINFO_NO_ZEROS = _ida_nalt.REFINFO_NO_ZEROS
r"""
an opval of 0 will be considered invalid
"""

REFINFO_NO_ONES = _ida_nalt.REFINFO_NO_ONES
r"""
an opval of ~0 will be considered invalid
"""

REFINFO_SELFREF = _ida_nalt.REFINFO_SELFREF
r"""
the self-based reference; refinfo_t::base will be forced to the reference
address
"""



def find_custom_refinfo(name: "char const *") -> "int":
    r"""
    find_custom_refinfo(name) -> int
    Get id of a custom refinfo type.

    @param name: (C++: const char *) char const *
    """
    return _ida_nalt.find_custom_refinfo(name)

def get_custom_refinfo(crid: "int") -> "custom_refinfo_handler_t const *":
    r"""
    get_custom_refinfo(crid) -> custom_refinfo_handler_t const *
    Get definition of a registered custom refinfo type.

    @param crid: (C++: int)
    """
    return _ida_nalt.get_custom_refinfo(crid)
MAXSTRUCPATH = _ida_nalt.MAXSTRUCPATH
r"""
maximal inclusion depth of unions
"""

class strpath_t(object):
    r"""
    Proxy of C++ strpath_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    len: "int" = property(_ida_nalt.strpath_t_len_get, _ida_nalt.strpath_t_len_set, doc=r"""len""")
    ids: "tid_t [32]" = property(_ida_nalt.strpath_t_ids_get, _ida_nalt.strpath_t_ids_set, doc=r"""ids""")
    delta: "adiff_t" = property(_ida_nalt.strpath_t_delta_get, _ida_nalt.strpath_t_delta_set, doc=r"""delta""")

    def __getIds(self) -> "wrapped_array_t< tid_t,32 >":
        r"""
        __getIds(self) -> strpath_ids_array
        """
        return _ida_nalt.strpath_t___getIds(self)

    ids = property(__getIds)


    def __init__(self):
        r"""
        __init__(self) -> strpath_t
        """
        _ida_nalt.strpath_t_swiginit(self, _ida_nalt.new_strpath_t())
    __swig_destroy__ = _ida_nalt.delete_strpath_t

# Register strpath_t in _ida_nalt:
_ida_nalt.strpath_t_swigregister(strpath_t)
class enum_const_t(object):
    r"""
    Proxy of C++ enum_const_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    tid: "tid_t" = property(_ida_nalt.enum_const_t_tid_get, _ida_nalt.enum_const_t_tid_set, doc=r"""tid""")
    serial: "uchar" = property(_ida_nalt.enum_const_t_serial_get, _ida_nalt.enum_const_t_serial_set, doc=r"""serial""")

    def __init__(self):
        r"""
        __init__(self) -> enum_const_t
        """
        _ida_nalt.enum_const_t_swiginit(self, _ida_nalt.new_enum_const_t())
    __swig_destroy__ = _ida_nalt.delete_enum_const_t

# Register enum_const_t in _ida_nalt:
_ida_nalt.enum_const_t_swigregister(enum_const_t)
class opinfo_t(object):
    r"""
    Proxy of C++ opinfo_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ri: "refinfo_t" = property(_ida_nalt.opinfo_t_ri_get, _ida_nalt.opinfo_t_ri_set, doc=r"""ri""")
    r"""
    for offset members
    """
    tid: "tid_t" = property(_ida_nalt.opinfo_t_tid_get, _ida_nalt.opinfo_t_tid_set, doc=r"""tid""")
    r"""
    for struct, etc. members
    """
    path: "strpath_t" = property(_ida_nalt.opinfo_t_path_get, _ida_nalt.opinfo_t_path_set, doc=r"""path""")
    r"""
    for stroff
    """
    strtype: "int32" = property(_ida_nalt.opinfo_t_strtype_get, _ida_nalt.opinfo_t_strtype_set, doc=r"""strtype""")
    r"""
    for strings (String type codes)
    """
    ec: "enum_const_t" = property(_ida_nalt.opinfo_t_ec_get, _ida_nalt.opinfo_t_ec_set, doc=r"""ec""")
    r"""
    for enums
    """
    cd: "custom_data_type_ids_t" = property(_ida_nalt.opinfo_t_cd_get, _ida_nalt.opinfo_t_cd_set, doc=r"""cd""")
    r"""
    for custom data
    """

    def __init__(self):
        r"""
        __init__(self) -> opinfo_t
        """
        _ida_nalt.opinfo_t_swiginit(self, _ida_nalt.new_opinfo_t())
    __swig_destroy__ = _ida_nalt.delete_opinfo_t

# Register opinfo_t in _ida_nalt:
_ida_nalt.opinfo_t_swigregister(opinfo_t)
class printop_t(object):
    r"""
    Proxy of C++ printop_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ti: "opinfo_t" = property(_ida_nalt.printop_t_ti_get, _ida_nalt.printop_t_ti_set, doc=r"""ti""")
    features: "uchar" = property(_ida_nalt.printop_t_features_get, _ida_nalt.printop_t_features_set, doc=r"""features""")
    suspop: "int" = property(_ida_nalt.printop_t_suspop_get, _ida_nalt.printop_t_suspop_set, doc=r"""suspop""")
    aflags: "aflags_t" = property(_ida_nalt.printop_t_aflags_get, _ida_nalt.printop_t_aflags_set, doc=r"""aflags""")
    flags: "flags64_t" = property(_ida_nalt.printop_t_flags_get, _ida_nalt.printop_t_flags_set, doc=r"""flags""")

    def __init__(self):
        r"""
        __init__(self) -> printop_t
        """
        _ida_nalt.printop_t_swiginit(self, _ida_nalt.new_printop_t())

    def is_ti_initialized(self) -> "bool":
        r"""
        is_ti_initialized(self) -> bool
        """
        return _ida_nalt.printop_t_is_ti_initialized(self)

    def set_ti_initialized(self, v: "bool"=True) -> "void":
        r"""
        set_ti_initialized(self, v=True)

        @param v: bool
        """
        return _ida_nalt.printop_t_set_ti_initialized(self, v)

    def is_aflags_initialized(self) -> "bool":
        r"""
        is_aflags_initialized(self) -> bool
        """
        return _ida_nalt.printop_t_is_aflags_initialized(self)

    def set_aflags_initialized(self, v: "bool"=True) -> "void":
        r"""
        set_aflags_initialized(self, v=True)

        @param v: bool
        """
        return _ida_nalt.printop_t_set_aflags_initialized(self, v)

    def is_f64(self) -> "bool":
        r"""
        is_f64(self) -> bool
        """
        return _ida_nalt.printop_t_is_f64(self)

    def get_ti(self) -> "opinfo_t const *":
        r"""
        get_ti(self) -> opinfo_t
        """
        return _ida_nalt.printop_t_get_ti(self)

    is_ti_valid = property(is_ti_initialized, set_ti_initialized)

    __swig_destroy__ = _ida_nalt.delete_printop_t

# Register printop_t in _ida_nalt:
_ida_nalt.printop_t_swigregister(printop_t)
POF_VALID_TI = _ida_nalt.POF_VALID_TI

POF_VALID_AFLAGS = _ida_nalt.POF_VALID_AFLAGS

POF_IS_F64 = _ida_nalt.POF_IS_F64



def set_refinfo_ex(ea: "ea_t", n: "int", ri: "refinfo_t") -> "bool":
    r"""
    set_refinfo_ex(ea, n, ri) -> bool

    @param ea: ea_t
    @param n: int
    @param ri: refinfo_t const *
    """
    return _ida_nalt.set_refinfo_ex(ea, n, ri)

def set_refinfo(*args) -> "bool":
    r"""
    set_refinfo(ea, n, type, target=BADADDR, base=0, tdelta=0) -> bool

    @param ea: ea_t
    @param n: int
    @param type: reftype_t
    @param target: ea_t
    @param base: ea_t
    @param tdelta: adiff_t
    """
    return _ida_nalt.set_refinfo(*args)

def get_refinfo(ri: "refinfo_t", ea: "ea_t", n: "int") -> "bool":
    r"""
    get_refinfo(ri, ea, n) -> bool

    @param ri: refinfo_t *
    @param ea: ea_t
    @param n: int
    """
    return _ida_nalt.get_refinfo(ri, ea, n)

def del_refinfo(ea: "ea_t", n: "int") -> "bool":
    r"""
    del_refinfo(ea, n) -> bool

    @param ea: ea_t
    @param n: int
    """
    return _ida_nalt.del_refinfo(ea, n)

def get_tinfo(tif: "tinfo_t", ea: "ea_t") -> "bool":
    r"""
    get_tinfo(tif, ea) -> bool

    @param tif: tinfo_t *
    @param ea: ea_t
    """
    return _ida_nalt.get_tinfo(tif, ea)

def set_tinfo(ea: "ea_t", tif: "tinfo_t") -> "bool":
    r"""
    set_tinfo(ea, tif) -> bool

    @param ea: ea_t
    @param tif: tinfo_t const *
    """
    return _ida_nalt.set_tinfo(ea, tif)

def del_tinfo(ea: "ea_t") -> "void":
    r"""
    del_tinfo(ea)

    @param ea: ea_t
    """
    return _ida_nalt.del_tinfo(ea)

def get_op_tinfo(tif: "tinfo_t", ea: "ea_t", n: "int") -> "bool":
    r"""
    get_op_tinfo(tif, ea, n) -> bool

    @param tif: tinfo_t *
    @param ea: ea_t
    @param n: int
    """
    return _ida_nalt.get_op_tinfo(tif, ea, n)

def set_op_tinfo(ea: "ea_t", n: "int", tif: "tinfo_t") -> "bool":
    r"""
    set_op_tinfo(ea, n, tif) -> bool

    @param ea: ea_t
    @param n: int
    @param tif: tinfo_t const *
    """
    return _ida_nalt.set_op_tinfo(ea, n, tif)

def del_op_tinfo(ea: "ea_t", n: "int") -> "void":
    r"""
    del_op_tinfo(ea, n)

    @param ea: ea_t
    @param n: int
    """
    return _ida_nalt.del_op_tinfo(ea, n)
RIDX_FILE_FORMAT_NAME = _ida_nalt.RIDX_FILE_FORMAT_NAME
r"""
file format name for loader modules
"""

RIDX_SELECTORS = _ida_nalt.RIDX_SELECTORS
r"""
2..63 are for selector_t blob (see init_selectors())
"""

RIDX_GROUPS = _ida_nalt.RIDX_GROUPS
r"""
segment group information (see init_groups())
"""

RIDX_H_PATH = _ida_nalt.RIDX_H_PATH
r"""
C header path.
"""

RIDX_C_MACROS = _ida_nalt.RIDX_C_MACROS
r"""
C predefined macros.
"""

RIDX_SMALL_IDC_OLD = _ida_nalt.RIDX_SMALL_IDC_OLD
r"""
Instant IDC statements (obsolete)
"""

RIDX_NOTEPAD = _ida_nalt.RIDX_NOTEPAD
r"""
notepad blob, occupies 1000 indexes (1MB of text)
"""

RIDX_INCLUDE = _ida_nalt.RIDX_INCLUDE
r"""
assembler include file name
"""

RIDX_SMALL_IDC = _ida_nalt.RIDX_SMALL_IDC
r"""
Instant IDC statements, blob.
"""

RIDX_DUALOP_GRAPH = _ida_nalt.RIDX_DUALOP_GRAPH
r"""
Graph text representation options.
"""

RIDX_DUALOP_TEXT = _ida_nalt.RIDX_DUALOP_TEXT
r"""
Text text representation options.
"""

RIDX_MD5 = _ida_nalt.RIDX_MD5
r"""
MD5 of the input file.
"""

RIDX_IDA_VERSION = _ida_nalt.RIDX_IDA_VERSION
r"""
version of ida which created the database
"""

RIDX_STR_ENCODINGS = _ida_nalt.RIDX_STR_ENCODINGS
r"""
a list of encodings for the program strings
"""

RIDX_SRCDBG_PATHS = _ida_nalt.RIDX_SRCDBG_PATHS
r"""
source debug paths, occupies 20 indexes
"""

RIDX_DBG_BINPATHS = _ida_nalt.RIDX_DBG_BINPATHS
r"""
unused (20 indexes)
"""

RIDX_SHA256 = _ida_nalt.RIDX_SHA256
r"""
SHA256 of the input file.
"""

RIDX_ABINAME = _ida_nalt.RIDX_ABINAME
r"""
ABI name (processor specific)
"""

RIDX_ARCHIVE_PATH = _ida_nalt.RIDX_ARCHIVE_PATH
r"""
archive file path
"""

RIDX_PROBLEMS = _ida_nalt.RIDX_PROBLEMS
r"""
problem lists
"""

RIDX_SRCDBG_UNDESIRED = _ida_nalt.RIDX_SRCDBG_UNDESIRED
r"""
user-closed source files, occupies 20 indexes
"""


def get_root_filename() -> "size_t":
    r"""
    get_root_filename() -> str
    Get file name only of the input file.
    """
    return _ida_nalt.get_root_filename()

def dbg_get_input_path() -> "size_t":
    r"""
    dbg_get_input_path() -> str
    Get debugger input file name/path (see LFLG_DBG_NOPATH)
    """
    return _ida_nalt.dbg_get_input_path()

def get_input_file_path() -> "size_t":
    r"""
    get_input_file_path() -> str
    Get full path of the input file.
    """
    return _ida_nalt.get_input_file_path()

def set_root_filename(file: "char const *") -> "void":
    r"""
    set_root_filename(file)
    Set full path of the input file.

    @param file: (C++: const char *) char const *
    """
    return _ida_nalt.set_root_filename(file)

def retrieve_input_file_size() -> "size_t":
    r"""
    retrieve_input_file_size() -> size_t
    Get size of input file in bytes.
    """
    return _ida_nalt.retrieve_input_file_size()

def retrieve_input_file_crc32() -> "uint32":
    r"""
    retrieve_input_file_crc32() -> uint32
    Get input file crc32 stored in the database. it can be used to check that the
    input file has not been changed.
    """
    return _ida_nalt.retrieve_input_file_crc32()

def retrieve_input_file_md5() -> "uchar [ANY]":
    r"""
    retrieve_input_file_md5() -> bytes
    Get input file md5.
    """
    return _ida_nalt.retrieve_input_file_md5()

def retrieve_input_file_sha256() -> "uchar [ANY]":
    r"""
    retrieve_input_file_sha256() -> bytes
    Get input file sha256.
    """
    return _ida_nalt.retrieve_input_file_sha256()

def get_asm_inc_file() -> "qstring *":
    r"""
    get_asm_inc_file() -> str
    Get name of the include file.
    """
    return _ida_nalt.get_asm_inc_file()

def set_asm_inc_file(file: "char const *") -> "bool":
    r"""
    set_asm_inc_file(file) -> bool
    Set name of the include file.

    @param file: (C++: const char *) char const *
    """
    return _ida_nalt.set_asm_inc_file(file)

def get_imagebase() -> "ea_t":
    r"""
    get_imagebase() -> ea_t
    Get image base address.
    """
    return _ida_nalt.get_imagebase()

def set_imagebase(base: "ea_t") -> "void":
    r"""
    set_imagebase(base)
    Set image base address.

    @param base: (C++: ea_t)
    """
    return _ida_nalt.set_imagebase(base)

def get_ids_modnode() -> "netnode":
    r"""
    get_ids_modnode() -> netnode
    Get ids modnode.
    """
    return _ida_nalt.get_ids_modnode()

def set_ids_modnode(id: "netnode") -> "void":
    r"""
    set_ids_modnode(id)
    Set ids modnode.

    @param id: (C++: netnode)
    """
    return _ida_nalt.set_ids_modnode(id)

def get_archive_path() -> "qstring *":
    r"""
    get_archive_path() -> str
    Get archive file path from which input file was extracted.
    """
    return _ida_nalt.get_archive_path()

def set_archive_path(file: "char const *") -> "bool":
    r"""
    set_archive_path(file) -> bool
    Set archive file path from which input file was extracted.

    @param file: (C++: const char *) char const *
    """
    return _ida_nalt.set_archive_path(file)

def get_loader_format_name() -> "qstring *":
    r"""
    get_loader_format_name() -> str
    Get file format name for loader modules.
    """
    return _ida_nalt.get_loader_format_name()

def set_loader_format_name(name: "char const *") -> "void":
    r"""
    set_loader_format_name(name)
    Set file format name for loader modules.

    @param name: (C++: const char *) char const *
    """
    return _ida_nalt.set_loader_format_name(name)

def get_initial_ida_version() -> "qstring *":
    r"""
    get_initial_ida_version() -> str
    Get version of ida which created the database (string format like "7.5")
    """
    return _ida_nalt.get_initial_ida_version()

def get_ida_notepad_text() -> "qstring *":
    r"""
    get_ida_notepad_text() -> str
    Get notepad text.
    """
    return _ida_nalt.get_ida_notepad_text()

def set_ida_notepad_text(text: "char const *", size: "size_t"=0) -> "void":
    r"""
    set_ida_notepad_text(text, size=0)
    Set notepad text.

    @param text: (C++: const char *) char const *
    @param size: (C++: size_t)
    """
    return _ida_nalt.set_ida_notepad_text(text, size)

def get_srcdbg_paths() -> "qstring *":
    r"""
    get_srcdbg_paths() -> str
    Get source debug paths.
    """
    return _ida_nalt.get_srcdbg_paths()

def set_srcdbg_paths(paths: "char const *") -> "void":
    r"""
    set_srcdbg_paths(paths)
    Set source debug paths.

    @param paths: (C++: const char *) char const *
    """
    return _ida_nalt.set_srcdbg_paths(paths)

def get_srcdbg_undesired_paths() -> "qstring *":
    r"""
    get_srcdbg_undesired_paths() -> str
    Get user-closed source files.
    """
    return _ida_nalt.get_srcdbg_undesired_paths()

def set_srcdbg_undesired_paths(paths: "char const *") -> "void":
    r"""
    set_srcdbg_undesired_paths(paths)
    Set user-closed source files.

    @param paths: (C++: const char *) char const *
    """
    return _ida_nalt.set_srcdbg_undesired_paths(paths)

def get_initial_idb_version() -> "ushort":
    r"""
    get_initial_idb_version() -> ushort
    Get initial version of the database (numeric format like 700)
    """
    return _ida_nalt.get_initial_idb_version()

def get_idb_ctime() -> "time_t":
    r"""
    get_idb_ctime() -> time_t
    Get database creation timestamp.
    """
    return _ida_nalt.get_idb_ctime()

def get_elapsed_secs() -> "size_t":
    r"""
    get_elapsed_secs() -> size_t
    Get seconds database stayed open.
    """
    return _ida_nalt.get_elapsed_secs()

def get_idb_nopens() -> "size_t":
    r"""
    get_idb_nopens() -> size_t
    Get number of times the database is opened.
    """
    return _ida_nalt.get_idb_nopens()

def get_encoding_qty() -> "int":
    r"""
    get_encoding_qty() -> int
    Get total number of encodings (counted from 0)
    """
    return _ida_nalt.get_encoding_qty()

def get_encoding_name(idx: "int") -> "char const *":
    r"""
    get_encoding_name(idx) -> char const *
    Get encoding name for specific index (1-based).

    @param idx: (C++: int) the encoding index (1-based)
    @retval nullptr: if IDX is out of bounds
    @retval empty: string if the encoding was deleted
    """
    return _ida_nalt.get_encoding_name(idx)

def add_encoding(encname: "char const *") -> "int":
    r"""
    add_encoding(encname) -> int
    Add a new encoding (e.g. "UTF-8"). If it's already in the list, return its
    index.

    @param encname: (C++: const char *) the encoding name
    @return: its index (1-based); -1 means error
    """
    return _ida_nalt.add_encoding(encname)

def del_encoding(idx: "int") -> "bool":
    r"""
    del_encoding(idx) -> bool
    Delete an encoding The encoding is not actually removed because its index may be
    used in strtype. So the deletion just clears the encoding name. The default
    encoding cannot be deleted.

    @param idx: (C++: int) the encoding index (1-based)
    """
    return _ida_nalt.del_encoding(idx)

def rename_encoding(idx: "int", encname: "char const *") -> "bool":
    r"""
    rename_encoding(idx, encname) -> bool
    Change name for an encoding The number of bytes per unit (BPU) of the new
    encoding must match this number of the existing default encoding. Specifying the
    empty name simply deletes this encoding.

    @param idx: (C++: int) the encoding index (1-based)
    @param encname: (C++: const char *) the new encoding name
    """
    return _ida_nalt.rename_encoding(idx, encname)
BPU_1B = _ida_nalt.BPU_1B

BPU_2B = _ida_nalt.BPU_2B

BPU_4B = _ida_nalt.BPU_4B


def get_encoding_bpu(idx: "int") -> "int":
    r"""
    get_encoding_bpu(idx) -> int
    Get the amount of bytes per unit (e.g., 2 for UTF-16, 4 for UTF-32) for the
    encoding with the given index.

    @param idx: (C++: int) the encoding index (1-based)
    @return: the number of bytes per units (1/2/4); -1 means error
    """
    return _ida_nalt.get_encoding_bpu(idx)

def get_encoding_bpu_by_name(encname: "char const *") -> "int":
    r"""
    get_encoding_bpu_by_name(encname) -> int
    Get the amount of bytes per unit for the given encoding

    @param encname: (C++: const char *) the encoding name
    @return: the number of bytes per units (1/2/4); -1 means error
    """
    return _ida_nalt.get_encoding_bpu_by_name(encname)

def get_strtype_bpu(strtype: "int32") -> "int":
    r"""
    get_strtype_bpu(strtype) -> int

    @param strtype: int32
    """
    return _ida_nalt.get_strtype_bpu(strtype)

def get_default_encoding_idx(bpu: "int") -> "int":
    r"""
    get_default_encoding_idx(bpu) -> int
    Get default encoding index for a specific string type.

    @param bpu: (C++: int) the amount of bytes per unit (e.g., 1 for ASCII, CP1252, UTF-8..., 2
                for UTF-16, 4 for UTF-32)
    @retval 0: bad BPU argument
    """
    return _ida_nalt.get_default_encoding_idx(bpu)

def set_default_encoding_idx(bpu: "int", idx: "int") -> "bool":
    r"""
    set_default_encoding_idx(bpu, idx) -> bool
    Set default encoding for a string type

    @param bpu: (C++: int) the amount of bytes per unit
    @param idx: (C++: int) the encoding index. It cannot be 0
    """
    return _ida_nalt.set_default_encoding_idx(bpu, idx)

def encoding_from_strtype(strtype: "int32") -> "char const *":
    r"""
    encoding_from_strtype(strtype) -> char const *
    Get encoding name for this strtype
    @retval nullptr: if STRTYPE has an incorrect encoding index
    @retval empty: string if the encoding was deleted

    @param strtype: (C++: int32)
    """
    return _ida_nalt.encoding_from_strtype(strtype)

def get_outfile_encoding_idx() -> "int":
    r"""
    get_outfile_encoding_idx() -> int
    Get the index of the encoding used when producing files
    @retval 0: the IDB's default 1 byte-per-unit encoding is used
    """
    return _ida_nalt.get_outfile_encoding_idx()

def set_outfile_encoding_idx(idx: "int") -> "bool":
    r"""
    set_outfile_encoding_idx(idx) -> bool
    set encoding to be used when producing files

    @param idx: (C++: int) the encoding index IDX can be 0 to use the IDB's default 1-byte-per-
                unit encoding
    """
    return _ida_nalt.set_outfile_encoding_idx(idx)

def get_import_module_qty() -> "uint":
    r"""
    get_import_module_qty() -> uint
    Get number of import modules.
    """
    return _ida_nalt.get_import_module_qty()

def delete_imports() -> "void":
    r"""
    delete_imports()
    Delete all imported modules information.
    """
    return _ida_nalt.delete_imports()
GOTEA_NODE_NAME = _ida_nalt.GOTEA_NODE_NAME
r"""
node containing address of .got section
"""

GOTEA_NODE_IDX = _ida_nalt.GOTEA_NODE_IDX


def set_gotea(gotea: "ea_t") -> "void":
    r"""
    set_gotea(gotea)

    @param gotea: ea_t
    """
    return _ida_nalt.set_gotea(gotea)

def get_gotea() -> "ea_t":
    r"""
    get_gotea() -> ea_t
    """
    return _ida_nalt.get_gotea()

def get_import_module_name(mod_index: "int") -> "PyObject *":
    r"""
    get_import_module_name(mod_index) -> str
    Returns the name of an imported module given its index

    @param mod_index: int
    @return: None or the module name
    """
    return _ida_nalt.get_import_module_name(mod_index)

def enum_import_names(mod_index: "int", py_cb: "PyObject *") -> "int":
    r"""
    enum_import_names(mod_index, py_cb) -> int
    Enumerate imports from a specific module.
    Please refer to list_imports.py example.

    @param mod_index: The module index
    @param callback: A callable object that will be invoked with an ea, name (could be None) and ordinal.
    @return: 1-finished ok, -1 on error, otherwise callback return value (<=0)
    """
    return _ida_nalt.enum_import_names(mod_index, py_cb)

def switch_info_t__from_ptrval__(ptrval: "size_t") -> "switch_info_t *":
    r"""
    switch_info_t__from_ptrval__(ptrval) -> switch_info_t

    @param ptrval: size_t
    """
    return _ida_nalt.switch_info_t__from_ptrval__(ptrval)

#<pycode(py_nalt)>
_real_get_switch_info = get_switch_info
def get_switch_info(*args):
    if len(args) == 1:
        si, ea = switch_info_t(), args[0]
    else:
        si, ea = args
    return None if _real_get_switch_info(si, ea) <= 0 else si
def get_abi_name():
    import ida_typeinf
    return ida_typeinf.get_abi_name()
# for backward compatibility
get_initial_version = get_initial_idb_version
#</pycode(py_nalt)>



