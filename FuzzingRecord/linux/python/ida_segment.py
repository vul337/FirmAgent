r"""
Functions that deal with segments.

IDA requires that all program addresses belong to segments (each address must
belong to exactly one segment). The situation when an address doesn't belong to
any segment is allowed as a temporary situation only when the user changes
program segmentation. Bytes outside a segment can't be converted to
instructions, have names, comments, etc. Each segment has its start address,
ending address and represents a contiguous range of addresses. There might be
unused holes between segments.

Each segment has its unique segment selector. This selector is used to
distinguish the segment from other segments. For 16-bit programs the selector is
equal to the segment base paragraph. For 32-bit programs there is special array
to translate the selectors to the segment base paragraphs. A selector is a 32/64
bit value.

The segment base paragraph determines the offsets in the segment. If the start
address of the segment == (base << 4) then the first offset in the segment will
be 0. The start address should be higher or equal to (base << 4). We will call
the offsets in the segment 'virtual addresses'. So, the virtual address of the
first byte of the segment is

(start address of segment - segment base linear address)

For IBM PC, the virtual address corresponds to the offset part of the address.
For other processors (Z80, for example), virtual addresses correspond to Z80
addresses and linear addresses are used only internally. For MS Windows programs
the segment base paragraph is 0 and therefore the segment virtual addresses are
equal to linear addresses."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_segment
else:
    import _ida_segment

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

SWIG_PYTHON_LEGACY_BOOL = _ida_segment.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

import ida_range
class segment_defsr_array(object):
    r"""
    Proxy of C++ wrapped_array_t< sel_t,SREG_NUM > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    data: "unsigned long long (&)[SREG_NUM]" = property(_ida_segment.segment_defsr_array_data_get, doc=r"""data""")

    def __init__(self, data: "unsigned long long (&)[SREG_NUM]"):
        r"""
        __init__(self, data) -> segment_defsr_array

        @param data: unsigned long long (&)[SREG_NUM]
        """
        _ida_segment.segment_defsr_array_swiginit(self, _ida_segment.new_segment_defsr_array(data))

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_segment.segment_defsr_array___len__(self)

    def __getitem__(self, i: "size_t") -> "unsigned long long const &":
        r"""
        __getitem__(self, i) -> unsigned long long const &

        @param i: size_t
        """
        return _ida_segment.segment_defsr_array___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "unsigned long long const &") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: unsigned long long const &
        """
        return _ida_segment.segment_defsr_array___setitem__(self, i, v)

    def _get_bytes(self) -> "bytevec_t":
        r"""_get_bytes(self) -> bytevec_t"""
        return _ida_segment.segment_defsr_array__get_bytes(self)

    def _set_bytes(self, bts: "bytevec_t const &") -> "void":
        r"""
        _set_bytes(self, bts)

        Parameters
        ----------
        bts: bytevec_t const &

        """
        return _ida_segment.segment_defsr_array__set_bytes(self, bts)

    __iter__ = ida_idaapi._bounded_getitem_iterator
    bytes = property(_get_bytes, _set_bytes)

    __swig_destroy__ = _ida_segment.delete_segment_defsr_array

# Register segment_defsr_array in _ida_segment:
_ida_segment.segment_defsr_array_swigregister(segment_defsr_array)

def set_segment_translations(segstart: "ea_t", transmap: "eavec_t const &") -> "bool":
    r"""
    set_segment_translations(segstart, transmap) -> bool
    Set new translation list.

    @param segstart: (C++: ea_t) start address of the segment to add translation to
    @param transmap: (C++: const eavec_t &) vector of segment start addresses for the translation list. If
                     transmap is empty, the translation list is deleted.
    @retval 1: ok
    @retval 0: too many translations or bad segstart
    """
    return _ida_segment.set_segment_translations(segstart, transmap)
SREG_NUM = _ida_segment.SREG_NUM
r"""
Maximum number of segment registers is 16 (see segregs.hpp)
"""

class segment_t(ida_range.range_t):
    r"""
    Proxy of C++ segment_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    name: "uval_t" = property(_ida_segment.segment_t_name_get, _ida_segment.segment_t_name_set, doc=r"""name""")
    r"""
    use get/set_segm_name() functions
    """
    sclass: "uval_t" = property(_ida_segment.segment_t_sclass_get, _ida_segment.segment_t_sclass_set, doc=r"""sclass""")
    r"""
    use get/set_segm_class() functions
    """
    orgbase: "uval_t" = property(_ida_segment.segment_t_orgbase_get, _ida_segment.segment_t_orgbase_set, doc=r"""orgbase""")
    r"""
    this field is IDP dependent. you may keep your information about the segment
    here
    """
    align: "uchar" = property(_ida_segment.segment_t_align_get, _ida_segment.segment_t_align_set, doc=r"""align""")
    r"""
    Segment alignment codes
    """
    comb: "uchar" = property(_ida_segment.segment_t_comb_get, _ida_segment.segment_t_comb_set, doc=r"""comb""")
    r"""
    Segment combination codes
    """
    perm: "uchar" = property(_ida_segment.segment_t_perm_get, _ida_segment.segment_t_perm_set, doc=r"""perm""")
    r"""
    Segment permissions (0 means no information)
    """
    bitness: "uchar" = property(_ida_segment.segment_t_bitness_get, _ida_segment.segment_t_bitness_set, doc=r"""bitness""")
    r"""
    Number of bits in the segment addressing
    * 0: 16 bits
    * 1: 32 bits
    * 2: 64 bits
    """

    def is_16bit(self) -> "bool":
        r"""
        is_16bit(self) -> bool
        Is a 16-bit segment?
        """
        return _ida_segment.segment_t_is_16bit(self)

    def is_32bit(self) -> "bool":
        r"""
        is_32bit(self) -> bool
        Is a 32-bit segment?
        """
        return _ida_segment.segment_t_is_32bit(self)

    def is_64bit(self) -> "bool":
        r"""
        is_64bit(self) -> bool
        Is a 64-bit segment?
        """
        return _ida_segment.segment_t_is_64bit(self)

    def abits(self) -> "int":
        r"""
        abits(self) -> int
        Get number of address bits.
        """
        return _ida_segment.segment_t_abits(self)

    def abytes(self) -> "int":
        r"""
        abytes(self) -> int
        Get number of address bytes.
        """
        return _ida_segment.segment_t_abytes(self)
    flags: "ushort" = property(_ida_segment.segment_t_flags_get, _ida_segment.segment_t_flags_set, doc=r"""flags""")
    r"""
    Segment flags
    """

    def comorg(self) -> "bool":
        r"""
        comorg(self) -> bool
        """
        return _ida_segment.segment_t_comorg(self)

    def set_comorg(self) -> "void":
        r"""
        set_comorg(self)
        """
        return _ida_segment.segment_t_set_comorg(self)

    def clr_comorg(self) -> "void":
        r"""
        clr_comorg(self)
        """
        return _ida_segment.segment_t_clr_comorg(self)

    def ob_ok(self) -> "bool":
        r"""
        ob_ok(self) -> bool
        """
        return _ida_segment.segment_t_ob_ok(self)

    def set_ob_ok(self) -> "void":
        r"""
        set_ob_ok(self)
        """
        return _ida_segment.segment_t_set_ob_ok(self)

    def clr_ob_ok(self) -> "void":
        r"""
        clr_ob_ok(self)
        """
        return _ida_segment.segment_t_clr_ob_ok(self)

    def is_visible_segm(self) -> "bool":
        r"""
        is_visible_segm(self) -> bool
        """
        return _ida_segment.segment_t_is_visible_segm(self)

    def set_visible_segm(self, visible: "bool") -> "void":
        r"""
        set_visible_segm(self, visible)

        @param visible: bool
        """
        return _ida_segment.segment_t_set_visible_segm(self, visible)

    def set_debugger_segm(self, debseg: "bool") -> "void":
        r"""
        set_debugger_segm(self, debseg)

        @param debseg: bool
        """
        return _ida_segment.segment_t_set_debugger_segm(self, debseg)

    def is_loader_segm(self) -> "bool":
        r"""
        is_loader_segm(self) -> bool
        """
        return _ida_segment.segment_t_is_loader_segm(self)

    def set_loader_segm(self, ldrseg: "bool") -> "void":
        r"""
        set_loader_segm(self, ldrseg)

        @param ldrseg: bool
        """
        return _ida_segment.segment_t_set_loader_segm(self, ldrseg)

    def is_hidden_segtype(self) -> "bool":
        r"""
        is_hidden_segtype(self) -> bool
        """
        return _ida_segment.segment_t_is_hidden_segtype(self)

    def set_hidden_segtype(self, hide: "bool") -> "void":
        r"""
        set_hidden_segtype(self, hide)

        @param hide: bool
        """
        return _ida_segment.segment_t_set_hidden_segtype(self, hide)

    def is_header_segm(self) -> "bool":
        r"""
        is_header_segm(self) -> bool
        """
        return _ida_segment.segment_t_is_header_segm(self)

    def set_header_segm(self, on: "bool") -> "void":
        r"""
        set_header_segm(self, on)

        @param on: bool
        """
        return _ida_segment.segment_t_set_header_segm(self, on)
    sel: "sel_t" = property(_ida_segment.segment_t_sel_get, _ida_segment.segment_t_sel_set, doc=r"""sel""")
    r"""
    segment selector - should be unique. You can't change this field after creating
    the segment. Exception: 16bit OMF files may have several segments with the same
    selector, but this is not good (no way to denote a segment exactly) so it should
    be fixed in the future.
    """
    defsr: "sel_t [16]" = property(_ida_segment.segment_t_defsr_get, _ida_segment.segment_t_defsr_set, doc=r"""defsr""")
    r"""
    default segment register values. first element of this array keeps information
    about value of processor_t::reg_first_sreg
    """
    type: "uchar" = property(_ida_segment.segment_t_type_get, _ida_segment.segment_t_type_set, doc=r"""type""")
    r"""
    segment type (see Segment types). The kernel treats different segment types
    differently. Segments marked with '*' contain no instructions or data and are
    not declared as 'segments' in the disassembly.
    """
    color: "bgcolor_t" = property(_ida_segment.segment_t_color_get, _ida_segment.segment_t_color_set, doc=r"""color""")
    r"""
    the segment color
    """

    def update(self) -> "bool":
        r"""
        update(self) -> bool
        Update segment information. You must call this function after modification of
        segment characteristics. Note that not all fields of segment structure may be
        modified directly, there are special functions to modify some fields.

        @return: success
        """
        return _ida_segment.segment_t_update(self)

    def __init__(self):
        r"""
        __init__(self) -> segment_t
        """
        _ida_segment.segment_t_swiginit(self, _ida_segment.new_segment_t())
    start_ea: "ea_t" = property(_ida_segment.segment_t_start_ea_get, _ida_segment.segment_t_start_ea_set, doc=r"""start_ea""")
    end_ea: "ea_t" = property(_ida_segment.segment_t_end_ea_get, _ida_segment.segment_t_end_ea_set, doc=r"""end_ea""")

    def __getDefsr(self) -> "wrapped_array_t< sel_t,SREG_NUM >":
        r"""
        __getDefsr(self) -> segment_defsr_array
        """
        return _ida_segment.segment_t___getDefsr(self)

    use64 = is_64bit
    defsr = property(__getDefsr)

    __swig_destroy__ = _ida_segment.delete_segment_t

# Register segment_t in _ida_segment:
_ida_segment.segment_t_swigregister(segment_t)
saAbs = _ida_segment.saAbs
r"""
Absolute segment.
"""

saRelByte = _ida_segment.saRelByte
r"""
Relocatable, byte aligned.
"""

saRelWord = _ida_segment.saRelWord
r"""
Relocatable, word (2-byte) aligned.
"""

saRelPara = _ida_segment.saRelPara
r"""
Relocatable, paragraph (16-byte) aligned.
"""

saRelPage = _ida_segment.saRelPage
r"""
Relocatable, aligned on 256-byte boundary.
"""

saRelDble = _ida_segment.saRelDble
r"""
Relocatable, aligned on a double word (4-byte) boundary.
"""

saRel4K = _ida_segment.saRel4K
r"""
This value is used by the PharLap OMF for page (4K) alignment. It is not
supported by LINK.
"""

saGroup = _ida_segment.saGroup
r"""
Segment group.
"""

saRel32Bytes = _ida_segment.saRel32Bytes
r"""
32 bytes
"""

saRel64Bytes = _ida_segment.saRel64Bytes
r"""
64 bytes
"""

saRelQword = _ida_segment.saRelQword
r"""
8 bytes
"""

saRel128Bytes = _ida_segment.saRel128Bytes
r"""
128 bytes
"""

saRel512Bytes = _ida_segment.saRel512Bytes
r"""
512 bytes
"""

saRel1024Bytes = _ida_segment.saRel1024Bytes
r"""
1024 bytes
"""

saRel2048Bytes = _ida_segment.saRel2048Bytes
r"""
2048 bytes
"""

saRel_MAX_ALIGN_CODE = _ida_segment.saRel_MAX_ALIGN_CODE

scPriv = _ida_segment.scPriv
r"""
Private. Do not combine with any other program segment.
"""

scGroup = _ida_segment.scGroup
r"""
Segment group.
"""

scPub = _ida_segment.scPub
r"""
Public. Combine by appending at an offset that meets the alignment requirement.
"""

scPub2 = _ida_segment.scPub2
r"""
As defined by Microsoft, same as C=2 (public).
"""

scStack = _ida_segment.scStack
r"""
Stack. Combine as for C=2. This combine type forces byte alignment.
"""

scCommon = _ida_segment.scCommon
r"""
Common. Combine by overlay using maximum size.
"""

scPub3 = _ida_segment.scPub3
r"""
As defined by Microsoft, same as C=2 (public).
"""

sc_MAX_COMB_CODE = _ida_segment.sc_MAX_COMB_CODE

SEGPERM_EXEC = _ida_segment.SEGPERM_EXEC
r"""
Execute.
"""

SEGPERM_WRITE = _ida_segment.SEGPERM_WRITE
r"""
Write.
"""

SEGPERM_READ = _ida_segment.SEGPERM_READ
r"""
Read.
"""

SEGPERM_MAXVAL = _ida_segment.SEGPERM_MAXVAL
r"""
Execute + Write + Read.
"""

SEG_MAX_BITNESS_CODE = _ida_segment.SEG_MAX_BITNESS_CODE
r"""
Maximum segment bitness value.
"""

SFL_COMORG = _ida_segment.SFL_COMORG
r"""
IDP dependent field (IBM PC: if set, ORG directive is not commented out)
"""

SFL_OBOK = _ida_segment.SFL_OBOK
r"""
Orgbase is present? (IDP dependent field)
"""

SFL_HIDDEN = _ida_segment.SFL_HIDDEN
r"""
Is the segment hidden?
"""

SFL_DEBUG = _ida_segment.SFL_DEBUG
r"""
Is the segment created for the debugger?. Such segments are temporary and do not
have permanent flags.
"""

SFL_LOADER = _ida_segment.SFL_LOADER
r"""
Is the segment created by the loader?
"""

SFL_HIDETYPE = _ida_segment.SFL_HIDETYPE
r"""
Hide segment type (do not print it in the listing)
"""

SFL_HEADER = _ida_segment.SFL_HEADER
r"""
Header segment (do not create offsets to it in the disassembly)
"""

SEG_NORM = _ida_segment.SEG_NORM
r"""
unknown type, no assumptions
"""

SEG_XTRN = _ida_segment.SEG_XTRN
r"""
* segment with 'extern' definitions. no instructions are allowed
"""

SEG_CODE = _ida_segment.SEG_CODE
r"""
code segment
"""

SEG_DATA = _ida_segment.SEG_DATA
r"""
data segment
"""

SEG_IMP = _ida_segment.SEG_IMP
r"""
java: implementation segment
"""

SEG_GRP = _ida_segment.SEG_GRP
r"""
* group of segments
"""

SEG_NULL = _ida_segment.SEG_NULL
r"""
zero-length segment
"""

SEG_UNDF = _ida_segment.SEG_UNDF
r"""
undefined segment type (not used)
"""

SEG_BSS = _ida_segment.SEG_BSS
r"""
uninitialized segment
"""

SEG_ABSSYM = _ida_segment.SEG_ABSSYM
r"""
* segment with definitions of absolute symbols
"""

SEG_COMM = _ida_segment.SEG_COMM
r"""
* segment with communal definitions
"""

SEG_IMEM = _ida_segment.SEG_IMEM
r"""
internal processor memory & sfr (8051)
"""

SEG_MAX_SEGTYPE_CODE = _ida_segment.SEG_MAX_SEGTYPE_CODE
r"""
maximum value segment type can take
"""



def is_visible_segm(s: "segment_t") -> "bool":
    r"""
    is_visible_segm(s) -> bool
    See SFL_HIDDEN.

    @param s: (C++: segment_t *)
    """
    return _ida_segment.is_visible_segm(s)

def is_finally_visible_segm(s: "segment_t") -> "bool":
    r"""
    is_finally_visible_segm(s) -> bool
    See SFL_HIDDEN, SCF_SHHID_SEGM.

    @param s: (C++: segment_t *)
    """
    return _ida_segment.is_finally_visible_segm(s)

def set_visible_segm(s: "segment_t", visible: "bool") -> "void":
    r"""
    set_visible_segm(s, visible)
    See SFL_HIDDEN.

    @param s: (C++: segment_t *)
    @param visible: (C++: bool)
    """
    return _ida_segment.set_visible_segm(s, visible)

def is_spec_segm(seg_type: "uchar") -> "bool":
    r"""
    is_spec_segm(seg_type) -> bool
    Has segment a special type?. (SEG_XTRN, SEG_GRP, SEG_ABSSYM, SEG_COMM)

    @param seg_type: (C++: uchar)
    """
    return _ida_segment.is_spec_segm(seg_type)

def is_spec_ea(ea: "ea_t") -> "bool":
    r"""
    is_spec_ea(ea) -> bool
    Does the address belong to a segment with a special type?. (SEG_XTRN, SEG_GRP,
    SEG_ABSSYM, SEG_COMM)

    @param ea: (C++: ea_t) linear address
    """
    return _ida_segment.is_spec_ea(ea)

def lock_segm(segm: "segment_t", lock: "bool") -> "void":
    r"""
    lock_segm(segm, lock)
    Lock segment pointer Locked pointers are guaranteed to remain valid until they
    are unlocked. Ranges with locked pointers cannot be deleted or moved.

    @param segm: (C++: const segment_t *) segment_t const *
    @param lock: (C++: bool)
    """
    return _ida_segment.lock_segm(segm, lock)
class lock_segment(object):
    r"""
    Proxy of C++ lock_segment class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, _segm: "segment_t"):
        r"""
        __init__(self, _segm) -> lock_segment

        @param _segm: segment_t const *
        """
        _ida_segment.lock_segment_swiginit(self, _ida_segment.new_lock_segment(_segm))
    __swig_destroy__ = _ida_segment.delete_lock_segment

# Register lock_segment in _ida_segment:
_ida_segment.lock_segment_swigregister(lock_segment)

def is_segm_locked(segm: "segment_t") -> "bool":
    r"""
    is_segm_locked(segm) -> bool
    Is a segment pointer locked?

    @param segm: (C++: const segment_t *) segment_t const *
    """
    return _ida_segment.is_segm_locked(segm)

def getn_selector(n: "int") -> "sel_t *, ea_t *":
    r"""
    getn_selector(n) -> bool
    Get description of selector (0..get_selector_qty()-1)

    @param n: (C++: int)
    """
    return _ida_segment.getn_selector(n)

def get_selector_qty() -> "size_t":
    r"""
    get_selector_qty() -> size_t
    Get number of defined selectors.
    """
    return _ida_segment.get_selector_qty()

def setup_selector(segbase: "ea_t") -> "sel_t":
    r"""
    setup_selector(segbase) -> sel_t
    Allocate a selector for a segment if necessary. You must call this function
    before calling add_segm_ex(). add_segm() calls this function itself, so you
    don't need to allocate a selector. This function will allocate a selector if
    'segbase' requires more than 16 bits and the current processor is IBM PC.
    Otherwise it will return the segbase value.

    @param segbase: (C++: ea_t) a new segment base paragraph
    @return: the allocated selector number
    """
    return _ida_segment.setup_selector(segbase)

def allocate_selector(segbase: "ea_t") -> "sel_t":
    r"""
    allocate_selector(segbase) -> sel_t
    Allocate a selector for a segment unconditionally. You must call this function
    before calling add_segm_ex(). add_segm() calls this function itself, so you
    don't need to allocate a selector. This function will allocate a new free
    selector and setup its mapping using find_free_selector() and set_selector()
    functions.

    @param segbase: (C++: ea_t) a new segment base paragraph
    @return: the allocated selector number
    """
    return _ida_segment.allocate_selector(segbase)

def find_free_selector() -> "sel_t":
    r"""
    find_free_selector() -> sel_t
    Find first unused selector.

    @return: a number >= 1
    """
    return _ida_segment.find_free_selector()

def set_selector(selector: "sel_t", paragraph: "ea_t") -> "int":
    r"""
    set_selector(selector, paragraph) -> int
    Set mapping of selector to a paragraph. You should call this function _before_
    creating a segment which uses the selector, otherwise the creation of the
    segment will fail.

    @param selector: (C++: sel_t) number of selector to map
    * if selector == BADSEL, then return 0 (fail)
    * if the selector has had a mapping, old mapping is destroyed
    * if the selector number is equal to paragraph value, then the mapping is
    destroyed because we don't need to keep trivial mappings.
    @param paragraph: (C++: ea_t) paragraph to map selector
    @retval 1: ok
    @retval 0: failure (bad selector or too many mappings)
    """
    return _ida_segment.set_selector(selector, paragraph)

def del_selector(selector: "sel_t") -> "void":
    r"""
    del_selector(selector)
    Delete mapping of a selector. Be wary of deleting selectors that are being used
    in the program, this can make a mess in the segments.

    @param selector: (C++: sel_t) number of selector to remove from the translation table
    """
    return _ida_segment.del_selector(selector)

def sel2para(selector: "sel_t") -> "ea_t":
    r"""
    sel2para(selector) -> ea_t
    Get mapping of a selector.

    @param selector: (C++: sel_t) number of selector to translate
    @return: paragraph the specified selector is mapped to. if there is no mapping,
             returns 'selector'.
    """
    return _ida_segment.sel2para(selector)

def sel2ea(selector: "sel_t") -> "ea_t":
    r"""
    sel2ea(selector) -> ea_t
    Get mapping of a selector as a linear address.

    @param selector: (C++: sel_t) number of selector to translate to linear address
    @return: linear address the specified selector is mapped to. if there is no
             mapping, returns to_ea(selector,0);
    """
    return _ida_segment.sel2ea(selector)

def find_selector(base: "ea_t") -> "sel_t":
    r"""
    find_selector(base) -> sel_t
    Find a selector that has mapping to the specified paragraph.

    @param base: (C++: ea_t) paragraph to search in the translation table
    @return: selector value or base
    """
    return _ida_segment.find_selector(base)

def get_segm_by_sel(selector: "sel_t") -> "segment_t *":
    r"""
    get_segm_by_sel(selector) -> segment_t
    Get pointer to segment structure. This function finds a segment by its selector.
    If there are several segments with the same selectors, the last one will be
    returned.

    @param selector: (C++: sel_t) a segment with the specified selector will be returned
    @return: pointer to segment or nullptr
    """
    return _ida_segment.get_segm_by_sel(selector)

def add_segm_ex(NONNULL_s: "segment_t", name: "char const *", sclass: "char const *", flags: "int") -> "bool":
    r"""
    add_segm_ex(NONNULL_s, name, sclass, flags) -> bool
    Add a new segment. If a segment already exists at the specified range of
    addresses, this segment will be truncated. Instructions and data in the old
    segment will be deleted if the new segment has another addressing mode or
    another segment base address.

    @param NONNULL_s: (C++: segment_t *)
    @param name: (C++: const char *) name of new segment. may be nullptr. if specified, the segment is
                 immediately renamed
    @param sclass: (C++: const char *) class of the segment. may be nullptr. if specified, the segment
                   class is immediately changed
    @param flags: (C++: int) Add segment flags
    @retval 1: ok
    @retval 0: failed, a warning message is displayed
    """
    return _ida_segment.add_segm_ex(NONNULL_s, name, sclass, flags)
ADDSEG_NOSREG = _ida_segment.ADDSEG_NOSREG
r"""
set all default segment register values to BADSEL (undefine all default segment
registers)
"""

ADDSEG_OR_DIE = _ida_segment.ADDSEG_OR_DIE
r"""
qexit() if can't add a segment
"""

ADDSEG_NOTRUNC = _ida_segment.ADDSEG_NOTRUNC
r"""
don't truncate the new segment at the beginning of the next segment if they
overlap. destroy/truncate old segments instead.
"""

ADDSEG_QUIET = _ida_segment.ADDSEG_QUIET
r"""
silent mode, no "Adding segment..." in the messages window
"""

ADDSEG_FILLGAP = _ida_segment.ADDSEG_FILLGAP
r"""
fill gap between new segment and previous one. i.e. if such a gap exists, and
this gap is less than 64K, then fill the gap by extending the previous segment
and adding .align directive to it. This way we avoid gaps between segments. too
many gaps lead to a virtual array failure. it cannot hold more than ~1000 gaps.
"""

ADDSEG_SPARSE = _ida_segment.ADDSEG_SPARSE
r"""
use sparse storage method for the new ranges of the created segment. please note
that the ranges that were already enabled before creating the segment will not
change their storage type.
"""

ADDSEG_NOAA = _ida_segment.ADDSEG_NOAA
r"""
do not mark new segment for auto-analysis
"""

ADDSEG_IDBENC = _ida_segment.ADDSEG_IDBENC
r"""
'name' and 'sclass' are given in the IDB encoding; non-ASCII bytes will be
decoded accordingly
"""


def add_segm(para: "ea_t", start: "ea_t", end: "ea_t", name: "char const *", sclass: "char const *", flags: "int"=0) -> "bool":
    r"""
    add_segm(para, start, end, name, sclass, flags=0) -> bool
    Add a new segment, second form. Segment alignment is set to saRelByte. Segment
    combination is "public" or "stack" (if segment class is "STACK"). Addressing
    mode of segment is taken as default (16bit or 32bit). Default segment registers
    are set to BADSEL. If a segment already exists at the specified range of
    addresses, this segment will be truncated. Instructions and data in the old
    segment will be deleted if the new segment has another addressing mode or
    another segment base address.

    @param para: (C++: ea_t) segment base paragraph. if paragraph can't fit in 16bit, then a new
                 selector is allocated and mapped to the paragraph.
    @param start: (C++: ea_t) start address of the segment. if start==BADADDR then start <-
                  to_ea(para,0).
    @param end: (C++: ea_t) end address of the segment. end address should be higher than start
                address. For emulate empty segments, use SEG_NULL segment type. If
                the end address is lower than start address, then fail. If
                end==BADADDR, then a segment up to the next segment will be created
                (if the next segment doesn't exist, then 1 byte segment will be
                created). If 'end' is too high and the new segment would overlap the
                next segment, 'end' is adjusted properly.
    @param name: (C++: const char *) name of new segment. may be nullptr
    @param sclass: (C++: const char *) class of the segment. may be nullptr. type of the new segment is
                   modified if class is one of predefined names:
    * "CODE" -> SEG_CODE
    * "DATA" -> SEG_DATA
    * "CONST" -> SEG_DATA
    * "STACK" -> SEG_BSS
    * "BSS" -> SEG_BSS
    * "XTRN" -> SEG_XTRN
    * "COMM" -> SEG_COMM
    * "ABS" -> SEG_ABSSYM
    @param flags: (C++: int) Add segment flags
    @retval 1: ok
    @retval 0: failed, a warning message is displayed
    """
    return _ida_segment.add_segm(para, start, end, name, sclass, flags)

def del_segm(ea: "ea_t", flags: "int") -> "bool":
    r"""
    del_segm(ea, flags) -> bool
    Delete a segment.

    @param ea: (C++: ea_t) any address belonging to the segment
    @param flags: (C++: int) Segment modification flags
    @retval 1: ok
    @retval 0: failed, no segment at 'ea'.
    """
    return _ida_segment.del_segm(ea, flags)
SEGMOD_KILL = _ida_segment.SEGMOD_KILL
r"""
disable addresses if segment gets shrinked or deleted
"""

SEGMOD_KEEP = _ida_segment.SEGMOD_KEEP
r"""
keep information (code & data, etc)
"""

SEGMOD_SILENT = _ida_segment.SEGMOD_SILENT
r"""
be silent
"""

SEGMOD_KEEP0 = _ida_segment.SEGMOD_KEEP0
r"""
flag for internal use, don't set
"""

SEGMOD_KEEPSEL = _ida_segment.SEGMOD_KEEPSEL
r"""
do not try to delete unused selector
"""

SEGMOD_NOMOVE = _ida_segment.SEGMOD_NOMOVE
r"""
don't move info from the start of segment to the new start address (for
set_segm_start())
"""

SEGMOD_SPARSE = _ida_segment.SEGMOD_SPARSE
r"""
use sparse storage if extending the segment (for set_segm_start(),
set_segm_end())
"""


def get_segm_qty() -> "int":
    r"""
    get_segm_qty() -> int
    Get number of segments.
    """
    return _ida_segment.get_segm_qty()

def getseg(ea: "ea_t") -> "segment_t *":
    r"""
    getseg(ea) -> segment_t
    Get pointer to segment by linear address.

    @param ea: (C++: ea_t) linear address belonging to the segment
    @return: nullptr or pointer to segment structure
    """
    return _ida_segment.getseg(ea)

def getnseg(n: "int") -> "segment_t *":
    r"""
    getnseg(n) -> segment_t
    Get pointer to segment by its number.
    @warning: Obsoleted because it can slow down the debugger (it has to refresh the
              whole memory segmentation to calculate the correct answer)

    @param n: (C++: int) segment number in the range (0..get_segm_qty()-1)
    @return: nullptr or pointer to segment structure
    """
    return _ida_segment.getnseg(n)

def get_segm_num(ea: "ea_t") -> "int":
    r"""
    get_segm_num(ea) -> int
    Get number of segment by address.

    @param ea: (C++: ea_t) linear address belonging to the segment
    @return: -1 if no segment occupies the specified address. otherwise returns
             number of the specified segment (0..get_segm_qty()-1)
    """
    return _ida_segment.get_segm_num(ea)

def get_next_seg(ea: "ea_t") -> "segment_t *":
    r"""
    get_next_seg(ea) -> segment_t
    Get pointer to the next segment.

    @param ea: (C++: ea_t)
    """
    return _ida_segment.get_next_seg(ea)

def get_prev_seg(ea: "ea_t") -> "segment_t *":
    r"""
    get_prev_seg(ea) -> segment_t
    Get pointer to the previous segment.

    @param ea: (C++: ea_t)
    """
    return _ida_segment.get_prev_seg(ea)

def get_first_seg() -> "segment_t *":
    r"""
    get_first_seg() -> segment_t
    Get pointer to the first segment.
    """
    return _ida_segment.get_first_seg()

def get_last_seg() -> "segment_t *":
    r"""
    get_last_seg() -> segment_t
    Get pointer to the last segment.
    """
    return _ida_segment.get_last_seg()

def get_segm_by_name(name: "char const *") -> "segment_t *":
    r"""
    get_segm_by_name(name) -> segment_t
    Get pointer to segment by its name. If there are several segments with the same
    name, returns the first of them.

    @param name: (C++: const char *) segment name. may be nullptr.
    @return: nullptr or pointer to segment structure
    """
    return _ida_segment.get_segm_by_name(name)

def set_segm_end(ea: "ea_t", newend: "ea_t", flags: "int") -> "bool":
    r"""
    set_segm_end(ea, newend, flags) -> bool
    Set segment end address. The next segment is shrinked to allow expansion of the
    specified segment. The kernel might even delete the next segment if necessary.
    The kernel will ask the user for a permission to destroy instructions or data
    going out of segment scope if such instructions exist.

    @param ea: (C++: ea_t) any address belonging to the segment
    @param newend: (C++: ea_t) new end address of the segment
    @param flags: (C++: int) Segment modification flags
    @retval 1: ok
    @retval 0: failed, a warning message is displayed
    """
    return _ida_segment.set_segm_end(ea, newend, flags)

def set_segm_start(ea: "ea_t", newstart: "ea_t", flags: "int") -> "bool":
    r"""
    set_segm_start(ea, newstart, flags) -> bool
    Set segment start address. The previous segment is trimmed to allow expansion of
    the specified segment. The kernel might even delete the previous segment if
    necessary. The kernel will ask the user for a permission to destroy instructions
    or data going out of segment scope if such instructions exist.

    @param ea: (C++: ea_t) any address belonging to the segment
    @param newstart: (C++: ea_t) new start address of the segment note that segment start
                     address should be higher than segment base linear address.
    @param flags: (C++: int) Segment modification flags
    @retval 1: ok
    @retval 0: failed, a warning message is displayed
    """
    return _ida_segment.set_segm_start(ea, newstart, flags)

def move_segm_start(ea: "ea_t", newstart: "ea_t", mode: "int") -> "bool":
    r"""
    move_segm_start(ea, newstart, mode) -> bool
    Move segment start. The main difference between this function and
    set_segm_start() is that this function may expand the previous segment while
    set_segm_start() never does it. So, this function allows to change bounds of two
    segments simultaneously. If the previous segment and the specified segment have
    the same addressing mode and segment base, then instructions and data are not
    destroyed - they simply move from one segment to another. Otherwise all
    instructions/data which migrate from one segment to another are destroyed.
    @note: this function never disables addresses.

    @param ea: (C++: ea_t) any address belonging to the segment
    @param newstart: (C++: ea_t) new start address of the segment note that segment start
                     address should be higher than segment base linear address.
    @param mode: (C++: int) policy for destroying defined items
    * 0: if it is necessary to destroy defined items, display a dialog box and ask
    confirmation
    * 1: if it is necessary to destroy defined items, just destroy them without
    asking the user
    * -1: if it is necessary to destroy defined items, don't destroy them (i.e.
    function will fail)
    * -2: don't destroy defined items (function will succeed)
    @retval 1: ok
    @retval 0: failed, a warning message is displayed
    """
    return _ida_segment.move_segm_start(ea, newstart, mode)
MOVE_SEGM_OK = _ida_segment.MOVE_SEGM_OK
r"""
all ok
"""

MOVE_SEGM_PARAM = _ida_segment.MOVE_SEGM_PARAM
r"""
The specified segment does not exist.
"""

MOVE_SEGM_ROOM = _ida_segment.MOVE_SEGM_ROOM
r"""
Not enough free room at the target address.
"""

MOVE_SEGM_IDP = _ida_segment.MOVE_SEGM_IDP
r"""
IDP module forbids moving the segment.
"""

MOVE_SEGM_CHUNK = _ida_segment.MOVE_SEGM_CHUNK
r"""
Too many chunks are defined, can't move.
"""

MOVE_SEGM_LOADER = _ida_segment.MOVE_SEGM_LOADER
r"""
The segment has been moved but the loader complained.
"""

MOVE_SEGM_ODD = _ida_segment.MOVE_SEGM_ODD
r"""
Cannot move segments by an odd number of bytes.
"""

MOVE_SEGM_ORPHAN = _ida_segment.MOVE_SEGM_ORPHAN
r"""
Orphan bytes hinder segment movement.
"""

MOVE_SEGM_DEBUG = _ida_segment.MOVE_SEGM_DEBUG
r"""
Debugger segments cannot be moved.
"""

MOVE_SEGM_SOURCEFILES = _ida_segment.MOVE_SEGM_SOURCEFILES
r"""
Source files ranges of addresses hinder segment movement.
"""

MOVE_SEGM_MAPPING = _ida_segment.MOVE_SEGM_MAPPING
r"""
Memory mapping ranges of addresses hinder segment movement.
"""

MOVE_SEGM_INVAL = _ida_segment.MOVE_SEGM_INVAL
r"""
Invalid argument (delta/target does not fit the address space)
"""


def move_segm_strerror(code: "move_segm_code_t") -> "char const *":
    r"""
    move_segm_strerror(code) -> char const *
    Return string describing error MOVE_SEGM_... code.

    @param code: (C++: move_segm_code_t) enum move_segm_code_t
    """
    return _ida_segment.move_segm_strerror(code)

def move_segm(s: "segment_t", to: "ea_t", flags: "int"=0) -> "move_segm_code_t":
    r"""
    move_segm(s, to, flags=0) -> move_segm_code_t
    This function moves all information to the new address. It fixes up address
    sensitive information in the kernel. The total effect is equal to reloading the
    segment to the target address. For the file format dependent address sensitive
    information, loader_t::move_segm is called. Also IDB notification event
    idb_event::segm_moved is called.

    @param s: (C++: segment_t *) segment to move
    @param to: (C++: ea_t) new segment start address
    @param flags: (C++: int) Move segment flags
    @return: Move segment result codes
    """
    return _ida_segment.move_segm(s, to, flags)
MSF_SILENT = _ida_segment.MSF_SILENT
r"""
don't display a "please wait" box on the screen
"""

MSF_NOFIX = _ida_segment.MSF_NOFIX
r"""
don't call the loader to fix relocations
"""

MSF_LDKEEP = _ida_segment.MSF_LDKEEP
r"""
keep the loader in the memory (optimization)
"""

MSF_FIXONCE = _ida_segment.MSF_FIXONCE
r"""
call loader only once with the special calling method. valid for
rebase_program(). see loader_t::move_segm.
"""

MSF_PRIORITY = _ida_segment.MSF_PRIORITY
r"""
loader segments will overwrite any existing debugger segments when moved. valid
for move_segm()
"""

MSF_NETNODES = _ida_segment.MSF_NETNODES
r"""
move netnodes instead of changing inf.netdelta (this is slower); valid for
rebase_program()
"""


def change_segment_status(s: "segment_t", is_deb_segm: "bool") -> "int":
    r"""
    change_segment_status(s, is_deb_segm) -> int
    Convert a debugger segment to a regular segment and vice versa. When converting
    debug->regular, the memory contents will be copied to the database.

    @param s: (C++: segment_t *) segment to modify
    @param is_deb_segm: (C++: bool) new status of the segment
    @return: Change segment status result codes
    """
    return _ida_segment.change_segment_status(s, is_deb_segm)
CSS_OK = _ida_segment.CSS_OK
r"""
ok
"""

CSS_NODBG = _ida_segment.CSS_NODBG
r"""
debugger is not running
"""

CSS_NORANGE = _ida_segment.CSS_NORANGE
r"""
could not find corresponding memory range
"""

CSS_NOMEM = _ida_segment.CSS_NOMEM
r"""
not enough memory (might be because the segment is too big)
"""

CSS_BREAK = _ida_segment.CSS_BREAK
r"""
memory reading process stopped by user
"""

SNAP_ALL_SEG = _ida_segment.SNAP_ALL_SEG
r"""
Take a snapshot of all segments.
"""

SNAP_LOAD_SEG = _ida_segment.SNAP_LOAD_SEG
r"""
Take a snapshot of loader segments.
"""

SNAP_CUR_SEG = _ida_segment.SNAP_CUR_SEG
r"""
Take a snapshot of current segment.
"""


def take_memory_snapshot(type: "int") -> "bool":
    r"""
    take_memory_snapshot(type) -> bool
    Take a memory snapshot of the running process.

    @param type: (C++: int) specifies which snapshot we want (see SNAP_ Snapshot types)
    @return: success
    """
    return _ida_segment.take_memory_snapshot(type)

def is_miniidb() -> "bool":
    r"""
    is_miniidb() -> bool
    Is the database a miniidb created by the debugger?.

    @return: true if the database contains no segments or only debugger segments
    """
    return _ida_segment.is_miniidb()

def set_segm_base(s: "segment_t", newbase: "ea_t") -> "bool":
    r"""
    set_segm_base(s, newbase) -> bool
    Internal function.

    @param s: (C++: segment_t *)
    @param newbase: (C++: ea_t)
    """
    return _ida_segment.set_segm_base(s, newbase)

def set_group_selector(grp: "sel_t", sel: "sel_t") -> "int":
    r"""
    set_group_selector(grp, sel) -> int
    Create a new group of segments (used OMF files).

    @param grp: (C++: sel_t) selector of group segment (segment type is SEG_GRP) You should
                create an 'empty' (1 byte) group segment It won't contain anything
                and will be used to redirect references to the group of segments to
                the common selector.
    @param sel: (C++: sel_t) common selector of all segments belonging to the segment You should
                create all segments within the group with the same selector value.
    @return: 1 ok
    0 too many groups (see MAX_GROUPS)
    """
    return _ida_segment.set_group_selector(grp, sel)
MAX_GROUPS = _ida_segment.MAX_GROUPS
r"""
max number of segment groups
"""


def get_group_selector(grpsel: "sel_t") -> "sel_t":
    r"""
    get_group_selector(grpsel) -> sel_t
    Get common selector for a group of segments.

    @param grpsel: (C++: sel_t) selector of group segment
    @return: common selector of the group or 'grpsel' if no such group is found
    """
    return _ida_segment.get_group_selector(grpsel)

def add_segment_translation(segstart: "ea_t", mappedseg: "ea_t") -> "bool":
    r"""
    add_segment_translation(segstart, mappedseg) -> bool
    Add segment translation.

    @param segstart: (C++: ea_t) start address of the segment to add translation to
    @param mappedseg: (C++: ea_t) start address of the overlayed segment
    @retval 1: ok
    @retval 0: too many translations or bad segstart
    """
    return _ida_segment.add_segment_translation(segstart, mappedseg)
MAX_SEGM_TRANSLATIONS = _ida_segment.MAX_SEGM_TRANSLATIONS
r"""
max number of segment translations
"""


def del_segment_translations(segstart: "ea_t") -> "void":
    r"""
    del_segment_translations(segstart)
    Delete the translation list

    @param segstart: (C++: ea_t) start address of the segment to delete translation list
    """
    return _ida_segment.del_segment_translations(segstart)

def get_segment_translations(transmap: "eavec_t *", segstart: "ea_t") -> "ssize_t":
    r"""
    get_segment_translations(transmap, segstart) -> ssize_t
    Get segment translation list.

    @param transmap: (C++: eavec_t *) vector of segment start addresses for the translation list
    @param segstart: (C++: ea_t) start address of the segment to get information about
    @return: -1 if no translation list or bad segstart. otherwise returns size of
             translation list.
    """
    return _ida_segment.get_segment_translations(transmap, segstart)

def get_segment_cmt(s: "segment_t", repeatable: "bool") -> "qstring *":
    r"""
    get_segment_cmt(s, repeatable) -> str
    Get segment comment.

    @param s: (C++: const segment_t *) pointer to segment structure
    @param repeatable: (C++: bool) 0: get regular comment. 1: get repeatable comment.
    @return: size of comment or -1
    """
    return _ida_segment.get_segment_cmt(s, repeatable)

def set_segment_cmt(s: "segment_t", cmt: "char const *", repeatable: "bool") -> "void":
    r"""
    set_segment_cmt(s, cmt, repeatable)
    Set segment comment.

    @param s: (C++: const segment_t *) pointer to segment structure
    @param cmt: (C++: const char *) comment string, may be multiline (with '
    '). maximal size is 4096 bytes. Use empty str ("") to delete comment
    @param repeatable: (C++: bool) 0: set regular comment. 1: set repeatable comment.
    """
    return _ida_segment.set_segment_cmt(s, cmt, repeatable)

def std_out_segm_footer(ctx: "outctx_t &", seg: "segment_t") -> "void":
    r"""
    std_out_segm_footer(ctx, seg)
    Generate segment footer line as a comment line. This function may be used in IDP
    modules to generate segment footer if the target assembler doesn't have 'ends'
    directive.

    @param ctx: (C++: struct outctx_t &) outctx_t &
    @param seg: (C++: segment_t *)
    """
    return _ida_segment.std_out_segm_footer(ctx, seg)

def set_segm_name(s: "segment_t", name: "char const *", flags: "int"=0) -> "int":
    r"""
    set_segm_name(s, name, flags=0) -> int
    Rename segment. The new name is validated (see validate_name). A segment always
    has a name. If you hadn't specified a name, the kernel will assign it "seg###"
    name where ### is segment number.

    @param s: (C++: segment_t *) pointer to segment (may be nullptr)
    @param name: (C++: const char *) new segment name
    @param flags: (C++: int) ADDSEG_IDBENC or 0
    @retval 1: ok, name is good and segment is renamed
    @retval 0: failure, name is bad or segment is nullptr
    """
    return _ida_segment.set_segm_name(s, name, flags)

def get_segm_name(s: "segment_t", flags: "int"=0) -> "qstring *":
    r"""
    get_segm_name(s, flags=0) -> ssize_t
    Get true segment name by pointer to segment.

    @param s: (C++: const segment_t *) pointer to segment
    @param flags: (C++: int) 0-return name as is; 1-substitute bad symbols with _ 1 corresponds
                  to GN_VISIBLE
    @return: size of segment name (-1 if s==nullptr)
    """
    return _ida_segment.get_segm_name(s, flags)

def get_visible_segm_name(s: "segment_t") -> "qstring *":
    r"""
    get_visible_segm_name(s) -> str
    Get segment name by pointer to segment.

    @param s: (C++: const segment_t *) pointer to segment
    @return: size of segment name (-1 if s==nullptr)
    """
    return _ida_segment.get_visible_segm_name(s)

def get_segm_class(s: "segment_t") -> "qstring *":
    r"""
    get_segm_class(s) -> str
    Get segment class. Segment class is arbitrary text (max 8 characters).

    @param s: (C++: const segment_t *) pointer to segment
    @return: size of segment class (-1 if s==nullptr or bufsize<=0)
    """
    return _ida_segment.get_segm_class(s)

def set_segm_class(s: "segment_t", sclass: "char const *", flags: "int"=0) -> "int":
    r"""
    set_segm_class(s, sclass, flags=0) -> int
    Set segment class.

    @param s: (C++: segment_t *) pointer to segment (may be nullptr)
    @param sclass: (C++: const char *) segment class (may be nullptr). If segment type is SEG_NORM and
                   segment class is one of predefined names, then segment type is
                   changed to:
    * "CODE" -> SEG_CODE
    * "DATA" -> SEG_DATA
    * "STACK" -> SEG_BSS
    * "BSS" -> SEG_BSS
    * if "UNK" then segment type is reset to SEG_NORM.
    @param flags: (C++: int) Add segment flags
    @retval 1: ok, name is good and segment is renamed
    @retval 0: failure, name is nullptr or bad or segment is nullptr
    """
    return _ida_segment.set_segm_class(s, sclass, flags)

def segtype(ea: "ea_t") -> "uchar":
    r"""
    segtype(ea) -> uchar
    Get segment type.

    @param ea: (C++: ea_t) any linear address within the segment
    @return: Segment types, SEG_UNDF if no segment found at 'ea'
    """
    return _ida_segment.segtype(ea)

def get_segment_alignment(align: "uchar") -> "char const *":
    r"""
    get_segment_alignment(align) -> char const *
    Get text representation of segment alignment code.

    @param align: (C++: uchar)
    @return: text digestable by IBM PC assembler.
    """
    return _ida_segment.get_segment_alignment(align)

def get_segment_combination(comb: "uchar") -> "char const *":
    r"""
    get_segment_combination(comb) -> char const *
    Get text representation of segment combination code.

    @param comb: (C++: uchar)
    @return: text digestable by IBM PC assembler.
    """
    return _ida_segment.get_segment_combination(comb)

def get_segm_para(s: "segment_t") -> "ea_t":
    r"""
    get_segm_para(s) -> ea_t
    Get segment base paragraph. Segment base paragraph may be converted to segment
    base linear address using to_ea() function. In fact, to_ea(get_segm_para(s), 0)
    == get_segm_base(s).

    @param s: (C++: const segment_t *) pointer to segment
    @return: 0 if s == nullptr, the segment base paragraph
    """
    return _ida_segment.get_segm_para(s)

def get_segm_base(s: "segment_t") -> "ea_t":
    r"""
    get_segm_base(s) -> ea_t
    Get segment base linear address. Segment base linear address is used to
    calculate virtual addresses. The virtual address of the first byte of the
    segment will be (start address of segment - segment base linear address)

    @param s: (C++: const segment_t *) pointer to segment
    @return: 0 if s == nullptr, otherwise segment base linear address
    """
    return _ida_segment.get_segm_base(s)

def set_segm_addressing(s: "segment_t", bitness: "size_t") -> "bool":
    r"""
    set_segm_addressing(s, bitness) -> bool
    Change segment addressing mode (16, 32, 64 bits). You must use this function to
    change segment addressing, never change the 'bitness' field directly. This
    function will delete all instructions, comments and names in the segment

    @param s: (C++: segment_t *) pointer to segment
    @param bitness: (C++: size_t) new addressing mode of segment
    * 2: 64bit segment
    * 1: 32bit segment
    * 0: 16bit segment
    @return: success
    """
    return _ida_segment.set_segm_addressing(s, bitness)

def update_segm(s: "segment_t") -> "bool":
    r"""
    update_segm(s) -> bool

    @param s: segment_t *
    """
    return _ida_segment.update_segm(s)

def segm_adjust_diff(s: "segment_t", delta: "adiff_t") -> "adiff_t":
    r"""
    segm_adjust_diff(s, delta) -> adiff_t
    Truncate and sign extend a delta depending on the segment.

    @param s: (C++: const segment_t *) segment_t const *
    @param delta: (C++: adiff_t)
    """
    return _ida_segment.segm_adjust_diff(s, delta)

def segm_adjust_ea(s: "segment_t", ea: "ea_t") -> "ea_t":
    r"""
    segm_adjust_ea(s, ea) -> ea_t
    Truncate an address depending on the segment.

    @param s: (C++: const segment_t *) segment_t const *
    @param ea: (C++: ea_t)
    """
    return _ida_segment.segm_adjust_ea(s, ea)

def get_defsr(s: "segment_t", reg: "int") -> "sel_t":
    r"""
    get_defsr(s, reg) -> sel_t
    Deprecated, use instead:
        value = s.defsr[reg]

    @param s: segment_t *
    @param reg: int
    """
    return _ida_segment.get_defsr(s, reg)

def set_defsr(s: "segment_t", reg: "int", value: "sel_t") -> "void":
    r"""
    set_defsr(s, reg, value)
    Deprecated, use instead:
        s.defsr[reg] = value

    @param s: segment_t *
    @param reg: int
    @param value: sel_t
    """
    return _ida_segment.set_defsr(s, reg, value)

def rebase_program(delta: "PyObject *", flags: "int") -> "int":
    r"""
    rebase_program(delta, flags) -> int
    Rebase the whole program by 'delta' bytes.

    @param delta: (C++: adiff_t) number of bytes to move the program
    @param flags: (C++: int) Move segment flags it is recommended to use MSF_FIXONCE so that
                  the loader takes care of global variables it stored in the
                  database
    @return: Move segment result codes
    """
    return _ida_segment.rebase_program(delta, flags)


