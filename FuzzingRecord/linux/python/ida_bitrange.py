r"""
Definition of the bitrange_t class."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_bitrange
else:
    import _ida_bitrange

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

SWIG_PYTHON_LEGACY_BOOL = _ida_bitrange.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

class bitrange_t(object):
    r"""
    Proxy of C++ bitrange_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, bit_ofs: "uint16"=0, size_in_bits: "uint16"=0):
        r"""
        __init__(self, bit_ofs=0, size_in_bits=0) -> bitrange_t

        @param bit_ofs: uint16
        @param size_in_bits: uint16
        """
        _ida_bitrange.bitrange_t_swiginit(self, _ida_bitrange.new_bitrange_t(bit_ofs, size_in_bits))

    def init(self, bit_ofs: "uint16", size_in_bits: "uint16") -> "void":
        r"""
        init(self, bit_ofs, size_in_bits)
        Initialize offset and size to given values.

        @param bit_ofs: (C++: uint16)
        @param size_in_bits: (C++: uint16)
        """
        return _ida_bitrange.bitrange_t_init(self, bit_ofs, size_in_bits)

    def reset(self) -> "void":
        r"""
        reset(self)
        Make the bitrange empty.
        """
        return _ida_bitrange.bitrange_t_reset(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        Is the bitrange empty?
        """
        return _ida_bitrange.bitrange_t_empty(self)

    def bitoff(self) -> "uint":
        r"""
        bitoff(self) -> uint
        Get offset of 1st bit.
        """
        return _ida_bitrange.bitrange_t_bitoff(self)

    def bitsize(self) -> "uint":
        r"""
        bitsize(self) -> uint
        Get size of the value in bits.
        """
        return _ida_bitrange.bitrange_t_bitsize(self)

    def bytesize(self) -> "uint":
        r"""
        bytesize(self) -> uint
        Size of the value in bytes.
        """
        return _ida_bitrange.bitrange_t_bytesize(self)

    def mask64(self) -> "uint64":
        r"""
        mask64(self) -> uint64
        Convert to mask of 64 bits.
        """
        return _ida_bitrange.bitrange_t_mask64(self)

    def has_common(self, r: "bitrange_t") -> "bool":
        r"""
        has_common(self, r) -> bool
        Does have common bits with another bitrange?

        @param r: (C++: const bitrange_t &) bitrange_t const &
        """
        return _ida_bitrange.bitrange_t_has_common(self, r)

    def apply_mask(self, subrange: "bitrange_t") -> "bool":
        r"""
        apply_mask(self, subrange) -> bool
        Apply mask to a bitrange

        @param subrange: (C++: const bitrange_t &) range *inside* the main bitrange to keep After this operation
                         the main bitrange will be truncated to have only the bits that
                         are specified by subrange. Example: [off=8,nbits=4],
                         subrange[off=1,nbits=2] => [off=9,nbits=2]
        @return: success
        """
        return _ida_bitrange.bitrange_t_apply_mask(self, subrange)

    def intersect(self, r: "bitrange_t") -> "void":
        r"""
        intersect(self, r)
        Intersect two ranges.

        @param r: (C++: const bitrange_t &) bitrange_t const &
        """
        return _ida_bitrange.bitrange_t_intersect(self, r)

    def create_union(self, r: "bitrange_t") -> "void":
        r"""
        create_union(self, r)
        Create union of 2 ranges including the hole between them.

        @param r: (C++: const bitrange_t &) bitrange_t const &
        """
        return _ida_bitrange.bitrange_t_create_union(self, r)

    def sub(self, r: "bitrange_t") -> "bool":
        r"""
        sub(self, r) -> bool
        Subtract a bitrange.

        @param r: (C++: const bitrange_t &) bitrange_t const &
        """
        return _ida_bitrange.bitrange_t_sub(self, r)

    def shift_down(self, cnt: "uint") -> "void":
        r"""
        shift_down(self, cnt)
        Shift range down (left)

        @param cnt: (C++: uint)
        """
        return _ida_bitrange.bitrange_t_shift_down(self, cnt)

    def shift_up(self, cnt: "uint") -> "void":
        r"""
        shift_up(self, cnt)
        Shift range up (right)

        @param cnt: (C++: uint)
        """
        return _ida_bitrange.bitrange_t_shift_up(self, cnt)

    def extract(self, src: "void const *", is_mf: "bool") -> "bool":
        r"""
        extract(self, src, is_mf) -> bool

        @param src: void const *
        @param is_mf: bool
        """
        return _ida_bitrange.bitrange_t_extract(self, src, is_mf)

    def inject(self, dst: "void *", src: "bytevec_t const &", is_mf: "bool") -> "bool":
        r"""
        inject(self, dst, src, is_mf) -> bool

        @param dst: void *
        @param src: bytevec_t const &
        @param is_mf: bool
        """
        return _ida_bitrange.bitrange_t_inject(self, dst, src, is_mf)

    def __eq__(self, r: "bitrange_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: bitrange_t const &
        """
        return _ida_bitrange.bitrange_t___eq__(self, r)

    def __ne__(self, r: "bitrange_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: bitrange_t const &
        """
        return _ida_bitrange.bitrange_t___ne__(self, r)

    def __lt__(self, r: "bitrange_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: bitrange_t const &
        """
        return _ida_bitrange.bitrange_t___lt__(self, r)

    def __gt__(self, r: "bitrange_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: bitrange_t const &
        """
        return _ida_bitrange.bitrange_t___gt__(self, r)

    def __le__(self, r: "bitrange_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: bitrange_t const &
        """
        return _ida_bitrange.bitrange_t___le__(self, r)

    def __ge__(self, r: "bitrange_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: bitrange_t const &
        """
        return _ida_bitrange.bitrange_t___ge__(self, r)

    def compare(self, r: "bitrange_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: bitrange_t const &
        """
        return _ida_bitrange.bitrange_t_compare(self, r)

    def __str__(self) -> "qstring":
        r"""
        __str__(self) -> qstring
        """
        return _ida_bitrange.bitrange_t___str__(self)
    __swig_destroy__ = _ida_bitrange.delete_bitrange_t

# Register bitrange_t in _ida_bitrange:
_ida_bitrange.bitrange_t_swigregister(bitrange_t)


