r"""
IEEE floating point functions."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_ieee
else:
    import _ida_ieee

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

SWIG_PYTHON_LEGACY_BOOL = _ida_ieee.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

class fpvalue_shorts_array_t(object):
    r"""
    Proxy of C++ wrapped_array_t< uint16,FPVAL_NWORDS > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    data: "unsigned short (&)[FPVAL_NWORDS]" = property(_ida_ieee.fpvalue_shorts_array_t_data_get, doc=r"""data""")

    def __init__(self, data: "unsigned short (&)[FPVAL_NWORDS]"):
        r"""
        __init__(self, data) -> fpvalue_shorts_array_t

        @param data: unsigned short (&)[FPVAL_NWORDS]
        """
        _ida_ieee.fpvalue_shorts_array_t_swiginit(self, _ida_ieee.new_fpvalue_shorts_array_t(data))

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_ieee.fpvalue_shorts_array_t___len__(self)

    def __getitem__(self, i: "size_t") -> "unsigned short const &":
        r"""
        __getitem__(self, i) -> unsigned short const &

        @param i: size_t
        """
        return _ida_ieee.fpvalue_shorts_array_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "unsigned short const &") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: unsigned short const &
        """
        return _ida_ieee.fpvalue_shorts_array_t___setitem__(self, i, v)

    def _get_bytes(self) -> "bytevec_t":
        r"""_get_bytes(self) -> bytevec_t"""
        return _ida_ieee.fpvalue_shorts_array_t__get_bytes(self)

    def _set_bytes(self, bts: "bytevec_t const &") -> "void":
        r"""
        _set_bytes(self, bts)

        Parameters
        ----------
        bts: bytevec_t const &

        """
        return _ida_ieee.fpvalue_shorts_array_t__set_bytes(self, bts)

    __iter__ = ida_idaapi._bounded_getitem_iterator
    bytes = property(_get_bytes, _set_bytes)

    __swig_destroy__ = _ida_ieee.delete_fpvalue_shorts_array_t

# Register fpvalue_shorts_array_t in _ida_ieee:
_ida_ieee.fpvalue_shorts_array_t_swigregister(fpvalue_shorts_array_t)
FPVAL_NWORDS = _ida_ieee.FPVAL_NWORDS
r"""
number of words in fpvalue_t
"""

FPV_BADARG = _ida_ieee.FPV_BADARG
r"""
wrong value of max_exp
"""

FPV_NORM = _ida_ieee.FPV_NORM
r"""
regular value
"""

FPV_NAN = _ida_ieee.FPV_NAN
r"""
NaN.
"""

FPV_PINF = _ida_ieee.FPV_PINF
r"""
positive infinity
"""

FPV_NINF = _ida_ieee.FPV_NINF
r"""
negative infinity
"""

REAL_ERROR_OK = _ida_ieee.REAL_ERROR_OK
r"""
no error
"""

REAL_ERROR_FORMAT = _ida_ieee.REAL_ERROR_FORMAT
r"""
realcvt: not supported format for current .idp
"""

REAL_ERROR_RANGE = _ida_ieee.REAL_ERROR_RANGE
r"""
realcvt: number too big (small) for store (mem NOT modified)
"""

REAL_ERROR_BADDATA = _ida_ieee.REAL_ERROR_BADDATA
r"""
realcvt: illegal real data for load (IEEE data not filled)
"""

REAL_ERROR_FPOVER = _ida_ieee.REAL_ERROR_FPOVER
r"""
floating overflow or underflow
"""

REAL_ERROR_BADSTR = _ida_ieee.REAL_ERROR_BADSTR
r"""
asctoreal: illegal input string
"""

REAL_ERROR_ZERODIV = _ida_ieee.REAL_ERROR_ZERODIV
r"""
ediv: divide by 0
"""

REAL_ERROR_INTOVER = _ida_ieee.REAL_ERROR_INTOVER
r"""
eetol*: integer overflow
"""

class fpvalue_t(object):
    r"""
    Proxy of C++ fpvalue_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    w: "uint16 [8]" = property(_ida_ieee.fpvalue_t_w_get, _ida_ieee.fpvalue_t_w_set, doc=r"""w""")

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_ieee.fpvalue_t_clear(self)

    def __eq__(self, r: "fpvalue_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t___eq__(self, r)

    def __ne__(self, r: "fpvalue_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t___ne__(self, r)

    def __lt__(self, r: "fpvalue_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t___lt__(self, r)

    def __gt__(self, r: "fpvalue_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t___gt__(self, r)

    def __le__(self, r: "fpvalue_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t___le__(self, r)

    def __ge__(self, r: "fpvalue_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t___ge__(self, r)

    def compare(self, r: "fpvalue_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t_compare(self, r)

    def from_10bytes(self, fpval: "void const *") -> "fpvalue_error_t":
        r"""
        from_10bytes(self, fpval) -> fpvalue_error_t
        Conversions for 10-byte floating point values.

        @param fpval: (C++: const void *) void const *
        """
        return _ida_ieee.fpvalue_t_from_10bytes(self, fpval)

    def to_10bytes(self, fpval: "void *") -> "fpvalue_error_t":
        r"""
        to_10bytes(self, fpval) -> fpvalue_error_t

        @param fpval: void *
        """
        return _ida_ieee.fpvalue_t_to_10bytes(self, fpval)

    def from_12bytes(self, fpval: "void const *") -> "fpvalue_error_t":
        r"""
        from_12bytes(self, fpval) -> fpvalue_error_t
        Conversions for 12-byte floating point values.

        @param fpval: (C++: const void *) void const *
        """
        return _ida_ieee.fpvalue_t_from_12bytes(self, fpval)

    def to_12bytes(self, fpval: "void *") -> "fpvalue_error_t":
        r"""
        to_12bytes(self, fpval) -> fpvalue_error_t

        @param fpval: void *
        """
        return _ida_ieee.fpvalue_t_to_12bytes(self, fpval)

    def to_str(self, *args) -> "void":
        r"""
        to_str(self, mode)
        Convert IEEE to string.

        @param mode: (C++: uint) broken down into:
        * low byte: number of digits after '.'
        * second byte: FPNUM_LENGTH
        * third byte: FPNUM_DIGITS
        """
        return _ida_ieee.fpvalue_t_to_str(self, *args)

    def from_sval(self, x: "sval_t") -> "void":
        r"""
        from_sval(self, x)
        Convert integer to IEEE.

        @param x: (C++: sval_t)
        """
        return _ida_ieee.fpvalue_t_from_sval(self, x)

    def from_int64(self, x: "int64") -> "void":
        r"""
        from_int64(self, x)

        @param x: int64
        """
        return _ida_ieee.fpvalue_t_from_int64(self, x)

    def from_uint64(self, x: "uint64") -> "void":
        r"""
        from_uint64(self, x)

        @param x: uint64
        """
        return _ida_ieee.fpvalue_t_from_uint64(self, x)

    def to_sval(self, round: "bool"=False) -> "fpvalue_error_t":
        r"""
        to_sval(self, round=False) -> fpvalue_error_t
        Convert IEEE to integer (+-0.5 if round)

        @param round: (C++: bool)
        """
        return _ida_ieee.fpvalue_t_to_sval(self, round)

    def to_int64(self, round: "bool"=False) -> "fpvalue_error_t":
        r"""
        to_int64(self, round=False) -> fpvalue_error_t

        @param round: bool
        """
        return _ida_ieee.fpvalue_t_to_int64(self, round)

    def to_uint64(self, round: "bool"=False) -> "fpvalue_error_t":
        r"""
        to_uint64(self, round=False) -> fpvalue_error_t

        @param round: bool
        """
        return _ida_ieee.fpvalue_t_to_uint64(self, round)

    def fadd(self, y: "fpvalue_t") -> "fpvalue_error_t":
        r"""
        fadd(self, y) -> fpvalue_error_t
        Arithmetic operations.

        @param y: (C++: const fpvalue_t &) fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t_fadd(self, y)

    def fsub(self, y: "fpvalue_t") -> "fpvalue_error_t":
        r"""
        fsub(self, y) -> fpvalue_error_t

        @param y: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t_fsub(self, y)

    def fmul(self, y: "fpvalue_t") -> "fpvalue_error_t":
        r"""
        fmul(self, y) -> fpvalue_error_t

        @param y: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t_fmul(self, y)

    def fdiv(self, y: "fpvalue_t") -> "fpvalue_error_t":
        r"""
        fdiv(self, y) -> fpvalue_error_t

        @param y: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t_fdiv(self, y)

    def mul_pow2(self, power_of_2: "int32") -> "fpvalue_error_t":
        r"""
        mul_pow2(self, power_of_2) -> fpvalue_error_t
        Multiply by a power of 2.

        @param power_of_2: (C++: int32)
        """
        return _ida_ieee.fpvalue_t_mul_pow2(self, power_of_2)

    def eabs(self) -> "void":
        r"""
        eabs(self)
        Calculate absolute value.
        """
        return _ida_ieee.fpvalue_t_eabs(self)

    def is_negative(self) -> "bool":
        r"""
        is_negative(self) -> bool
        Is negative value?
        """
        return _ida_ieee.fpvalue_t_is_negative(self)

    def negate(self) -> "void":
        r"""
        negate(self)
        Negate.
        """
        return _ida_ieee.fpvalue_t_negate(self)

    def get_kind(self) -> "fpvalue_kind_t":
        r"""
        get_kind(self) -> fpvalue_kind_t
        Get value kind.
        """
        return _ida_ieee.fpvalue_t_get_kind(self)

    def __init__(self, *args):
        r"""
        __init__(self) -> fpvalue_t
        __init__(self, _in) -> fpvalue_t

        @param in: bytevec16_t const &
        """
        _ida_ieee.fpvalue_t_swiginit(self, _ida_ieee.new_fpvalue_t(*args))

    def _get_bytes(self) -> "void":
        r"""_get_bytes(self)"""
        return _ida_ieee.fpvalue_t__get_bytes(self)

    def _set_bytes(self, _in: "bytevec16_t const &") -> "void":
        r"""
        _set_bytes(self, _in)

        Parameters
        ----------
        in: bytevec16_t const &

        """
        return _ida_ieee.fpvalue_t__set_bytes(self, _in)

    def _get_float(self) -> "double":
        r"""_get_float(self) -> double"""
        return _ida_ieee.fpvalue_t__get_float(self)

    def _set_float(self, v: "double") -> "void":
        r"""
        _set_float(self, v)

        Parameters
        ----------
        v: double

        """
        return _ida_ieee.fpvalue_t__set_float(self, v)

    def copy(self) -> "fpvalue_t":
        r"""
        copy(self) -> fpvalue_t
        """
        return _ida_ieee.fpvalue_t_copy(self)

    def __str__(self) -> "qstring":
        r"""
        __str__(self) -> qstring
        """
        return _ida_ieee.fpvalue_t___str__(self)

    def _get_shorts(self) -> "wrapped_array_t< uint16,FPVAL_NWORDS >":
        r"""_get_shorts(self) -> fpvalue_shorts_array_t"""
        return _ida_ieee.fpvalue_t__get_shorts(self)

    def from_str(self, p: "char const *") -> "fpvalue_error_t":
        r"""
        from_str(self, p) -> fpvalue_error_t
        Convert string to IEEE.

        @param p_str: (C++: const char **) pointer to pointer to string. it will advanced.
        """
        return _ida_ieee.fpvalue_t_from_str(self, p)

    def assign(self, r: "fpvalue_t") -> "void":
        r"""
        assign(self, r)

        @param r: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t_assign(self, r)

    bytes = property(_get_bytes, _set_bytes)
    shorts = property(_get_shorts)
    float = property(_get_float, _set_float)
    sval = property(lambda self: self.to_sval(), lambda self, v: self.from_sval(v))
    int64 = property(lambda self: self.to_int64(), lambda self, v: self.from_int64(v))
    uint64 = property(lambda self: self.to_uint64(), lambda self, v: self.from_uint64(v))

    def __iter__(self):
        shorts = self.shorts
        for one in shorts:
            yield one

    def __getitem__(self, i):
        return self.shorts[i]

    def __setitem__(self, i, v):
        self.shorts[i] = v


    def __add__(self, o: "fpvalue_t") -> "fpvalue_t":
        r"""
        __add__(self, o) -> fpvalue_t

        @param o: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t___add__(self, o)

    def __sub__(self, o: "fpvalue_t") -> "fpvalue_t":
        r"""
        __sub__(self, o) -> fpvalue_t

        @param o: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t___sub__(self, o)

    def __mul__(self, o: "fpvalue_t") -> "fpvalue_t":
        r"""
        __mul__(self, o) -> fpvalue_t

        @param o: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t___mul__(self, o)

    def __truediv__(self, o: "fpvalue_t") -> "fpvalue_t":
        r"""
        __truediv__(self, o) -> fpvalue_t

        @param o: fpvalue_t const &
        """
        return _ida_ieee.fpvalue_t___truediv__(self, o)
    __swig_destroy__ = _ida_ieee.delete_fpvalue_t

# Register fpvalue_t in _ida_ieee:
_ida_ieee.fpvalue_t_swigregister(fpvalue_t)
cvar = _ida_ieee.cvar
MAXEXP_FLOAT = cvar.MAXEXP_FLOAT
r"""
maximum exponent for 32-bit float
"""
MAXEXP_DOUBLE = cvar.MAXEXP_DOUBLE
r"""
maximum exponent for 64-bit double
"""
MAXEXP_LNGDBL = cvar.MAXEXP_LNGDBL
r"""
maximum exponent for 80-bit long double
"""

IEEE_EXONE = _ida_ieee.IEEE_EXONE
r"""
The exponent of 1.0.
"""

E_SPECIAL_EXP = _ida_ieee.E_SPECIAL_EXP
r"""
Exponent in fpvalue_t for NaN and Inf.
"""

IEEE_NI = _ida_ieee.IEEE_NI
r"""
Number of 16 bit words in eNI.
"""

IEEE_E = _ida_ieee.IEEE_E
r"""
Array offset to exponent.
"""

IEEE_M = _ida_ieee.IEEE_M
r"""
Array offset to high guard word
"""


def ecleaz(x: "eNI") -> "void":
    r"""
    ecleaz(x)

    @param x: unsigned short [(8+3)]
    """
    return _ida_ieee.ecleaz(x)

#<pycode(py_ieee)>
EZERO = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
EONE  = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\xFF\x3F"
ETWO  = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x40"
#</pycode(py_ieee)>



