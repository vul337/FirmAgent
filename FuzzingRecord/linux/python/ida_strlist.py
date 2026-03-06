r"""
Functions that deal with the string list.

While the kernel keeps the string list, it does not update it. The string list
is not used by the kernel because keeping it up-to-date would slow down IDA
without any benefit. If the string list is not cleared using clear_strlist(),
the list will be saved to the database and restored on the next startup.

The users of this list should call build_strlist() if they need an up-to-date
version."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_strlist
else:
    import _ida_strlist

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

SWIG_PYTHON_LEGACY_BOOL = _ida_strlist.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

class strwinsetup_t(object):
    r"""
    Proxy of C++ strwinsetup_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    minlen: "sval_t" = property(_ida_strlist.strwinsetup_t_minlen_get, _ida_strlist.strwinsetup_t_minlen_set, doc=r"""minlen""")
    display_only_existing_strings: "uchar" = property(_ida_strlist.strwinsetup_t_display_only_existing_strings_get, _ida_strlist.strwinsetup_t_display_only_existing_strings_set, doc=r"""display_only_existing_strings""")
    only_7bit: "uchar" = property(_ida_strlist.strwinsetup_t_only_7bit_get, _ida_strlist.strwinsetup_t_only_7bit_set, doc=r"""only_7bit""")
    ignore_heads: "uchar" = property(_ida_strlist.strwinsetup_t_ignore_heads_get, _ida_strlist.strwinsetup_t_ignore_heads_set, doc=r"""ignore_heads""")

    def _get_strtypes(self) -> "PyObject *":
        r"""_get_strtypes(self) -> PyObject *"""
        return _ida_strlist.strwinsetup_t__get_strtypes(self)

    def _set_strtypes(self, py_t: "PyObject *") -> "PyObject *":
        r"""
        _set_strtypes(self, py_t) -> PyObject *

        Parameters
        ----------
        py_t: PyObject *

        """
        return _ida_strlist.strwinsetup_t__set_strtypes(self, py_t)

    strtypes = property(_get_strtypes, _set_strtypes)


    def __init__(self):
        r"""
        __init__(self) -> strwinsetup_t
        """
        _ida_strlist.strwinsetup_t_swiginit(self, _ida_strlist.new_strwinsetup_t())
    __swig_destroy__ = _ida_strlist.delete_strwinsetup_t

# Register strwinsetup_t in _ida_strlist:
_ida_strlist.strwinsetup_t_swigregister(strwinsetup_t)
class string_info_t(object):
    r"""
    Proxy of C++ string_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ea: "ea_t" = property(_ida_strlist.string_info_t_ea_get, _ida_strlist.string_info_t_ea_set, doc=r"""ea""")
    length: "int" = property(_ida_strlist.string_info_t_length_get, _ida_strlist.string_info_t_length_set, doc=r"""length""")
    type: "int" = property(_ida_strlist.string_info_t_type_get, _ida_strlist.string_info_t_type_set, doc=r"""type""")

    def __init__(self, *args):
        r"""
        __init__(self, _ea=BADADDR) -> string_info_t

        @param _ea: ea_t
        """
        _ida_strlist.string_info_t_swiginit(self, _ida_strlist.new_string_info_t(*args))

    def __lt__(self, r: "string_info_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: string_info_t const &
        """
        return _ida_strlist.string_info_t___lt__(self, r)
    __swig_destroy__ = _ida_strlist.delete_string_info_t

# Register string_info_t in _ida_strlist:
_ida_strlist.string_info_t_swigregister(string_info_t)

def get_strlist_options() -> "strwinsetup_t const *":
    r"""
    get_strlist_options() -> strwinsetup_t
    Get the static string list options.
    """
    return _ida_strlist.get_strlist_options()

def build_strlist() -> "void":
    r"""
    build_strlist()
    Rebuild the string list.
    """
    return _ida_strlist.build_strlist()

def clear_strlist() -> "void":
    r"""
    clear_strlist()
    Clear the string list.
    """
    return _ida_strlist.clear_strlist()

def get_strlist_qty() -> "size_t":
    r"""
    get_strlist_qty() -> size_t
    Get number of elements in the string list. The list will be loaded from the
    database (if saved) or built from scratch.
    """
    return _ida_strlist.get_strlist_qty()

def get_strlist_item(si: "string_info_t", n: "size_t") -> "bool":
    r"""
    get_strlist_item(si, n) -> bool
    Get nth element of the string list (n=0..get_strlist_qty()-1)

    @param si: (C++: string_info_t *)
    @param n: (C++: size_t)
    """
    return _ida_strlist.get_strlist_item(si, n)


