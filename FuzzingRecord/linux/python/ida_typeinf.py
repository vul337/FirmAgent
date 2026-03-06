r"""
Describes the type information records in IDA.

The recommended way of using type info is to use the tinfo_t class. The type
information is internally kept as an array of bytes terminated by 0.

Items in brackets [] are optional and sometimes are omitted. type_t... means a
sequence of type_t bytes which defines a type.

@note: to work with the types of instructions or data in the database, use
       get_tinfo()/set_tinfo() and similar functions."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_typeinf
else:
    import _ida_typeinf

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

SWIG_PYTHON_LEGACY_BOOL = _ida_typeinf.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

import ida_idp
DEFMASK64 = _ida_typeinf.DEFMASK64
r"""
default bitmask 64bits
"""


def deserialize_tinfo(tif: "tinfo_t", til: "til_t", ptype: "type_t const **", pfields: "p_list const **", pfldcmts: "p_list const **", cmt: "char const *"=None) -> "bool":
    r"""
    deserialize_tinfo(tif, til, ptype, pfields, pfldcmts, cmt=None) -> bool

    @param tif: tinfo_t *
    @param til: til_t const *
    @param ptype: type_t const **
    @param pfields: p_list const **
    @param pfldcmts: p_list const **
    @param cmt: char const *
    """
    return _ida_typeinf.deserialize_tinfo(tif, til, ptype, pfields, pfldcmts, cmt)
class funcargvec_t(object):
    r"""
    Proxy of C++ qvector< funcarg_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> funcargvec_t
        __init__(self, x) -> funcargvec_t

        @param x: qvector< funcarg_t > const &
        """
        _ida_typeinf.funcargvec_t_swiginit(self, _ida_typeinf.new_funcargvec_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_funcargvec_t

    def push_back(self, *args) -> "funcarg_t &":
        r"""
        push_back(self, x)

        @param x: funcarg_t const &

        push_back(self) -> funcarg_t
        """
        return _ida_typeinf.funcargvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_typeinf.funcargvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_typeinf.funcargvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_typeinf.funcargvec_t_empty(self)

    def at(self, _idx: "size_t") -> "funcarg_t const &":
        r"""
        at(self, _idx) -> funcarg_t

        @param _idx: size_t
        """
        return _ida_typeinf.funcargvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_typeinf.funcargvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_typeinf.funcargvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: funcarg_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_typeinf.funcargvec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=funcarg_t())

        @param x: funcarg_t const &
        """
        return _ida_typeinf.funcargvec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_typeinf.funcargvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_typeinf.funcargvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_typeinf.funcargvec_t_truncate(self)

    def swap(self, r: "funcargvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< funcarg_t > &
        """
        return _ida_typeinf.funcargvec_t_swap(self, r)

    def extract(self) -> "funcarg_t *":
        r"""
        extract(self) -> funcarg_t
        """
        return _ida_typeinf.funcargvec_t_extract(self)

    def inject(self, s: "funcarg_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: funcarg_t *
        @param len: size_t
        """
        return _ida_typeinf.funcargvec_t_inject(self, s, len)

    def __eq__(self, r: "funcargvec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< funcarg_t > const &
        """
        return _ida_typeinf.funcargvec_t___eq__(self, r)

    def __ne__(self, r: "funcargvec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< funcarg_t > const &
        """
        return _ida_typeinf.funcargvec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< funcarg_t >::const_iterator":
        r"""
        begin(self) -> funcarg_t
        """
        return _ida_typeinf.funcargvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< funcarg_t >::const_iterator":
        r"""
        end(self) -> funcarg_t
        """
        return _ida_typeinf.funcargvec_t_end(self, *args)

    def insert(self, it: "funcarg_t", x: "funcarg_t") -> "qvector< funcarg_t >::iterator":
        r"""
        insert(self, it, x) -> funcarg_t

        @param it: qvector< funcarg_t >::iterator
        @param x: funcarg_t const &
        """
        return _ida_typeinf.funcargvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< funcarg_t >::iterator":
        r"""
        erase(self, it) -> funcarg_t

        @param it: qvector< funcarg_t >::iterator

        erase(self, first, last) -> funcarg_t

        @param first: qvector< funcarg_t >::iterator
        @param last: qvector< funcarg_t >::iterator
        """
        return _ida_typeinf.funcargvec_t_erase(self, *args)

    def find(self, *args) -> "qvector< funcarg_t >::const_iterator":
        r"""
        find(self, x) -> funcarg_t

        @param x: funcarg_t const &

        """
        return _ida_typeinf.funcargvec_t_find(self, *args)

    def has(self, x: "funcarg_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: funcarg_t const &
        """
        return _ida_typeinf.funcargvec_t_has(self, x)

    def add_unique(self, x: "funcarg_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: funcarg_t const &
        """
        return _ida_typeinf.funcargvec_t_add_unique(self, x)

    def _del(self, x: "funcarg_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: funcarg_t const &

        """
        return _ida_typeinf.funcargvec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_typeinf.funcargvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "funcarg_t const &":
        r"""
        __getitem__(self, i) -> funcarg_t

        @param i: size_t
        """
        return _ida_typeinf.funcargvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "funcarg_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: funcarg_t const &
        """
        return _ida_typeinf.funcargvec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register funcargvec_t in _ida_typeinf:
_ida_typeinf.funcargvec_t_swigregister(funcargvec_t)
class reginfovec_t(object):
    r"""
    Proxy of C++ qvector< reg_info_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> reginfovec_t
        __init__(self, x) -> reginfovec_t

        @param x: qvector< reg_info_t > const &
        """
        _ida_typeinf.reginfovec_t_swiginit(self, _ida_typeinf.new_reginfovec_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_reginfovec_t

    def push_back(self, *args) -> "reg_info_t &":
        r"""
        push_back(self, x)

        @param x: reg_info_t const &

        push_back(self) -> reg_info_t
        """
        return _ida_typeinf.reginfovec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_typeinf.reginfovec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_typeinf.reginfovec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_typeinf.reginfovec_t_empty(self)

    def at(self, _idx: "size_t") -> "reg_info_t const &":
        r"""
        at(self, _idx) -> reg_info_t

        @param _idx: size_t
        """
        return _ida_typeinf.reginfovec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_typeinf.reginfovec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_typeinf.reginfovec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: reg_info_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_typeinf.reginfovec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=reg_info_t())

        @param x: reg_info_t const &
        """
        return _ida_typeinf.reginfovec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_typeinf.reginfovec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_typeinf.reginfovec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_typeinf.reginfovec_t_truncate(self)

    def swap(self, r: "reginfovec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< reg_info_t > &
        """
        return _ida_typeinf.reginfovec_t_swap(self, r)

    def extract(self) -> "reg_info_t *":
        r"""
        extract(self) -> reg_info_t
        """
        return _ida_typeinf.reginfovec_t_extract(self)

    def inject(self, s: "reg_info_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: reg_info_t *
        @param len: size_t
        """
        return _ida_typeinf.reginfovec_t_inject(self, s, len)

    def __eq__(self, r: "reginfovec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< reg_info_t > const &
        """
        return _ida_typeinf.reginfovec_t___eq__(self, r)

    def __ne__(self, r: "reginfovec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< reg_info_t > const &
        """
        return _ida_typeinf.reginfovec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< reg_info_t >::const_iterator":
        r"""
        begin(self) -> reg_info_t
        """
        return _ida_typeinf.reginfovec_t_begin(self, *args)

    def end(self, *args) -> "qvector< reg_info_t >::const_iterator":
        r"""
        end(self) -> reg_info_t
        """
        return _ida_typeinf.reginfovec_t_end(self, *args)

    def insert(self, it: "reg_info_t", x: "reg_info_t") -> "qvector< reg_info_t >::iterator":
        r"""
        insert(self, it, x) -> reg_info_t

        @param it: qvector< reg_info_t >::iterator
        @param x: reg_info_t const &
        """
        return _ida_typeinf.reginfovec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< reg_info_t >::iterator":
        r"""
        erase(self, it) -> reg_info_t

        @param it: qvector< reg_info_t >::iterator

        erase(self, first, last) -> reg_info_t

        @param first: qvector< reg_info_t >::iterator
        @param last: qvector< reg_info_t >::iterator
        """
        return _ida_typeinf.reginfovec_t_erase(self, *args)

    def find(self, *args) -> "qvector< reg_info_t >::const_iterator":
        r"""
        find(self, x) -> reg_info_t

        @param x: reg_info_t const &

        """
        return _ida_typeinf.reginfovec_t_find(self, *args)

    def has(self, x: "reg_info_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: reg_info_t const &
        """
        return _ida_typeinf.reginfovec_t_has(self, x)

    def add_unique(self, x: "reg_info_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: reg_info_t const &
        """
        return _ida_typeinf.reginfovec_t_add_unique(self, x)

    def _del(self, x: "reg_info_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: reg_info_t const &

        """
        return _ida_typeinf.reginfovec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_typeinf.reginfovec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "reg_info_t const &":
        r"""
        __getitem__(self, i) -> reg_info_t

        @param i: size_t
        """
        return _ida_typeinf.reginfovec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "reg_info_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: reg_info_t const &
        """
        return _ida_typeinf.reginfovec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register reginfovec_t in _ida_typeinf:
_ida_typeinf.reginfovec_t_swigregister(reginfovec_t)
class edmvec_t(object):
    r"""
    Proxy of C++ qvector< edm_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> edmvec_t
        __init__(self, x) -> edmvec_t

        @param x: qvector< edm_t > const &
        """
        _ida_typeinf.edmvec_t_swiginit(self, _ida_typeinf.new_edmvec_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_edmvec_t

    def push_back(self, *args) -> "edm_t &":
        r"""
        push_back(self, x)

        @param x: edm_t const &

        push_back(self) -> edm_t
        """
        return _ida_typeinf.edmvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_typeinf.edmvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_typeinf.edmvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_typeinf.edmvec_t_empty(self)

    def at(self, _idx: "size_t") -> "edm_t const &":
        r"""
        at(self, _idx) -> edm_t

        @param _idx: size_t
        """
        return _ida_typeinf.edmvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_typeinf.edmvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_typeinf.edmvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: edm_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_typeinf.edmvec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=edm_t())

        @param x: edm_t const &
        """
        return _ida_typeinf.edmvec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_typeinf.edmvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_typeinf.edmvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_typeinf.edmvec_t_truncate(self)

    def swap(self, r: "edmvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< edm_t > &
        """
        return _ida_typeinf.edmvec_t_swap(self, r)

    def extract(self) -> "edm_t *":
        r"""
        extract(self) -> edm_t
        """
        return _ida_typeinf.edmvec_t_extract(self)

    def inject(self, s: "edm_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: edm_t *
        @param len: size_t
        """
        return _ida_typeinf.edmvec_t_inject(self, s, len)

    def __eq__(self, r: "edmvec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< edm_t > const &
        """
        return _ida_typeinf.edmvec_t___eq__(self, r)

    def __ne__(self, r: "edmvec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< edm_t > const &
        """
        return _ida_typeinf.edmvec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< edm_t >::const_iterator":
        r"""
        begin(self) -> edm_t
        """
        return _ida_typeinf.edmvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< edm_t >::const_iterator":
        r"""
        end(self) -> edm_t
        """
        return _ida_typeinf.edmvec_t_end(self, *args)

    def insert(self, it: "edm_t", x: "edm_t") -> "qvector< edm_t >::iterator":
        r"""
        insert(self, it, x) -> edm_t

        @param it: qvector< edm_t >::iterator
        @param x: edm_t const &
        """
        return _ida_typeinf.edmvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< edm_t >::iterator":
        r"""
        erase(self, it) -> edm_t

        @param it: qvector< edm_t >::iterator

        erase(self, first, last) -> edm_t

        @param first: qvector< edm_t >::iterator
        @param last: qvector< edm_t >::iterator
        """
        return _ida_typeinf.edmvec_t_erase(self, *args)

    def find(self, *args) -> "qvector< edm_t >::const_iterator":
        r"""
        find(self, x) -> edm_t

        @param x: edm_t const &

        """
        return _ida_typeinf.edmvec_t_find(self, *args)

    def has(self, x: "edm_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: edm_t const &
        """
        return _ida_typeinf.edmvec_t_has(self, x)

    def add_unique(self, x: "edm_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: edm_t const &
        """
        return _ida_typeinf.edmvec_t_add_unique(self, x)

    def _del(self, x: "edm_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: edm_t const &

        """
        return _ida_typeinf.edmvec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_typeinf.edmvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "edm_t const &":
        r"""
        __getitem__(self, i) -> edm_t

        @param i: size_t
        """
        return _ida_typeinf.edmvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "edm_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: edm_t const &
        """
        return _ida_typeinf.edmvec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register edmvec_t in _ida_typeinf:
_ida_typeinf.edmvec_t_swigregister(edmvec_t)
class argpartvec_t(object):
    r"""
    Proxy of C++ qvector< argpart_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> argpartvec_t
        __init__(self, x) -> argpartvec_t

        @param x: qvector< argpart_t > const &
        """
        _ida_typeinf.argpartvec_t_swiginit(self, _ida_typeinf.new_argpartvec_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_argpartvec_t

    def push_back(self, *args) -> "argpart_t &":
        r"""
        push_back(self, x)

        @param x: argpart_t const &

        push_back(self) -> argpart_t
        """
        return _ida_typeinf.argpartvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_typeinf.argpartvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_typeinf.argpartvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_typeinf.argpartvec_t_empty(self)

    def at(self, _idx: "size_t") -> "argpart_t const &":
        r"""
        at(self, _idx) -> argpart_t

        @param _idx: size_t
        """
        return _ida_typeinf.argpartvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_typeinf.argpartvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_typeinf.argpartvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: argpart_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_typeinf.argpartvec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=argpart_t())

        @param x: argpart_t const &
        """
        return _ida_typeinf.argpartvec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_typeinf.argpartvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_typeinf.argpartvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_typeinf.argpartvec_t_truncate(self)

    def swap(self, r: "argpartvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< argpart_t > &
        """
        return _ida_typeinf.argpartvec_t_swap(self, r)

    def extract(self) -> "argpart_t *":
        r"""
        extract(self) -> argpart_t
        """
        return _ida_typeinf.argpartvec_t_extract(self)

    def inject(self, s: "argpart_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: argpart_t *
        @param len: size_t
        """
        return _ida_typeinf.argpartvec_t_inject(self, s, len)

    def __eq__(self, r: "argpartvec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< argpart_t > const &
        """
        return _ida_typeinf.argpartvec_t___eq__(self, r)

    def __ne__(self, r: "argpartvec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< argpart_t > const &
        """
        return _ida_typeinf.argpartvec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< argpart_t >::const_iterator":
        r"""
        begin(self) -> argpart_t
        """
        return _ida_typeinf.argpartvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< argpart_t >::const_iterator":
        r"""
        end(self) -> argpart_t
        """
        return _ida_typeinf.argpartvec_t_end(self, *args)

    def insert(self, it: "argpart_t", x: "argpart_t") -> "qvector< argpart_t >::iterator":
        r"""
        insert(self, it, x) -> argpart_t

        @param it: qvector< argpart_t >::iterator
        @param x: argpart_t const &
        """
        return _ida_typeinf.argpartvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< argpart_t >::iterator":
        r"""
        erase(self, it) -> argpart_t

        @param it: qvector< argpart_t >::iterator

        erase(self, first, last) -> argpart_t

        @param first: qvector< argpart_t >::iterator
        @param last: qvector< argpart_t >::iterator
        """
        return _ida_typeinf.argpartvec_t_erase(self, *args)

    def find(self, *args) -> "qvector< argpart_t >::const_iterator":
        r"""
        find(self, x) -> argpart_t

        @param x: argpart_t const &

        """
        return _ida_typeinf.argpartvec_t_find(self, *args)

    def has(self, x: "argpart_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: argpart_t const &
        """
        return _ida_typeinf.argpartvec_t_has(self, x)

    def add_unique(self, x: "argpart_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: argpart_t const &
        """
        return _ida_typeinf.argpartvec_t_add_unique(self, x)

    def _del(self, x: "argpart_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: argpart_t const &

        """
        return _ida_typeinf.argpartvec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_typeinf.argpartvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "argpart_t const &":
        r"""
        __getitem__(self, i) -> argpart_t

        @param i: size_t
        """
        return _ida_typeinf.argpartvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "argpart_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: argpart_t const &
        """
        return _ida_typeinf.argpartvec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register argpartvec_t in _ida_typeinf:
_ida_typeinf.argpartvec_t_swigregister(argpartvec_t)
class valstrvec_t(object):
    r"""
    Proxy of C++ qvector< valstr_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> valstrvec_t
        __init__(self, x) -> valstrvec_t

        @param x: qvector< valstr_t > const &
        """
        _ida_typeinf.valstrvec_t_swiginit(self, _ida_typeinf.new_valstrvec_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_valstrvec_t

    def push_back(self, *args) -> "valstr_t &":
        r"""
        push_back(self, x)

        @param x: valstr_t const &

        push_back(self) -> valstr_t
        """
        return _ida_typeinf.valstrvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_typeinf.valstrvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_typeinf.valstrvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_typeinf.valstrvec_t_empty(self)

    def at(self, _idx: "size_t") -> "valstr_t const &":
        r"""
        at(self, _idx) -> valstr_t

        @param _idx: size_t
        """
        return _ida_typeinf.valstrvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_typeinf.valstrvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_typeinf.valstrvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: valstr_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_typeinf.valstrvec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=valstr_t())

        @param x: valstr_t const &
        """
        return _ida_typeinf.valstrvec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_typeinf.valstrvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_typeinf.valstrvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_typeinf.valstrvec_t_truncate(self)

    def swap(self, r: "valstrvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< valstr_t > &
        """
        return _ida_typeinf.valstrvec_t_swap(self, r)

    def extract(self) -> "valstr_t *":
        r"""
        extract(self) -> valstr_t
        """
        return _ida_typeinf.valstrvec_t_extract(self)

    def inject(self, s: "valstr_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: valstr_t *
        @param len: size_t
        """
        return _ida_typeinf.valstrvec_t_inject(self, s, len)

    def begin(self, *args) -> "qvector< valstr_t >::const_iterator":
        r"""
        begin(self) -> valstr_t
        """
        return _ida_typeinf.valstrvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< valstr_t >::const_iterator":
        r"""
        end(self) -> valstr_t
        """
        return _ida_typeinf.valstrvec_t_end(self, *args)

    def insert(self, it: "valstr_t", x: "valstr_t") -> "qvector< valstr_t >::iterator":
        r"""
        insert(self, it, x) -> valstr_t

        @param it: qvector< valstr_t >::iterator
        @param x: valstr_t const &
        """
        return _ida_typeinf.valstrvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< valstr_t >::iterator":
        r"""
        erase(self, it) -> valstr_t

        @param it: qvector< valstr_t >::iterator

        erase(self, first, last) -> valstr_t

        @param first: qvector< valstr_t >::iterator
        @param last: qvector< valstr_t >::iterator
        """
        return _ida_typeinf.valstrvec_t_erase(self, *args)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_typeinf.valstrvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "valstr_t const &":
        r"""
        __getitem__(self, i) -> valstr_t

        @param i: size_t
        """
        return _ida_typeinf.valstrvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "valstr_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: valstr_t const &
        """
        return _ida_typeinf.valstrvec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register valstrvec_t in _ida_typeinf:
_ida_typeinf.valstrvec_t_swigregister(valstrvec_t)
class regobjvec_t(object):
    r"""
    Proxy of C++ qvector< regobj_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> regobjvec_t
        __init__(self, x) -> regobjvec_t

        @param x: qvector< regobj_t > const &
        """
        _ida_typeinf.regobjvec_t_swiginit(self, _ida_typeinf.new_regobjvec_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_regobjvec_t

    def push_back(self, *args) -> "regobj_t &":
        r"""
        push_back(self, x)

        @param x: regobj_t const &

        push_back(self) -> regobj_t
        """
        return _ida_typeinf.regobjvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_typeinf.regobjvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_typeinf.regobjvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_typeinf.regobjvec_t_empty(self)

    def at(self, _idx: "size_t") -> "regobj_t const &":
        r"""
        at(self, _idx) -> regobj_t

        @param _idx: size_t
        """
        return _ida_typeinf.regobjvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_typeinf.regobjvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_typeinf.regobjvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: regobj_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_typeinf.regobjvec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=regobj_t())

        @param x: regobj_t const &
        """
        return _ida_typeinf.regobjvec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_typeinf.regobjvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_typeinf.regobjvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_typeinf.regobjvec_t_truncate(self)

    def swap(self, r: "regobjvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< regobj_t > &
        """
        return _ida_typeinf.regobjvec_t_swap(self, r)

    def extract(self) -> "regobj_t *":
        r"""
        extract(self) -> regobj_t
        """
        return _ida_typeinf.regobjvec_t_extract(self)

    def inject(self, s: "regobj_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: regobj_t *
        @param len: size_t
        """
        return _ida_typeinf.regobjvec_t_inject(self, s, len)

    def begin(self, *args) -> "qvector< regobj_t >::const_iterator":
        r"""
        begin(self) -> regobj_t
        """
        return _ida_typeinf.regobjvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< regobj_t >::const_iterator":
        r"""
        end(self) -> regobj_t
        """
        return _ida_typeinf.regobjvec_t_end(self, *args)

    def insert(self, it: "regobj_t", x: "regobj_t") -> "qvector< regobj_t >::iterator":
        r"""
        insert(self, it, x) -> regobj_t

        @param it: qvector< regobj_t >::iterator
        @param x: regobj_t const &
        """
        return _ida_typeinf.regobjvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< regobj_t >::iterator":
        r"""
        erase(self, it) -> regobj_t

        @param it: qvector< regobj_t >::iterator

        erase(self, first, last) -> regobj_t

        @param first: qvector< regobj_t >::iterator
        @param last: qvector< regobj_t >::iterator
        """
        return _ida_typeinf.regobjvec_t_erase(self, *args)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_typeinf.regobjvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "regobj_t const &":
        r"""
        __getitem__(self, i) -> regobj_t

        @param i: size_t
        """
        return _ida_typeinf.regobjvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "regobj_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: regobj_t const &
        """
        return _ida_typeinf.regobjvec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register regobjvec_t in _ida_typeinf:
_ida_typeinf.regobjvec_t_swigregister(regobjvec_t)
class type_attrs_t(object):
    r"""
    Proxy of C++ qvector< type_attr_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> type_attrs_t
        __init__(self, x) -> type_attrs_t

        @param x: qvector< type_attr_t > const &
        """
        _ida_typeinf.type_attrs_t_swiginit(self, _ida_typeinf.new_type_attrs_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_type_attrs_t

    def push_back(self, *args) -> "type_attr_t &":
        r"""
        push_back(self, x)

        @param x: type_attr_t const &

        push_back(self) -> type_attr_t
        """
        return _ida_typeinf.type_attrs_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_typeinf.type_attrs_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_typeinf.type_attrs_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_typeinf.type_attrs_t_empty(self)

    def at(self, _idx: "size_t") -> "type_attr_t const &":
        r"""
        at(self, _idx) -> type_attr_t

        @param _idx: size_t
        """
        return _ida_typeinf.type_attrs_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_typeinf.type_attrs_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_typeinf.type_attrs_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: type_attr_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_typeinf.type_attrs_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=type_attr_t())

        @param x: type_attr_t const &
        """
        return _ida_typeinf.type_attrs_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_typeinf.type_attrs_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_typeinf.type_attrs_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_typeinf.type_attrs_t_truncate(self)

    def swap(self, r: "type_attrs_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< type_attr_t > &
        """
        return _ida_typeinf.type_attrs_t_swap(self, r)

    def extract(self) -> "type_attr_t *":
        r"""
        extract(self) -> type_attr_t
        """
        return _ida_typeinf.type_attrs_t_extract(self)

    def inject(self, s: "type_attr_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: type_attr_t *
        @param len: size_t
        """
        return _ida_typeinf.type_attrs_t_inject(self, s, len)

    def begin(self, *args) -> "qvector< type_attr_t >::const_iterator":
        r"""
        begin(self) -> type_attr_t
        """
        return _ida_typeinf.type_attrs_t_begin(self, *args)

    def end(self, *args) -> "qvector< type_attr_t >::const_iterator":
        r"""
        end(self) -> type_attr_t
        """
        return _ida_typeinf.type_attrs_t_end(self, *args)

    def insert(self, it: "type_attr_t", x: "type_attr_t") -> "qvector< type_attr_t >::iterator":
        r"""
        insert(self, it, x) -> type_attr_t

        @param it: qvector< type_attr_t >::iterator
        @param x: type_attr_t const &
        """
        return _ida_typeinf.type_attrs_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< type_attr_t >::iterator":
        r"""
        erase(self, it) -> type_attr_t

        @param it: qvector< type_attr_t >::iterator

        erase(self, first, last) -> type_attr_t

        @param first: qvector< type_attr_t >::iterator
        @param last: qvector< type_attr_t >::iterator
        """
        return _ida_typeinf.type_attrs_t_erase(self, *args)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_typeinf.type_attrs_t___len__(self)

    def __getitem__(self, i: "size_t") -> "type_attr_t const &":
        r"""
        __getitem__(self, i) -> type_attr_t

        @param i: size_t
        """
        return _ida_typeinf.type_attrs_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "type_attr_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: type_attr_t const &
        """
        return _ida_typeinf.type_attrs_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register type_attrs_t in _ida_typeinf:
_ida_typeinf.type_attrs_t_swigregister(type_attrs_t)
class udtmembervec_template_t(object):
    r"""
    Proxy of C++ qvector< udm_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> udtmembervec_template_t
        __init__(self, x) -> udtmembervec_template_t

        @param x: qvector< udm_t > const &
        """
        _ida_typeinf.udtmembervec_template_t_swiginit(self, _ida_typeinf.new_udtmembervec_template_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_udtmembervec_template_t

    def push_back(self, *args) -> "udm_t &":
        r"""
        push_back(self, x)

        @param x: udm_t const &

        push_back(self) -> udm_t
        """
        return _ida_typeinf.udtmembervec_template_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_typeinf.udtmembervec_template_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_typeinf.udtmembervec_template_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_typeinf.udtmembervec_template_t_empty(self)

    def at(self, _idx: "size_t") -> "udm_t const &":
        r"""
        at(self, _idx) -> udm_t

        @param _idx: size_t
        """
        return _ida_typeinf.udtmembervec_template_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_typeinf.udtmembervec_template_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_typeinf.udtmembervec_template_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: udm_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_typeinf.udtmembervec_template_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=udm_t())

        @param x: udm_t const &
        """
        return _ida_typeinf.udtmembervec_template_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_typeinf.udtmembervec_template_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_typeinf.udtmembervec_template_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_typeinf.udtmembervec_template_t_truncate(self)

    def swap(self, r: "udtmembervec_template_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< udm_t > &
        """
        return _ida_typeinf.udtmembervec_template_t_swap(self, r)

    def extract(self) -> "udm_t *":
        r"""
        extract(self) -> udm_t
        """
        return _ida_typeinf.udtmembervec_template_t_extract(self)

    def inject(self, s: "udm_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: udm_t *
        @param len: size_t
        """
        return _ida_typeinf.udtmembervec_template_t_inject(self, s, len)

    def __eq__(self, r: "udtmembervec_template_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< udm_t > const &
        """
        return _ida_typeinf.udtmembervec_template_t___eq__(self, r)

    def __ne__(self, r: "udtmembervec_template_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< udm_t > const &
        """
        return _ida_typeinf.udtmembervec_template_t___ne__(self, r)

    def begin(self, *args) -> "qvector< udm_t >::const_iterator":
        r"""
        begin(self) -> udm_t
        """
        return _ida_typeinf.udtmembervec_template_t_begin(self, *args)

    def end(self, *args) -> "qvector< udm_t >::const_iterator":
        r"""
        end(self) -> udm_t
        """
        return _ida_typeinf.udtmembervec_template_t_end(self, *args)

    def insert(self, it: "udm_t", x: "udm_t") -> "qvector< udm_t >::iterator":
        r"""
        insert(self, it, x) -> udm_t

        @param it: qvector< udm_t >::iterator
        @param x: udm_t const &
        """
        return _ida_typeinf.udtmembervec_template_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< udm_t >::iterator":
        r"""
        erase(self, it) -> udm_t

        @param it: qvector< udm_t >::iterator

        erase(self, first, last) -> udm_t

        @param first: qvector< udm_t >::iterator
        @param last: qvector< udm_t >::iterator
        """
        return _ida_typeinf.udtmembervec_template_t_erase(self, *args)

    def find(self, *args) -> "qvector< udm_t >::const_iterator":
        r"""
        find(self, x) -> udm_t

        @param x: udm_t const &

        """
        return _ida_typeinf.udtmembervec_template_t_find(self, *args)

    def has(self, x: "udm_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: udm_t const &
        """
        return _ida_typeinf.udtmembervec_template_t_has(self, x)

    def add_unique(self, x: "udm_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: udm_t const &
        """
        return _ida_typeinf.udtmembervec_template_t_add_unique(self, x)

    def _del(self, x: "udm_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: udm_t const &

        """
        return _ida_typeinf.udtmembervec_template_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_typeinf.udtmembervec_template_t___len__(self)

    def __getitem__(self, i: "size_t") -> "udm_t const &":
        r"""
        __getitem__(self, i) -> udm_t

        @param i: size_t
        """
        return _ida_typeinf.udtmembervec_template_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "udm_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: udm_t const &
        """
        return _ida_typeinf.udtmembervec_template_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register udtmembervec_template_t in _ida_typeinf:
_ida_typeinf.udtmembervec_template_t_swigregister(udtmembervec_template_t)
RESERVED_BYTE = _ida_typeinf.RESERVED_BYTE
r"""
multifunctional purpose
"""


def is_type_const(t: "type_t") -> "bool":
    r"""
    is_type_const(t) -> bool
    See BTM_CONST.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_const(t)

def is_type_volatile(t: "type_t") -> "bool":
    r"""
    is_type_volatile(t) -> bool
    See BTM_VOLATILE.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_volatile(t)

def get_base_type(t: "type_t") -> "type_t":
    r"""
    get_base_type(t) -> type_t
    Get get basic type bits (TYPE_BASE_MASK)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.get_base_type(t)

def get_type_flags(t: "type_t") -> "type_t":
    r"""
    get_type_flags(t) -> type_t
    Get type flags (TYPE_FLAGS_MASK)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.get_type_flags(t)

def get_full_type(t: "type_t") -> "type_t":
    r"""
    get_full_type(t) -> type_t
    Get basic type bits + type flags (TYPE_FULL_MASK)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.get_full_type(t)

def is_typeid_last(t: "type_t") -> "bool":
    r"""
    is_typeid_last(t) -> bool
    Is the type_t the last byte of type declaration? (there are no additional bytes
    after a basic type, see _BT_LAST_BASIC)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_typeid_last(t)

def is_type_partial(t: "type_t") -> "bool":
    r"""
    is_type_partial(t) -> bool
    Identifies an unknown or void type with a known size (see Basic type: unknown &
    void)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_partial(t)

def is_type_void(t: "type_t") -> "bool":
    r"""
    is_type_void(t) -> bool
    See BTF_VOID.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_void(t)

def is_type_unknown(t: "type_t") -> "bool":
    r"""
    is_type_unknown(t) -> bool
    See BT_UNKNOWN.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_unknown(t)

def is_type_ptr(t: "type_t") -> "bool":
    r"""
    is_type_ptr(t) -> bool
    See BT_PTR.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_ptr(t)

def is_type_complex(t: "type_t") -> "bool":
    r"""
    is_type_complex(t) -> bool
    See BT_COMPLEX.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_complex(t)

def is_type_func(t: "type_t") -> "bool":
    r"""
    is_type_func(t) -> bool
    See BT_FUNC.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_func(t)

def is_type_array(t: "type_t") -> "bool":
    r"""
    is_type_array(t) -> bool
    See BT_ARRAY.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_array(t)

def is_type_typedef(t: "type_t") -> "bool":
    r"""
    is_type_typedef(t) -> bool
    See BTF_TYPEDEF.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_typedef(t)

def is_type_sue(t: "type_t") -> "bool":
    r"""
    is_type_sue(t) -> bool
    Is the type a struct/union/enum?

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_sue(t)

def is_type_struct(t: "type_t") -> "bool":
    r"""
    is_type_struct(t) -> bool
    See BTF_STRUCT.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_struct(t)

def is_type_union(t: "type_t") -> "bool":
    r"""
    is_type_union(t) -> bool
    See BTF_UNION.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_union(t)

def is_type_struni(t: "type_t") -> "bool":
    r"""
    is_type_struni(t) -> bool
    Is the type a struct or union?

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_struni(t)

def is_type_enum(t: "type_t") -> "bool":
    r"""
    is_type_enum(t) -> bool
    See BTF_ENUM.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_enum(t)

def is_type_bitfld(t: "type_t") -> "bool":
    r"""
    is_type_bitfld(t) -> bool
    See BT_BITFIELD.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_bitfld(t)

def is_type_int(bt: "type_t") -> "bool":
    r"""
    is_type_int(bt) -> bool
    Does the type_t specify one of the basic types in Basic type: integer?

    @param bt: (C++: type_t)
    """
    return _ida_typeinf.is_type_int(bt)

def is_type_int128(t: "type_t") -> "bool":
    r"""
    is_type_int128(t) -> bool
    Does the type specify a 128-bit value? (signed or unsigned, see Basic type:
    integer)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_int128(t)

def is_type_int64(t: "type_t") -> "bool":
    r"""
    is_type_int64(t) -> bool
    Does the type specify a 64-bit value? (signed or unsigned, see Basic type:
    integer)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_int64(t)

def is_type_int32(t: "type_t") -> "bool":
    r"""
    is_type_int32(t) -> bool
    Does the type specify a 32-bit value? (signed or unsigned, see Basic type:
    integer)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_int32(t)

def is_type_int16(t: "type_t") -> "bool":
    r"""
    is_type_int16(t) -> bool
    Does the type specify a 16-bit value? (signed or unsigned, see Basic type:
    integer)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_int16(t)

def is_type_char(t: "type_t") -> "bool":
    r"""
    is_type_char(t) -> bool
    Does the type specify a char value? (signed or unsigned, see Basic type:
    integer)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_char(t)

def is_type_paf(t: "type_t") -> "bool":
    r"""
    is_type_paf(t) -> bool
    Is the type a pointer, array, or function type?

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_paf(t)

def is_type_ptr_or_array(t: "type_t") -> "bool":
    r"""
    is_type_ptr_or_array(t) -> bool
    Is the type a pointer or array type?

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_ptr_or_array(t)

def is_type_floating(t: "type_t") -> "bool":
    r"""
    is_type_floating(t) -> bool
    Is the type a floating point type?

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_floating(t)

def is_type_integral(t: "type_t") -> "bool":
    r"""
    is_type_integral(t) -> bool
    Is the type an integral type (char/short/int/long/bool)?

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_integral(t)

def is_type_ext_integral(t: "type_t") -> "bool":
    r"""
    is_type_ext_integral(t) -> bool
    Is the type an extended integral type? (integral or enum)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_ext_integral(t)

def is_type_arithmetic(t: "type_t") -> "bool":
    r"""
    is_type_arithmetic(t) -> bool
    Is the type an arithmetic type? (floating or integral)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_arithmetic(t)

def is_type_ext_arithmetic(t: "type_t") -> "bool":
    r"""
    is_type_ext_arithmetic(t) -> bool
    Is the type an extended arithmetic type? (arithmetic or enum)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_ext_arithmetic(t)

def is_type_uint(t: "type_t") -> "bool":
    r"""
    is_type_uint(t) -> bool
    See BTF_UINT.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_uint(t)

def is_type_uchar(t: "type_t") -> "bool":
    r"""
    is_type_uchar(t) -> bool
    See BTF_UCHAR.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_uchar(t)

def is_type_uint16(t: "type_t") -> "bool":
    r"""
    is_type_uint16(t) -> bool
    See BTF_UINT16.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_uint16(t)

def is_type_uint32(t: "type_t") -> "bool":
    r"""
    is_type_uint32(t) -> bool
    See BTF_UINT32.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_uint32(t)

def is_type_uint64(t: "type_t") -> "bool":
    r"""
    is_type_uint64(t) -> bool
    See BTF_UINT64.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_uint64(t)

def is_type_uint128(t: "type_t") -> "bool":
    r"""
    is_type_uint128(t) -> bool
    See BTF_UINT128.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_uint128(t)

def is_type_ldouble(t: "type_t") -> "bool":
    r"""
    is_type_ldouble(t) -> bool
    See BTF_LDOUBLE.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_ldouble(t)

def is_type_double(t: "type_t") -> "bool":
    r"""
    is_type_double(t) -> bool
    See BTF_DOUBLE.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_double(t)

def is_type_float(t: "type_t") -> "bool":
    r"""
    is_type_float(t) -> bool
    See BTF_FLOAT.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_float(t)

def is_type_tbyte(t: "type_t") -> "bool":
    r"""
    is_type_tbyte(t) -> bool
    See BTF_FLOAT.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_tbyte(t)

def is_type_bool(t: "type_t") -> "bool":
    r"""
    is_type_bool(t) -> bool
    See BTF_BOOL.

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_type_bool(t)
TAH_BYTE = _ida_typeinf.TAH_BYTE
r"""
type attribute header byte
"""

FAH_BYTE = _ida_typeinf.FAH_BYTE
r"""
function argument attribute header byte
"""

MAX_DECL_ALIGN = _ida_typeinf.MAX_DECL_ALIGN

TAH_HASATTRS = _ida_typeinf.TAH_HASATTRS
r"""
has extended attributes
"""

TAUDT_UNALIGNED = _ida_typeinf.TAUDT_UNALIGNED
r"""
struct: unaligned struct
"""

TAUDT_MSSTRUCT = _ida_typeinf.TAUDT_MSSTRUCT
r"""
struct: gcc msstruct attribute
"""

TAUDT_CPPOBJ = _ida_typeinf.TAUDT_CPPOBJ
r"""
struct: a c++ object, not simple pod type
"""

TAUDT_VFTABLE = _ida_typeinf.TAUDT_VFTABLE
r"""
struct: is virtual function table
"""

TAUDT_FIXED = _ida_typeinf.TAUDT_FIXED
r"""
struct: fixed field offsets, stored in serialized form; cannot be set for unions
"""

TAFLD_BASECLASS = _ida_typeinf.TAFLD_BASECLASS
r"""
field: do not include but inherit from the current field
"""

TAFLD_UNALIGNED = _ida_typeinf.TAFLD_UNALIGNED
r"""
field: unaligned field
"""

TAFLD_VIRTBASE = _ida_typeinf.TAFLD_VIRTBASE
r"""
field: virtual base (not supported yet)
"""

TAFLD_VFTABLE = _ida_typeinf.TAFLD_VFTABLE
r"""
field: ptr to virtual function table
"""

TAFLD_METHOD = _ida_typeinf.TAFLD_METHOD
r"""
denotes a udt member function
"""

TAFLD_GAP = _ida_typeinf.TAFLD_GAP
r"""
field: gap member (displayed as padding in type details)
"""

TAFLD_REGCMT = _ida_typeinf.TAFLD_REGCMT
r"""
field: the comment is regular (if not set, it is repeatable)
"""

TAFLD_FRAME_R = _ida_typeinf.TAFLD_FRAME_R
r"""
frame: function return address frame slot
"""

TAFLD_FRAME_S = _ida_typeinf.TAFLD_FRAME_S
r"""
frame: function saved registers frame slot
"""

TAFLD_BYTIL = _ida_typeinf.TAFLD_BYTIL
r"""
field: was the member created due to the type system
"""

TAPTR_PTR32 = _ida_typeinf.TAPTR_PTR32
r"""
ptr: __ptr32
"""

TAPTR_PTR64 = _ida_typeinf.TAPTR_PTR64
r"""
ptr: __ptr64
"""

TAPTR_RESTRICT = _ida_typeinf.TAPTR_RESTRICT
r"""
ptr: __restrict
"""

TAPTR_SHIFTED = _ida_typeinf.TAPTR_SHIFTED
r"""
ptr: __shifted(parent_struct, delta)
"""

TAENUM_64BIT = _ida_typeinf.TAENUM_64BIT
r"""
enum: store 64-bit values
"""

TAENUM_UNSIGNED = _ida_typeinf.TAENUM_UNSIGNED
r"""
enum: unsigned
"""

TAENUM_SIGNED = _ida_typeinf.TAENUM_SIGNED
r"""
enum: signed
"""

TAENUM_OCT = _ida_typeinf.TAENUM_OCT
r"""
enum: octal representation, if BTE_HEX
"""

TAENUM_BIN = _ida_typeinf.TAENUM_BIN
r"""
enum: binary representation, if BTE_HEX only one of OCT/BIN bits can be set.
they are meaningful only if BTE_HEX is used.
"""

TAENUM_NUMSIGN = _ida_typeinf.TAENUM_NUMSIGN
r"""
enum: signed representation, if BTE_HEX
"""

TAENUM_LZERO = _ida_typeinf.TAENUM_LZERO
r"""
enum: print numbers with leading zeroes (only for HEX/OCT/BIN)
"""

TAH_ALL = _ida_typeinf.TAH_ALL
r"""
all defined bits
"""


def is_tah_byte(t: "type_t") -> "bool":
    r"""
    is_tah_byte(t) -> bool
    The TAH byte (type attribute header byte) denotes the start of type attributes.
    (see "tah-typeattrs" in the type bit definitions)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_tah_byte(t)

def is_sdacl_byte(t: "type_t") -> "bool":
    r"""
    is_sdacl_byte(t) -> bool
    Identify an sdacl byte. The first sdacl byte has the following format: 11xx000x.
    The sdacl bytes are appended to udt fields. They indicate the start of type
    attributes (as the tah-bytes do). The sdacl bytes are used in the udt headers
    instead of the tah-byte. This is done for compatibility with old databases, they
    were already using sdacl bytes in udt headers and as udt field postfixes. (see
    "sdacl-typeattrs" in the type bit definitions)

    @param t: (C++: type_t)
    """
    return _ida_typeinf.is_sdacl_byte(t)
class type_attr_t(object):
    r"""
    Proxy of C++ type_attr_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    key: "qstring" = property(_ida_typeinf.type_attr_t_key_get, _ida_typeinf.type_attr_t_key_set, doc=r"""key""")
    r"""
    one symbol keys are reserved to be used by the kernel the ones starting with an
    underscore are reserved too
    """
    value: "bytevec_t" = property(_ida_typeinf.type_attr_t_value_get, _ida_typeinf.type_attr_t_value_set, doc=r"""value""")
    r"""
    attribute bytes
    """

    def __lt__(self, r: "type_attr_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: type_attr_t const &
        """
        return _ida_typeinf.type_attr_t___lt__(self, r)

    def __ge__(self, r: "type_attr_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: type_attr_t const &
        """
        return _ida_typeinf.type_attr_t___ge__(self, r)

    def __init__(self):
        r"""
        __init__(self) -> type_attr_t
        """
        _ida_typeinf.type_attr_t_swiginit(self, _ida_typeinf.new_type_attr_t())
    __swig_destroy__ = _ida_typeinf.delete_type_attr_t

# Register type_attr_t in _ida_typeinf:
_ida_typeinf.type_attr_t_swigregister(type_attr_t)
cvar = _ida_typeinf.cvar
TYPE_BASE_MASK = cvar.TYPE_BASE_MASK
r"""
the low 4 bits define the basic type
"""
TYPE_FLAGS_MASK = cvar.TYPE_FLAGS_MASK
r"""
type flags - they have different meaning depending on the basic type
"""
TYPE_MODIF_MASK = cvar.TYPE_MODIF_MASK
r"""
modifiers.
* for BT_ARRAY see Derived type: array
* BT_VOID can have them ONLY in 'void *'
"""
TYPE_FULL_MASK = cvar.TYPE_FULL_MASK
r"""
basic type with type flags
"""
BT_UNK = cvar.BT_UNK
r"""
unknown
"""
BT_VOID = cvar.BT_VOID
r"""
void
"""
BTMT_SIZE0 = cvar.BTMT_SIZE0
r"""
BT_VOID - normal void; BT_UNK - don't use
"""
BTMT_SIZE12 = cvar.BTMT_SIZE12
r"""
size = 1 byte if BT_VOID; 2 if BT_UNK
"""
BTMT_SIZE48 = cvar.BTMT_SIZE48
r"""
size = 4 bytes if BT_VOID; 8 if BT_UNK
"""
BTMT_SIZE128 = cvar.BTMT_SIZE128
r"""
size = 16 bytes if BT_VOID; unknown if BT_UNK (IN struct alignment - see below)
"""
BT_INT8 = cvar.BT_INT8
r"""
__int8
"""
BT_INT16 = cvar.BT_INT16
r"""
__int16
"""
BT_INT32 = cvar.BT_INT32
r"""
__int32
"""
BT_INT64 = cvar.BT_INT64
r"""
__int64
"""
BT_INT128 = cvar.BT_INT128
r"""
__int128 (for alpha & future use)
"""
BT_INT = cvar.BT_INT
r"""
natural int. (size provided by idp module)
"""
BTMT_UNKSIGN = cvar.BTMT_UNKSIGN
r"""
unknown signedness
"""
BTMT_SIGNED = cvar.BTMT_SIGNED
r"""
signed
"""
BTMT_USIGNED = cvar.BTMT_USIGNED
r"""
unsigned
"""
BTMT_UNSIGNED = cvar.BTMT_UNSIGNED
BTMT_CHAR = cvar.BTMT_CHAR
r"""
specify char or segment register
* BT_INT8 - char
* BT_INT - segment register
* other BT_INT... - don't use
"""
BT_BOOL = cvar.BT_BOOL
r"""
bool
"""
BTMT_DEFBOOL = cvar.BTMT_DEFBOOL
r"""
size is model specific or unknown(?)
"""
BTMT_BOOL1 = cvar.BTMT_BOOL1
r"""
size 1byte
"""
BTMT_BOOL2 = cvar.BTMT_BOOL2
r"""
size 2bytes - !inf_is_64bit()
"""
BTMT_BOOL8 = cvar.BTMT_BOOL8
r"""
size 8bytes - inf_is_64bit()
"""
BTMT_BOOL4 = cvar.BTMT_BOOL4
r"""
size 4bytes
"""
BT_FLOAT = cvar.BT_FLOAT
r"""
float
"""
BTMT_FLOAT = cvar.BTMT_FLOAT
r"""
float (4 bytes)
"""
BTMT_DOUBLE = cvar.BTMT_DOUBLE
r"""
double (8 bytes)
"""
BTMT_LNGDBL = cvar.BTMT_LNGDBL
r"""
long double (compiler specific)
"""
BTMT_SPECFLT = cvar.BTMT_SPECFLT
r"""
float (variable size). if processor_t::use_tbyte() then use
processor_t::tbyte_size, otherwise 2 bytes
"""
_BT_LAST_BASIC = cvar._BT_LAST_BASIC
r"""
the last basic type, all basic types may be followed by [tah-typeattrs]
"""
BT_PTR = cvar.BT_PTR
r"""
pointer. has the following format: [db sizeof(ptr)]; [tah-typeattrs]; type_t...
"""
BTMT_DEFPTR = cvar.BTMT_DEFPTR
r"""
default for model
"""
BTMT_NEAR = cvar.BTMT_NEAR
r"""
near
"""
BTMT_FAR = cvar.BTMT_FAR
r"""
far
"""
BTMT_CLOSURE = cvar.BTMT_CLOSURE
r"""
closure.
* if ptr to BT_FUNC - __closure. in this case next byte MUST be RESERVED_BYTE,
and after it BT_FUNC
* else the next byte contains sizeof(ptr) allowed values are 1 - ph.max_ptr_size
* if value is bigger than ph.max_ptr_size, based_ptr_name_and_size() is called
to find out the typeinfo
"""
BT_ARRAY = cvar.BT_ARRAY
r"""
array
"""
BTMT_NONBASED = cvar.BTMT_NONBASED
r"""
if set
array base==0
format: dt num_elem; [tah-typeattrs]; type_t...
if num_elem==0 then the array size is unknown
else
format: da num_elem, base; [tah-typeattrs]; type_t...
used only for serialization
"""
BTMT_ARRESERV = cvar.BTMT_ARRESERV
r"""
reserved bit
"""
BT_FUNC = cvar.BT_FUNC
r"""
function. format:
optional: CM_CC_SPOILED | num_of_spoiled_regs
                if num_of_spoiled_reg == BFA_FUNC_MARKER:
                  ::bfa_byte
                  if (bfa_byte & BFA_FUNC_EXT_FORMAT) != 0
                   ::fti_bits (only low bits: FTI_SPOILED,...,FTI_VIRTUAL)
                   num_of_spoiled_reg times: spoiled reg info (see
extract_spoiledreg)
                  else
                    bfa_byte is function attribute byte (see Function attribute
byte...)
                else:
                  num_of_spoiled_reg times: spoiled reg info (see
extract_spoiledreg)
      cm_t ... calling convention and memory model
      [tah-typeattrs];
      type_t ... return type;
      [serialized argloc_t of returned value (if CM_CC_SPECIAL{PE} && !return
void);
      if !CM_CC_VOIDARG:
        dt N (N=number of parameters)
        if ( N == 0 )
        if CM_CC_ELLIPSIS or CM_CC_SPECIALE
            func(...)
          else
            parameters are unknown
        else
          N records:
            type_t ... (i.e. type of each parameter)
            [serialized argloc_t (if CM_CC_SPECIAL{PE})] (i.e. place of each
parameter)
            [FAH_BYTE + de( funcarg_t::flags )]
"""
BTMT_DEFCALL = cvar.BTMT_DEFCALL
r"""
call method - default for model or unknown
"""
BTMT_NEARCALL = cvar.BTMT_NEARCALL
r"""
function returns by retn
"""
BTMT_FARCALL = cvar.BTMT_FARCALL
r"""
function returns by retf
"""
BTMT_INTCALL = cvar.BTMT_INTCALL
r"""
function returns by iret in this case cc MUST be 'unknown'
"""
BT_COMPLEX = cvar.BT_COMPLEX
r"""
struct/union/enum/typedef. format:
[dt N (N=field count) if !BTMT_TYPEDEF]
       if N == 0:
         p_string name (unnamed types have names "anon_...")
         [sdacl-typeattrs];
       else, for struct & union:
         if N == 0x7FFE   // Support for high (i.e., > 4095) members count
           N = deserialize_de()
         ALPOW = N & 0x7
         MCNT = N >> 3
         if MCNT == 0
           empty struct
         if ALPOW == 0
           ALIGN = get_default_align()
         else
           ALIGN = (1 << (ALPOW - 1))
         [sdacl-typeattrs];
       else, for enums:
         if N == 0x7FFE   // Support for high enum entries count.
           N = deserialize_de()
         [tah-typeattrs];
"""
BTMT_STRUCT = cvar.BTMT_STRUCT
r"""
struct: MCNT records: type_t; [sdacl-typeattrs];
"""
BTMT_UNION = cvar.BTMT_UNION
r"""
union: MCNT records: type_t...
"""
BTMT_ENUM = cvar.BTMT_ENUM
r"""
enum: next byte bte_t (see below) N records: de delta(s) OR blocks (see below)
"""
BTMT_TYPEDEF = cvar.BTMT_TYPEDEF
r"""
named reference always p_string name
"""
BT_BITFIELD = cvar.BT_BITFIELD
r"""
bitfield (only in struct) ['bitmasked' enum see below] next byte is dt ((size in
bits << 1) | (unsigned ? 1 : 0))
"""
BTMT_BFLDI8 = cvar.BTMT_BFLDI8
r"""
__int8
"""
BTMT_BFLDI16 = cvar.BTMT_BFLDI16
r"""
__int16
"""
BTMT_BFLDI32 = cvar.BTMT_BFLDI32
r"""
__int32
"""
BTMT_BFLDI64 = cvar.BTMT_BFLDI64
r"""
__int64
"""
BT_RESERVED = cvar.BT_RESERVED
r"""
RESERVED.
"""
BTM_CONST = cvar.BTM_CONST
r"""
const
"""
BTM_VOLATILE = cvar.BTM_VOLATILE
r"""
volatile
"""
BTE_SIZE_MASK = cvar.BTE_SIZE_MASK
r"""
storage size.
* if == 0 then inf_get_cc_size_e()
* else 1 << (n -1) = 1,2,4,8
* n == 5,6,7 are reserved
"""
BTE_RESERVED = cvar.BTE_RESERVED
r"""
must be 0, in order to distinguish from a tah-byte
"""
BTE_BITMASK = cvar.BTE_BITMASK
r"""
'subarrays'. In this case ANY record has the following format:
* 'de' mask (has name)
* 'dt' cnt
* cnt records of 'de' values (cnt CAN be 0)
@note: delta for ALL subsegment is ONE
"""
BTE_OUT_MASK = cvar.BTE_OUT_MASK
r"""
output style mask
"""
BTE_HEX = cvar.BTE_HEX
r"""
hex
"""
BTE_CHAR = cvar.BTE_CHAR
r"""
char or hex
"""
BTE_SDEC = cvar.BTE_SDEC
r"""
signed decimal
"""
BTE_UDEC = cvar.BTE_UDEC
r"""
unsigned decimal
"""
BTE_ALWAYS = cvar.BTE_ALWAYS
r"""
this bit MUST be present
"""
BT_SEGREG = cvar.BT_SEGREG
r"""
segment register
"""
BT_UNK_BYTE = cvar.BT_UNK_BYTE
r"""
1 byte
"""
BT_UNK_WORD = cvar.BT_UNK_WORD
r"""
2 bytes
"""
BT_UNK_DWORD = cvar.BT_UNK_DWORD
r"""
4 bytes
"""
BT_UNK_QWORD = cvar.BT_UNK_QWORD
r"""
8 bytes
"""
BT_UNK_OWORD = cvar.BT_UNK_OWORD
r"""
16 bytes
"""
BT_UNKNOWN = cvar.BT_UNKNOWN
r"""
unknown size - for parameters
"""
BTF_BYTE = cvar.BTF_BYTE
r"""
byte
"""
BTF_UNK = cvar.BTF_UNK
r"""
unknown
"""
BTF_VOID = cvar.BTF_VOID
r"""
void
"""
BTF_INT8 = cvar.BTF_INT8
r"""
signed byte
"""
BTF_CHAR = cvar.BTF_CHAR
r"""
signed char
"""
BTF_UCHAR = cvar.BTF_UCHAR
r"""
unsigned char
"""
BTF_UINT8 = cvar.BTF_UINT8
r"""
unsigned byte
"""
BTF_INT16 = cvar.BTF_INT16
r"""
signed short
"""
BTF_UINT16 = cvar.BTF_UINT16
r"""
unsigned short
"""
BTF_INT32 = cvar.BTF_INT32
r"""
signed int
"""
BTF_UINT32 = cvar.BTF_UINT32
r"""
unsigned int
"""
BTF_INT64 = cvar.BTF_INT64
r"""
signed long
"""
BTF_UINT64 = cvar.BTF_UINT64
r"""
unsigned long
"""
BTF_INT128 = cvar.BTF_INT128
r"""
signed 128-bit value
"""
BTF_UINT128 = cvar.BTF_UINT128
r"""
unsigned 128-bit value
"""
BTF_INT = cvar.BTF_INT
r"""
int, unknown signedness
"""
BTF_UINT = cvar.BTF_UINT
r"""
unsigned int
"""
BTF_SINT = cvar.BTF_SINT
r"""
singed int
"""
BTF_BOOL = cvar.BTF_BOOL
r"""
boolean
"""
BTF_FLOAT = cvar.BTF_FLOAT
r"""
float
"""
BTF_DOUBLE = cvar.BTF_DOUBLE
r"""
double
"""
BTF_LDOUBLE = cvar.BTF_LDOUBLE
r"""
long double
"""
BTF_TBYTE = cvar.BTF_TBYTE
r"""
see BTMT_SPECFLT
"""
BTF_STRUCT = cvar.BTF_STRUCT
r"""
struct
"""
BTF_UNION = cvar.BTF_UNION
r"""
union
"""
BTF_ENUM = cvar.BTF_ENUM
r"""
enum
"""
BTF_TYPEDEF = cvar.BTF_TYPEDEF
r"""
typedef
"""
TA_ORG_TYPEDEF = _ida_typeinf.TA_ORG_TYPEDEF
r"""
the original typedef name (simple string)
"""

TA_ORG_ARRDIM = _ida_typeinf.TA_ORG_ARRDIM
r"""
the original array dimension (pack_dd)
"""

TA_FORMAT = _ida_typeinf.TA_FORMAT
r"""
info about the 'format' argument. 3 times pack_dd: format_functype_t, argument
number of 'format', argument number of '...'
"""

TA_VALUE_REPR = _ida_typeinf.TA_VALUE_REPR
r"""
serialized value_repr_t (used for scalars and arrays)
"""



def append_argloc(out: "qtype *", vloc: "argloc_t") -> "bool":
    r"""
    append_argloc(out, vloc) -> bool
    Serialize argument location

    @param out: (C++: qtype *)
    @param vloc: (C++: const argloc_t &) argloc_t const &
    """
    return _ida_typeinf.append_argloc(out, vloc)

def extract_argloc(vloc: "argloc_t", ptype: "type_t const **", forbid_stkoff: "bool") -> "bool":
    r"""
    extract_argloc(vloc, ptype, forbid_stkoff) -> bool
    Deserialize an argument location. Argument FORBID_STKOFF checks location type.
    It can be used, for example, to check the return location of a function that
    cannot return a value in the stack

    @param vloc: (C++: argloc_t *)
    @param ptype: (C++: const type_t **) type_t const **
    @param forbid_stkoff: (C++: bool)
    """
    return _ida_typeinf.extract_argloc(vloc, ptype, forbid_stkoff)

def resolve_typedef(til: "til_t", type: "type_t const *") -> "type_t const *":
    r"""
    resolve_typedef(til, type) -> type_t const *

    @param til: til_t const *
    @param type: type_t const *
    """
    return _ida_typeinf.resolve_typedef(til, type)

def is_restype_void(til: "til_t", type: "type_t const *") -> "bool":
    r"""
    is_restype_void(til, type) -> bool

    @param til: til_t const *
    @param type: type_t const *
    """
    return _ida_typeinf.is_restype_void(til, type)

def is_restype_enum(til: "til_t", type: "type_t const *") -> "bool":
    r"""
    is_restype_enum(til, type) -> bool

    @param til: til_t const *
    @param type: type_t const *
    """
    return _ida_typeinf.is_restype_enum(til, type)

def is_restype_struni(til: "til_t", type: "type_t const *") -> "bool":
    r"""
    is_restype_struni(til, type) -> bool

    @param til: til_t const *
    @param type: type_t const *
    """
    return _ida_typeinf.is_restype_struni(til, type)

def is_restype_struct(til: "til_t", type: "type_t const *") -> "bool":
    r"""
    is_restype_struct(til, type) -> bool

    @param til: til_t const *
    @param type: type_t const *
    """
    return _ida_typeinf.is_restype_struct(til, type)

def get_scalar_bt(size: "int") -> "type_t":
    r"""
    get_scalar_bt(size) -> type_t

    @param size: int
    """
    return _ida_typeinf.get_scalar_bt(size)
class til_t(object):
    r"""
    Proxy of C++ til_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    name: "char *" = property(_ida_typeinf.til_t_name_get, _ida_typeinf.til_t_name_set, doc=r"""name""")
    r"""
    short file name (without path and extension)
    """
    desc: "char *" = property(_ida_typeinf.til_t_desc_get, _ida_typeinf.til_t_desc_set, doc=r"""desc""")
    r"""
    human readable til description
    """
    nbases: "int" = property(_ida_typeinf.til_t_nbases_get, _ida_typeinf.til_t_nbases_set, doc=r"""nbases""")
    r"""
    number of base tils
    """
    flags: "uint32" = property(_ida_typeinf.til_t_flags_get, _ida_typeinf.til_t_flags_set, doc=r"""flags""")
    r"""
    Type info library property bits
    """

    def is_dirty(self) -> "bool":
        r"""
        is_dirty(self) -> bool
        Has the til been modified? (TIL_MOD)
        """
        return _ida_typeinf.til_t_is_dirty(self)

    def set_dirty(self) -> "void":
        r"""
        set_dirty(self)
        Mark the til as modified (TIL_MOD)
        """
        return _ida_typeinf.til_t_set_dirty(self)

    def find_base(self, n: "char const *") -> "til_t *":
        r"""
        find_base(self, n) -> til_t
        Find the base til with the provided name

        @param n: (C++: const char *) the base til name
        @return: the found til_t, or nullptr
        """
        return _ida_typeinf.til_t_find_base(self, n)
    cc: "compiler_info_t" = property(_ida_typeinf.til_t_cc_get, _ida_typeinf.til_t_cc_set, doc=r"""cc""")
    r"""
    information about the target compiler
    """
    nrefs: "int" = property(_ida_typeinf.til_t_nrefs_get, _ida_typeinf.til_t_nrefs_set, doc=r"""nrefs""")
    r"""
    number of references to the til
    """
    nstreams: "int" = property(_ida_typeinf.til_t_nstreams_get, _ida_typeinf.til_t_nstreams_set, doc=r"""nstreams""")
    r"""
    number of extra streams
    """
    streams: "til_stream_t **" = property(_ida_typeinf.til_t_streams_get, _ida_typeinf.til_t_streams_set, doc=r"""streams""")
    r"""
    symbol stream storage
    """

    def base(self, n: "int") -> "til_t *":
        r"""
        base(self, n) -> til_t
        tils that our til is based on

        @param n: int
        """
        return _ida_typeinf.til_t_base(self, n)

    def get_type_names(self):
        n = first_named_type(self, NTF_TYPE)
        while n:
            yield n
            n = next_named_type(self, n, NTF_TYPE)

    type_names = property(get_type_names)


    def __init__(self):
        r"""
        __init__(self) -> til_t
        """
        _ida_typeinf.til_t_swiginit(self, _ida_typeinf.new_til_t())
    __swig_destroy__ = _ida_typeinf.delete_til_t

# Register til_t in _ida_typeinf:
_ida_typeinf.til_t_swigregister(til_t)
no_sign = cvar.no_sign
r"""
no sign, or unknown
"""
type_signed = cvar.type_signed
r"""
signed type
"""
type_unsigned = cvar.type_unsigned
r"""
unsigned type
"""
TIL_ZIP = _ida_typeinf.TIL_ZIP
r"""
pack buckets using zip
"""

TIL_MAC = _ida_typeinf.TIL_MAC
r"""
til has macro table
"""

TIL_ESI = _ida_typeinf.TIL_ESI
r"""
extended sizeof info (short, long, longlong)
"""

TIL_UNI = _ida_typeinf.TIL_UNI
r"""
universal til for any compiler
"""

TIL_ORD = _ida_typeinf.TIL_ORD
r"""
type ordinal numbers are present
"""

TIL_ALI = _ida_typeinf.TIL_ALI
r"""
type aliases are present (this bit is used only on the disk)
"""

TIL_MOD = _ida_typeinf.TIL_MOD
r"""
til has been modified, should be saved
"""

TIL_STM = _ida_typeinf.TIL_STM
r"""
til has extra streams
"""

TIL_SLD = _ida_typeinf.TIL_SLD
r"""
sizeof(long double)
"""



def new_til(name: "char const *", desc: "char const *") -> "til_t *":
    r"""
    new_til(name, desc) -> til_t
    Initialize a til.

    @param name: (C++: const char *) char const *
    @param desc: (C++: const char *) char const *
    """
    return _ida_typeinf.new_til(name, desc)
TIL_ADD_FAILED = _ida_typeinf.TIL_ADD_FAILED
r"""
see errbuf
"""

TIL_ADD_OK = _ida_typeinf.TIL_ADD_OK
r"""
some tils were added
"""

TIL_ADD_ALREADY = _ida_typeinf.TIL_ADD_ALREADY
r"""
the base til was already added
"""


def load_til(name: "char const *", tildir: "char const *"=None) -> "qstring *":
    r"""
    load_til(name, tildir=None) -> til_t
    Load til from a file without adding it to the database list (see also add_til).
    Failure to load base tils are reported into 'errbuf'. They do not prevent
    loading of the main til.

    @param name: (C++: const char *) filename of the til. If it's an absolute path, tildir is ignored.
    * NB: the file extension is forced to .til
    @param tildir: (C++: const char *) directory where to load the til from. nullptr means default til
                   subdirectories.
    @return: pointer to resulting til, nullptr if failed and error message is in
             errbuf
    """
    return _ida_typeinf.load_til(name, tildir)

def compact_til(ti: "til_t") -> "bool":
    r"""
    compact_til(ti) -> bool
    Collect garbage in til. Must be called before storing the til.

    @param ti: (C++: til_t *)
    @return: true if any memory was freed
    """
    return _ida_typeinf.compact_til(ti)

def store_til(ti: "til_t", tildir: "char const *", name: "char const *") -> "bool":
    r"""
    store_til(ti, tildir, name) -> bool
    Store til to a file. If the til contains garbage, it will be collected before
    storing the til. Your plugin should call compact_til() before calling
    store_til().

    @param ti: (C++: til_t *) type library to store
    @param tildir: (C++: const char *) directory where to store the til. nullptr means current
                   directory.
    @param name: (C++: const char *) filename of the til. If it's an absolute path, tildir is ignored.
    * NB: the file extension is forced to .til
    @return: success
    """
    return _ida_typeinf.store_til(ti, tildir, name)

def free_til(ti: "til_t") -> "void":
    r"""
    free_til(ti)
    Free memory allocated by til.

    @param ti: (C++: til_t *)
    """
    return _ida_typeinf.free_til(ti)

def load_til_header(tildir: "char const *", name: "char const *") -> "qstring *":
    r"""
    load_til_header(tildir, name) -> til_t
    Get human-readable til description.

    @param tildir: (C++: const char *) char const *
    @param name: (C++: const char *) char const *
    """
    return _ida_typeinf.load_til_header(tildir, name)

def is_code_far(cm: "cm_t") -> "bool":
    r"""
    is_code_far(cm) -> bool
    Does the given model specify far code?.

    @param cm: (C++: cm_t)
    """
    return _ida_typeinf.is_code_far(cm)

def is_data_far(cm: "cm_t") -> "bool":
    r"""
    is_data_far(cm) -> bool
    Does the given model specify far data?.

    @param cm: (C++: cm_t)
    """
    return _ida_typeinf.is_data_far(cm)
class rrel_t(object):
    r"""
    Proxy of C++ rrel_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    off: "sval_t" = property(_ida_typeinf.rrel_t_off_get, _ida_typeinf.rrel_t_off_set, doc=r"""off""")
    r"""
    displacement from the address pointed by the register
    """
    reg: "int" = property(_ida_typeinf.rrel_t_reg_get, _ida_typeinf.rrel_t_reg_set, doc=r"""reg""")
    r"""
    register index (into ph.reg_names)
    """

    def __init__(self):
        r"""
        __init__(self) -> rrel_t
        """
        _ida_typeinf.rrel_t_swiginit(self, _ida_typeinf.new_rrel_t())
    __swig_destroy__ = _ida_typeinf.delete_rrel_t

# Register rrel_t in _ida_typeinf:
_ida_typeinf.rrel_t_swigregister(rrel_t)
CM_MASK = cvar.CM_MASK
CM_UNKNOWN = cvar.CM_UNKNOWN
r"""
unknown
"""
CM_N8_F16 = cvar.CM_N8_F16
r"""
if sizeof(int)<=2: near 1 byte, far 2 bytes
"""
CM_N64 = cvar.CM_N64
r"""
if sizeof(int)>2: near 8 bytes, far 8 bytes
"""
CM_N16_F32 = cvar.CM_N16_F32
r"""
near 2 bytes, far 4 bytes
"""
CM_N32_F48 = cvar.CM_N32_F48
r"""
near 4 bytes, far 6 bytes
"""
CM_M_MASK = cvar.CM_M_MASK
CM_M_NN = cvar.CM_M_NN
r"""
small: code=near, data=near (or unknown if CM_UNKNOWN)
"""
CM_M_FF = cvar.CM_M_FF
r"""
large: code=far, data=far
"""
CM_M_NF = cvar.CM_M_NF
r"""
compact: code=near, data=far
"""
CM_M_FN = cvar.CM_M_FN
r"""
medium: code=far, data=near
"""
CM_CC_MASK = cvar.CM_CC_MASK
CM_CC_INVALID = cvar.CM_CC_INVALID
r"""
this value is invalid
"""
CM_CC_UNKNOWN = cvar.CM_CC_UNKNOWN
r"""
unknown calling convention
"""
CM_CC_VOIDARG = cvar.CM_CC_VOIDARG
r"""
function without arguments if has other cc and argnum == 0, represent as f() -
unknown list
"""
CM_CC_CDECL = cvar.CM_CC_CDECL
r"""
stack
"""
CM_CC_ELLIPSIS = cvar.CM_CC_ELLIPSIS
r"""
cdecl + ellipsis
"""
CM_CC_STDCALL = cvar.CM_CC_STDCALL
r"""
stack, purged
"""
CM_CC_PASCAL = cvar.CM_CC_PASCAL
r"""
stack, purged, reverse order of args
"""
CM_CC_FASTCALL = cvar.CM_CC_FASTCALL
r"""
stack, purged (x86), first args are in regs (compiler-dependent)
"""
CM_CC_THISCALL = cvar.CM_CC_THISCALL
r"""
stack, purged (x86), first arg is in reg (compiler-dependent)
"""
CM_CC_SWIFT = cvar.CM_CC_SWIFT
r"""
(Swift) arguments and return values in registers (compiler-dependent)
"""
CM_CC_SPOILED = cvar.CM_CC_SPOILED
r"""
This is NOT a cc! Mark of __spoil record the low nibble is count and after n
{spoilreg_t} present real cm_t byte. if n == BFA_FUNC_MARKER, the next byte is
the function attribute byte.
"""
CM_CC_GOLANG = cvar.CM_CC_GOLANG
r"""
(Go) arguments and return value in stack
"""
CM_CC_RESERVE3 = cvar.CM_CC_RESERVE3
CM_CC_SPECIALE = cvar.CM_CC_SPECIALE
r"""
CM_CC_SPECIAL with ellipsis
"""
CM_CC_SPECIALP = cvar.CM_CC_SPECIALP
r"""
Equal to CM_CC_SPECIAL, but with purged stack.
"""
CM_CC_SPECIAL = cvar.CM_CC_SPECIAL
r"""
usercall: locations of all arguments and the return value are explicitly
specified
"""
BFA_NORET = cvar.BFA_NORET
r"""
__noreturn
"""
BFA_PURE = cvar.BFA_PURE
r"""
__pure
"""
BFA_HIGH = cvar.BFA_HIGH
r"""
high level prototype (with possibly hidden args)
"""
BFA_STATIC = cvar.BFA_STATIC
r"""
static
"""
BFA_VIRTUAL = cvar.BFA_VIRTUAL
r"""
virtual
"""
BFA_FUNC_MARKER = cvar.BFA_FUNC_MARKER
r"""
This is NOT a cc! (used internally as a marker)
"""
BFA_FUNC_EXT_FORMAT = cvar.BFA_FUNC_EXT_FORMAT
r"""
This is NOT a real attribute (used internally as marker for extended format)
"""
ALOC_NONE = cvar.ALOC_NONE
r"""
none
"""
ALOC_STACK = cvar.ALOC_STACK
r"""
stack offset
"""
ALOC_DIST = cvar.ALOC_DIST
r"""
distributed (scattered)
"""
ALOC_REG1 = cvar.ALOC_REG1
r"""
one register (and offset within it)
"""
ALOC_REG2 = cvar.ALOC_REG2
r"""
register pair
"""
ALOC_RREL = cvar.ALOC_RREL
r"""
register relative
"""
ALOC_STATIC = cvar.ALOC_STATIC
r"""
global address
"""
ALOC_CUSTOM = cvar.ALOC_CUSTOM
r"""
custom argloc (7 or higher)
"""

class argloc_t(object):
    r"""
    Proxy of C++ argloc_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> argloc_t
        __init__(self, r) -> argloc_t

        @param r: argloc_t const &
        """
        _ida_typeinf.argloc_t_swiginit(self, _ida_typeinf.new_argloc_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_argloc_t

    def swap(self, r: "argloc_t") -> "void":
        r"""
        swap(self, r)
        Assign this == r and r == this.

        @param r: (C++: argloc_t &)
        """
        return _ida_typeinf.argloc_t_swap(self, r)

    def atype(self) -> "argloc_type_t":
        r"""
        atype(self) -> argloc_type_t
        Get type (Argument location types)
        """
        return _ida_typeinf.argloc_t_atype(self)

    def is_reg1(self) -> "bool":
        r"""
        is_reg1(self) -> bool
        See ALOC_REG1.
        """
        return _ida_typeinf.argloc_t_is_reg1(self)

    def is_reg2(self) -> "bool":
        r"""
        is_reg2(self) -> bool
        See ALOC_REG2.
        """
        return _ida_typeinf.argloc_t_is_reg2(self)

    def is_reg(self) -> "bool":
        r"""
        is_reg(self) -> bool
        is_reg1() || is_reg2()
        """
        return _ida_typeinf.argloc_t_is_reg(self)

    def is_rrel(self) -> "bool":
        r"""
        is_rrel(self) -> bool
        See ALOC_RREL.
        """
        return _ida_typeinf.argloc_t_is_rrel(self)

    def is_ea(self) -> "bool":
        r"""
        is_ea(self) -> bool
        See ALOC_STATIC.
        """
        return _ida_typeinf.argloc_t_is_ea(self)

    def is_stkoff(self) -> "bool":
        r"""
        is_stkoff(self) -> bool
        See ALOC_STACK.
        """
        return _ida_typeinf.argloc_t_is_stkoff(self)

    def is_scattered(self) -> "bool":
        r"""
        is_scattered(self) -> bool
        See ALOC_DIST.
        """
        return _ida_typeinf.argloc_t_is_scattered(self)

    def has_reg(self) -> "bool":
        r"""
        has_reg(self) -> bool
        TRUE if argloc has a register part.
        """
        return _ida_typeinf.argloc_t_has_reg(self)

    def has_stkoff(self) -> "bool":
        r"""
        has_stkoff(self) -> bool
        TRUE if argloc has a stack part.
        """
        return _ida_typeinf.argloc_t_has_stkoff(self)

    def is_mixed_scattered(self) -> "bool":
        r"""
        is_mixed_scattered(self) -> bool
        mixed scattered: consists of register and stack parts
        """
        return _ida_typeinf.argloc_t_is_mixed_scattered(self)

    def in_stack(self) -> "bool":
        r"""
        in_stack(self) -> bool
        TRUE if argloc is in stack entirely.
        """
        return _ida_typeinf.argloc_t_in_stack(self)

    def is_fragmented(self) -> "bool":
        r"""
        is_fragmented(self) -> bool
        is_scattered() || is_reg2()
        """
        return _ida_typeinf.argloc_t_is_fragmented(self)

    def is_custom(self) -> "bool":
        r"""
        is_custom(self) -> bool
        See ALOC_CUSTOM.
        """
        return _ida_typeinf.argloc_t_is_custom(self)

    def is_badloc(self) -> "bool":
        r"""
        is_badloc(self) -> bool
        See ALOC_NONE.
        """
        return _ida_typeinf.argloc_t_is_badloc(self)

    def reg1(self) -> "int":
        r"""
        reg1(self) -> int
        Get the register info. Use when atype() == ALOC_REG1 or ALOC_REG2
        """
        return _ida_typeinf.argloc_t_reg1(self)

    def regoff(self) -> "int":
        r"""
        regoff(self) -> int
        Get offset from the beginning of the register in bytes. Use when atype() ==
        ALOC_REG1
        """
        return _ida_typeinf.argloc_t_regoff(self)

    def reg2(self) -> "int":
        r"""
        reg2(self) -> int
        Get info for the second register. Use when atype() == ALOC_REG2
        """
        return _ida_typeinf.argloc_t_reg2(self)

    def get_reginfo(self) -> "uint32":
        r"""
        get_reginfo(self) -> uint32
        Get all register info. Use when atype() == ALOC_REG1 or ALOC_REG2
        """
        return _ida_typeinf.argloc_t_get_reginfo(self)

    def stkoff(self) -> "sval_t":
        r"""
        stkoff(self) -> sval_t
        Get the stack offset. Use if atype() == ALOC_STACK
        """
        return _ida_typeinf.argloc_t_stkoff(self)

    def get_ea(self) -> "ea_t":
        r"""
        get_ea(self) -> ea_t
        Get the global address. Use when atype() == ALOC_STATIC
        """
        return _ida_typeinf.argloc_t_get_ea(self)

    def scattered(self, *args) -> "scattered_aloc_t const &":
        r"""
        scattered(self) -> scattered_aloc_t
        Get scattered argument info. Use when atype() == ALOC_DIST
        """
        return _ida_typeinf.argloc_t_scattered(self, *args)

    def get_rrel(self, *args) -> "rrel_t const &":
        r"""
        get_rrel(self) -> rrel_t
        Get register-relative info. Use when atype() == ALOC_RREL
        """
        return _ida_typeinf.argloc_t_get_rrel(self, *args)

    def get_custom(self) -> "void *":
        r"""
        get_custom(self) -> void *
        Get custom argloc info. Use if atype() == ALOC_CUSTOM
        """
        return _ida_typeinf.argloc_t_get_custom(self)

    def get_biggest(self) -> "argloc_t::biggest_t":
        r"""
        get_biggest(self) -> argloc_t::biggest_t
        Get largest element in internal union.
        """
        return _ida_typeinf.argloc_t_get_biggest(self)

    def _set_badloc(self) -> "void":
        r"""_set_badloc(self)"""
        return _ida_typeinf.argloc_t__set_badloc(self)

    def _set_reg1(self, reg: "int", off: "int"=0) -> "void":
        r"""
        _set_reg1(self, reg, off=0)

        Parameters
        ----------
        reg: int
        off: int

        """
        return _ida_typeinf.argloc_t__set_reg1(self, reg, off)

    def _set_reg2(self, _reg1: "int", _reg2: "int") -> "void":
        r"""
        _set_reg2(self, _reg1, _reg2)

        Parameters
        ----------
        _reg1: int
        _reg2: int

        """
        return _ida_typeinf.argloc_t__set_reg2(self, _reg1, _reg2)

    def _set_stkoff(self, off: "sval_t") -> "void":
        r"""
        _set_stkoff(self, off)

        Parameters
        ----------
        off: sval_t

        """
        return _ida_typeinf.argloc_t__set_stkoff(self, off)

    def _set_ea(self, _ea: "ea_t") -> "void":
        r"""
        _set_ea(self, _ea)

        Parameters
        ----------
        _ea: ea_t

        """
        return _ida_typeinf.argloc_t__set_ea(self, _ea)

    def _consume_rrel(self, p: "rrel_t") -> "bool":
        r"""
        _consume_rrel(self, p) -> bool

        Parameters
        ----------
        p: rrel_t *

        """
        return _ida_typeinf.argloc_t__consume_rrel(self, p)

    def _consume_scattered(self, p: "scattered_aloc_t") -> "bool":
        r"""
        _consume_scattered(self, p) -> bool

        Parameters
        ----------
        p: scattered_aloc_t *

        """
        return _ida_typeinf.argloc_t__consume_scattered(self, p)

    def _set_custom(self, ct: "argloc_type_t", pdata: "void *") -> "void":
        r"""
        _set_custom(self, ct, pdata)

        Parameters
        ----------
        ct: argloc_type_t
        pdata: void *

        """
        return _ida_typeinf.argloc_t__set_custom(self, ct, pdata)

    def _set_biggest(self, ct: "argloc_type_t", data: "argloc_t::biggest_t") -> "void":
        r"""
        _set_biggest(self, ct, data)

        Parameters
        ----------
        ct: argloc_type_t
        data: argloc_t::biggest_t

        """
        return _ida_typeinf.argloc_t__set_biggest(self, ct, data)

    def set_reg1(self, reg: "int", off: "int"=0) -> "void":
        r"""
        set_reg1(self, reg, off=0)
        Set register location.

        @param reg: (C++: int)
        @param off: (C++: int)
        """
        return _ida_typeinf.argloc_t_set_reg1(self, reg, off)

    def set_reg2(self, _reg1: "int", _reg2: "int") -> "void":
        r"""
        set_reg2(self, _reg1, _reg2)
        Set secondary register location.

        @param _reg1: (C++: int)
        @param _reg2: (C++: int)
        """
        return _ida_typeinf.argloc_t_set_reg2(self, _reg1, _reg2)

    def set_stkoff(self, off: "sval_t") -> "void":
        r"""
        set_stkoff(self, off)
        Set stack offset location.

        @param off: (C++: sval_t)
        """
        return _ida_typeinf.argloc_t_set_stkoff(self, off)

    def set_ea(self, _ea: "ea_t") -> "void":
        r"""
        set_ea(self, _ea)
        Set static ea location.

        @param _ea: (C++: ea_t)
        """
        return _ida_typeinf.argloc_t_set_ea(self, _ea)

    def consume_rrel(self, p: "rrel_t") -> "void":
        r"""
        consume_rrel(self, p)
        Set register-relative location - can't be nullptr.

        @param p: (C++: rrel_t *)
        """
        return _ida_typeinf.argloc_t_consume_rrel(self, p)

    def set_badloc(self) -> "void":
        r"""
        set_badloc(self)
        Set to invalid location.
        """
        return _ida_typeinf.argloc_t_set_badloc(self)

    def calc_offset(self) -> "sval_t":
        r"""
        calc_offset(self) -> sval_t
        Calculate offset that can be used to compare 2 similar arglocs.
        """
        return _ida_typeinf.argloc_t_calc_offset(self)

    def advance(self, delta: "int") -> "bool":
        r"""
        advance(self, delta) -> bool
        Move the location to point 'delta' bytes further.

        @param delta: (C++: int)
        """
        return _ida_typeinf.argloc_t_advance(self, delta)

    def align_reg_high(self, size: "size_t", _slotsize: "size_t") -> "void":
        r"""
        align_reg_high(self, size, _slotsize)
        Set register offset to align it to the upper part of _SLOTSIZE.

        @param size: (C++: size_t)
        @param _slotsize: (C++: size_t)
        """
        return _ida_typeinf.argloc_t_align_reg_high(self, size, _slotsize)

    def align_stkoff_high(self, size: "size_t", _slotsize: "size_t") -> "void":
        r"""
        align_stkoff_high(self, size, _slotsize)
        Set stack offset to align to the upper part of _SLOTSIZE.

        @param size: (C++: size_t)
        @param _slotsize: (C++: size_t)
        """
        return _ida_typeinf.argloc_t_align_stkoff_high(self, size, _slotsize)

    def __eq__(self, r: "argloc_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: argloc_t const &
        """
        return _ida_typeinf.argloc_t___eq__(self, r)

    def __ne__(self, r: "argloc_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: argloc_t const &
        """
        return _ida_typeinf.argloc_t___ne__(self, r)

    def __lt__(self, r: "argloc_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: argloc_t const &
        """
        return _ida_typeinf.argloc_t___lt__(self, r)

    def __gt__(self, r: "argloc_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: argloc_t const &
        """
        return _ida_typeinf.argloc_t___gt__(self, r)

    def __le__(self, r: "argloc_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: argloc_t const &
        """
        return _ida_typeinf.argloc_t___le__(self, r)

    def __ge__(self, r: "argloc_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: argloc_t const &
        """
        return _ida_typeinf.argloc_t___ge__(self, r)

    def compare(self, r: "argloc_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: argloc_t const &
        """
        return _ida_typeinf.argloc_t_compare(self, r)

    def consume_scattered(self, p: "scattered_aloc_t") -> "void":
        r"""
        consume_scattered(self, p)
        Set distributed argument location.

        @param p: (C++: scattered_aloc_t *) scattered_aloc_t const &
        """
        return _ida_typeinf.argloc_t_consume_scattered(self, p)

# Register argloc_t in _ida_typeinf:
_ida_typeinf.argloc_t_swigregister(argloc_t)
class argpart_t(argloc_t):
    r"""
    Proxy of C++ argpart_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    off: "ushort" = property(_ida_typeinf.argpart_t_off_get, _ida_typeinf.argpart_t_off_set, doc=r"""off""")
    r"""
    offset from the beginning of the argument
    """
    size: "ushort" = property(_ida_typeinf.argpart_t_size_get, _ida_typeinf.argpart_t_size_set, doc=r"""size""")
    r"""
    the number of bytes
    """

    def __init__(self, *args):
        r"""
        __init__(self, a) -> argpart_t

        @param a: argloc_t const &

        __init__(self) -> argpart_t
        """
        _ida_typeinf.argpart_t_swiginit(self, _ida_typeinf.new_argpart_t(*args))

    def bad_offset(self) -> "bool":
        r"""
        bad_offset(self) -> bool
        Does this argpart have a valid offset?
        """
        return _ida_typeinf.argpart_t_bad_offset(self)

    def bad_size(self) -> "bool":
        r"""
        bad_size(self) -> bool
        Does this argpart have a valid size?
        """
        return _ida_typeinf.argpart_t_bad_size(self)

    def __lt__(self, r: "argpart_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: argpart_t const &
        """
        return _ida_typeinf.argpart_t___lt__(self, r)

    def swap(self, r: "argpart_t") -> "void":
        r"""
        swap(self, r)
        Assign this = r and r = this.

        @param r: (C++: argpart_t &)
        """
        return _ida_typeinf.argpart_t_swap(self, r)
    __swig_destroy__ = _ida_typeinf.delete_argpart_t

# Register argpart_t in _ida_typeinf:
_ida_typeinf.argpart_t_swigregister(argpart_t)
class scattered_aloc_t(argpartvec_t):
    r"""
    Proxy of C++ scattered_aloc_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> scattered_aloc_t
        """
        _ida_typeinf.scattered_aloc_t_swiginit(self, _ida_typeinf.new_scattered_aloc_t())
    __swig_destroy__ = _ida_typeinf.delete_scattered_aloc_t

# Register scattered_aloc_t in _ida_typeinf:
_ida_typeinf.scattered_aloc_t_swigregister(scattered_aloc_t)

def verify_argloc(vloc: "argloc_t", size: "int", gaps: "rangeset_t") -> "int":
    r"""
    verify_argloc(vloc, size, gaps) -> int
    Verify argloc_t.

    @param vloc: (C++: const argloc_t &) argloc to verify
    @param size: (C++: int) total size of the variable
    @param gaps: (C++: const rangeset_t *) if not nullptr, specifies gaps in structure definition. these gaps
                 should not map to any argloc, but everything else must be covered
    @return: 0 if ok, otherwise an interr code.
    """
    return _ida_typeinf.verify_argloc(vloc, size, gaps)

def optimize_argloc(vloc: "argloc_t", size: "int", gaps: "rangeset_t") -> "bool":
    r"""
    optimize_argloc(vloc, size, gaps) -> bool
    Verify and optimize scattered argloc into simple form. All new arglocs must be
    processed by this function.
    @retval true: success
    @retval false: the input argloc was illegal

    @param vloc: (C++: argloc_t *)
    @param size: (C++: int)
    @param gaps: (C++: const rangeset_t *) rangeset_t const *
    """
    return _ida_typeinf.optimize_argloc(vloc, size, gaps)

def print_argloc(vloc: "argloc_t", size: "int"=0, vflags: "int"=0) -> "size_t":
    r"""
    print_argloc(vloc, size=0, vflags=0) -> size_t
    Convert an argloc to human readable form.

    @param vloc: (C++: const argloc_t &) argloc_t const &
    @param size: (C++: int)
    @param vflags: (C++: int)
    """
    return _ida_typeinf.print_argloc(vloc, size, vflags)
PRALOC_VERIFY = _ida_typeinf.PRALOC_VERIFY
r"""
interr if illegal argloc
"""

PRALOC_STKOFF = _ida_typeinf.PRALOC_STKOFF
r"""
print stack offsets
"""

class aloc_visitor_t(object):
    r"""
    Proxy of C++ aloc_visitor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def visit_location(self, v: "argloc_t", off: "int", size: "int") -> "int":
        r"""
        visit_location(self, v, off, size) -> int

        @param v: argloc_t &
        @param off: int
        @param size: int
        """
        return _ida_typeinf.aloc_visitor_t_visit_location(self, v, off, size)
    __swig_destroy__ = _ida_typeinf.delete_aloc_visitor_t

    def __init__(self):
        r"""
        __init__(self) -> aloc_visitor_t

        @param self: PyObject *
        """
        if self.__class__ == aloc_visitor_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.aloc_visitor_t_swiginit(self, _ida_typeinf.new_aloc_visitor_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_aloc_visitor_t(self)
        return weakref.proxy(self)

# Register aloc_visitor_t in _ida_typeinf:
_ida_typeinf.aloc_visitor_t_swigregister(aloc_visitor_t)

def for_all_arglocs(vv: "aloc_visitor_t", vloc: "argloc_t", size: "int", off: "int"=0) -> "int":
    r"""
    for_all_arglocs(vv, vloc, size, off=0) -> int
    Compress larger argloc types and initiate the aloc visitor.

    @param vv: (C++: aloc_visitor_t &)
    @param vloc: (C++: argloc_t &)
    @param size: (C++: int)
    @param off: (C++: int)
    """
    return _ida_typeinf.for_all_arglocs(vv, vloc, size, off)
class const_aloc_visitor_t(object):
    r"""
    Proxy of C++ const_aloc_visitor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def visit_location(self, v: "argloc_t", off: "int", size: "int") -> "int":
        r"""
        visit_location(self, v, off, size) -> int

        @param v: argloc_t const &
        @param off: int
        @param size: int
        """
        return _ida_typeinf.const_aloc_visitor_t_visit_location(self, v, off, size)
    __swig_destroy__ = _ida_typeinf.delete_const_aloc_visitor_t

    def __init__(self):
        r"""
        __init__(self) -> const_aloc_visitor_t

        @param self: PyObject *
        """
        if self.__class__ == const_aloc_visitor_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.const_aloc_visitor_t_swiginit(self, _ida_typeinf.new_const_aloc_visitor_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_const_aloc_visitor_t(self)
        return weakref.proxy(self)

# Register const_aloc_visitor_t in _ida_typeinf:
_ida_typeinf.const_aloc_visitor_t_swigregister(const_aloc_visitor_t)

def for_all_const_arglocs(vv: "const_aloc_visitor_t", vloc: "argloc_t", size: "int", off: "int"=0) -> "int":
    r"""
    for_all_const_arglocs(vv, vloc, size, off=0) -> int
    See for_all_arglocs()

    @param vv: (C++: const_aloc_visitor_t &)
    @param vloc: (C++: const argloc_t &) argloc_t const &
    @param size: (C++: int)
    @param off: (C++: int)
    """
    return _ida_typeinf.for_all_const_arglocs(vv, vloc, size, off)

def is_user_cc(cm: "cm_t") -> "bool":
    r"""
    is_user_cc(cm) -> bool
    Does the calling convention specify argument locations explicitly?

    @param cm: (C++: cm_t)
    """
    return _ida_typeinf.is_user_cc(cm)

def is_vararg_cc(cm: "cm_t") -> "bool":
    r"""
    is_vararg_cc(cm) -> bool
    Does the calling convention use ellipsis?

    @param cm: (C++: cm_t)
    """
    return _ida_typeinf.is_vararg_cc(cm)

def is_purging_cc(cm: "cm_t") -> "bool":
    r"""
    is_purging_cc(cm) -> bool
    Does the calling convention clean the stack arguments upon return?.
    @note: this function is valid only for x86 code

    @param cm: (C++: cm_t)
    """
    return _ida_typeinf.is_purging_cc(cm)

def is_golang_cc(cc: "cm_t") -> "bool":
    r"""
    is_golang_cc(cc) -> bool
    GO language calling convention (return value in stack)?

    @param cc: (C++: cm_t)
    """
    return _ida_typeinf.is_golang_cc(cc)

def is_swift_cc(cc: "cm_t") -> "bool":
    r"""
    is_swift_cc(cc) -> bool
    Swift calling convention (arguments and return values in registers)?

    @param cc: (C++: cm_t)
    """
    return _ida_typeinf.is_swift_cc(cc)
ARGREGS_POLICY_UNDEFINED = _ida_typeinf.ARGREGS_POLICY_UNDEFINED

ARGREGS_GP_ONLY = _ida_typeinf.ARGREGS_GP_ONLY
r"""
GP registers used for all arguments.
"""

ARGREGS_INDEPENDENT = _ida_typeinf.ARGREGS_INDEPENDENT
r"""
FP/GP registers used separately (like gcc64)
"""

ARGREGS_BY_SLOTS = _ida_typeinf.ARGREGS_BY_SLOTS
r"""
fixed FP/GP register per each slot (like vc64)
"""

ARGREGS_FP_MASKS_GP = _ida_typeinf.ARGREGS_FP_MASKS_GP
r"""
FP register also consumes one or more GP regs but not vice versa (aix ppc ABI)
"""

ARGREGS_MIPS_O32 = _ida_typeinf.ARGREGS_MIPS_O32
r"""
MIPS ABI o32.
"""

ARGREGS_RISCV = _ida_typeinf.ARGREGS_RISCV
r"""
Risc-V API FP arguments are passed in GP registers if FP registers are exhausted
and GP ones are not. Wide FP arguments are passed in GP registers. Variadic FP
arguments are passed in GP registers.
"""

class callregs_t(object):
    r"""
    Proxy of C++ callregs_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    policy: "argreg_policy_t" = property(_ida_typeinf.callregs_t_policy_get, _ida_typeinf.callregs_t_policy_set, doc=r"""policy""")
    r"""
    argument policy
    """
    nregs: "int" = property(_ida_typeinf.callregs_t_nregs_get, _ida_typeinf.callregs_t_nregs_set, doc=r"""nregs""")
    r"""
    max number of registers that can be used in a call
    """
    gpregs: "intvec_t" = property(_ida_typeinf.callregs_t_gpregs_get, _ida_typeinf.callregs_t_gpregs_set, doc=r"""gpregs""")
    r"""
    array of gp registers
    """
    fpregs: "intvec_t" = property(_ida_typeinf.callregs_t_fpregs_get, _ida_typeinf.callregs_t_fpregs_set, doc=r"""fpregs""")
    r"""
    array of fp registers
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> callregs_t
        __init__(self, cc) -> callregs_t

        @param cc: cm_t
        """
        _ida_typeinf.callregs_t_swiginit(self, _ida_typeinf.new_callregs_t(*args))

    def swap(self, r: "callregs_t") -> "void":
        r"""
        swap(self, r)
        swap two instances

        @param r: (C++: callregs_t &)
        """
        return _ida_typeinf.callregs_t_swap(self, r)

    def init_regs(self, cc: "cm_t") -> "void":
        r"""
        init_regs(self, cc)
        Init policy & registers for given CC.

        @param cc: (C++: cm_t)
        """
        return _ida_typeinf.callregs_t_init_regs(self, cc)

    def by_slots(self) -> "bool":
        r"""
        by_slots(self) -> bool
        """
        return _ida_typeinf.callregs_t_by_slots(self)

    def set(self, _policy: "argreg_policy_t", gprs: "int const *", fprs: "int const *") -> "void":
        r"""
        set(self, _policy, gprs, fprs)
        Init policy & registers (arrays are -1-terminated)

        @param _policy: (C++: argreg_policy_t) enum argreg_policy_t
        @param gprs: (C++: const int *) int const *
        @param fprs: (C++: const int *) int const *
        """
        return _ida_typeinf.callregs_t_set(self, _policy, gprs, fprs)
    GPREGS = _ida_typeinf.callregs_t_GPREGS
    
    FPREGS = _ida_typeinf.callregs_t_FPREGS
    

    def set_registers(self, kind: "callregs_t::reg_kind_t", first_reg: "int", last_reg: "int") -> "void":
        r"""
        set_registers(self, kind, first_reg, last_reg)

        @param kind: enum callregs_t::reg_kind_t
        @param first_reg: int
        @param last_reg: int
        """
        return _ida_typeinf.callregs_t_set_registers(self, kind, first_reg, last_reg)

    def reset(self) -> "void":
        r"""
        reset(self)
        Set policy and registers to invalid values.
        """
        return _ida_typeinf.callregs_t_reset(self)

    @staticmethod
    def regcount(cc: "cm_t") -> "int":
        r"""
        regcount(cc) -> int
        Get max number of registers may be used in a function call.

        @param cc: (C++: cm_t)
        """
        return _ida_typeinf.callregs_t_regcount(cc)

    def reginds(self, gp_ind: "int *", fp_ind: "int *", r: "int") -> "bool":
        r"""
        reginds(self, gp_ind, fp_ind, r) -> bool
        Get register indexes within GP/FP arrays. (-1 -> is not present in the
        corresponding array)

        @param gp_ind: (C++: int *)
        @param fp_ind: (C++: int *)
        @param r: (C++: int)
        """
        return _ida_typeinf.callregs_t_reginds(self, gp_ind, fp_ind, r)
    __swig_destroy__ = _ida_typeinf.delete_callregs_t

# Register callregs_t in _ida_typeinf:
_ida_typeinf.callregs_t_swigregister(callregs_t)
C_PC_TINY = cvar.C_PC_TINY
C_PC_SMALL = cvar.C_PC_SMALL
C_PC_COMPACT = cvar.C_PC_COMPACT
C_PC_MEDIUM = cvar.C_PC_MEDIUM
C_PC_LARGE = cvar.C_PC_LARGE
C_PC_HUGE = cvar.C_PC_HUGE
C_PC_FLAT = cvar.C_PC_FLAT


def get_comp(comp: "comp_t") -> "comp_t":
    r"""
    get_comp(comp) -> comp_t
    Get compiler bits.

    @param comp: (C++: comp_t)
    """
    return _ida_typeinf.get_comp(comp)

def get_compiler_name(id: "comp_t") -> "char const *":
    r"""
    get_compiler_name(id) -> char const *
    Get full compiler name.

    @param id: (C++: comp_t)
    """
    return _ida_typeinf.get_compiler_name(id)

def get_compiler_abbr(id: "comp_t") -> "char const *":
    r"""
    get_compiler_abbr(id) -> char const *
    Get abbreviated compiler name.

    @param id: (C++: comp_t)
    """
    return _ida_typeinf.get_compiler_abbr(id)

def get_compilers(ids: "compvec_t *", names: "qstrvec_t *", abbrs: "qstrvec_t *") -> "void":
    r"""
    get_compilers(ids, names, abbrs)
    Get names of all built-in compilers.

    @param ids: (C++: compvec_t *)
    @param names: (C++: qstrvec_t *)
    @param abbrs: (C++: qstrvec_t *)
    """
    return _ida_typeinf.get_compilers(ids, names, abbrs)

def is_comp_unsure(comp: "comp_t") -> "comp_t":
    r"""
    is_comp_unsure(comp) -> comp_t
    See COMP_UNSURE.

    @param comp: (C++: comp_t)
    """
    return _ida_typeinf.is_comp_unsure(comp)

def default_compiler() -> "comp_t":
    r"""
    default_compiler() -> comp_t
    Get compiler specified by inf.cc.
    """
    return _ida_typeinf.default_compiler()

def is_gcc() -> "bool":
    r"""
    is_gcc() -> bool
    Is the target compiler COMP_GNU?
    """
    return _ida_typeinf.is_gcc()

def is_gcc32() -> "bool":
    r"""
    is_gcc32() -> bool
    Is the target compiler 32 bit gcc?
    """
    return _ida_typeinf.is_gcc32()

def is_gcc64() -> "bool":
    r"""
    is_gcc64() -> bool
    Is the target compiler 64 bit gcc?
    """
    return _ida_typeinf.is_gcc64()

def gcc_layout() -> "bool":
    r"""
    gcc_layout() -> bool
    Should use the struct/union layout as done by gcc?
    """
    return _ida_typeinf.gcc_layout()

def set_compiler(cc: "compiler_info_t", flags: "int", abiname: "char const *"=None) -> "bool":
    r"""
    set_compiler(cc, flags, abiname=None) -> bool
    Change current compiler.

    @param cc: (C++: const compiler_info_t &) compiler to switch to
    @param flags: (C++: int) Set compiler flags
    @param abiname: (C++: const char *) ABI name
    @return: success
    """
    return _ida_typeinf.set_compiler(cc, flags, abiname)
SETCOMP_OVERRIDE = _ida_typeinf.SETCOMP_OVERRIDE
r"""
may override old compiler info
"""

SETCOMP_ONLY_ID = _ida_typeinf.SETCOMP_ONLY_ID
r"""
cc has only 'id' field; the rest will be set to defaults corresponding to the
program bitness
"""

SETCOMP_ONLY_ABI = _ida_typeinf.SETCOMP_ONLY_ABI
r"""
ignore cc field complete, use only abiname
"""

SETCOMP_BY_USER = _ida_typeinf.SETCOMP_BY_USER
r"""
invoked by user, cannot be replaced by module/loader
"""


def set_compiler_id(id: "comp_t", abiname: "char const *"=None) -> "bool":
    r"""
    set_compiler_id(id, abiname=None) -> bool
    Set the compiler id (see Compiler IDs)

    @param id: (C++: comp_t)
    @param abiname: (C++: const char *) char const *
    """
    return _ida_typeinf.set_compiler_id(id, abiname)

def set_abi_name(abiname: "char const *", user_level: "bool"=False) -> "bool":
    r"""
    set_abi_name(abiname, user_level=False) -> bool
    Set abi name (see Compiler IDs)

    @param abiname: (C++: const char *) char const *
    @param user_level: (C++: bool)
    """
    return _ida_typeinf.set_abi_name(abiname, user_level)

def get_abi_name() -> "qstring *":
    r"""
    get_abi_name() -> str
    Get ABI name.

    @return: length of the name (>=0)
    """
    return _ida_typeinf.get_abi_name()

def append_abi_opts(abi_opts: "char const *", user_level: "bool"=False) -> "bool":
    r"""
    append_abi_opts(abi_opts, user_level=False) -> bool
    Add/remove/check ABI option General form of full abi name: abiname-opt1-opt2-...
    or -opt1-opt2-...

    @param abi_opts: (C++: const char *) - ABI options to add/remove in form opt1-opt2-...
    @param user_level: (C++: bool) - initiated by user if TRUE (==SETCOMP_BY_USER)
    @return: success
    """
    return _ida_typeinf.append_abi_opts(abi_opts, user_level)

def remove_abi_opts(abi_opts: "char const *", user_level: "bool"=False) -> "bool":
    r"""
    remove_abi_opts(abi_opts, user_level=False) -> bool

    @param abi_opts: char const *
    @param user_level: bool
    """
    return _ida_typeinf.remove_abi_opts(abi_opts, user_level)

def set_compiler_string(compstr: "char const *", user_level: "bool") -> "bool":
    r"""
    set_compiler_string(compstr, user_level) -> bool

    @param compstr: (C++: const char *) - compiler description in form <abbr>:<abiname>
    @param user_level: (C++: bool) - initiated by user if TRUE
    @return: success
    """
    return _ida_typeinf.set_compiler_string(compstr, user_level)

def use_golang_cc() -> "bool":
    r"""
    use_golang_cc() -> bool
    is GOLANG calling convention used by default?
    """
    return _ida_typeinf.use_golang_cc()

def switch_to_golang() -> "void":
    r"""
    switch_to_golang()
    switch to GOLANG calling convention (to be used as default CC)
    """
    return _ida_typeinf.switch_to_golang()
MAX_FUNC_ARGS = _ida_typeinf.MAX_FUNC_ARGS
r"""
max number of function arguments
"""

ABS_UNK = _ida_typeinf.ABS_UNK

ABS_NO = _ida_typeinf.ABS_NO

ABS_YES = _ida_typeinf.ABS_YES

SC_UNK = _ida_typeinf.SC_UNK
r"""
unknown
"""

SC_TYPE = _ida_typeinf.SC_TYPE
r"""
typedef
"""

SC_EXT = _ida_typeinf.SC_EXT
r"""
extern
"""

SC_STAT = _ida_typeinf.SC_STAT
r"""
static
"""

SC_REG = _ida_typeinf.SC_REG
r"""
register
"""

SC_AUTO = _ida_typeinf.SC_AUTO
r"""
auto
"""

SC_FRIEND = _ida_typeinf.SC_FRIEND
r"""
friend
"""

SC_VIRT = _ida_typeinf.SC_VIRT
r"""
virtual
"""

HTI_CPP = _ida_typeinf.HTI_CPP
r"""
C++ mode (not implemented)
"""

HTI_INT = _ida_typeinf.HTI_INT
r"""
debug: print internal representation of types
"""

HTI_EXT = _ida_typeinf.HTI_EXT
r"""
debug: print external representation of types
"""

HTI_LEX = _ida_typeinf.HTI_LEX
r"""
debug: print tokens
"""

HTI_UNP = _ida_typeinf.HTI_UNP
r"""
debug: check the result by unpacking it
"""

HTI_TST = _ida_typeinf.HTI_TST
r"""
test mode: discard the result
"""

HTI_FIL = _ida_typeinf.HTI_FIL
r"""
"input" is file name, otherwise "input" contains a C declaration
"""

HTI_MAC = _ida_typeinf.HTI_MAC
r"""
define macros from the base tils
"""

HTI_NWR = _ida_typeinf.HTI_NWR
r"""
no warning messages
"""

HTI_NER = _ida_typeinf.HTI_NER
r"""
ignore all errors but display them
"""

HTI_DCL = _ida_typeinf.HTI_DCL
r"""
don't complain about redeclarations
"""

HTI_NDC = _ida_typeinf.HTI_NDC
r"""
don't decorate names
"""

HTI_PAK = _ida_typeinf.HTI_PAK
r"""
explicit structure pack value (#pragma pack)
"""

HTI_PAK_SHIFT = _ida_typeinf.HTI_PAK_SHIFT
r"""
shift for HTI_PAK. This field should be used if you want to remember an explicit
pack value for each structure/union type. See HTI_PAK... definitions
"""

HTI_PAKDEF = _ida_typeinf.HTI_PAKDEF
r"""
default pack value
"""

HTI_PAK1 = _ida_typeinf.HTI_PAK1
r"""
#pragma pack(1)
"""

HTI_PAK2 = _ida_typeinf.HTI_PAK2
r"""
#pragma pack(2)
"""

HTI_PAK4 = _ida_typeinf.HTI_PAK4
r"""
#pragma pack(4)
"""

HTI_PAK8 = _ida_typeinf.HTI_PAK8
r"""
#pragma pack(8)
"""

HTI_PAK16 = _ida_typeinf.HTI_PAK16
r"""
#pragma pack(16)
"""

HTI_HIGH = _ida_typeinf.HTI_HIGH
r"""
assume high level prototypes (with hidden args, etc)
"""

HTI_LOWER = _ida_typeinf.HTI_LOWER
r"""
lower the function prototypes
"""

HTI_RAWARGS = _ida_typeinf.HTI_RAWARGS
r"""
leave argument names unchanged (do not remove underscores)
"""

HTI_RELAXED = _ida_typeinf.HTI_RELAXED
r"""
accept references to unknown namespaces
"""

HTI_NOBASE = _ida_typeinf.HTI_NOBASE
r"""
do not inspect base tils
"""


def convert_pt_flags_to_hti(pt_flags: "int") -> "int":
    r"""
    convert_pt_flags_to_hti(pt_flags) -> int
    Convert Type parsing flags to Type formatting flags. Type parsing flags lesser
    than 0x10 don't have stable meaning and will be ignored (more on these flags can
    be seen in idc.idc)

    @param pt_flags: (C++: int)
    """
    return _ida_typeinf.convert_pt_flags_to_hti(pt_flags)

def parse_decl(out_tif: "tinfo_t", til: "til_t", decl: "char const *", pt_flags: "int") -> "qstring *":
    r"""
    parse_decl(out_tif, til, decl, pt_flags) -> str
    Parse ONE declaration. If the input string contains more than one declaration,
    the first complete type declaration (PT_TYP) or the last variable declaration
    (PT_VAR) will be used.
    @note: name & tif may be empty after the call!

    @param out_tif: (C++: tinfo_t *) type info
    @param til: (C++: til_t *) type library to use. may be nullptr
    @param decl: (C++: const char *) C declaration to parse
    @param pt_flags: (C++: int) combination of Type parsing flags bits
    @retval true: ok
    @retval false: declaration is bad, the error message is displayed if !PT_SIL
    """
    return _ida_typeinf.parse_decl(out_tif, til, decl, pt_flags)
PT_SIL = _ida_typeinf.PT_SIL
r"""
silent, no messages
"""

PT_NDC = _ida_typeinf.PT_NDC
r"""
don't decorate names
"""

PT_TYP = _ida_typeinf.PT_TYP
r"""
return declared type information
"""

PT_VAR = _ida_typeinf.PT_VAR
r"""
return declared object information
"""

PT_PACKMASK = _ida_typeinf.PT_PACKMASK
r"""
mask for pack alignment values
"""

PT_HIGH = _ida_typeinf.PT_HIGH
r"""
assume high level prototypes (with hidden args, etc)
"""

PT_LOWER = _ida_typeinf.PT_LOWER
r"""
lower the function prototypes
"""

PT_REPLACE = _ida_typeinf.PT_REPLACE
r"""
replace the old type (used in idc)
"""

PT_RAWARGS = _ida_typeinf.PT_RAWARGS
r"""
leave argument names unchanged (do not remove underscores)
"""

PT_RELAXED = _ida_typeinf.PT_RELAXED
r"""
accept references to unknown namespaces
"""

PT_EMPTY = _ida_typeinf.PT_EMPTY
r"""
accept empty decl
"""


def parse_decls(til: "til_t", input: "char const *", printer: "printer_t *", hti_flags: "int") -> "int":
    r"""
    parse_decls(til, input, printer, hti_flags) -> int
    Parse many declarations and store them in a til. If there are any errors, they
    will be printed using 'printer'. This function uses default include path and
    predefined macros from the database settings. It always uses the HTI_DCL bit.

    @param til: (C++: til_t *) type library to store the result
    @param input: (C++: const char *) input string or file name (see hti_flags)
    @param printer: (C++: printer_t *) function to output error messages (use msg or nullptr or your
                    own callback)
    @param hti_flags: (C++: int) combination of Type formatting flags
    @return: number of errors, 0 means ok.
    """
    return _ida_typeinf.parse_decls(til, input, printer, hti_flags)

def print_type(ea: "ea_t", prtype_flags: "int") -> "qstring *":
    r"""
    print_type(ea, prtype_flags) -> str
    Get type declaration for the specified address.

    @param ea: (C++: ea_t) address
    @param prtype_flags: (C++: int) combination of Type printing flags
    @return: success
    """
    return _ida_typeinf.print_type(ea, prtype_flags)
PRTYPE_1LINE = _ida_typeinf.PRTYPE_1LINE
r"""
print to one line
"""

PRTYPE_MULTI = _ida_typeinf.PRTYPE_MULTI
r"""
print to many lines
"""

PRTYPE_TYPE = _ida_typeinf.PRTYPE_TYPE
r"""
print type declaration (not variable declaration)
"""

PRTYPE_PRAGMA = _ida_typeinf.PRTYPE_PRAGMA
r"""
print pragmas for alignment
"""

PRTYPE_SEMI = _ida_typeinf.PRTYPE_SEMI
r"""
append ; to the end
"""

PRTYPE_CPP = _ida_typeinf.PRTYPE_CPP
r"""
use c++ name (only for print_type())
"""

PRTYPE_DEF = _ida_typeinf.PRTYPE_DEF
r"""
tinfo_t: print definition, if available
"""

PRTYPE_NOARGS = _ida_typeinf.PRTYPE_NOARGS
r"""
tinfo_t: do not print function argument names
"""

PRTYPE_NOARRS = _ida_typeinf.PRTYPE_NOARRS
r"""
tinfo_t: print arguments with FAI_ARRAY as pointers
"""

PRTYPE_NORES = _ida_typeinf.PRTYPE_NORES
r"""
tinfo_t: never resolve types (meaningful with PRTYPE_DEF)
"""

PRTYPE_RESTORE = _ida_typeinf.PRTYPE_RESTORE
r"""
tinfo_t: print restored types for FAI_ARRAY and FAI_STRUCT
"""

PRTYPE_NOREGEX = _ida_typeinf.PRTYPE_NOREGEX
r"""
do not apply regular expressions to beautify name
"""

PRTYPE_COLORED = _ida_typeinf.PRTYPE_COLORED
r"""
add color tag COLOR_SYMBOL for any parentheses, commas and colons
"""

PRTYPE_METHODS = _ida_typeinf.PRTYPE_METHODS
r"""
tinfo_t: print udt methods
"""

PRTYPE_1LINCMT = _ida_typeinf.PRTYPE_1LINCMT
r"""
print comments even in the one line mode
"""

PRTYPE_HEADER = _ida_typeinf.PRTYPE_HEADER
r"""
print only type header (only for definitions)
"""

PRTYPE_OFFSETS = _ida_typeinf.PRTYPE_OFFSETS
r"""
print udt member offsets
"""

PRTYPE_MAXSTR = _ida_typeinf.PRTYPE_MAXSTR
r"""
limit the output length to 1024 bytes (the output may be slightly longer)
"""

PRTYPE_TAIL = _ida_typeinf.PRTYPE_TAIL
r"""
print only the definition tail (only for definitions, exclusive with
PRTYPE_HEADER)
"""

PRTYPE_ARGLOCS = _ida_typeinf.PRTYPE_ARGLOCS
r"""
print function arglocs (not only for usercall)
"""

NTF_TYPE = _ida_typeinf.NTF_TYPE
r"""
type name
"""

NTF_SYMU = _ida_typeinf.NTF_SYMU
r"""
symbol, name is unmangled ('func')
"""

NTF_SYMM = _ida_typeinf.NTF_SYMM
r"""
symbol, name is mangled ('_func'); only one of NTF_TYPE and NTF_SYMU, NTF_SYMM
can be used
"""

NTF_NOBASE = _ida_typeinf.NTF_NOBASE
r"""
don't inspect base tils (for get_named_type)
"""

NTF_REPLACE = _ida_typeinf.NTF_REPLACE
r"""
replace original type (for set_named_type)
"""

NTF_UMANGLED = _ida_typeinf.NTF_UMANGLED
r"""
name is unmangled (don't use this flag)
"""

NTF_NOCUR = _ida_typeinf.NTF_NOCUR
r"""
don't inspect current til file (for get_named_type)
"""

NTF_64BIT = _ida_typeinf.NTF_64BIT
r"""
value is 64bit
"""

NTF_FIXNAME = _ida_typeinf.NTF_FIXNAME
r"""
force-validate the name of the type when setting (set_named_type,
set_numbered_type only)
"""

NTF_IDBENC = _ida_typeinf.NTF_IDBENC
r"""
the name is given in the IDB encoding; non-ASCII bytes will be decoded
accordingly (set_named_type, set_numbered_type only)
"""

NTF_CHKSYNC = _ida_typeinf.NTF_CHKSYNC
r"""
check that synchronization to IDB passed OK (set_numbered_type, set_named_type)
"""

NTF_NO_NAMECHK = _ida_typeinf.NTF_NO_NAMECHK
r"""
do not validate type name (set_numbered_type, set_named_type)
"""

NTF_COPY = _ida_typeinf.NTF_COPY
r"""
save a new type definition, not a typeref (tinfo_t::set_numbered_type,
tinfo_t::set_named_type)
"""

TERR_OK = _ida_typeinf.TERR_OK
r"""
ok
"""

TERR_SAVE_ERROR = _ida_typeinf.TERR_SAVE_ERROR
r"""
failed to save
"""

TERR_SERIALIZE = _ida_typeinf.TERR_SERIALIZE
r"""
failed to serialize
"""

TERR_BAD_NAME = _ida_typeinf.TERR_BAD_NAME
r"""
name s is not acceptable
"""

TERR_BAD_ARG = _ida_typeinf.TERR_BAD_ARG
r"""
bad argument
"""

TERR_BAD_TYPE = _ida_typeinf.TERR_BAD_TYPE
r"""
bad type
"""

TERR_BAD_SIZE = _ida_typeinf.TERR_BAD_SIZE
r"""
bad size d
"""

TERR_BAD_INDEX = _ida_typeinf.TERR_BAD_INDEX
r"""
bad index d
"""

TERR_BAD_ARRAY = _ida_typeinf.TERR_BAD_ARRAY
r"""
arrays are forbidden as function arguments
"""

TERR_BAD_BF = _ida_typeinf.TERR_BAD_BF
r"""
bitfields are forbidden as function arguments
"""

TERR_BAD_OFFSET = _ida_typeinf.TERR_BAD_OFFSET
r"""
bad member offset s
"""

TERR_BAD_UNIVAR = _ida_typeinf.TERR_BAD_UNIVAR
r"""
unions cannot have variable sized members
"""

TERR_BAD_VARLAST = _ida_typeinf.TERR_BAD_VARLAST
r"""
variable sized member must be the last member in the structure
"""

TERR_OVERLAP = _ida_typeinf.TERR_OVERLAP
r"""
the member overlaps with other members that cannot be deleted
"""

TERR_BAD_SUBTYPE = _ida_typeinf.TERR_BAD_SUBTYPE
r"""
recursive structure nesting is forbidden
"""

TERR_BAD_VALUE = _ida_typeinf.TERR_BAD_VALUE
r"""
value 0xI64X is not acceptable
"""

TERR_NO_BMASK = _ida_typeinf.TERR_NO_BMASK
r"""
bitmask 0xI64X is not found
"""

TERR_BAD_BMASK = _ida_typeinf.TERR_BAD_BMASK
r"""
Bad enum member mask 0xI64X. The specified mask should not intersect with any
existing mask in the enum. Zero masks are prohibited too.
"""

TERR_BAD_MSKVAL = _ida_typeinf.TERR_BAD_MSKVAL
r"""
bad bmask and value combination (value=0xI64X; bitmask 0xI64X)
"""

TERR_BAD_REPR = _ida_typeinf.TERR_BAD_REPR
r"""
bad or incompatible field representation
"""

TERR_GRP_NOEMPTY = _ida_typeinf.TERR_GRP_NOEMPTY
r"""
could not delete group mask for not empty group 0xI64X
"""

TERR_DUPNAME = _ida_typeinf.TERR_DUPNAME
r"""
duplicate name s
"""

TERR_UNION_BF = _ida_typeinf.TERR_UNION_BF
r"""
unions cannot have bitfields
"""

TERR_BAD_TAH = _ida_typeinf.TERR_BAD_TAH
r"""
bad bits in the type attributes (TAH bits)
"""

TERR_BAD_BASE = _ida_typeinf.TERR_BAD_BASE
r"""
bad base class
"""

TERR_BAD_GAP = _ida_typeinf.TERR_BAD_GAP
r"""
bad gap
"""

TERR_NESTED = _ida_typeinf.TERR_NESTED
r"""
recursive structure nesting is forbidden
"""

TERR_NOT_COMPAT = _ida_typeinf.TERR_NOT_COMPAT
r"""
the new type is not compatible with the old type
"""

TERR_BAD_LAYOUT = _ida_typeinf.TERR_BAD_LAYOUT
r"""
failed to calculate the structure/union layout
"""

TERR_BAD_GROUPS = _ida_typeinf.TERR_BAD_GROUPS
r"""
bad group sizes for bitmask enum
"""

TERR_BAD_SERIAL = _ida_typeinf.TERR_BAD_SERIAL
r"""
enum value has too many serials
"""

TERR_ALIEN_NAME = _ida_typeinf.TERR_ALIEN_NAME
r"""
enum member name is used in another enum
"""

TERR_STOCK = _ida_typeinf.TERR_STOCK
r"""
stock type info cannot be modified
"""

TERR_ENUM_SIZE = _ida_typeinf.TERR_ENUM_SIZE
r"""
bad enum size
"""

TERR_NOT_IMPL = _ida_typeinf.TERR_NOT_IMPL
r"""
not implemented
"""

TERR_TYPE_WORSE = _ida_typeinf.TERR_TYPE_WORSE
r"""
the new type is worse than the old type
"""

TERR_BAD_FX_SIZE = _ida_typeinf.TERR_BAD_FX_SIZE
r"""
cannot extend struct beyond fixed size
"""

TERR_STRUCT_SIZE = _ida_typeinf.TERR_STRUCT_SIZE
r"""
bad fixed structure size
"""

TERR_COUNT = _ida_typeinf.TERR_COUNT


def tinfo_errstr(code: "tinfo_code_t") -> "char const *":
    r"""
    tinfo_errstr(code) -> char const *
    Helper function to convert an error code into a printable string. Additional
    arguments are handled using the functions from err.h

    @param code: (C++: tinfo_code_t) enum tinfo_code_t
    """
    return _ida_typeinf.tinfo_errstr(code)

def del_named_type(ti: "til_t", name: "char const *", ntf_flags: "int") -> "bool":
    r"""
    del_named_type(ti, name, ntf_flags) -> bool
    Delete information about a symbol.

    @param ti: (C++: til_t *) type library
    @param name: (C++: const char *) name of symbol
    @param ntf_flags: (C++: int) combination of Flags for named types
    @return: success
    """
    return _ida_typeinf.del_named_type(ti, name, ntf_flags)

def first_named_type(ti: "til_t", ntf_flags: "int") -> "char const *":
    r"""
    first_named_type(ti, ntf_flags) -> char const *
    Enumerate types.

    @param ti: (C++: const til_t *) type library. nullptr means the local type library for the current
               database.
    @param ntf_flags: (C++: int) combination of Flags for named types
    @return: Type or symbol names, depending of ntf_flags. Returns mangled names.
             Never returns anonymous types. To include them, enumerate types by
             ordinals.
    """
    return _ida_typeinf.first_named_type(ti, ntf_flags)

def next_named_type(ti: "til_t", name: "char const *", ntf_flags: "int") -> "char const *":
    r"""
    next_named_type(ti, name, ntf_flags) -> char const *
    Enumerate types.

    @param ti: (C++: const til_t *) type library. nullptr means the local type library for the current
               database.
    @param name: (C++: const char *) the current name. the name that follows this one will be returned.
    @param ntf_flags: (C++: int) combination of Flags for named types
    @return: Type or symbol names, depending of ntf_flags. Returns mangled names.
             Never returns anonymous types. To include them, enumerate types by
             ordinals.
    """
    return _ida_typeinf.next_named_type(ti, name, ntf_flags)

def copy_named_type(dsttil: "til_t", srctil: "til_t", name: "char const *") -> "uint32":
    r"""
    copy_named_type(dsttil, srctil, name) -> uint32
    Copy a named type from one til to another. This function will copy the specified
    type and all dependent types from the source type library to the destination
    library.

    @param dsttil: (C++: til_t *) Destination til. It must have original types enabled
    @param srctil: (C++: const til_t *) Source til.
    @param name: (C++: const char *) name of the type to copy
    @return: ordinal number of the copied type. 0 means error
    """
    return _ida_typeinf.copy_named_type(dsttil, srctil, name)

def gen_decorate_name(name: "char const *", mangle: "bool", cc: "cm_t", type: "tinfo_t") -> "qstring *":
    r"""
    gen_decorate_name(name, mangle, cc, type) -> str
    Generic function for decorate_name() (may be used in IDP modules)

    @param name: (C++: const char *) char const *
    @param mangle: (C++: bool)
    @param cc: (C++: cm_t)
    @param type: (C++: const tinfo_t *) tinfo_t const *
    """
    return _ida_typeinf.gen_decorate_name(name, mangle, cc, type)

def calc_c_cpp_name(name: "char const *", type: "tinfo_t", ccn_flags: "int") -> "qstring *":
    r"""
    calc_c_cpp_name(name, type, ccn_flags) -> str
    Get C or C++ form of the name.

    @param name: (C++: const char *) original (mangled or decorated) name
    @param type: (C++: const tinfo_t *) name type if known, otherwise nullptr
    @param ccn_flags: (C++: int) one of C/C++ naming flags
    """
    return _ida_typeinf.calc_c_cpp_name(name, type, ccn_flags)
CCN_C = _ida_typeinf.CCN_C

CCN_CPP = _ida_typeinf.CCN_CPP


def enable_numbered_types(ti: "til_t", enable: "bool") -> "bool":
    r"""
    enable_numbered_types(ti, enable) -> bool
    Enable the use of numbered types in til. Currently it is impossible to disable
    numbered types once they are enabled

    @param ti: (C++: til_t *)
    @param enable: (C++: bool)
    """
    return _ida_typeinf.enable_numbered_types(ti, enable)

def alloc_type_ordinals(ti: "til_t", qty: "int") -> "uint32":
    r"""
    alloc_type_ordinals(ti, qty) -> uint32
    Allocate a range of ordinal numbers for new types.

    @param ti: (C++: til_t *) type library
    @param qty: (C++: int) number of ordinals to allocate
    @return: the first ordinal. 0 means failure.
    """
    return _ida_typeinf.alloc_type_ordinals(ti, qty)

def alloc_type_ordinal(ti: "til_t") -> "uint32":
    r"""
    alloc_type_ordinal(ti) -> uint32
    alloc_type_ordinals(ti, 1)

    @param ti: (C++: til_t *)
    """
    return _ida_typeinf.alloc_type_ordinal(ti)

def get_ordinal_limit(ti: "til_t"=None) -> "uint32":
    r"""
    get_ordinal_limit(ti=None) -> uint32
    Get number of allocated ordinals + 1. If there are no allocated ordinals, return
    0. To enumerate all ordinals, use: for ( uint32 i = 1; i < limit; ++i )

    @param ti: (C++: const til_t *) type library; nullptr means the local types for the current database.
    @return: uint32(-1) if ordinals have not been enabled for the til. For local
             types (idati), ordinals are always enabled.
    """
    return _ida_typeinf.get_ordinal_limit(ti)

def get_ordinal_count(ti: "til_t"=None) -> "uint32":
    r"""
    get_ordinal_count(ti=None) -> uint32
    Get number of allocated ordinals.

    @param ti: (C++: const til_t *) type library; nullptr means the local types for the current database.
    @return: 0 if ordinals have not been enabled for the til.
    """
    return _ida_typeinf.get_ordinal_count(ti)

def del_numbered_type(ti: "til_t", ordinal: "uint32") -> "bool":
    r"""
    del_numbered_type(ti, ordinal) -> bool
    Delete a numbered type.

    @param ti: (C++: til_t *)
    @param ordinal: (C++: uint32)
    """
    return _ida_typeinf.del_numbered_type(ti, ordinal)

def set_type_alias(ti: "til_t", src_ordinal: "uint32", dst_ordinal: "uint32") -> "bool":
    r"""
    set_type_alias(ti, src_ordinal, dst_ordinal) -> bool
    Create a type alias. Redirects all references to source type to the destination
    type. This is equivalent to instantaneous replacement all references to srctype
    by dsttype.

    @param ti: (C++: til_t *)
    @param src_ordinal: (C++: uint32)
    @param dst_ordinal: (C++: uint32)
    """
    return _ida_typeinf.set_type_alias(ti, src_ordinal, dst_ordinal)

def get_alias_target(ti: "til_t", ordinal: "uint32") -> "uint32":
    r"""
    get_alias_target(ti, ordinal) -> uint32
    Find the final alias destination. If the ordinal has not been aliased, return
    the specified ordinal itself If failed, returns 0.

    @param ti: (C++: const til_t *) til_t const *
    @param ordinal: (C++: uint32)
    """
    return _ida_typeinf.get_alias_target(ti, ordinal)

def get_type_ordinal(ti: "til_t", name: "char const *") -> "int32":
    r"""
    get_type_ordinal(ti, name) -> int32
    Get type ordinal by its name.

    @param ti: (C++: const til_t *) til_t const *
    @param name: (C++: const char *) char const *
    """
    return _ida_typeinf.get_type_ordinal(ti, name)

def get_numbered_type_name(ti: "til_t", ordinal: "uint32") -> "char const *":
    r"""
    get_numbered_type_name(ti, ordinal) -> char const *
    Get type name (if exists) by its ordinal. If the type is anonymous, returns "".
    If failed, returns nullptr

    @param ti: (C++: const til_t *) til_t const *
    @param ordinal: (C++: uint32)
    """
    return _ida_typeinf.get_numbered_type_name(ti, ordinal)

def create_numbered_type_name(ord: "int32") -> "qstring *":
    r"""
    create_numbered_type_name(ord) -> str
    Create anonymous name for numbered type. This name can be used to reference a
    numbered type by its ordinal Ordinal names have the following format: '#' +
    set_de(ord) Returns: -1 if error, otherwise the name length

    @param ord: (C++: int32)
    """
    return _ida_typeinf.create_numbered_type_name(ord)

def is_ordinal_name(name: "char const *", ord: "uint32 *"=None) -> "bool":
    r"""
    is_ordinal_name(name, ord=None) -> bool
    Check if the name is an ordinal name. Ordinal names have the following format:
    '#' + set_de(ord)

    @param name: (C++: const char *) char const *
    @param ord: (C++: uint32 *)
    """
    return _ida_typeinf.is_ordinal_name(name, ord)

def is_type_choosable(ti: "til_t", ordinal: "uint32") -> "bool":
    r"""
    is_type_choosable(ti, ordinal) -> bool
    Check if a struct/union type is choosable

    @param ti: (C++: const til_t *) type library
    @param ordinal: (C++: uint32) ordinal number of a UDT type
    """
    return _ida_typeinf.is_type_choosable(ti, ordinal)

def set_type_choosable(ti: "til_t", ordinal: "uint32", value: "bool") -> "void":
    r"""
    set_type_choosable(ti, ordinal, value)
    Enable/disable 'choosability' flag for a struct/union type

    @param ti: (C++: til_t *) type library
    @param ordinal: (C++: uint32) ordinal number of a UDT type
    @param value: (C++: bool) flag value
    """
    return _ida_typeinf.set_type_choosable(ti, ordinal, value)

def get_vftable_ea(ordinal: "uint32") -> "ea_t":
    r"""
    get_vftable_ea(ordinal) -> ea_t
    Get address of a virtual function table.

    @param ordinal: (C++: uint32) ordinal number of a vftable type.
    @return: address of the corresponding virtual function table in the current
             database.
    """
    return _ida_typeinf.get_vftable_ea(ordinal)

def get_vftable_ordinal(vftable_ea: "ea_t") -> "uint32":
    r"""
    get_vftable_ordinal(vftable_ea) -> uint32
    Get ordinal number of the virtual function table.

    @param vftable_ea: (C++: ea_t) address of a virtual function table.
    @return: ordinal number of the corresponding vftable type. 0 - failure.
    """
    return _ida_typeinf.get_vftable_ordinal(vftable_ea)

def set_vftable_ea(ordinal: "uint32", vftable_ea: "ea_t") -> "bool":
    r"""
    set_vftable_ea(ordinal, vftable_ea) -> bool
    Set the address of a vftable instance for a vftable type.

    @param ordinal: (C++: uint32) ordinal number of the corresponding vftable type.
    @param vftable_ea: (C++: ea_t) address of a virtual function table.
    @return: success
    """
    return _ida_typeinf.set_vftable_ea(ordinal, vftable_ea)

def del_vftable_ea(ordinal: "uint32") -> "bool":
    r"""
    del_vftable_ea(ordinal) -> bool
    Delete the address of a vftable instance for a vftable type.

    @param ordinal: (C++: uint32) ordinal number of a vftable type.
    @return: success
    """
    return _ida_typeinf.del_vftable_ea(ordinal)

def deref_ptr(ptr_ea: "ea_t *", tif: "tinfo_t", closure_obj: "ea_t *"=None) -> "bool":
    r"""
    deref_ptr(ptr_ea, tif, closure_obj=None) -> bool
    Dereference a pointer.

    @param ptr_ea: (C++: ea_t *) in/out parameter
    * in: address of the pointer
    * out: the pointed address
    @param tif: (C++: const tinfo_t &) type of the pointer
    @param closure_obj: (C++: ea_t *) closure object (not used yet)
    @return: success
    """
    return _ida_typeinf.deref_ptr(ptr_ea, tif, closure_obj)

def add_til(name: "char const *", flags: "int") -> "int":
    r"""
    add_til(name, flags) -> int
    Load a til file and add it the database type libraries list. IDA will also apply
    function prototypes for matching function names.

    @param name: (C++: const char *) til name
    @param flags: (C++: int) combination of Load TIL flags
    @return: one of Load TIL result codes
    """
    return _ida_typeinf.add_til(name, flags)
ADDTIL_DEFAULT = _ida_typeinf.ADDTIL_DEFAULT
r"""
default behavior
"""

ADDTIL_INCOMP = _ida_typeinf.ADDTIL_INCOMP
r"""
load incompatible tils
"""

ADDTIL_SILENT = _ida_typeinf.ADDTIL_SILENT
r"""
do not ask any questions
"""

ADDTIL_FAILED = _ida_typeinf.ADDTIL_FAILED
r"""
something bad, the warning is displayed
"""

ADDTIL_OK = _ida_typeinf.ADDTIL_OK
r"""
ok, til is loaded
"""

ADDTIL_COMP = _ida_typeinf.ADDTIL_COMP
r"""
ok, but til is not compatible with the current compiler
"""

ADDTIL_ABORTED = _ida_typeinf.ADDTIL_ABORTED
r"""
til was not loaded (incompatible til rejected by user)
"""


def del_til(name: "char const *") -> "bool":
    r"""
    del_til(name) -> bool
    Unload a til file.

    @param name: (C++: const char *) char const *
    """
    return _ida_typeinf.del_til(name)

def apply_named_type(ea: "ea_t", name: "char const *") -> "bool":
    r"""
    apply_named_type(ea, name) -> bool
    Apply the specified named type to the address.

    @param ea: (C++: ea_t) linear address
    @param name: (C++: const char *) the type name, e.g. "FILE"
    @return: success
    """
    return _ida_typeinf.apply_named_type(ea, name)

def apply_tinfo(ea: "ea_t", tif: "tinfo_t", flags: "uint32") -> "bool":
    r"""
    apply_tinfo(ea, tif, flags) -> bool
    Apply the specified type to the specified address. This function sets the type
    and tries to convert the item at the specified address to conform the type.

    @param ea: (C++: ea_t) linear address
    @param tif: (C++: const tinfo_t &) type string in internal format
    @param flags: (C++: uint32) combination of Apply tinfo flags
    @return: success
    """
    return _ida_typeinf.apply_tinfo(ea, tif, flags)
TINFO_GUESSED = _ida_typeinf.TINFO_GUESSED
r"""
this is a guessed type
"""

TINFO_DEFINITE = _ida_typeinf.TINFO_DEFINITE
r"""
this is a definite type
"""

TINFO_DELAYFUNC = _ida_typeinf.TINFO_DELAYFUNC
r"""
if type is a function and no function exists at ea, schedule its creation and
argument renaming to auto-analysis, otherwise try to create it immediately
"""

TINFO_STRICT = _ida_typeinf.TINFO_STRICT
r"""
never convert given type to another one before applying
"""


def apply_cdecl(til: "til_t", ea: "ea_t", decl: "char const *", flags: "int"=0) -> "bool":
    r"""
    apply_cdecl(til, ea, decl, flags=0) -> bool
    Apply the specified type to the address. This function parses the declaration
    and calls apply_tinfo()

    @param til: (C++: til_t *) type library
    @param ea: (C++: ea_t) linear address
    @param decl: (C++: const char *) type declaration in C form
    @param flags: (C++: int) flags to pass to apply_tinfo (TINFO_DEFINITE is always passed)
    @return: success
    """
    return _ida_typeinf.apply_cdecl(til, ea, decl, flags)

def apply_callee_tinfo(caller: "ea_t", tif: "tinfo_t") -> "bool":
    r"""
    apply_callee_tinfo(caller, tif) -> bool
    Apply the type of the called function to the calling instruction. This function
    will append parameter comments and rename the local variables of the calling
    function. It also stores information about the instructions that initialize call
    arguments in the database. Use get_arg_addrs() to retrieve it if necessary.
    Alternatively it is possible to hook to processor_t::arg_addrs_ready event.

    @param caller: (C++: ea_t) linear address of the calling instruction. must belong to a
                   function.
    @param tif: (C++: const tinfo_t &) type info
    @return: success
    """
    return _ida_typeinf.apply_callee_tinfo(caller, tif)

def apply_once_tinfo_and_name(dea: "ea_t", tif: "tinfo_t", name: "char const *") -> "bool":
    r"""
    apply_once_tinfo_and_name(dea, tif, name) -> bool
    Apply the specified type and name to the address. This function checks if the
    address already has a type. If the old type
    does not exist or the new type is 'better' than the old type, then the
    new type will be applied. A type is considered better if it has more
    information (e.g. BTMT_STRUCT is better than BT_INT).
    The same logic is with the name: if the address already have a meaningful
    name, it will be preserved. Only if the old name does not exist or it
    is a dummy name like byte_123, it will be replaced by the new name.

    @param dea: (C++: ea_t) linear address
    @param tif: (C++: const tinfo_t &) type string in the internal format
    @param name: (C++: const char *) new name for the address
    @return: success
    """
    return _ida_typeinf.apply_once_tinfo_and_name(dea, tif, name)

def guess_tinfo(out: "tinfo_t", id: "tid_t") -> "int":
    r"""
    guess_tinfo(out, id) -> int
    Generate a type information about the id from the disassembly. id can be a
    structure/union/enum id or an address.

    @param out: (C++: tinfo_t *)
    @param id: (C++: tid_t)
    @return: one of Guess tinfo codes
    """
    return _ida_typeinf.guess_tinfo(out, id)
GUESS_FUNC_FAILED = _ida_typeinf.GUESS_FUNC_FAILED
r"""
couldn't guess the function type
"""

GUESS_FUNC_TRIVIAL = _ida_typeinf.GUESS_FUNC_TRIVIAL
r"""
the function type doesn't have interesting info
"""

GUESS_FUNC_OK = _ida_typeinf.GUESS_FUNC_OK
r"""
ok, some non-trivial information is gathered
"""


def set_c_header_path(incdir: "char const *") -> "void":
    r"""
    set_c_header_path(incdir)
    Set include directory path the target compiler.

    @param incdir: (C++: const char *) char const *
    """
    return _ida_typeinf.set_c_header_path(incdir)

def get_c_header_path() -> "qstring *":
    r"""
    get_c_header_path() -> str
    Get the include directory path of the target compiler.
    """
    return _ida_typeinf.get_c_header_path()

def set_c_macros(macros: "char const *") -> "void":
    r"""
    set_c_macros(macros)
    Set predefined macros for the target compiler.

    @param macros: (C++: const char *) char const *
    """
    return _ida_typeinf.set_c_macros(macros)

def get_c_macros() -> "qstring *":
    r"""
    get_c_macros() -> str
    Get predefined macros for the target compiler.
    """
    return _ida_typeinf.get_c_macros()

def get_idati() -> "til_t *":
    r"""
    get_idati() -> til_t
    Pointer to the local type library - this til is private for each IDB file
    Functions that accept til_t* default to `idati` when is nullptr provided.
    """
    return _ida_typeinf.get_idati()

def get_idainfo_by_type(tif: "tinfo_t") -> "size_t *, flags64_t *, opinfo_t *, size_t *":
    r"""
    get_idainfo_by_type(tif) -> bool
    Extract information from a tinfo_t.

    @param tif: (C++: const tinfo_t &) the type to inspect
    """
    return _ida_typeinf.get_idainfo_by_type(tif)

def get_tinfo_by_flags(out: "tinfo_t", flags: "flags64_t") -> "bool":
    r"""
    get_tinfo_by_flags(out, flags) -> bool
    Get tinfo object that corresponds to data flags

    @param out: (C++: tinfo_t *) type info
    @param flags: (C++: flags64_t) simple flags (byte, word, ..., zword)
    """
    return _ida_typeinf.get_tinfo_by_flags(out, flags)
STI_PCHAR = _ida_typeinf.STI_PCHAR
r"""
char *
"""

STI_PUCHAR = _ida_typeinf.STI_PUCHAR
r"""
uint8 *
"""

STI_PCCHAR = _ida_typeinf.STI_PCCHAR
r"""
const char *
"""

STI_PCUCHAR = _ida_typeinf.STI_PCUCHAR
r"""
const uint8 *
"""

STI_PBYTE = _ida_typeinf.STI_PBYTE
r"""
_BYTE *
"""

STI_PINT = _ida_typeinf.STI_PINT
r"""
int *
"""

STI_PUINT = _ida_typeinf.STI_PUINT
r"""
unsigned int *
"""

STI_PVOID = _ida_typeinf.STI_PVOID
r"""
void *
"""

STI_PPVOID = _ida_typeinf.STI_PPVOID
r"""
void **
"""

STI_PCVOID = _ida_typeinf.STI_PCVOID
r"""
const void *
"""

STI_ACHAR = _ida_typeinf.STI_ACHAR
r"""
char[]
"""

STI_AUCHAR = _ida_typeinf.STI_AUCHAR
r"""
uint8[]
"""

STI_ACCHAR = _ida_typeinf.STI_ACCHAR
r"""
const char[]
"""

STI_ACUCHAR = _ida_typeinf.STI_ACUCHAR
r"""
const uint8[]
"""

STI_FPURGING = _ida_typeinf.STI_FPURGING
r"""
void __userpurge(int)
"""

STI_FDELOP = _ida_typeinf.STI_FDELOP
r"""
void __cdecl(void *)
"""

STI_MSGSEND = _ida_typeinf.STI_MSGSEND
r"""
void *(void *, const char *, ...)
"""

STI_AEABI_LCMP = _ida_typeinf.STI_AEABI_LCMP
r"""
int __fastcall __pure(int64 x, int64 y)
"""

STI_AEABI_ULCMP = _ida_typeinf.STI_AEABI_ULCMP
r"""
int __fastcall __pure(uint64 x, uint64 y)
"""

STI_DONT_USE = _ida_typeinf.STI_DONT_USE
r"""
unused stock type id; should not be used
"""

STI_SIZE_T = _ida_typeinf.STI_SIZE_T
r"""
size_t
"""

STI_SSIZE_T = _ida_typeinf.STI_SSIZE_T
r"""
ssize_t
"""

STI_AEABI_MEMCPY = _ida_typeinf.STI_AEABI_MEMCPY
r"""
void __fastcall(void *, const void *, size_t)
"""

STI_AEABI_MEMSET = _ida_typeinf.STI_AEABI_MEMSET
r"""
void __fastcall(void *, size_t, int)
"""

STI_AEABI_MEMCLR = _ida_typeinf.STI_AEABI_MEMCLR
r"""
void __fastcall(void *, size_t)
"""

STI_RTC_CHECK_2 = _ida_typeinf.STI_RTC_CHECK_2
r"""
int16 __fastcall(int16 x)
"""

STI_RTC_CHECK_4 = _ida_typeinf.STI_RTC_CHECK_4
r"""
int32 __fastcall(int32 x)
"""

STI_RTC_CHECK_8 = _ida_typeinf.STI_RTC_CHECK_8
r"""
int64 __fastcall(int64 x)
"""

STI_COMPLEX64 = _ida_typeinf.STI_COMPLEX64
r"""
struct complex64_t { float real, imag; }
"""

STI_COMPLEX128 = _ida_typeinf.STI_COMPLEX128
r"""
struct complex128_t { double real, imag; }
"""

STI_PUNKNOWN = _ida_typeinf.STI_PUNKNOWN
r"""
_UNKNOWN *
"""

STI_LAST = _ida_typeinf.STI_LAST

ETF_NO_SAVE = _ida_typeinf.ETF_NO_SAVE
r"""
don't save to til (normally typerefs are saved to til) A call with ETF_NO_SAVE
must be followed by a call without it. Otherwise there may be inconsistencies
between the memory and the type library.
"""

ETF_NO_LAYOUT = _ida_typeinf.ETF_NO_LAYOUT
r"""
don't calc type layout before editing
"""

ETF_MAY_DESTROY = _ida_typeinf.ETF_MAY_DESTROY
r"""
may destroy other members
"""

ETF_COMPATIBLE = _ida_typeinf.ETF_COMPATIBLE
r"""
new type must be compatible with the old
"""

ETF_FUNCARG = _ida_typeinf.ETF_FUNCARG
r"""
udm - member is a function argument (cannot create arrays)
"""

ETF_FORCENAME = _ida_typeinf.ETF_FORCENAME
r"""
anyway use name, see below for more usage description
"""

ETF_AUTONAME = _ida_typeinf.ETF_AUTONAME
r"""
udm - generate a member name if was not specified (add_udm, set_udm_type)
"""

ETF_BYTIL = _ida_typeinf.ETF_BYTIL
r"""
udm - new type was created by the type subsystem
"""

ETF_NO_ARRAY = _ida_typeinf.ETF_NO_ARRAY
r"""
add_udm, set_udm_type - do not convert type to an array on the size mismatch
"""

GTD_CALC_LAYOUT = _ida_typeinf.GTD_CALC_LAYOUT
r"""
calculate udt layout
"""

GTD_NO_LAYOUT = _ida_typeinf.GTD_NO_LAYOUT
r"""
don't calculate udt layout please note that udt layout may have been calculated
earlier
"""

GTD_DEL_BITFLDS = _ida_typeinf.GTD_DEL_BITFLDS
r"""
delete udt bitfields
"""

GTD_CALC_ARGLOCS = _ida_typeinf.GTD_CALC_ARGLOCS
r"""
calculate func arg locations
"""

GTD_NO_ARGLOCS = _ida_typeinf.GTD_NO_ARGLOCS
r"""
don't calculate func arg locations please note that the locations may have been
calculated earlier
"""

GTS_NESTED = _ida_typeinf.GTS_NESTED
r"""
nested type (embedded into a udt)
"""

GTS_BASECLASS = _ida_typeinf.GTS_BASECLASS
r"""
is baseclass of a udt
"""

SUDT_SORT = _ida_typeinf.SUDT_SORT
r"""
fields are not sorted by offset, sort them first
"""

SUDT_ALIGN = _ida_typeinf.SUDT_ALIGN
r"""
recalculate field alignments, struct packing, etc to match the offsets and size
info
"""

SUDT_GAPS = _ida_typeinf.SUDT_GAPS
r"""
allow to fill gaps with additional members (_BYTE[])
"""

SUDT_UNEX = _ida_typeinf.SUDT_UNEX
r"""
references to nonexistent member types are acceptable; in this case it is better
to set the corresponding udm_t::fda field to the type alignment. If this field
is not set, ida will try to guess the alignment.
"""

SUDT_FAST = _ida_typeinf.SUDT_FAST
r"""
serialize without verifying offsets and alignments
"""

SUDT_CONST = _ida_typeinf.SUDT_CONST
r"""
only for serialize_udt: make type const
"""

SUDT_VOLATILE = _ida_typeinf.SUDT_VOLATILE
r"""
only for serialize_udt: make type volatile
"""

SUDT_TRUNC = _ida_typeinf.SUDT_TRUNC
r"""
serialize: truncate useless strings from fields, fldcmts
"""

SUDT_SERDEF = _ida_typeinf.SUDT_SERDEF
r"""
serialize: if a typeref, serialize its definition
"""


def copy_tinfo_t(_this: "tinfo_t", r: "tinfo_t") -> "void":
    r"""
    copy_tinfo_t(_this, r)

    @param _this: tinfo_t *
    @param r: tinfo_t const &
    """
    return _ida_typeinf.copy_tinfo_t(_this, r)

def detach_tinfo_t(_this: "tinfo_t") -> "bool":
    r"""
    detach_tinfo_t(_this) -> bool

    @param _this: tinfo_t *
    """
    return _ida_typeinf.detach_tinfo_t(_this)

def clear_tinfo_t(_this: "tinfo_t") -> "void":
    r"""
    clear_tinfo_t(_this)

    @param _this: tinfo_t *
    """
    return _ida_typeinf.clear_tinfo_t(_this)

def create_tinfo(_this: "tinfo_t", bt: "type_t", bt2: "type_t", ptr: "void *") -> "bool":
    r"""
    create_tinfo(_this, bt, bt2, ptr) -> bool

    @param _this: tinfo_t *
    @param bt: type_t
    @param bt2: type_t
    @param ptr: void *
    """
    return _ida_typeinf.create_tinfo(_this, bt, bt2, ptr)

def verify_tinfo(typid: "typid_t") -> "int":
    r"""
    verify_tinfo(typid) -> int

    @param typid: typid_t
    """
    return _ida_typeinf.verify_tinfo(typid)

def get_tinfo_details(typid: "typid_t", bt2: "type_t", buf: "void *") -> "bool":
    r"""
    get_tinfo_details(typid, bt2, buf) -> bool

    @param typid: typid_t
    @param bt2: type_t
    @param buf: void *
    """
    return _ida_typeinf.get_tinfo_details(typid, bt2, buf)

def get_tinfo_size(p_effalign: "uint32 *", typid: "typid_t", gts_code: "int") -> "size_t":
    r"""
    get_tinfo_size(p_effalign, typid, gts_code) -> size_t

    @param p_effalign: uint32 *
    @param typid: typid_t
    @param gts_code: int
    """
    return _ida_typeinf.get_tinfo_size(p_effalign, typid, gts_code)

def get_tinfo_pdata(outptr: "void *", typid: "typid_t", what: "int") -> "size_t":
    r"""
    get_tinfo_pdata(outptr, typid, what) -> size_t

    @param outptr: void *
    @param typid: typid_t
    @param what: int
    """
    return _ida_typeinf.get_tinfo_pdata(outptr, typid, what)

def get_tinfo_property(typid: "typid_t", gta_prop: "int") -> "size_t":
    r"""
    get_tinfo_property(typid, gta_prop) -> size_t

    @param typid: typid_t
    @param gta_prop: int
    """
    return _ida_typeinf.get_tinfo_property(typid, gta_prop)

def get_tinfo_property4(typid: "typid_t", gta_prop: "int", p1: "size_t", p2: "size_t", p3: "size_t", p4: "size_t") -> "size_t":
    r"""
    get_tinfo_property4(typid, gta_prop, p1, p2, p3, p4) -> size_t

    @param typid: typid_t
    @param gta_prop: int
    @param p1: size_t
    @param p2: size_t
    @param p3: size_t
    @param p4: size_t
    """
    return _ida_typeinf.get_tinfo_property4(typid, gta_prop, p1, p2, p3, p4)

def set_tinfo_property(tif: "tinfo_t", sta_prop: "int", x: "size_t") -> "size_t":
    r"""
    set_tinfo_property(tif, sta_prop, x) -> size_t

    @param tif: tinfo_t *
    @param sta_prop: int
    @param x: size_t
    """
    return _ida_typeinf.set_tinfo_property(tif, sta_prop, x)

def set_tinfo_property4(tif: "tinfo_t", sta_prop: "int", p1: "size_t", p2: "size_t", p3: "size_t", p4: "size_t") -> "size_t":
    r"""
    set_tinfo_property4(tif, sta_prop, p1, p2, p3, p4) -> size_t

    @param tif: tinfo_t *
    @param sta_prop: int
    @param p1: size_t
    @param p2: size_t
    @param p3: size_t
    @param p4: size_t
    """
    return _ida_typeinf.set_tinfo_property4(tif, sta_prop, p1, p2, p3, p4)

def serialize_tinfo(type: "qtype *", fields: "qtype *", fldcmts: "qtype *", tif: "tinfo_t", sudt_flags: "int") -> "bool":
    r"""
    serialize_tinfo(type, fields, fldcmts, tif, sudt_flags) -> bool

    @param type: qtype *
    @param fields: qtype *
    @param fldcmts: qtype *
    @param tif: tinfo_t const *
    @param sudt_flags: int
    """
    return _ida_typeinf.serialize_tinfo(type, fields, fldcmts, tif, sudt_flags)

def find_tinfo_udt_member(udm: "udm_t", typid: "typid_t", strmem_flags: "int") -> "int":
    r"""
    find_tinfo_udt_member(udm, typid, strmem_flags) -> int

    @param udm: udm_t *
    @param typid: typid_t
    @param strmem_flags: int
    """
    return _ida_typeinf.find_tinfo_udt_member(udm, typid, strmem_flags)

def print_tinfo(prefix: "char const *", indent: "int", cmtindent: "int", flags: "int", tif: "tinfo_t", name: "char const *", cmt: "char const *") -> "qstring *":
    r"""
    print_tinfo(prefix, indent, cmtindent, flags, tif, name, cmt) -> str

    @param prefix: char const *
    @param indent: int
    @param cmtindent: int
    @param flags: int
    @param tif: tinfo_t const *
    @param name: char const *
    @param cmt: char const *
    """
    return _ida_typeinf.print_tinfo(prefix, indent, cmtindent, flags, tif, name, cmt)

def dstr_tinfo(tif: "tinfo_t") -> "char const *":
    r"""
    dstr_tinfo(tif) -> char const *

    @param tif: tinfo_t const *
    """
    return _ida_typeinf.dstr_tinfo(tif)

def visit_subtypes(visitor: "tinfo_visitor_t", out: "type_mods_t", tif: "tinfo_t", name: "char const *", cmt: "char const *") -> "int":
    r"""
    visit_subtypes(visitor, out, tif, name, cmt) -> int

    @param visitor: tinfo_visitor_t *
    @param out: type_mods_t *
    @param tif: tinfo_t const &
    @param name: char const *
    @param cmt: char const *
    """
    return _ida_typeinf.visit_subtypes(visitor, out, tif, name, cmt)

def compare_tinfo(t1: "typid_t", t2: "typid_t", tcflags: "int") -> "bool":
    r"""
    compare_tinfo(t1, t2, tcflags) -> bool

    @param t1: typid_t
    @param t2: typid_t
    @param tcflags: int
    """
    return _ida_typeinf.compare_tinfo(t1, t2, tcflags)

def lexcompare_tinfo(t1: "typid_t", t2: "typid_t", arg3: "int") -> "int":
    r"""
    lexcompare_tinfo(t1, t2, arg3) -> int

    @param t1: typid_t
    @param t2: typid_t
    @param arg3: int
    """
    return _ida_typeinf.lexcompare_tinfo(t1, t2, arg3)

def get_stock_tinfo(tif: "tinfo_t", id: "stock_type_id_t") -> "bool":
    r"""
    get_stock_tinfo(tif, id) -> bool

    @param tif: tinfo_t *
    @param id: enum stock_type_id_t
    """
    return _ida_typeinf.get_stock_tinfo(tif, id)

def read_tinfo_bitfield_value(typid: "typid_t", v: "uint64", bitoff: "int") -> "uint64":
    r"""
    read_tinfo_bitfield_value(typid, v, bitoff) -> uint64

    @param typid: typid_t
    @param v: uint64
    @param bitoff: int
    """
    return _ida_typeinf.read_tinfo_bitfield_value(typid, v, bitoff)

def write_tinfo_bitfield_value(typid: "typid_t", dst: "uint64", v: "uint64", bitoff: "int") -> "uint64":
    r"""
    write_tinfo_bitfield_value(typid, dst, v, bitoff) -> uint64

    @param typid: typid_t
    @param dst: uint64
    @param v: uint64
    @param bitoff: int
    """
    return _ida_typeinf.write_tinfo_bitfield_value(typid, dst, v, bitoff)

def get_tinfo_attr(typid: "typid_t", key: "qstring const &", bv: "bytevec_t *", all_attrs: "bool") -> "bool":
    r"""
    get_tinfo_attr(typid, key, bv, all_attrs) -> bool

    @param typid: typid_t
    @param key: qstring const &
    @param bv: bytevec_t *
    @param all_attrs: bool
    """
    return _ida_typeinf.get_tinfo_attr(typid, key, bv, all_attrs)

def set_tinfo_attr(tif: "tinfo_t", ta: "type_attr_t", may_overwrite: "bool") -> "bool":
    r"""
    set_tinfo_attr(tif, ta, may_overwrite) -> bool

    @param tif: tinfo_t *
    @param ta: type_attr_t const &
    @param may_overwrite: bool
    """
    return _ida_typeinf.set_tinfo_attr(tif, ta, may_overwrite)

def del_tinfo_attr(tif: "tinfo_t", key: "qstring const &", make_copy: "bool") -> "bool":
    r"""
    del_tinfo_attr(tif, key, make_copy) -> bool

    @param tif: tinfo_t *
    @param key: qstring const &
    @param make_copy: bool
    """
    return _ida_typeinf.del_tinfo_attr(tif, key, make_copy)

def get_tinfo_attrs(typid: "typid_t", tav: "type_attrs_t", include_ref_attrs: "bool") -> "bool":
    r"""
    get_tinfo_attrs(typid, tav, include_ref_attrs) -> bool

    @param typid: typid_t
    @param tav: type_attrs_t *
    @param include_ref_attrs: bool
    """
    return _ida_typeinf.get_tinfo_attrs(typid, tav, include_ref_attrs)

def set_tinfo_attrs(tif: "tinfo_t", ta: "type_attrs_t") -> "bool":
    r"""
    set_tinfo_attrs(tif, ta) -> bool

    @param tif: tinfo_t *
    @param ta: type_attrs_t *
    """
    return _ida_typeinf.set_tinfo_attrs(tif, ta)

def score_tinfo(tif: "tinfo_t") -> "uint32":
    r"""
    score_tinfo(tif) -> uint32

    @param tif: tinfo_t const *
    """
    return _ida_typeinf.score_tinfo(tif)

def save_tinfo(tif: "tinfo_t", til: "til_t", ord: "size_t", name: "char const *", ntf_flags: "int") -> "tinfo_code_t":
    r"""
    save_tinfo(tif, til, ord, name, ntf_flags) -> tinfo_code_t

    @param tif: tinfo_t *
    @param til: til_t *
    @param ord: size_t
    @param name: char const *
    @param ntf_flags: int
    """
    return _ida_typeinf.save_tinfo(tif, til, ord, name, ntf_flags)

def append_tinfo_covered(out: "rangeset_t", typid: "typid_t", offset: "uint64") -> "bool":
    r"""
    append_tinfo_covered(out, typid, offset) -> bool

    @param out: rangeset_t *
    @param typid: typid_t
    @param offset: uint64
    """
    return _ida_typeinf.append_tinfo_covered(out, typid, offset)

def calc_tinfo_gaps(out: "rangeset_t", typid: "typid_t") -> "bool":
    r"""
    calc_tinfo_gaps(out, typid) -> bool

    @param out: rangeset_t *
    @param typid: typid_t
    """
    return _ida_typeinf.calc_tinfo_gaps(out, typid)

def value_repr_t__from_opinfo(_this: "value_repr_t", flags: "flags64_t", afl: "aflags_t", opinfo: "opinfo_t", ap: "array_parameters_t") -> "bool":
    r"""
    value_repr_t__from_opinfo(_this, flags, afl, opinfo, ap) -> bool

    @param _this: value_repr_t *
    @param flags: flags64_t
    @param afl: aflags_t
    @param opinfo: opinfo_t const *
    @param ap: array_parameters_t const *
    """
    return _ida_typeinf.value_repr_t__from_opinfo(_this, flags, afl, opinfo, ap)

def value_repr_t__print_(_this: "value_repr_t", colored: "bool") -> "qstring *":
    r"""
    value_repr_t__print_(_this, colored) -> str

    @param _this: value_repr_t const *
    @param colored: bool
    """
    return _ida_typeinf.value_repr_t__print_(_this, colored)

def udt_type_data_t__find_member(_this: "udt_type_data_t", udm: "udm_t", strmem_flags: "int") -> "ssize_t":
    r"""
    udt_type_data_t__find_member(_this, udm, strmem_flags) -> ssize_t

    @param _this: udt_type_data_t const *
    @param udm: udm_t *
    @param strmem_flags: int
    """
    return _ida_typeinf.udt_type_data_t__find_member(_this, udm, strmem_flags)

def udm_t__make_gap(_this: "udm_t", byteoff: "uval_t", nbytes: "uval_t") -> "bool":
    r"""
    udm_t__make_gap(_this, byteoff, nbytes) -> bool

    @param _this: udm_t *
    @param byteoff: uval_t
    @param nbytes: uval_t
    """
    return _ida_typeinf.udm_t__make_gap(_this, byteoff, nbytes)

def udt_type_data_t__get_best_fit_member(_this: "udt_type_data_t", disp: "asize_t") -> "ssize_t":
    r"""
    udt_type_data_t__get_best_fit_member(_this, disp) -> ssize_t

    @param _this: udt_type_data_t const *
    @param disp: asize_t
    """
    return _ida_typeinf.udt_type_data_t__get_best_fit_member(_this, disp)

def get_tinfo_by_edm_name(tif: "tinfo_t", til: "til_t", mname: "char const *") -> "ssize_t":
    r"""
    get_tinfo_by_edm_name(tif, til, mname) -> ssize_t

    @param tif: tinfo_t *
    @param til: til_t const *
    @param mname: char const *
    """
    return _ida_typeinf.get_tinfo_by_edm_name(tif, til, mname)
class tinfo_t(object):
    r"""
    Proxy of C++ tinfo_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> tinfo_t
        __init__(self, decl_type) -> tinfo_t

        @param decl_type: type_t

        __init__(self, r) -> tinfo_t

        @param r: tinfo_t const &
        """
        _ida_typeinf.tinfo_t_swiginit(self, _ida_typeinf.new_tinfo_t(*args))

    def clear(self) -> "void":
        r"""
        clear(self)
        Clear contents of this tinfo, and remove from the type system.
        """
        return _ida_typeinf.tinfo_t_clear(self)

    def swap(self, r: "tinfo_t") -> "void":
        r"""
        swap(self, r)
        Assign this = r and r = this.

        @param r: (C++: tinfo_t &)
        """
        return _ida_typeinf.tinfo_t_swap(self, r)

    def get_named_type(self, *args) -> "bool":
        r"""
        get_named_type(self, til, name, decl_type=BTF_TYPEDEF, resolve=True, try_ordinal=True) -> bool

        @param til: til_t const *
        @param name: char const *
        @param decl_type: type_t
        @param resolve: bool
        @param try_ordinal: bool

        get_named_type(self, name, decl_type=BTF_TYPEDEF, resolve=True, try_ordinal=True) -> bool

        @param name: char const *
        @param decl_type: type_t
        @param resolve: bool
        @param try_ordinal: bool
        """
        return _ida_typeinf.tinfo_t_get_named_type(self, *args)

    def get_numbered_type(self, *args) -> "bool":
        r"""
        get_numbered_type(self, til, ordinal, decl_type=BTF_TYPEDEF, resolve=True) -> bool

        @param til: til_t const *
        @param ordinal: uint32
        @param decl_type: type_t
        @param resolve: bool

        get_numbered_type(self, ordinal, decl_type=BTF_TYPEDEF, resolve=True) -> bool

        @param ordinal: uint32
        @param decl_type: type_t
        @param resolve: bool
        """
        return _ida_typeinf.tinfo_t_get_numbered_type(self, *args)

    def detach(self) -> "bool":
        r"""
        detach(self) -> bool
        Detach tinfo_t from the underlying type. After calling this finction, tinfo_t
        will lose its link to the underlying named or numbered type (if any) and will
        become a reference to a unique type. After that, any modifications to tinfo_t
        will affect only its type.
        """
        return _ida_typeinf.tinfo_t_detach(self)

    def is_correct(self) -> "bool":
        r"""
        is_correct(self) -> bool
        Is the type object correct?. It is possible to create incorrect types. For
        example, we can define a function that returns an enum and then delete the enum
        type. If this function returns false, the type should not be used in
        disassembly. Please note that this function does not verify all involved types:
        for example, pointers to undefined types are permitted.
        """
        return _ida_typeinf.tinfo_t_is_correct(self)

    def get_realtype(self, full: "bool"=False) -> "type_t":
        r"""
        get_realtype(self, full=False) -> type_t
        Get the resolved base type. Deserialization options:
        * if full=true, the referenced type will be deserialized fully, this may not
        always be desirable (slows down things)
        * if full=false, we just return the base type, the referenced type will be
        resolved again later if necessary (this may lead to multiple resolvings of the
        same type) imho full=false is a better approach because it does not perform
        unnecessary actions just in case. however, in some cases the caller knows that
        it is very likely that full type info will be required. in those cases full=true
        makes sense

        @param full: (C++: bool)
        """
        return _ida_typeinf.tinfo_t_get_realtype(self, full)

    def get_decltype(self) -> "type_t":
        r"""
        get_decltype(self) -> type_t
        Get declared type (without resolving type references; they are returned as is).
        Obviously this is a very fast function and should be used instead of
        get_realtype() if possible. Please note that for typerefs this function will
        return BTF_TYPEDEF. To determine if a typeref is a typedef, use is_typedef()
        """
        return _ida_typeinf.tinfo_t_get_decltype(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        Was tinfo_t initialized with some type info or not?
        """
        return _ida_typeinf.tinfo_t_empty(self)

    def present(self) -> "bool":
        r"""
        present(self) -> bool
        Is the type really present? (not a reference to a missing type, for example)
        """
        return _ida_typeinf.tinfo_t_present(self)

    def get_size(self, p_effalign: "uint32 *"=None, gts_code: "int"=0) -> "size_t":
        r"""
        get_size(self, p_effalign=None, gts_code=0) -> size_t
        Get the type size in bytes.

        @param p_effalign: (C++: uint32 *) buffer for the alignment value
        @param gts_code: (C++: int) combination of GTS_... constants
        @return: BADSIZE in case of problems
        """
        return _ida_typeinf.tinfo_t_get_size(self, p_effalign, gts_code)

    def get_unpadded_size(self) -> "size_t":
        r"""
        get_unpadded_size(self) -> size_t
        Get the type size in bytes without the final padding, in bytes. For some UDTs
        get_unpadded_size() != get_size()
        """
        return _ida_typeinf.tinfo_t_get_unpadded_size(self)

    def get_sign(self) -> "type_sign_t":
        r"""
        get_sign(self) -> type_sign_t
        Get type sign.
        """
        return _ida_typeinf.tinfo_t_get_sign(self)

    def is_signed(self) -> "bool":
        r"""
        is_signed(self) -> bool
        Is this a signed type?
        """
        return _ida_typeinf.tinfo_t_is_signed(self)

    def is_unsigned(self) -> "bool":
        r"""
        is_unsigned(self) -> bool
        Is this an unsigned type?
        """
        return _ida_typeinf.tinfo_t_is_unsigned(self)

    def get_declalign(self) -> "uchar":
        r"""
        get_declalign(self) -> uchar
        Get declared alignment of the type.
        """
        return _ida_typeinf.tinfo_t_get_declalign(self)

    def is_typeref(self) -> "bool":
        r"""
        is_typeref(self) -> bool
        Is this type a type reference?.
        """
        return _ida_typeinf.tinfo_t_is_typeref(self)

    def has_details(self) -> "bool":
        r"""
        has_details(self) -> bool
        Does this type refer to a nontrivial type?
        """
        return _ida_typeinf.tinfo_t_has_details(self)

    def get_type_name(self) -> "bool":
        r"""
        get_type_name(self) -> bool
        Does a type refer to a name?. If yes, fill the provided buffer with the type
        name and return true. Names are returned for numbered types too: either a user-
        defined nice name or, if a user-provided name does not exist, an ordinal name
        (like #xx, see create_numbered_type_name()).
        """
        return _ida_typeinf.tinfo_t_get_type_name(self)

    def get_nice_type_name(self) -> "bool":
        r"""
        get_nice_type_name(self) -> bool
        Get the beautified type name. Get the referenced name and apply regular
        expressions from goodname.cfg to beautify the name
        """
        return _ida_typeinf.tinfo_t_get_nice_type_name(self)

    def rename_type(self, name: "char const *", ntf_flags: "int"=0) -> "tinfo_code_t":
        r"""
        rename_type(self, name, ntf_flags=0) -> tinfo_code_t
        Rename a type

        @param name: (C++: const char *) new type name
        @param ntf_flags: (C++: int) Flags for named types
        @note: The change is saved immediately
        """
        return _ida_typeinf.tinfo_t_rename_type(self, name, ntf_flags)

    def get_final_type_name(self) -> "bool":
        r"""
        get_final_type_name(self) -> bool
        Use in the case of typedef chain (TYPE1 -> TYPE2 -> TYPE3...TYPEn).

        @return: the name of the last type in the chain (TYPEn). if there is no chain,
                 returns TYPE1
        """
        return _ida_typeinf.tinfo_t_get_final_type_name(self)

    def get_next_type_name(self) -> "bool":
        r"""
        get_next_type_name(self) -> bool
        Use In the case of typedef chain (TYPE1 -> TYPE2 -> TYPE3...TYPEn).

        @return: the name of the next type in the chain (TYPE2). if there is no chain,
                 returns failure
        """
        return _ida_typeinf.tinfo_t_get_next_type_name(self)

    def get_tid(self) -> "tid_t":
        r"""
        get_tid(self) -> tid_t
        Get the type tid Each type in the local type library has a so-called `tid`
        associated with it. The tid is used to collect xrefs to the type. The tid is
        created when the type is created in the local type library and does not change
        afterwards. It can be passed to xref-related functions instead of the address.

        @return: tid or BADADDR
        @note: types that do not come from a type library (that exist only in the
               memory) can not have a tid.
        """
        return _ida_typeinf.tinfo_t_get_tid(self)

    def force_tid(self) -> "tid_t":
        r"""
        force_tid(self) -> tid_t
        Get the type tid. Create if it does not exist yet. If the type comes from a base
        til, the type will be copied to the local til and a new tid will be created for
        it. (if the type comes from a base til, it does not have a tid yet). If the type
        comes from the local til, this function is equivalent to get_tid()

        @return: tid or BADADDR
        """
        return _ida_typeinf.tinfo_t_force_tid(self)

    def get_ordinal(self) -> "uint32":
        r"""
        get_ordinal(self) -> uint32
        Get type ordinal (only if the type was created as a numbered type, 0 if none)
        """
        return _ida_typeinf.tinfo_t_get_ordinal(self)

    def get_final_ordinal(self) -> "uint32":
        r"""
        get_final_ordinal(self) -> uint32
        Get final type ordinal (0 if none)
        """
        return _ida_typeinf.tinfo_t_get_final_ordinal(self)

    def get_til(self) -> "til_t *":
        r"""
        get_til(self) -> til_t
        Get the type library for tinfo_t.
        """
        return _ida_typeinf.tinfo_t_get_til(self)

    def is_from_subtil(self) -> "bool":
        r"""
        is_from_subtil(self) -> bool
        Was the named type found in some base type library (not the top level type
        library)?. If yes, it usually means that the type comes from some loaded type
        library, not the local type library for the database
        """
        return _ida_typeinf.tinfo_t_is_from_subtil(self)

    def is_forward_decl(self) -> "bool":
        r"""
        is_forward_decl(self) -> bool
        Is this a forward declaration?. Forward declarations are placeholders: the type
        definition does not exist
        """
        return _ida_typeinf.tinfo_t_is_forward_decl(self)

    def get_forward_type(self) -> "type_t":
        r"""
        get_forward_type(self) -> type_t
        Get type of a forward declaration. For a forward declaration this function
        returns its base type. In other cases it returns BT_UNK
        """
        return _ida_typeinf.tinfo_t_get_forward_type(self)

    def is_forward_struct(self) -> "bool":
        r"""
        is_forward_struct(self) -> bool
        """
        return _ida_typeinf.tinfo_t_is_forward_struct(self)

    def is_forward_union(self) -> "bool":
        r"""
        is_forward_union(self) -> bool
        """
        return _ida_typeinf.tinfo_t_is_forward_union(self)

    def is_forward_enum(self) -> "bool":
        r"""
        is_forward_enum(self) -> bool
        """
        return _ida_typeinf.tinfo_t_is_forward_enum(self)

    def is_typedef(self) -> "bool":
        r"""
        is_typedef(self) -> bool
        Is this a typedef?. This function will return true for a reference to a local
        type that is declared as a typedef.
        """
        return _ida_typeinf.tinfo_t_is_typedef(self)

    def get_type_cmt(self) -> "int":
        r"""
        get_type_cmt(self) -> int
        Get type comment

        @return: 0-failed, 1-returned regular comment, 2-returned repeatable comment
        """
        return _ida_typeinf.tinfo_t_get_type_cmt(self)

    def get_type_rptcmt(self) -> "bool":
        r"""
        get_type_rptcmt(self) -> bool
        Get type comment only if it is repeatable.
        """
        return _ida_typeinf.tinfo_t_get_type_rptcmt(self)

    def is_decl_const(self) -> "bool":
        r"""
        is_decl_const(self) -> bool
        is_type_const(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_const(self)

    def is_decl_volatile(self) -> "bool":
        r"""
        is_decl_volatile(self) -> bool
        is_type_volatile(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_volatile(self)

    def is_decl_void(self) -> "bool":
        r"""
        is_decl_void(self) -> bool
        is_type_void(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_void(self)

    def is_decl_partial(self) -> "bool":
        r"""
        is_decl_partial(self) -> bool
        is_type_partial(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_partial(self)

    def is_decl_unknown(self) -> "bool":
        r"""
        is_decl_unknown(self) -> bool
        is_type_unknown(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_unknown(self)

    def is_decl_last(self) -> "bool":
        r"""
        is_decl_last(self) -> bool
        is_typeid_last(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_last(self)

    def is_decl_ptr(self) -> "bool":
        r"""
        is_decl_ptr(self) -> bool
        is_type_ptr(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_ptr(self)

    def is_decl_array(self) -> "bool":
        r"""
        is_decl_array(self) -> bool
        is_type_array(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_array(self)

    def is_decl_func(self) -> "bool":
        r"""
        is_decl_func(self) -> bool
        is_type_func(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_func(self)

    def is_decl_complex(self) -> "bool":
        r"""
        is_decl_complex(self) -> bool
        is_type_complex(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_complex(self)

    def is_decl_typedef(self) -> "bool":
        r"""
        is_decl_typedef(self) -> bool
        is_type_typedef(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_typedef(self)

    def is_decl_sue(self) -> "bool":
        r"""
        is_decl_sue(self) -> bool
        is_type_sue(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_sue(self)

    def is_decl_struct(self) -> "bool":
        r"""
        is_decl_struct(self) -> bool
        is_type_struct(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_struct(self)

    def is_decl_union(self) -> "bool":
        r"""
        is_decl_union(self) -> bool
        is_type_union(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_union(self)

    def is_decl_udt(self) -> "bool":
        r"""
        is_decl_udt(self) -> bool
        is_type_struni(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_udt(self)

    def is_decl_enum(self) -> "bool":
        r"""
        is_decl_enum(self) -> bool
        is_type_enum(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_enum(self)

    def is_decl_bitfield(self) -> "bool":
        r"""
        is_decl_bitfield(self) -> bool
        is_type_bitfld(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_bitfield(self)

    def is_decl_int128(self) -> "bool":
        r"""
        is_decl_int128(self) -> bool
        is_type_int128(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_int128(self)

    def is_decl_int64(self) -> "bool":
        r"""
        is_decl_int64(self) -> bool
        is_type_int64(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_int64(self)

    def is_decl_int32(self) -> "bool":
        r"""
        is_decl_int32(self) -> bool
        is_type_int32(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_int32(self)

    def is_decl_int16(self) -> "bool":
        r"""
        is_decl_int16(self) -> bool
        is_type_int16(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_int16(self)

    def is_decl_int(self) -> "bool":
        r"""
        is_decl_int(self) -> bool
        is_type_int(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_int(self)

    def is_decl_char(self) -> "bool":
        r"""
        is_decl_char(self) -> bool
        is_type_char(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_char(self)

    def is_decl_uint(self) -> "bool":
        r"""
        is_decl_uint(self) -> bool
        is_type_uint(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_uint(self)

    def is_decl_uchar(self) -> "bool":
        r"""
        is_decl_uchar(self) -> bool
        is_type_uchar(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_uchar(self)

    def is_decl_uint16(self) -> "bool":
        r"""
        is_decl_uint16(self) -> bool
        is_type_uint16(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_uint16(self)

    def is_decl_uint32(self) -> "bool":
        r"""
        is_decl_uint32(self) -> bool
        is_type_uint32(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_uint32(self)

    def is_decl_uint64(self) -> "bool":
        r"""
        is_decl_uint64(self) -> bool
        is_type_uint64(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_uint64(self)

    def is_decl_uint128(self) -> "bool":
        r"""
        is_decl_uint128(self) -> bool
        is_type_uint128(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_uint128(self)

    def is_decl_ldouble(self) -> "bool":
        r"""
        is_decl_ldouble(self) -> bool
        is_type_ldouble(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_ldouble(self)

    def is_decl_double(self) -> "bool":
        r"""
        is_decl_double(self) -> bool
        is_type_double(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_double(self)

    def is_decl_float(self) -> "bool":
        r"""
        is_decl_float(self) -> bool
        is_type_float(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_float(self)

    def is_decl_tbyte(self) -> "bool":
        r"""
        is_decl_tbyte(self) -> bool
        is_type_tbyte(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_tbyte(self)

    def is_decl_floating(self) -> "bool":
        r"""
        is_decl_floating(self) -> bool
        is_type_floating(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_floating(self)

    def is_decl_bool(self) -> "bool":
        r"""
        is_decl_bool(self) -> bool
        is_type_bool(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_bool(self)

    def is_decl_paf(self) -> "bool":
        r"""
        is_decl_paf(self) -> bool
        is_type_paf(get_decltype())
        """
        return _ida_typeinf.tinfo_t_is_decl_paf(self)

    def is_well_defined(self) -> "bool":
        r"""
        is_well_defined(self) -> bool
        !(empty()) && !(is_decl_partial()) && !(is_punknown())
        """
        return _ida_typeinf.tinfo_t_is_well_defined(self)

    def is_const(self) -> "bool":
        r"""
        is_const(self) -> bool
        is_type_const(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_const(self)

    def is_volatile(self) -> "bool":
        r"""
        is_volatile(self) -> bool
        is_type_volatile(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_volatile(self)

    def is_void(self) -> "bool":
        r"""
        is_void(self) -> bool
        is_type_void(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_void(self)

    def is_partial(self) -> "bool":
        r"""
        is_partial(self) -> bool
        is_type_partial(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_partial(self)

    def is_unknown(self) -> "bool":
        r"""
        is_unknown(self) -> bool
        is_type_unknown(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_unknown(self)

    def is_ptr(self) -> "bool":
        r"""
        is_ptr(self) -> bool
        is_type_ptr(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_ptr(self)

    def is_array(self) -> "bool":
        r"""
        is_array(self) -> bool
        is_type_array(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_array(self)

    def is_func(self) -> "bool":
        r"""
        is_func(self) -> bool
        is_type_func(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_func(self)

    def is_complex(self) -> "bool":
        r"""
        is_complex(self) -> bool
        is_type_complex(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_complex(self)

    def is_struct(self) -> "bool":
        r"""
        is_struct(self) -> bool
        is_type_struct(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_struct(self)

    def is_union(self) -> "bool":
        r"""
        is_union(self) -> bool
        is_type_union(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_union(self)

    def is_udt(self) -> "bool":
        r"""
        is_udt(self) -> bool
        is_type_struni(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_udt(self)

    def is_enum(self) -> "bool":
        r"""
        is_enum(self) -> bool
        is_type_enum(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_enum(self)

    def is_sue(self) -> "bool":
        r"""
        is_sue(self) -> bool
        is_type_sue(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_sue(self)

    def is_bitfield(self) -> "bool":
        r"""
        is_bitfield(self) -> bool
        is_type_bitfld(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_bitfield(self)

    def is_int128(self) -> "bool":
        r"""
        is_int128(self) -> bool
        is_type_int128(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_int128(self)

    def is_int64(self) -> "bool":
        r"""
        is_int64(self) -> bool
        is_type_int64(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_int64(self)

    def is_int32(self) -> "bool":
        r"""
        is_int32(self) -> bool
        is_type_int32(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_int32(self)

    def is_int16(self) -> "bool":
        r"""
        is_int16(self) -> bool
        is_type_int16(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_int16(self)

    def is_int(self) -> "bool":
        r"""
        is_int(self) -> bool
        is_type_int(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_int(self)

    def is_char(self) -> "bool":
        r"""
        is_char(self) -> bool
        is_type_char(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_char(self)

    def is_uint(self) -> "bool":
        r"""
        is_uint(self) -> bool
        is_type_uint(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_uint(self)

    def is_uchar(self) -> "bool":
        r"""
        is_uchar(self) -> bool
        is_type_uchar(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_uchar(self)

    def is_uint16(self) -> "bool":
        r"""
        is_uint16(self) -> bool
        is_type_uint16(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_uint16(self)

    def is_uint32(self) -> "bool":
        r"""
        is_uint32(self) -> bool
        is_type_uint32(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_uint32(self)

    def is_uint64(self) -> "bool":
        r"""
        is_uint64(self) -> bool
        is_type_uint64(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_uint64(self)

    def is_uint128(self) -> "bool":
        r"""
        is_uint128(self) -> bool
        is_type_uint128(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_uint128(self)

    def is_ldouble(self) -> "bool":
        r"""
        is_ldouble(self) -> bool
        is_type_ldouble(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_ldouble(self)

    def is_double(self) -> "bool":
        r"""
        is_double(self) -> bool
        is_type_double(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_double(self)

    def is_float(self) -> "bool":
        r"""
        is_float(self) -> bool
        is_type_float(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_float(self)

    def is_tbyte(self) -> "bool":
        r"""
        is_tbyte(self) -> bool
        is_type_tbyte(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_tbyte(self)

    def is_bool(self) -> "bool":
        r"""
        is_bool(self) -> bool
        is_type_bool(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_bool(self)

    def is_paf(self) -> "bool":
        r"""
        is_paf(self) -> bool
        is_type_paf(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_paf(self)

    def is_ptr_or_array(self) -> "bool":
        r"""
        is_ptr_or_array(self) -> bool
        is_type_ptr_or_array(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_ptr_or_array(self)

    def is_integral(self) -> "bool":
        r"""
        is_integral(self) -> bool
        is_type_integral(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_integral(self)

    def is_ext_integral(self) -> "bool":
        r"""
        is_ext_integral(self) -> bool
        is_type_ext_integral(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_ext_integral(self)

    def is_floating(self) -> "bool":
        r"""
        is_floating(self) -> bool
        is_type_floating(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_floating(self)

    def is_arithmetic(self) -> "bool":
        r"""
        is_arithmetic(self) -> bool
        is_type_arithmetic(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_arithmetic(self)

    def is_ext_arithmetic(self) -> "bool":
        r"""
        is_ext_arithmetic(self) -> bool
        is_type_ext_arithmetic(get_realtype())
        """
        return _ida_typeinf.tinfo_t_is_ext_arithmetic(self)

    def is_scalar(self) -> "bool":
        r"""
        is_scalar(self) -> bool
        Does the type represent a single number?
        """
        return _ida_typeinf.tinfo_t_is_scalar(self)

    def get_ptr_details(self, pi: "ptr_type_data_t") -> "bool":
        r"""
        get_ptr_details(self, pi) -> bool
        Get the pointer info.

        @param pi: (C++: ptr_type_data_t *)
        """
        return _ida_typeinf.tinfo_t_get_ptr_details(self, pi)

    def get_array_details(self, ai: "array_type_data_t") -> "bool":
        r"""
        get_array_details(self, ai) -> bool
        Get the array specific info.

        @param ai: (C++: array_type_data_t *)
        """
        return _ida_typeinf.tinfo_t_get_array_details(self, ai)

    def get_enum_details(self, ei: "enum_type_data_t") -> "bool":
        r"""
        get_enum_details(self, ei) -> bool
        Get the enum specific info.

        @param ei: (C++: enum_type_data_t *)
        """
        return _ida_typeinf.tinfo_t_get_enum_details(self, ei)

    def get_bitfield_details(self, bi: "bitfield_type_data_t") -> "bool":
        r"""
        get_bitfield_details(self, bi) -> bool
        Get the bitfield specific info.

        @param bi: (C++: bitfield_type_data_t *)
        """
        return _ida_typeinf.tinfo_t_get_bitfield_details(self, bi)

    def get_udt_details(self, udt: "udt_type_data_t", gtd: "gtd_udt_t"=GTD_CALC_LAYOUT) -> "bool":
        r"""
        get_udt_details(self, udt, gtd=GTD_CALC_LAYOUT) -> bool
        Get the udt specific info.

        @param udt: (C++: udt_type_data_t *)
        @param gtd: (C++: gtd_udt_t) enum gtd_udt_t
        """
        return _ida_typeinf.tinfo_t_get_udt_details(self, udt, gtd)

    def get_func_details(self, fi: "func_type_data_t", gtd: "gtd_func_t"=GTD_CALC_ARGLOCS) -> "bool":
        r"""
        get_func_details(self, fi, gtd=GTD_CALC_ARGLOCS) -> bool
        Get only the function specific info for this tinfo_t.

        @param fi: (C++: func_type_data_t *)
        @param gtd: (C++: gtd_func_t) enum gtd_func_t
        """
        return _ida_typeinf.tinfo_t_get_func_details(self, fi, gtd)

    def is_funcptr(self) -> "bool":
        r"""
        is_funcptr(self) -> bool
        Is this pointer to a function?
        """
        return _ida_typeinf.tinfo_t_is_funcptr(self)

    def is_shifted_ptr(self) -> "bool":
        r"""
        is_shifted_ptr(self) -> bool
        Is a shifted pointer?
        """
        return _ida_typeinf.tinfo_t_is_shifted_ptr(self)

    def is_varstruct(self) -> "bool":
        r"""
        is_varstruct(self) -> bool
        Is a variable-size structure?
        """
        return _ida_typeinf.tinfo_t_is_varstruct(self)

    def is_varmember(self) -> "bool":
        r"""
        is_varmember(self) -> bool
        Can the type be of a variable struct member? This function checks for:
        is_array() && array.nelems==0 Such a member can be only the very last member of
        a structure
        """
        return _ida_typeinf.tinfo_t_is_varmember(self)

    def get_ptrarr_objsize(self) -> "int":
        r"""
        get_ptrarr_objsize(self) -> int
        BT_PTR & BT_ARRAY: get size of pointed object or array element. On error returns
        -1
        """
        return _ida_typeinf.tinfo_t_get_ptrarr_objsize(self)

    def get_ptrarr_object(self) -> "tinfo_t":
        r"""
        get_ptrarr_object(self) -> tinfo_t
        BT_PTR & BT_ARRAY: get the pointed object or array element. If the current type
        is not a pointer or array, return empty type info.
        """
        return _ida_typeinf.tinfo_t_get_ptrarr_object(self)

    def get_pointed_object(self) -> "tinfo_t":
        r"""
        get_pointed_object(self) -> tinfo_t
        """
        return _ida_typeinf.tinfo_t_get_pointed_object(self)

    def is_pvoid(self) -> "bool":
        r"""
        is_pvoid(self) -> bool
        Is "void *"?. This function does not check the pointer attributes and type
        modifiers.
        """
        return _ida_typeinf.tinfo_t_is_pvoid(self)

    def is_punknown(self) -> "bool":
        r"""
        is_punknown(self) -> bool
        Is "_UNKNOWN *"?. This function does not check the pointer attributes and type
        modifiers.
        """
        return _ida_typeinf.tinfo_t_is_punknown(self)

    def get_array_element(self) -> "tinfo_t":
        r"""
        get_array_element(self) -> tinfo_t
        """
        return _ida_typeinf.tinfo_t_get_array_element(self)

    def get_final_element(self) -> "tinfo_t":
        r"""
        get_final_element(self) -> tinfo_t
        repeat recursively: if an array, return the type of its element; else return the
        type itself.
        """
        return _ida_typeinf.tinfo_t_get_final_element(self)

    def get_array_nelems(self) -> "int":
        r"""
        get_array_nelems(self) -> int
        """
        return _ida_typeinf.tinfo_t_get_array_nelems(self)

    def get_nth_arg(self, n: "int") -> "tinfo_t":
        r"""
        get_nth_arg(self, n) -> tinfo_t
        BT_FUNC or BT_PTR BT_FUNC: Get type of n-th arg (-1 means return type, see
        get_rettype())

        @param n: (C++: int)
        """
        return _ida_typeinf.tinfo_t_get_nth_arg(self, n)

    def get_rettype(self) -> "tinfo_t":
        r"""
        get_rettype(self) -> tinfo_t
        BT_FUNC or BT_PTR BT_FUNC: Get the function's return type
        """
        return _ida_typeinf.tinfo_t_get_rettype(self)

    def get_nargs(self) -> "int":
        r"""
        get_nargs(self) -> int
        BT_FUNC or BT_PTR BT_FUNC: Calculate number of arguments (-1 - error)
        """
        return _ida_typeinf.tinfo_t_get_nargs(self)

    def is_user_cc(self) -> "bool":
        r"""
        is_user_cc(self) -> bool
        is_user_cc(get_cc())
        """
        return _ida_typeinf.tinfo_t_is_user_cc(self)

    def is_vararg_cc(self) -> "bool":
        r"""
        is_vararg_cc(self) -> bool
        is_vararg_cc(get_cc())
        """
        return _ida_typeinf.tinfo_t_is_vararg_cc(self)

    def is_purging_cc(self) -> "bool":
        r"""
        is_purging_cc(self) -> bool
        is_purging_cc(get_cc())
        """
        return _ida_typeinf.tinfo_t_is_purging_cc(self)

    def calc_purged_bytes(self) -> "int":
        r"""
        calc_purged_bytes(self) -> int
        """
        return _ida_typeinf.tinfo_t_calc_purged_bytes(self)

    def is_high_func(self) -> "bool":
        r"""
        is_high_func(self) -> bool
        """
        return _ida_typeinf.tinfo_t_is_high_func(self)

    def get_methods(self, methods: "udtmembervec_t") -> "bool":
        r"""
        get_methods(self, methods) -> bool

        @param BT_COMPLEX: get a list of member functions declared in this udt.
        @return: false if no member functions exist
        """
        return _ida_typeinf.tinfo_t_get_methods(self, methods)

    def get_bit_buckets(self, buckets: "range64vec_t") -> "bool":
        r"""
        get_bit_buckets(self, buckets) -> bool
        ::BT_STRUCT: get bit buckets Bit buckets are used to layout bitfields

        @param buckets: (C++: range64vec_t *)
        @return: false if wrong type was passed
        """
        return _ida_typeinf.tinfo_t_get_bit_buckets(self, buckets)

    def find_udm(self, *args) -> "int":
        r"""
        find_udm(self, udm, strmem_flags) -> int
        BTF_STRUCT,BTF_UNION: Find an udt member by name

        @param udm: udm_t *
        @param strmem_flags: (C++: int)

        @return: the index of the found member or -1
        find_udm(self, offset, strmem_flags=0) -> int

        @param offset: uint64
        @param strmem_flags: int

        find_udm(self, name, strmem_flags=0) -> int

        @param name: char const *
        @param strmem_flags: int
        """
        return _ida_typeinf.tinfo_t_find_udm(self, *args)

    def get_udt_nmembers(self) -> "int":
        r"""
        get_udt_nmembers(self) -> int
        Get number of udt members. -1-error.
        """
        return _ida_typeinf.tinfo_t_get_udt_nmembers(self)

    def is_empty_udt(self) -> "bool":
        r"""
        is_empty_udt(self) -> bool
        Is an empty struct/union? (has no fields)
        """
        return _ida_typeinf.tinfo_t_is_empty_udt(self)

    def is_small_udt(self) -> "bool":
        r"""
        is_small_udt(self) -> bool
        Is a small udt? (can fit a register or a pair of registers)
        """
        return _ida_typeinf.tinfo_t_is_small_udt(self)

    def requires_qualifier(self, name: "char const *", offset: "uint64") -> "bool":
        r"""
        requires_qualifier(self, name, offset) -> bool
        Requires full qualifier? (name is not unique)

        @param name: (C++: const char *) field name
        @param offset: (C++: uint64) field offset in bits
        @return: if the name is not unique, returns true
        """
        return _ida_typeinf.tinfo_t_requires_qualifier(self, name, offset)

    def append_covered(self, out: "rangeset_t", offset: "uint64"=0) -> "bool":
        r"""
        append_covered(self, out, offset=0) -> bool
        Calculate set of covered bytes for the type

        @param out: (C++: rangeset_t *) pointer to the output buffer. covered bytes will be appended to it.
        @param offset: (C++: uint64) delta in bytes to add to all calculations. used internally during
                       recurion.
        """
        return _ida_typeinf.tinfo_t_append_covered(self, out, offset)

    def calc_gaps(self, out: "rangeset_t") -> "bool":
        r"""
        calc_gaps(self, out) -> bool
        Calculate set of padding bytes for the type

        @param out: (C++: rangeset_t *) pointer to the output buffer; old buffer contents will be lost.
        """
        return _ida_typeinf.tinfo_t_calc_gaps(self, out)

    def is_one_fpval(self) -> "bool":
        r"""
        is_one_fpval(self) -> bool
        Floating value or an object consisting of one floating member entirely.
        """
        return _ida_typeinf.tinfo_t_is_one_fpval(self)

    def is_sse_type(self) -> "bool":
        r"""
        is_sse_type(self) -> bool
        Is a SSE vector type?
        """
        return _ida_typeinf.tinfo_t_is_sse_type(self)

    def is_anonymous_udt(self) -> "bool":
        r"""
        is_anonymous_udt(self) -> bool
        Is an anonymous struct/union? We assume that types with names are anonymous if
        the name starts with $
        """
        return _ida_typeinf.tinfo_t_is_anonymous_udt(self)

    def is_vftable(self) -> "bool":
        r"""
        is_vftable(self) -> bool
        Is a vftable type?
        """
        return _ida_typeinf.tinfo_t_is_vftable(self)

    def has_vftable(self) -> "bool":
        r"""
        has_vftable(self) -> bool
        Has a vftable?
        """
        return _ida_typeinf.tinfo_t_has_vftable(self)

    def has_union(self) -> "bool":
        r"""
        has_union(self) -> bool
        Has a member of type "union"?
        """
        return _ida_typeinf.tinfo_t_has_union(self)

    def get_enum_nmembers(self) -> "size_t":
        r"""
        get_enum_nmembers(self) -> size_t
        Get number of enum members.

        @return: BADSIZE if error
        """
        return _ida_typeinf.tinfo_t_get_enum_nmembers(self)

    def is_empty_enum(self) -> "bool":
        r"""
        is_empty_enum(self) -> bool
        Is an empty enum? (has no constants)
        """
        return _ida_typeinf.tinfo_t_is_empty_enum(self)

    def get_enum_base_type(self) -> "type_t":
        r"""
        get_enum_base_type(self) -> type_t
        Get enum base type (convert enum to integer type) Returns BT_UNK if failed to
        convert
        """
        return _ida_typeinf.tinfo_t_get_enum_base_type(self)

    def is_bitmask_enum(self) -> "bool":
        r"""
        is_bitmask_enum(self) -> bool
        Is bitmask enum?

        @return: true for bitmask enum and false in other cases
                 enum_type_data_t::is_bf()
        """
        return _ida_typeinf.tinfo_t_is_bitmask_enum(self)

    def get_enum_radix(self) -> "int":
        r"""
        get_enum_radix(self) -> int
        Get enum constant radix

        @return: radix or 1 for BTE_CHAR enum_type_data_t::get_enum_radix()
        """
        return _ida_typeinf.tinfo_t_get_enum_radix(self)

    def get_enum_repr(self, repr: "value_repr_t") -> "tinfo_code_t":
        r"""
        get_enum_repr(self, repr) -> tinfo_code_t
        Set the representation of enum members.

        @param repr: (C++: value_repr_t *) value_repr_t
        """
        return _ida_typeinf.tinfo_t_get_enum_repr(self, repr)

    def get_enum_width(self) -> "int":
        r"""
        get_enum_width(self) -> int
        Get enum width

        @return: width of enum base type in bytes, 0 - unspecified, or -1
                 enum_type_data_t::calc_nbytes()
        """
        return _ida_typeinf.tinfo_t_get_enum_width(self)

    def calc_enum_mask(self) -> "uint64":
        r"""
        calc_enum_mask(self) -> uint64
        """
        return _ida_typeinf.tinfo_t_calc_enum_mask(self)

    def get_edm(self, edm: "edm_t", idx: "size_t") -> "tinfo_code_t":
        r"""
        get_edm(self, edm, idx) -> tinfo_code_t
        Get enum member

        @param edm: (C++: edm_t *) enum type member
        @param idx: (C++: size_t) enum member index
        """
        return _ida_typeinf.tinfo_t_get_edm(self, edm, idx)

    def find_edm(self, *args) -> "ssize_t":
        r"""
        find_edm(self, edm, value, bmask=bmask64_t(-1), serial=0) -> ssize_t
        Find enum member

        @param edm: (C++: edm_t *) enum type member, may be nullptr
        @param value: uint64
        @param bmask: bmask64_t
        @return: member index, otherwise returns -1.
        find_edm(self, edm, name) -> ssize_t

        @param edm: edm_t *
        @param name: char const *
        """
        return _ida_typeinf.tinfo_t_find_edm(self, *args)

    def get_edm_tid(self, idx: "size_t") -> "tid_t":
        r"""
        get_edm_tid(self, idx) -> tid_t
        Get enum member TID

        @param idx: (C++: size_t) enum member index
        @return: tid or BADADDR The tid is used to collect xrefs to the member, it can
                 be passed to xref-related functions instead of the address.
        """
        return _ida_typeinf.tinfo_t_get_edm_tid(self, idx)

    def get_onemember_type(self) -> "tinfo_t":
        r"""
        get_onemember_type(self) -> tinfo_t
        For objects consisting of one member entirely: return type of the member.
        """
        return _ida_typeinf.tinfo_t_get_onemember_type(self)

    def get_innermost_udm(self, bitoffset: "uint64") -> "tinfo_t":
        r"""
        get_innermost_udm(self, bitoffset) -> tinfo_t
        Get the innermost member at the given offset

        @param bitoffset: (C++: uint64) bit offset into the structure
        @retval udt: with the innermost member
        @retval empty: type if it is not a struct type or OFFSET could not be found
        """
        return _ida_typeinf.tinfo_t_get_innermost_udm(self, bitoffset)

    def get_innermost_member_type(self, bitoffset: "uint64") -> "tinfo_t":
        r"""
        get_innermost_member_type(self, bitoffset) -> tinfo_t
        Get the innermost member type at the given offset

        @param bitoffset: (C++: uint64) bit offset into the structure
        @retval the: innermost member type
        """
        return _ida_typeinf.tinfo_t_get_innermost_member_type(self, bitoffset)

    def calc_score(self) -> "uint32":
        r"""
        calc_score(self) -> uint32
        Calculate the type score (the higher - the nicer is the type)
        """
        return _ida_typeinf.tinfo_t_calc_score(self)

    def _print(self, name: "char const *"=None, prtype_flags: "int"=0, indent: "int"=0, cmtindent: "int"=0, prefix: "char const *"=None, cmt: "char const *"=None) -> "bool":
        r"""
        _print(self, name=None, prtype_flags=0, indent=0, cmtindent=0, prefix=None, cmt=None) -> bool

        Parameters
        ----------
        name: char const *
        prtype_flags: int
        indent: int
        cmtindent: int
        prefix: char const *
        cmt: char const *

        """
        return _ida_typeinf.tinfo_t__print(self, name, prtype_flags, indent, cmtindent, prefix, cmt)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        Function to facilitate debugging.
        """
        return _ida_typeinf.tinfo_t_dstr(self)

    def get_attrs(self, tav: "type_attrs_t", all_attrs: "bool"=False) -> "bool":
        r"""
        get_attrs(self, tav, all_attrs=False) -> bool
        Get type attributes (all_attrs: include attributes of referenced types, if any)

        @param tav: (C++: type_attrs_t *)
        @param all_attrs: (C++: bool)
        """
        return _ida_typeinf.tinfo_t_get_attrs(self, tav, all_attrs)

    def set_attrs(self, tav: "type_attrs_t") -> "bool":
        r"""
        set_attrs(self, tav) -> bool
        Set type attributes. If necessary, a new typid will be created. this function
        modifies tav! (returns old attributes, if any)

        @param tav: (C++: type_attrs_t *)
        @return: false: bad attributes
        """
        return _ida_typeinf.tinfo_t_set_attrs(self, tav)

    def set_attr(self, ta: "type_attr_t", may_overwrite: "bool"=True) -> "bool":
        r"""
        set_attr(self, ta, may_overwrite=True) -> bool
        Set a type attribute. If necessary, a new typid will be created.

        @param ta: (C++: const type_attr_t &) type_attr_t const &
        @param may_overwrite: (C++: bool)
        """
        return _ida_typeinf.tinfo_t_set_attr(self, ta, may_overwrite)

    def del_attrs(self) -> "void":
        r"""
        del_attrs(self)
        Del all type attributes. typerefs cannot be modified by this function.
        """
        return _ida_typeinf.tinfo_t_del_attrs(self)

    def del_attr(self, key: "qstring const &", make_copy: "bool"=True) -> "bool":
        r"""
        del_attr(self, key, make_copy=True) -> bool
        Del a type attribute. typerefs cannot be modified by this function.

        @param key: (C++: const qstring &) qstring const &
        @param make_copy: (C++: bool)
        """
        return _ida_typeinf.tinfo_t_del_attr(self, key, make_copy)

    def create_simple_type(self, decl_type: "type_t") -> "bool":
        r"""
        create_simple_type(self, decl_type) -> bool

        @param decl_type: type_t
        """
        return _ida_typeinf.tinfo_t_create_simple_type(self, decl_type)

    def create_ptr(self, *args) -> "bool":
        r"""
        create_ptr(self, p, decl_type=BT_PTR) -> bool

        @param p: ptr_type_data_t const &
        @param decl_type: type_t

        create_ptr(self, tif, bps=0, decl_type=BT_PTR) -> bool

        @param tif: tinfo_t const &
        @param bps: uchar
        @param decl_type: type_t
        """
        return _ida_typeinf.tinfo_t_create_ptr(self, *args)

    def create_array(self, *args) -> "bool":
        r"""
        create_array(self, p, decl_type=BT_ARRAY) -> bool

        @param p: array_type_data_t const &
        @param decl_type: type_t

        create_array(self, tif, nelems=0, base=0, decl_type=BT_ARRAY) -> bool

        @param tif: tinfo_t const &
        @param nelems: uint32
        @param base: uint32
        @param decl_type: type_t
        """
        return _ida_typeinf.tinfo_t_create_array(self, *args)

    def create_typedef(self, *args) -> "void":
        r"""
        create_typedef(self, p, decl_type=BTF_TYPEDEF, try_ordinal=True) -> bool

        @param p: typedef_type_data_t const &
        @param decl_type: type_t
        @param try_ordinal: bool

        create_typedef(self, til, name, decl_type=BTF_TYPEDEF, try_ordinal=True)

        @param til: til_t const *
        @param name: char const *
        @param decl_type: type_t
        @param try_ordinal: bool

        create_typedef(self, til, ord, decl_type=BTF_TYPEDEF)

        @param til: til_t const *
        @param ord: uint
        @param decl_type: type_t
        """
        return _ida_typeinf.tinfo_t_create_typedef(self, *args)

    def create_bitfield(self, *args) -> "bool":
        r"""
        create_bitfield(self, p, decl_type=BT_BITFIELD) -> bool

        @param p: bitfield_type_data_t const &
        @param decl_type: type_t

        create_bitfield(self, nbytes, width, is_unsigned=False, decl_type=BT_BITFIELD) -> bool

        @param nbytes: uchar
        @param width: uchar
        @param is_unsigned: bool
        @param decl_type: type_t
        """
        return _ida_typeinf.tinfo_t_create_bitfield(self, *args)

    def parse(self, decl: "char const *", til: "til_t"=None, pt_flags: "int"=0) -> "bool":
        r"""
        parse(self, decl, til=None, pt_flags=0) -> bool
        Convenience function to parse a string with a type declaration

        @param decl: (C++: const char *) a type declaration
        @param til: (C++: til_t *) type library to use
        @param pt_flags: (C++: int) combination of Type parsing flags bits
        """
        return _ida_typeinf.tinfo_t_parse(self, decl, til, pt_flags)

    def create_udt(self, *args) -> "bool":
        r"""
        create_udt(self, p) -> bool

        @param p: udt_type_data_t &

        create_udt(self, p, decl_type) -> bool

        @param p: udt_type_data_t &
        @param decl_type: type_t
        """
        return _ida_typeinf.tinfo_t_create_udt(self, *args)

    def create_enum(self, *args) -> "bool":
        r"""
        create_enum(self, p, decl_type=BTF_ENUM) -> bool

        @param p: enum_type_data_t &
        @param decl_type: type_t
        """
        return _ida_typeinf.tinfo_t_create_enum(self, *args)

    def create_func(self, *args) -> "bool":
        r"""
        create_func(self, p, decl_type=BT_FUNC) -> bool

        @param p: func_type_data_t &
        @param decl_type: type_t
        """
        return _ida_typeinf.tinfo_t_create_func(self, *args)

    def get_udm_by_tid(self, udm: "udm_t", tid: "tid_t") -> "ssize_t":
        r"""
        get_udm_by_tid(self, udm, tid) -> ssize_t
        Retrive tinfo using type TID or struct/enum member MID

        @param udm: (C++: udm_t *) [out]: place to save the found member to, may be nullptr
        @param tid: (C++: tid_t) tid can denote a type tid or a member tid.
        @return: if a member tid was specified, returns the member index, otherwise
                 returns -1. if the function fails, THIS object becomes empty.
        """
        return _ida_typeinf.tinfo_t_get_udm_by_tid(self, udm, tid)

    def get_edm_by_tid(self, edm: "edm_t", tid: "tid_t") -> "ssize_t":
        r"""
        get_edm_by_tid(self, edm, tid) -> ssize_t

        @param edm: edm_t *
        @param tid: tid_t
        """
        return _ida_typeinf.tinfo_t_get_edm_by_tid(self, edm, tid)

    def get_type_by_tid(self, tid: "tid_t") -> "bool":
        r"""
        get_type_by_tid(self, tid) -> bool

        @param tid: tid_t
        """
        return _ida_typeinf.tinfo_t_get_type_by_tid(self, tid)

    def get_edm_by_name(self, mname: "char const *", til: "til_t"=None) -> "ssize_t":
        r"""
        get_edm_by_name(self, mname, til=None) -> ssize_t
        Retrieve enum tinfo using enum member name

        @param mname: (C++: const char *) enum type member name
        @param til: (C++: const til_t *) type library
        @return: member index, otherwise returns -1. If the function fails, THIS object
                 becomes empty.
        """
        return _ida_typeinf.tinfo_t_get_edm_by_name(self, mname, til)

    def set_named_type(self, til: "til_t", name: "char const *", ntf_flags: "int"=0) -> "tinfo_code_t":
        r"""
        set_named_type(self, til, name, ntf_flags=0) -> tinfo_code_t

        @param til: til_t *
        @param name: char const *
        @param ntf_flags: int
        """
        return _ida_typeinf.tinfo_t_set_named_type(self, til, name, ntf_flags)

    def set_symbol_type(self, til: "til_t", name: "char const *", ntf_flags: "int"=0) -> "tinfo_code_t":
        r"""
        set_symbol_type(self, til, name, ntf_flags=0) -> tinfo_code_t

        @param til: til_t *
        @param name: char const *
        @param ntf_flags: int
        """
        return _ida_typeinf.tinfo_t_set_symbol_type(self, til, name, ntf_flags)

    def set_numbered_type(self, til: "til_t", ord: "uint32", ntf_flags: "int"=0, name: "char const *"=None) -> "tinfo_code_t":
        r"""
        set_numbered_type(self, til, ord, ntf_flags=0, name=None) -> tinfo_code_t

        @param til: til_t *
        @param ord: uint32
        @param ntf_flags: int
        @param name: char const *
        """
        return _ida_typeinf.tinfo_t_set_numbered_type(self, til, ord, ntf_flags, name)

    def save_type(self, *args) -> "tinfo_code_t":
        r"""
        save_type(self, ntf_flags=0x0001|0x0004) -> tinfo_code_t

        @param ntf_flags: int
        """
        return _ida_typeinf.tinfo_t_save_type(self, *args)

    def copy_type(self, *args) -> "tinfo_code_t":
        r"""
        copy_type(self, til, name, ntf_flags=0x0001|0x1000) -> tinfo_code_t

        @param til: til_t *
        @param name: char const *
        @param ntf_flags: int
        """
        return _ida_typeinf.tinfo_t_copy_type(self, *args)

    def create_forward_decl(self, til: "til_t", decl_type: "type_t", name: "char const *", ntf_flags: "int"=0) -> "tinfo_code_t":
        r"""
        create_forward_decl(self, til, decl_type, name, ntf_flags=0) -> tinfo_code_t
        Create a forward declaration. decl_type: BTF_STRUCT, BTF_UNION, or BTF_ENUM

        @param til: (C++: til_t *)
        @param decl_type: (C++: type_t)
        @param name: (C++: const char *) char const *
        @param ntf_flags: (C++: int)
        """
        return _ida_typeinf.tinfo_t_create_forward_decl(self, til, decl_type, name, ntf_flags)

    @staticmethod
    def get_stock(id: "stock_type_id_t") -> "tinfo_t":
        r"""
        get_stock(id) -> tinfo_t
        Get stock type information. This function can be used to get tinfo_t for some
        common types. The same tinfo_t will be returned for the same id, thus saving
        memory and increasing the speed Please note that retrieving the STI_SIZE_T or
        STI_SSIZE_T stock type, will also have the side-effect of adding that type to
        the 'idati' TIL, under the well-known name 'size_t' or 'ssize_t' (respectively).
        The same is valid for STI_COMPLEX64 and STI_COMPLEX64 stock types with names
        'complex64_t' and 'complex128_t' (respectively).

        @param id: (C++: stock_type_id_t) enum stock_type_id_t
        """
        return _ida_typeinf.tinfo_t_get_stock(id)

    def convert_array_to_ptr(self) -> "bool":
        r"""
        convert_array_to_ptr(self) -> bool
        Convert an array into a pointer. type[] => type *
        """
        return _ida_typeinf.tinfo_t_convert_array_to_ptr(self)

    def remove_ptr_or_array(self) -> "bool":
        r"""
        remove_ptr_or_array(self) -> bool
        Replace the current type with the ptr obj or array element. This function
        performs one of the following conversions:
        * type[] => type
        * type* => type If the conversion is performed successfully, return true
        """
        return _ida_typeinf.tinfo_t_remove_ptr_or_array(self)

    def read_bitfield_value(self, v: "uint64", bitoff: "int") -> "uint64":
        r"""
        read_bitfield_value(self, v, bitoff) -> uint64

        @param v: uint64
        @param bitoff: int
        """
        return _ida_typeinf.tinfo_t_read_bitfield_value(self, v, bitoff)

    def write_bitfield_value(self, dst: "uint64", v: "uint64", bitoff: "int") -> "uint64":
        r"""
        write_bitfield_value(self, dst, v, bitoff) -> uint64

        @param dst: uint64
        @param v: uint64
        @param bitoff: int
        """
        return _ida_typeinf.tinfo_t_write_bitfield_value(self, dst, v, bitoff)

    def get_modifiers(self) -> "type_t":
        r"""
        get_modifiers(self) -> type_t
        """
        return _ida_typeinf.tinfo_t_get_modifiers(self)

    def set_modifiers(self, mod: "type_t") -> "void":
        r"""
        set_modifiers(self, mod)

        @param mod: type_t
        """
        return _ida_typeinf.tinfo_t_set_modifiers(self, mod)

    def set_const(self) -> "void":
        r"""
        set_const(self)
        """
        return _ida_typeinf.tinfo_t_set_const(self)

    def set_volatile(self) -> "void":
        r"""
        set_volatile(self)
        """
        return _ida_typeinf.tinfo_t_set_volatile(self)

    def clr_decl_const_volatile(self) -> "void":
        r"""
        clr_decl_const_volatile(self)
        """
        return _ida_typeinf.tinfo_t_clr_decl_const_volatile(self)

    def clr_const(self) -> "bool":
        r"""
        clr_const(self) -> bool
        """
        return _ida_typeinf.tinfo_t_clr_const(self)

    def clr_volatile(self) -> "bool":
        r"""
        clr_volatile(self) -> bool
        """
        return _ida_typeinf.tinfo_t_clr_volatile(self)

    def clr_const_volatile(self) -> "bool":
        r"""
        clr_const_volatile(self) -> bool
        """
        return _ida_typeinf.tinfo_t_clr_const_volatile(self)

    def set_type_alignment(self, declalign: "uchar", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_type_alignment(self, declalign, etf_flags=0) -> tinfo_code_t
        Set type alignment.

        @param declalign: (C++: uchar)
        @param etf_flags: (C++: uint)
        """
        return _ida_typeinf.tinfo_t_set_type_alignment(self, declalign, etf_flags)

    def set_declalign(self, declalign: "uchar") -> "bool":
        r"""
        set_declalign(self, declalign) -> bool

        @param declalign: uchar
        """
        return _ida_typeinf.tinfo_t_set_declalign(self, declalign)

    def change_sign(self, sign: "type_sign_t") -> "bool":
        r"""
        change_sign(self, sign) -> bool
        Change the type sign. Works only for the types that may have sign.

        @param sign: (C++: type_sign_t)
        """
        return _ida_typeinf.tinfo_t_change_sign(self, sign)

    def calc_udt_aligns(self, sudt_flags: "int"=0x0004) -> "bool":
        r"""
        calc_udt_aligns(self, sudt_flags=0x0004) -> bool
        Calculate the udt alignments using the field offsets/sizes and the total udt
        size This function does not work on typerefs

        @param sudt_flags: (C++: int)
        """
        return _ida_typeinf.tinfo_t_calc_udt_aligns(self, sudt_flags)

    def set_methods(self, methods: "udtmembervec_t") -> "bool":
        r"""
        set_methods(self, methods) -> bool

        @param BT_COMPLEX: set the list of member functions. This function consumes 'methods'
        (makes it empty).
        @return: false if this type is not a udt, or if the given list is empty
        """
        return _ida_typeinf.tinfo_t_set_methods(self, methods)

    def set_type_cmt(self, cmt: "char const *", is_regcmt: "bool"=False, etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_type_cmt(self, cmt, is_regcmt=False, etf_flags=0) -> tinfo_code_t
        Set type comment This function works only for non-trivial types

        @param cmt: (C++: const char *) char const *
        @param is_regcmt: (C++: bool)
        @param etf_flags: (C++: uint)
        """
        return _ida_typeinf.tinfo_t_set_type_cmt(self, cmt, is_regcmt, etf_flags)

    def get_alias_target(self) -> "uint32":
        r"""
        get_alias_target(self) -> uint32
        Get type alias If the type has no alias, return 0.
        """
        return _ida_typeinf.tinfo_t_get_alias_target(self)

    def is_aliased(self) -> "bool":
        r"""
        is_aliased(self) -> bool
        """
        return _ida_typeinf.tinfo_t_is_aliased(self)

    def set_type_alias(self, dest_ord: "uint32") -> "bool":
        r"""
        set_type_alias(self, dest_ord) -> bool
        Set type alias Redirects all references to source type to the destination type.
        This is equivalent to instantaneous replacement all references to srctype by
        dsttype.

        @param dest_ord: (C++: uint32)
        """
        return _ida_typeinf.tinfo_t_set_type_alias(self, dest_ord)

    def set_udt_alignment(self, sda: "int", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_udt_alignment(self, sda, etf_flags=0) -> tinfo_code_t
        Set declared structure alignment (sda) This alignment supersedes the alignment
        returned by get_declalign() and is really used when calculating the struct
        layout. However, the effective structure alignment may differ from `sda` because
        of packing. The type editing functions (they accept etf_flags) may overwrite
        this attribute.

        @param sda: (C++: int)
        @param etf_flags: (C++: uint)
        """
        return _ida_typeinf.tinfo_t_set_udt_alignment(self, sda, etf_flags)

    def set_udt_pack(self, pack: "int", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_udt_pack(self, pack, etf_flags=0) -> tinfo_code_t
        Set structure packing. The value controls how little a structure member
        alignment can be. Example: if pack=1, then it is possible to align a double to a
        byte. __attribute__((aligned(1))) double x; However, if pack=3, a double will be
        aligned to 8 (2**3) even if requested to be aligned to a byte. pack==0 will have
        the same effect. The type editing functions (they accept etf_flags) may
        overwrite this attribute.

        @param pack: (C++: int)
        @param etf_flags: (C++: uint)
        """
        return _ida_typeinf.tinfo_t_set_udt_pack(self, pack, etf_flags)

    def get_udm_tid(self, idx: "size_t") -> "tid_t":
        r"""
        get_udm_tid(self, idx) -> tid_t
        Get udt member TID

        @param idx: (C++: size_t) the index of udt the member
        @return: tid or BADADDR The tid is used to collect xrefs to the member, it can
                 be passed to xref-related functions instead of the address.
        """
        return _ida_typeinf.tinfo_t_get_udm_tid(self, idx)

    def add_udm(self, udm: "udm_t", etf_flags: "uint"=0, times: "size_t"=1, idx: "ssize_t"=-1) -> "tinfo_code_t":
        r"""
        add_udm(self, udm, etf_flags=0, times=1, idx=-1) -> tinfo_code_t
        Add a structure/union member.

        @param udm: (C++: const udm_t &) member to add
        @param etf_flags: (C++: uint) type changing flags flags
        @param times: (C++: size_t) how many times to add. if times > 1, the member name will be
                      appended a suffix like "_2" and so on
        @param idx: (C++: ssize_t) the index in the udm array where the new udm should be placed. if
                    the specified index cannot be honored because it would spoil the udm
                    sorting order, it is silently ignored.
        @note: ETF_NO_SAVE is ignored
        """
        return _ida_typeinf.tinfo_t_add_udm(self, udm, etf_flags, times, idx)

    def del_udm(self, index: "size_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        del_udm(self, index, etf_flags=0) -> tinfo_code_t
        Delete a structure/union member.

        @param index: (C++: size_t)
        @param etf_flags: (C++: uint)
        """
        return _ida_typeinf.tinfo_t_del_udm(self, index, etf_flags)

    def del_udms(self, idx1: "size_t", idx2: "size_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        del_udms(self, idx1, idx2, etf_flags=0) -> tinfo_code_t
        Delete structure/union members in the range [idx1, idx2)

        @param idx1: (C++: size_t)
        @param idx2: (C++: size_t)
        @param etf_flags: (C++: uint)
        """
        return _ida_typeinf.tinfo_t_del_udms(self, idx1, idx2, etf_flags)

    def rename_udm(self, index: "size_t", name: "char const *", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        rename_udm(self, index, name, etf_flags=0) -> tinfo_code_t
        Rename a structure/union member. The new name must be unique.
        @note: ETF_NO_SAVE is ignored

        @param index: (C++: size_t)
        @param name: (C++: const char *) char const *
        @param etf_flags: (C++: uint)
        """
        return _ida_typeinf.tinfo_t_rename_udm(self, index, name, etf_flags)

    def set_udm_type(self, index: "size_t", tif: "tinfo_t", etf_flags: "uint"=0, repr: "value_repr_t"=None) -> "tinfo_code_t":
        r"""
        set_udm_type(self, index, tif, etf_flags=0, repr=None) -> tinfo_code_t
        Set type of a structure/union member.

        @param index: (C++: size_t) member index in the udm array
        @param tif: (C++: const tinfo_t &) new type for the member
        @param etf_flags: (C++: uint) etf_flag_t
        @param repr: (C++: const value_repr_t *) new representation for the member (optional)
        @return: tinfo_code_t
        """
        return _ida_typeinf.tinfo_t_set_udm_type(self, index, tif, etf_flags, repr)

    def set_udm_cmt(self, index: "size_t", cmt: "char const *", is_regcmt: "bool"=False, etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_udm_cmt(self, index, cmt, is_regcmt=False, etf_flags=0) -> tinfo_code_t
        Set a comment for a structure/union member. A member may have just one comment,
        and it is either repeatable or regular.

        @param index: (C++: size_t)
        @param cmt: (C++: const char *) char const *
        @param is_regcmt: (C++: bool)
        @param etf_flags: (C++: uint)
        """
        return _ida_typeinf.tinfo_t_set_udm_cmt(self, index, cmt, is_regcmt, etf_flags)

    def set_udm_repr(self, index: "size_t", repr: "value_repr_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_udm_repr(self, index, repr, etf_flags=0) -> tinfo_code_t
        Set the representation of a structure/union member.

        @param index: (C++: size_t)
        @param repr: (C++: const value_repr_t &) value_repr_t const &
        @param etf_flags: (C++: uint)
        """
        return _ida_typeinf.tinfo_t_set_udm_repr(self, index, repr, etf_flags)

    def is_udm_by_til(self, idx: "size_t") -> "bool":
        r"""
        is_udm_by_til(self, idx) -> bool
        Was the member created due to the type system

        @param idx: (C++: size_t) index of the member
        """
        return _ida_typeinf.tinfo_t_is_udm_by_til(self, idx)

    def set_udm_by_til(self, idx: "size_t", on: "bool"=True, etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_udm_by_til(self, idx, on=True, etf_flags=0) -> tinfo_code_t
        The member is created due to the type system

        @param idx: (C++: size_t) index of the member
        @param on: (C++: bool)
        @param etf_flags: (C++: uint) etf_flag_t
        """
        return _ida_typeinf.tinfo_t_set_udm_by_til(self, idx, on, etf_flags)

    def set_fixed_struct(self, on: "bool"=True) -> "tinfo_code_t":
        r"""
        set_fixed_struct(self, on=True) -> tinfo_code_t
        Declare struct member offsets as fixed. For such structures, IDA will not
        recalculate the member offsets. If a member does not fit into its place anymore,
        it will be deleted. This function works only with structures (not unions).

        @param on: (C++: bool)
        """
        return _ida_typeinf.tinfo_t_set_fixed_struct(self, on)

    def set_struct_size(self, new_size: "size_t") -> "tinfo_code_t":
        r"""
        set_struct_size(self, new_size) -> tinfo_code_t
        Explicitly specify the struct size. This function works only with fixed
        structures. The new struct size can be equal or higher the unpadded struct size
        (IOW, all existing members should fit into the specified size).

        @param new_size: (C++: size_t) new structure size in bytes
        """
        return _ida_typeinf.tinfo_t_set_struct_size(self, new_size)

    def is_fixed_struct(self) -> "bool":
        r"""
        is_fixed_struct(self) -> bool
        Is a structure with fixed offsets?
        """
        return _ida_typeinf.tinfo_t_is_fixed_struct(self)

    def expand_udt(self, idx: "size_t", delta: "adiff_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        expand_udt(self, idx, delta, etf_flags=0) -> tinfo_code_t
        Expand/shrink a structure by adding/removing a gap before the specified member.

        @param idx: (C++: size_t) index of the member
        @param delta: (C++: adiff_t) number of bytes to add or remove
        @param etf_flags: (C++: uint) etf_flag_t Please note that it is impossible to add a gap at
                          the very end of a structure. However, adding before a regular
                          member is possible. This function can be used to remove gaps
                          in the middle of a structure by specifying a negative delta
                          value.
        @note: It is possible to add/remove a gap at the end of a fixed structure. Use
               IDX equal to the number of members for that.
        """
        return _ida_typeinf.tinfo_t_expand_udt(self, idx, delta, etf_flags)

    def get_func_frame(self, pfn: "func_t const *") -> "bool":
        r"""
        get_func_frame(self, pfn) -> bool
        Create a tinfo_t object for the function frame

        @param pfn: (C++: const func_t *) function
        """
        return _ida_typeinf.tinfo_t_get_func_frame(self, pfn)

    def is_frame(self) -> "bool":
        r"""
        is_frame(self) -> bool
        Is a function frame?
        """
        return _ida_typeinf.tinfo_t_is_frame(self)

    def get_frame_func(self) -> "ea_t":
        r"""
        get_frame_func(self) -> ea_t
        Get function address for the frame.
        """
        return _ida_typeinf.tinfo_t_get_frame_func(self)

    def set_enum_width(self, nbytes: "int", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_enum_width(self, nbytes, etf_flags=0) -> tinfo_code_t
        Set the width of enum base type

        @param nbytes: (C++: int) width of enum base type, allowed values: 0
                       (unspecified),1,2,4,8,16,32,64
        @param etf_flags: (C++: uint) etf_flag_t
        """
        return _ida_typeinf.tinfo_t_set_enum_width(self, nbytes, etf_flags)

    def set_enum_sign(self, sign: "type_sign_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_enum_sign(self, sign, etf_flags=0) -> tinfo_code_t
        Set enum sign

        @param sign: (C++: type_sign_t)
        @param etf_flags: (C++: uint) etf_flag_t
        """
        return _ida_typeinf.tinfo_t_set_enum_sign(self, sign, etf_flags)
    ENUMBM_OFF = _ida_typeinf.tinfo_t_ENUMBM_OFF
    r"""
    convert to ordinal enum
    """
    
    ENUMBM_ON = _ida_typeinf.tinfo_t_ENUMBM_ON
    r"""
    convert to bitmask enum
    """
    
    ENUMBM_AUTO = _ida_typeinf.tinfo_t_ENUMBM_AUTO
    r"""
    convert to bitmask if the outcome is nice and useful
    """
    

    def set_enum_is_bitmask(self, *args) -> "tinfo_code_t":
        r"""
        set_enum_is_bitmask(self, stance=ENUMBM_ON, etf_flags=0) -> tinfo_code_t

        @param stance: enum tinfo_t::bitmask_cvt_stance_t
        @param etf_flags: uint
        """
        return _ida_typeinf.tinfo_t_set_enum_is_bitmask(self, *args)

    def set_enum_repr(self, repr: "value_repr_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_enum_repr(self, repr, etf_flags=0) -> tinfo_code_t
        Set the representation of enum members.

        @param repr: (C++: const value_repr_t &) value_repr_t
        @param etf_flags: (C++: uint) etf_flag_t
        """
        return _ida_typeinf.tinfo_t_set_enum_repr(self, repr, etf_flags)

    def set_enum_radix(self, radix: "int", sign: "bool", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_enum_radix(self, radix, sign, etf_flags=0) -> tinfo_code_t
        Set enum radix to display constants

        @param radix: (C++: int) radix 2, 4, 8, 16, with the special case 1 to display as character
        @param sign: (C++: bool) display as signed or unsigned
        @param etf_flags: (C++: uint) etf_flag_t
        """
        return _ida_typeinf.tinfo_t_set_enum_radix(self, radix, sign, etf_flags)

    def add_edm(self, *args) -> "tinfo_code_t":
        r"""
        add_edm(self, edm, bmask=bmask64_t(-1), etf_flags=0, idx=-1) -> tinfo_code_t
        Add a new enum member (a new symbolic constant)

        @param edm: (C++: const edm_t &) the constant name, value, and comment
        @param bmask: (C++: bmask64_t) bmask of the group to add the constant to
        @note: 1. For non-bitmask enum push back constant, BMASK is not used (set it ot
               -1), never failed 2. For bitmask enum:
        * if VAL and BMASK are not agreed, return TERR_BAD_MSKVAL
        * if group with BMASK exists, push back constant to group
        * otherwise use constant as bitmask for a new group
        @note: ETF_NO_SAVE is ignored
        """
        return _ida_typeinf.tinfo_t_add_edm(self, *args)

    def del_edms(self, idx1: "size_t", idx2: "size_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        del_edms(self, idx1, idx2, etf_flags=0) -> tinfo_code_t
        Delete enum members

        @param idx1: (C++: size_t) index in edmvec_t
        @param idx2: (C++: size_t) index in edmvec_t or size_t(-1)
        @param etf_flags: (C++: uint) etf_flag_t Delete enum members in [idx1, idx2)
        @note: For bitmask enum, the first member of a non-trivial group (having 2 or
               more members) is considered as a group mask. It is impossible to delete
               the group mask of a non-trivial group, other members of the group must be
               deleted first. Empty groups are automatically deleted.
        """
        return _ida_typeinf.tinfo_t_del_edms(self, idx1, idx2, etf_flags)

    def del_edm(self, idx: "size_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        del_edm(self, idx, etf_flags=0) -> tinfo_code_t

        @param idx: size_t
        @param etf_flags: uint
        """
        return _ida_typeinf.tinfo_t_del_edm(self, idx, etf_flags)

    def rename_edm(self, idx: "size_t", name: "char const *", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        rename_edm(self, idx, name, etf_flags=0) -> tinfo_code_t
        Rename a enum member

        @param idx: (C++: size_t) index in edmvec_t
        @param name: (C++: const char *) new name
        @param etf_flags: (C++: uint) etf_flag_t ETF_FORCENAME may be used in case of
                          TERR_ALIEN_NAME
        @note: ETF_NO_SAVE is ignored
        """
        return _ida_typeinf.tinfo_t_rename_edm(self, idx, name, etf_flags)

    def set_edm_cmt(self, idx: "size_t", cmt: "char const *", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_edm_cmt(self, idx, cmt, etf_flags=0) -> tinfo_code_t
        Set a comment for an enum member. Such comments are always considered as
        repeatable.

        @param idx: (C++: size_t) index in edmvec_t
        @param cmt: (C++: const char *) comment
        @param etf_flags: (C++: uint) etf_flag_t
        """
        return _ida_typeinf.tinfo_t_set_edm_cmt(self, idx, cmt, etf_flags)

    def edit_edm(self, *args) -> "tinfo_code_t":
        r"""
        edit_edm(self, idx, value, bmask=bmask64_t(-1), etf_flags=0) -> tinfo_code_t
        Change constant value and/or bitmask

        @param idx: (C++: size_t) index in edmvec_t
        @param value: (C++: uint64) old or new value
        @param bmask: (C++: bmask64_t) old or new bitmask
        @note: if new bitmask is specified the index of constant may be changed
        """
        return _ida_typeinf.tinfo_t_edit_edm(self, *args)

    def rename_funcarg(self, index: "size_t", name: "char const *", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        rename_funcarg(self, index, name, etf_flags=0) -> tinfo_code_t
        Rename a function argument. The new name must be unique.

        @param index: (C++: size_t) argument index in the function array
        @param name: (C++: const char *) new name
        @param etf_flags: (C++: uint) etf_flag_t
        @note: ETF_NO_SAVE is ignored
        """
        return _ida_typeinf.tinfo_t_rename_funcarg(self, index, name, etf_flags)

    def set_funcarg_type(self, index: "size_t", tif: "tinfo_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_funcarg_type(self, index, tif, etf_flags=0) -> tinfo_code_t
        Set type of a function argument.

        @param index: (C++: size_t) argument index in the function array
        @param tif: (C++: const tinfo_t &) new type for the argument
        @param etf_flags: (C++: uint) etf_flag_t
        @return: tinfo_code_t
        """
        return _ida_typeinf.tinfo_t_set_funcarg_type(self, index, tif, etf_flags)

    def set_func_rettype(self, tif: "tinfo_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_func_rettype(self, tif, etf_flags=0) -> tinfo_code_t
        Set function return type .

        @param tif: (C++: const tinfo_t &) new type for the return type
        @param etf_flags: (C++: uint) etf_flag_t
        @return: tinfo_code_t
        """
        return _ida_typeinf.tinfo_t_set_func_rettype(self, tif, etf_flags)

    def del_funcargs(self, idx1: "size_t", idx2: "size_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        del_funcargs(self, idx1, idx2, etf_flags=0) -> tinfo_code_t
        Delete function arguments

        @param idx1: (C++: size_t) index in funcargvec_t
        @param idx2: (C++: size_t) index in funcargvec_t or size_t(-1)
        @param etf_flags: (C++: uint) etf_flag_t Delete function arguments in [idx1, idx2)
        """
        return _ida_typeinf.tinfo_t_del_funcargs(self, idx1, idx2, etf_flags)

    def del_funcarg(self, idx: "size_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        del_funcarg(self, idx, etf_flags=0) -> tinfo_code_t

        @param idx: size_t
        @param etf_flags: uint
        """
        return _ida_typeinf.tinfo_t_del_funcarg(self, idx, etf_flags)

    def add_funcarg(self, farg: "funcarg_t", etf_flags: "uint"=0, idx: "ssize_t"=-1) -> "tinfo_code_t":
        r"""
        add_funcarg(self, farg, etf_flags=0, idx=-1) -> tinfo_code_t
        Add a function argument.

        @param farg: (C++: const funcarg_t &) argument to add
        @param etf_flags: (C++: uint) type changing flags flags
        @param idx: (C++: ssize_t) the index in the funcarg array where the new funcarg should be
                    placed. if the specified index cannot be honored because it would
                    spoil the funcarg sorting order, it is silently ignored.
        @note: ETF_NO_SAVE is ignored
        """
        return _ida_typeinf.tinfo_t_add_funcarg(self, farg, etf_flags, idx)

    def set_func_cc(self, cc: "cm_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_func_cc(self, cc, etf_flags=0) -> tinfo_code_t
        Set function calling convention.

        @param cc: (C++: cm_t)
        @param etf_flags: (C++: uint)
        """
        return _ida_typeinf.tinfo_t_set_func_cc(self, cc, etf_flags)

    def set_funcarg_loc(self, index: "size_t", argloc: "argloc_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_funcarg_loc(self, index, argloc, etf_flags=0) -> tinfo_code_t
        Set location of a function argument.

        @param index: (C++: size_t) argument index in the function array
        @param argloc: (C++: const argloc_t &) new location for the argument
        @param etf_flags: (C++: uint) etf_flag_t
        @return: tinfo_code_t
        """
        return _ida_typeinf.tinfo_t_set_funcarg_loc(self, index, argloc, etf_flags)

    def set_func_retloc(self, argloc: "argloc_t", etf_flags: "uint"=0) -> "tinfo_code_t":
        r"""
        set_func_retloc(self, argloc, etf_flags=0) -> tinfo_code_t
        Set location of function return value.

        @param argloc: (C++: const argloc_t &) new location for the return value
        @param etf_flags: (C++: uint) etf_flag_t
        @return: tinfo_code_t
        """
        return _ida_typeinf.tinfo_t_set_func_retloc(self, argloc, etf_flags)

    def __eq__(self, r: "tinfo_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: tinfo_t const &
        """
        return _ida_typeinf.tinfo_t___eq__(self, r)

    def __ne__(self, r: "tinfo_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: tinfo_t const &
        """
        return _ida_typeinf.tinfo_t___ne__(self, r)

    def __lt__(self, r: "tinfo_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: tinfo_t const &
        """
        return _ida_typeinf.tinfo_t___lt__(self, r)

    def __gt__(self, r: "tinfo_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: tinfo_t const &
        """
        return _ida_typeinf.tinfo_t___gt__(self, r)

    def __le__(self, r: "tinfo_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: tinfo_t const &
        """
        return _ida_typeinf.tinfo_t___le__(self, r)

    def __ge__(self, r: "tinfo_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: tinfo_t const &
        """
        return _ida_typeinf.tinfo_t___ge__(self, r)

    def compare(self, r: "tinfo_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: tinfo_t const &
        """
        return _ida_typeinf.tinfo_t_compare(self, r)

    def compare_with(self, r: "tinfo_t", tcflags: "int"=0) -> "bool":
        r"""
        compare_with(self, r, tcflags=0) -> bool
        Compare two types, based on given flags (see tinfo_t comparison flags)

        @param r: (C++: const tinfo_t &) tinfo_t const &
        @param tcflags: (C++: int)
        """
        return _ida_typeinf.tinfo_t_compare_with(self, r, tcflags)

    def equals_to(self, r: "tinfo_t") -> "bool":
        r"""
        equals_to(self, r) -> bool

        @param r: tinfo_t const &
        """
        return _ida_typeinf.tinfo_t_equals_to(self, r)

    def is_castable_to(self, target: "tinfo_t") -> "bool":
        r"""
        is_castable_to(self, target) -> bool

        @param target: tinfo_t const &
        """
        return _ida_typeinf.tinfo_t_is_castable_to(self, target)

    def is_manually_castable_to(self, target: "tinfo_t") -> "bool":
        r"""
        is_manually_castable_to(self, target) -> bool

        @param target: tinfo_t const &
        """
        return _ida_typeinf.tinfo_t_is_manually_castable_to(self, target)

    def serialize(self, *args) -> "PyObject *":
        r"""
        serialize(self, sudt_flags=SUDT_FAST|SUDT_TRUNC) -> PyObject
        Serialize tinfo_t object into a type string.

        @param sudt_flags: (C++: int)
        """
        return _ida_typeinf.tinfo_t_serialize(self, *args)

    def deserialize(self, *args) -> "bool":
        r"""
        deserialize(self, til, ptype, pfields=None, pfldcmts=None, cmt=None) -> bool
        Deserialize a type string into a tinfo_t object.

        @param til: (C++: const til_t *) til_t const *
        @param ptype: (C++: const qtype *) type_t const **
        @param pfields: (C++: const qtype *) p_list const **
        @param pfldcmts: (C++: const qtype *) p_list const **
        @param cmt: (C++: const char *) char const *

        deserialize(self, til, type, fields, cmts=None) -> bool

        @param til: til_t const *
        @param type: type_t const *
        @param fields: p_list const *
        @param cmts: p_list const *
        """
        return _ida_typeinf.tinfo_t_deserialize(self, *args)

    def get_stkvar(self, insn: "insn_t const &", x: "op_t const", v: "sval_t") -> "ssize_t":
        r"""
        get_stkvar(self, insn, x, v) -> ssize_t
        Retrieve frame tinfo for a stack variable

        @param insn: (C++: const insn_t &) the instruction
        @param x: (C++: const op_t *) reference to instruction operand, may be nullptr
        @param v: (C++: sval_t) immediate value in the operand (usually x.addr)
        @return: returns the member index, otherwise returns -1. if the function fails,
                 THIS object becomes empty.
        """
        return _ida_typeinf.tinfo_t_get_stkvar(self, insn, x, v)

    def copy(self) -> "tinfo_t":
        r"""
        copy(self) -> tinfo_t
        """
        return _ida_typeinf.tinfo_t_copy(self)

    def __str__(self) -> "qstring":
        r"""
        __str__(self) -> qstring
        """
        return _ida_typeinf.tinfo_t___str__(self)
    __swig_destroy__ = _ida_typeinf.delete_tinfo_t

    def get_attr(self, key: "qstring const &", all_attrs: "bool"=True) -> "PyObject *":
        r"""
        get_attr(self, key, all_attrs=True) -> PyObject
        Get a type attribute.

        @param key: (C++: const qstring &) qstring const &
        @param all_attrs: (C++: bool)
        """
        return _ida_typeinf.tinfo_t_get_attr(self, key, all_attrs)

# Register tinfo_t in _ida_typeinf:
_ida_typeinf.tinfo_t_swigregister(tinfo_t)
COMP_MASK = cvar.COMP_MASK
COMP_UNK = cvar.COMP_UNK
r"""
Unknown.
"""
COMP_MS = cvar.COMP_MS
r"""
Visual C++.
"""
COMP_BC = cvar.COMP_BC
r"""
Borland C++.
"""
COMP_WATCOM = cvar.COMP_WATCOM
r"""
Watcom C++.
"""
COMP_GNU = cvar.COMP_GNU
r"""
GNU C++.
"""
COMP_VISAGE = cvar.COMP_VISAGE
r"""
Visual Age C++.
"""
COMP_BP = cvar.COMP_BP
r"""
Delphi.
"""
COMP_UNSURE = cvar.COMP_UNSURE
r"""
uncertain compiler id
"""
BADSIZE = cvar.BADSIZE
r"""
bad type size
"""
FIRST_NONTRIVIAL_TYPID = cvar.FIRST_NONTRIVIAL_TYPID
r"""
Denotes the first bit describing a nontrivial type.
"""
TYPID_ISREF = cvar.TYPID_ISREF
r"""
Identifies that a type that is a typeref.
"""
TYPID_SHIFT = cvar.TYPID_SHIFT
r"""
First type detail bit.
"""

def remove_pointer(tif: "tinfo_t") -> "tinfo_t":
    r"""
    remove_pointer(tif) -> tinfo_t

    @param BT_PTR: If the current type is a pointer, return the pointed object. If the
    current type is not a pointer, return the current type. See also
    get_ptrarr_object() and get_pointed_object()
    """
    return _ida_typeinf.remove_pointer(tif)
STRMEM_MASK = _ida_typeinf.STRMEM_MASK

STRMEM_OFFSET = _ida_typeinf.STRMEM_OFFSET
r"""
get member by offset
* in: udm->offset - is a member offset in bits
"""

STRMEM_INDEX = _ida_typeinf.STRMEM_INDEX
r"""
get member by number
* in: udm->offset - is a member number
"""

STRMEM_AUTO = _ida_typeinf.STRMEM_AUTO
r"""
get member by offset if struct, or get member by index if union
* nb: union: index is stored in the udm->offset field!
* nb: struct: offset is in bytes (not in bits)!
"""

STRMEM_NAME = _ida_typeinf.STRMEM_NAME
r"""
get member by name
* in: udm->name - the desired member name.
"""

STRMEM_TYPE = _ida_typeinf.STRMEM_TYPE
r"""
get member by type.
* in: udm->type - the desired member type. member types are compared with
tinfo_t::equals_to()
"""

STRMEM_SIZE = _ida_typeinf.STRMEM_SIZE
r"""
get member by size.
* in: udm->size - the desired member size.
"""

STRMEM_MINS = _ida_typeinf.STRMEM_MINS
r"""
get smallest member by size.
"""

STRMEM_MAXS = _ida_typeinf.STRMEM_MAXS
r"""
get biggest member by size.
"""

STRMEM_LOWBND = _ida_typeinf.STRMEM_LOWBND
r"""
get member by offset or the next member (lower bound)
* in: udm->offset - is a member offset in bits
"""

STRMEM_NEXT = _ida_typeinf.STRMEM_NEXT
r"""
get next member after the offset
* in: udm->offset - is a member offset in bits
"""

STRMEM_VFTABLE = _ida_typeinf.STRMEM_VFTABLE
r"""
can be combined with STRMEM_OFFSET, STRMEM_AUTO get vftable instead of the base
class
"""

STRMEM_SKIP_EMPTY = _ida_typeinf.STRMEM_SKIP_EMPTY
r"""
can be combined with STRMEM_OFFSET, STRMEM_AUTO skip empty members (i.e. having
zero size) only last empty member can be returned
"""

STRMEM_CASTABLE_TO = _ida_typeinf.STRMEM_CASTABLE_TO
r"""
can be combined with STRMEM_TYPE: member type must be castable to the specified
type
"""

STRMEM_ANON = _ida_typeinf.STRMEM_ANON
r"""
can be combined with STRMEM_NAME: look inside anonymous members too.
"""

STRMEM_SKIP_GAPS = _ida_typeinf.STRMEM_SKIP_GAPS
r"""
can be combined with STRMEM_OFFSET, STRMEM_LOWBND skip gap members
"""

TCMP_EQUAL = _ida_typeinf.TCMP_EQUAL
r"""
are types equal?
"""

TCMP_IGNMODS = _ida_typeinf.TCMP_IGNMODS
r"""
ignore const/volatile modifiers
"""

TCMP_AUTOCAST = _ida_typeinf.TCMP_AUTOCAST
r"""
can t1 be cast into t2 automatically?
"""

TCMP_MANCAST = _ida_typeinf.TCMP_MANCAST
r"""
can t1 be cast into t2 manually?
"""

TCMP_CALL = _ida_typeinf.TCMP_CALL
r"""
can t1 be called with t2 type?
"""

TCMP_DELPTR = _ida_typeinf.TCMP_DELPTR
r"""
remove pointer from types before comparing
"""

TCMP_DECL = _ida_typeinf.TCMP_DECL
r"""
compare declarations without resolving them
"""

TCMP_ANYBASE = _ida_typeinf.TCMP_ANYBASE
r"""
accept any base class when casting
"""

TCMP_SKIPTHIS = _ida_typeinf.TCMP_SKIPTHIS
r"""
skip the first function argument in comparison
"""


class simd_info_t(object):
    r"""
    Proxy of C++ simd_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    name: "char const *" = property(_ida_typeinf.simd_info_t_name_get, _ida_typeinf.simd_info_t_name_set, doc=r"""name""")
    r"""
    name of SIMD type (nullptr-undefined)
    """
    tif: "tinfo_t" = property(_ida_typeinf.simd_info_t_tif_get, _ida_typeinf.simd_info_t_tif_set, doc=r"""tif""")
    r"""
    SIMD type (empty-undefined)
    """
    size: "uint16" = property(_ida_typeinf.simd_info_t_size_get, _ida_typeinf.simd_info_t_size_set, doc=r"""size""")
    r"""
    SIMD type size in bytes (0-undefined)
    """
    memtype: "type_t" = property(_ida_typeinf.simd_info_t_memtype_get, _ida_typeinf.simd_info_t_memtype_set, doc=r"""memtype""")
    r"""
    member type BTF_INT8/16/32/64/128, BTF_UINT8/16/32/64/128 BTF_INT - integrals of
    any size/sign BTF_FLOAT, BTF_DOUBLE BTF_TBYTE - floatings of any size BTF_UNION
    - union of integral and floating types BTF_UNK - undefined
    """

    def __init__(self, *args):
        r"""
        __init__(self, nm=None, sz=0, memt=BTF_UNK) -> simd_info_t

        @param nm: char const *
        @param sz: uint16
        @param memt: type_t
        """
        _ida_typeinf.simd_info_t_swiginit(self, _ida_typeinf.new_simd_info_t(*args))

    def match_pattern(self, pattern: "simd_info_t") -> "bool":
        r"""
        match_pattern(self, pattern) -> bool

        @param pattern: simd_info_t const *
        """
        return _ida_typeinf.simd_info_t_match_pattern(self, pattern)
    __swig_destroy__ = _ida_typeinf.delete_simd_info_t

# Register simd_info_t in _ida_typeinf:
_ida_typeinf.simd_info_t_swigregister(simd_info_t)

def guess_func_cc(fti: "func_type_data_t", npurged: "int", cc_flags: "int") -> "cm_t":
    r"""
    guess_func_cc(fti, npurged, cc_flags) -> cm_t
    Use func_type_data_t::guess_cc()

    @param fti: (C++: const func_type_data_t &) func_type_data_t const &
    @param npurged: (C++: int)
    @param cc_flags: (C++: int)
    """
    return _ida_typeinf.guess_func_cc(fti, npurged, cc_flags)

def dump_func_type_data(fti: "func_type_data_t", praloc_bits: "int") -> "qstring *":
    r"""
    dump_func_type_data(fti, praloc_bits) -> str
    Use func_type_data_t::dump()

    @param fti: (C++: const func_type_data_t &) func_type_data_t const &
    @param praloc_bits: (C++: int)
    """
    return _ida_typeinf.dump_func_type_data(fti, praloc_bits)
class ptr_type_data_t(object):
    r"""
    Proxy of C++ ptr_type_data_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    obj_type: "tinfo_t" = property(_ida_typeinf.ptr_type_data_t_obj_type_get, _ida_typeinf.ptr_type_data_t_obj_type_set, doc=r"""obj_type""")
    r"""
    pointed object type
    """
    closure: "tinfo_t" = property(_ida_typeinf.ptr_type_data_t_closure_get, _ida_typeinf.ptr_type_data_t_closure_set, doc=r"""closure""")
    r"""
    cannot have both closure and based_ptr_size
    """
    parent: "tinfo_t" = property(_ida_typeinf.ptr_type_data_t_parent_get, _ida_typeinf.ptr_type_data_t_parent_set, doc=r"""parent""")
    r"""
    Parent struct.
    """
    delta: "int32" = property(_ida_typeinf.ptr_type_data_t_delta_get, _ida_typeinf.ptr_type_data_t_delta_set, doc=r"""delta""")
    r"""
    Offset from the beginning of the parent struct.
    """
    based_ptr_size: "uchar" = property(_ida_typeinf.ptr_type_data_t_based_ptr_size_get, _ida_typeinf.ptr_type_data_t_based_ptr_size_set, doc=r"""based_ptr_size""")
    taptr_bits: "uchar" = property(_ida_typeinf.ptr_type_data_t_taptr_bits_get, _ida_typeinf.ptr_type_data_t_taptr_bits_set, doc=r"""taptr_bits""")
    r"""
    TAH bits.
    """

    def __init__(self, *args):
        r"""
        __init__(self, c=tinfo_t(), bps=0, p=tinfo_t(), d=0) -> ptr_type_data_t

        @param c: tinfo_t
        @param bps: uchar
        @param p: tinfo_t
        @param d: int32
        """
        _ida_typeinf.ptr_type_data_t_swiginit(self, _ida_typeinf.new_ptr_type_data_t(*args))

    def swap(self, r: "ptr_type_data_t") -> "void":
        r"""
        swap(self, r)
        Set this = r and r = this.

        @param r: (C++: ptr_type_data_t &)
        """
        return _ida_typeinf.ptr_type_data_t_swap(self, r)

    def __eq__(self, r: "ptr_type_data_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: ptr_type_data_t const &
        """
        return _ida_typeinf.ptr_type_data_t___eq__(self, r)

    def __ne__(self, r: "ptr_type_data_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: ptr_type_data_t const &
        """
        return _ida_typeinf.ptr_type_data_t___ne__(self, r)

    def is_code_ptr(self) -> "bool":
        r"""
        is_code_ptr(self) -> bool
        Are we pointing to code?
        """
        return _ida_typeinf.ptr_type_data_t_is_code_ptr(self)

    def is_shifted(self) -> "bool":
        r"""
        is_shifted(self) -> bool
        """
        return _ida_typeinf.ptr_type_data_t_is_shifted(self)
    __swig_destroy__ = _ida_typeinf.delete_ptr_type_data_t

# Register ptr_type_data_t in _ida_typeinf:
_ida_typeinf.ptr_type_data_t_swigregister(ptr_type_data_t)
class array_type_data_t(object):
    r"""
    Proxy of C++ array_type_data_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    elem_type: "tinfo_t" = property(_ida_typeinf.array_type_data_t_elem_type_get, _ida_typeinf.array_type_data_t_elem_type_set, doc=r"""elem_type""")
    r"""
    element type
    """
    base: "uint32" = property(_ida_typeinf.array_type_data_t_base_get, _ida_typeinf.array_type_data_t_base_set, doc=r"""base""")
    r"""
    array base
    """
    nelems: "uint32" = property(_ida_typeinf.array_type_data_t_nelems_get, _ida_typeinf.array_type_data_t_nelems_set, doc=r"""nelems""")
    r"""
    number of elements
    """

    def __init__(self, b: "size_t"=0, n: "size_t"=0):
        r"""
        __init__(self, b=0, n=0) -> array_type_data_t

        @param b: size_t
        @param n: size_t
        """
        _ida_typeinf.array_type_data_t_swiginit(self, _ida_typeinf.new_array_type_data_t(b, n))

    def swap(self, r: "array_type_data_t") -> "void":
        r"""
        swap(self, r)
        set this = r and r = this

        @param r: (C++: array_type_data_t &)
        """
        return _ida_typeinf.array_type_data_t_swap(self, r)
    __swig_destroy__ = _ida_typeinf.delete_array_type_data_t

# Register array_type_data_t in _ida_typeinf:
_ida_typeinf.array_type_data_t_swigregister(array_type_data_t)
class funcarg_t(object):
    r"""
    Proxy of C++ funcarg_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    argloc: "argloc_t" = property(_ida_typeinf.funcarg_t_argloc_get, _ida_typeinf.funcarg_t_argloc_set, doc=r"""argloc""")
    r"""
    argument location
    """
    name: "qstring" = property(_ida_typeinf.funcarg_t_name_get, _ida_typeinf.funcarg_t_name_set, doc=r"""name""")
    r"""
    argument name (may be empty)
    """
    cmt: "qstring" = property(_ida_typeinf.funcarg_t_cmt_get, _ida_typeinf.funcarg_t_cmt_set, doc=r"""cmt""")
    r"""
    argument comment (may be empty)
    """
    type: "tinfo_t" = property(_ida_typeinf.funcarg_t_type_get, _ida_typeinf.funcarg_t_type_set, doc=r"""type""")
    r"""
    argument type
    """
    flags: "uint32" = property(_ida_typeinf.funcarg_t_flags_get, _ida_typeinf.funcarg_t_flags_set, doc=r"""flags""")
    r"""
    Function argument property bits
    """

    def __eq__(self, r: "funcarg_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: funcarg_t const &
        """
        return _ida_typeinf.funcarg_t___eq__(self, r)

    def __ne__(self, r: "funcarg_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: funcarg_t const &
        """
        return _ida_typeinf.funcarg_t___ne__(self, r)

    def __init__(self):
        r"""
        __init__(self) -> funcarg_t
        """
        _ida_typeinf.funcarg_t_swiginit(self, _ida_typeinf.new_funcarg_t())
    __swig_destroy__ = _ida_typeinf.delete_funcarg_t

# Register funcarg_t in _ida_typeinf:
_ida_typeinf.funcarg_t_swigregister(funcarg_t)
FAI_HIDDEN = _ida_typeinf.FAI_HIDDEN
r"""
hidden argument
"""

FAI_RETPTR = _ida_typeinf.FAI_RETPTR
r"""
pointer to return value. implies hidden
"""

FAI_STRUCT = _ida_typeinf.FAI_STRUCT
r"""
was initially a structure
"""

FAI_ARRAY = _ida_typeinf.FAI_ARRAY
r"""
was initially an array; see "__org_typedef" or "__org_arrdim" type attributes to
determine the original type
"""

FAI_UNUSED = _ida_typeinf.FAI_UNUSED
r"""
argument is not used by the function
"""


class func_type_data_t(funcargvec_t):
    r"""
    Proxy of C++ func_type_data_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    flags: "int" = property(_ida_typeinf.func_type_data_t_flags_get, _ida_typeinf.func_type_data_t_flags_set, doc=r"""flags""")
    r"""
    Function type data property bits
    """
    rettype: "tinfo_t" = property(_ida_typeinf.func_type_data_t_rettype_get, _ida_typeinf.func_type_data_t_rettype_set, doc=r"""rettype""")
    r"""
    return type
    """
    retloc: "argloc_t" = property(_ida_typeinf.func_type_data_t_retloc_get, _ida_typeinf.func_type_data_t_retloc_set, doc=r"""retloc""")
    r"""
    return location
    """
    stkargs: "uval_t" = property(_ida_typeinf.func_type_data_t_stkargs_get, _ida_typeinf.func_type_data_t_stkargs_set, doc=r"""stkargs""")
    r"""
    size of stack arguments (not used in build_func_type)
    """
    spoiled: "reginfovec_t" = property(_ida_typeinf.func_type_data_t_spoiled_get, _ida_typeinf.func_type_data_t_spoiled_set, doc=r"""spoiled""")
    r"""
    spoiled register information. if spoiled register info is present, it overrides
    the standard spoil info (eax, edx, ecx for x86)
    """
    cc: "cm_t" = property(_ida_typeinf.func_type_data_t_cc_get, _ida_typeinf.func_type_data_t_cc_set, doc=r"""cc""")
    r"""
    calling convention
    """

    def swap(self, r: "func_type_data_t") -> "void":
        r"""
        swap(self, r)

        @param r: func_type_data_t &
        """
        return _ida_typeinf.func_type_data_t_swap(self, r)

    def is_high(self) -> "bool":
        r"""
        is_high(self) -> bool
        """
        return _ida_typeinf.func_type_data_t_is_high(self)

    def is_noret(self) -> "bool":
        r"""
        is_noret(self) -> bool
        """
        return _ida_typeinf.func_type_data_t_is_noret(self)

    def is_pure(self) -> "bool":
        r"""
        is_pure(self) -> bool
        """
        return _ida_typeinf.func_type_data_t_is_pure(self)

    def is_static(self) -> "bool":
        r"""
        is_static(self) -> bool
        """
        return _ida_typeinf.func_type_data_t_is_static(self)

    def is_virtual(self) -> "bool":
        r"""
        is_virtual(self) -> bool
        """
        return _ida_typeinf.func_type_data_t_is_virtual(self)

    def is_const(self) -> "bool":
        r"""
        is_const(self) -> bool
        """
        return _ida_typeinf.func_type_data_t_is_const(self)

    def is_ctor(self) -> "bool":
        r"""
        is_ctor(self) -> bool
        """
        return _ida_typeinf.func_type_data_t_is_ctor(self)

    def is_dtor(self) -> "bool":
        r"""
        is_dtor(self) -> bool
        """
        return _ida_typeinf.func_type_data_t_is_dtor(self)

    def get_call_method(self) -> "int":
        r"""
        get_call_method(self) -> int
        """
        return _ida_typeinf.func_type_data_t_get_call_method(self)

    def is_vararg_cc(self) -> "bool":
        r"""
        is_vararg_cc(self) -> bool
        """
        return _ida_typeinf.func_type_data_t_is_vararg_cc(self)

    def is_golang_cc(self) -> "bool":
        r"""
        is_golang_cc(self) -> bool
        """
        return _ida_typeinf.func_type_data_t_is_golang_cc(self)

    def is_swift_cc(self) -> "bool":
        r"""
        is_swift_cc(self) -> bool
        """
        return _ida_typeinf.func_type_data_t_is_swift_cc(self)

    def guess_cc(self, purged: "int", cc_flags: "int") -> "cm_t":
        r"""
        guess_cc(self, purged, cc_flags) -> cm_t
        Guess function calling convention use the following info: argument locations and
        'stkargs'

        @param purged: (C++: int)
        @param cc_flags: (C++: int)
        """
        return _ida_typeinf.func_type_data_t_guess_cc(self, purged, cc_flags)

    def dump(self, praloc_bits: "int"=0x02) -> "bool":
        r"""
        dump(self, praloc_bits=0x02) -> bool
        Dump information that is not always visible in the function prototype. (argument
        locations, return location, total stkarg size)

        @param praloc_bits: (C++: int)
        """
        return _ida_typeinf.func_type_data_t_dump(self, praloc_bits)

    def find_argument(self, *args) -> "ssize_t":
        r"""
        find_argument(self, name, _from=0, to=size_t(-1)) -> ssize_t
        find argument by name

        @param name: (C++: const char *) char const *
        @param from: (C++: size_t)
        @param to: (C++: size_t)
        """
        return _ida_typeinf.func_type_data_t_find_argument(self, *args)
    __swig_destroy__ = _ida_typeinf.delete_func_type_data_t

    def __init__(self):
        r"""
        __init__(self) -> func_type_data_t
        """
        _ida_typeinf.func_type_data_t_swiginit(self, _ida_typeinf.new_func_type_data_t())

# Register func_type_data_t in _ida_typeinf:
_ida_typeinf.func_type_data_t_swigregister(func_type_data_t)
FTI_SPOILED = _ida_typeinf.FTI_SPOILED
r"""
information about spoiled registers is present
"""

FTI_NORET = _ida_typeinf.FTI_NORET
r"""
noreturn
"""

FTI_PURE = _ida_typeinf.FTI_PURE
r"""
__pure
"""

FTI_HIGH = _ida_typeinf.FTI_HIGH
r"""
high level prototype (with possibly hidden args)
"""

FTI_STATIC = _ida_typeinf.FTI_STATIC
r"""
static
"""

FTI_VIRTUAL = _ida_typeinf.FTI_VIRTUAL
r"""
virtual
"""

FTI_CALLTYPE = _ida_typeinf.FTI_CALLTYPE
r"""
mask for FTI_*CALL
"""

FTI_DEFCALL = _ida_typeinf.FTI_DEFCALL
r"""
default call
"""

FTI_NEARCALL = _ida_typeinf.FTI_NEARCALL
r"""
near call
"""

FTI_FARCALL = _ida_typeinf.FTI_FARCALL
r"""
far call
"""

FTI_INTCALL = _ida_typeinf.FTI_INTCALL
r"""
interrupt call
"""

FTI_ARGLOCS = _ida_typeinf.FTI_ARGLOCS
r"""
info about argument locations has been calculated (stkargs and retloc too)
"""

FTI_EXPLOCS = _ida_typeinf.FTI_EXPLOCS
r"""
all arglocs are specified explicitly
"""

FTI_CONST = _ida_typeinf.FTI_CONST
r"""
const member function
"""

FTI_CTOR = _ida_typeinf.FTI_CTOR
r"""
constructor
"""

FTI_DTOR = _ida_typeinf.FTI_DTOR
r"""
destructor
"""

FTI_ALL = _ida_typeinf.FTI_ALL
r"""
all defined bits
"""

CC_CDECL_OK = _ida_typeinf.CC_CDECL_OK
r"""
can use __cdecl calling convention?
"""

CC_ALLOW_ARGPERM = _ida_typeinf.CC_ALLOW_ARGPERM
r"""
disregard argument order?
"""

CC_ALLOW_REGHOLES = _ida_typeinf.CC_ALLOW_REGHOLES
r"""
allow holes in register argument list?
"""

CC_HAS_ELLIPSIS = _ida_typeinf.CC_HAS_ELLIPSIS
r"""
function has a variable list of arguments?
"""

CC_GOLANG_OK = _ida_typeinf.CC_GOLANG_OK
r"""
can use __golang calling convention
"""


FMTFUNC_PRINTF = _ida_typeinf.FMTFUNC_PRINTF

FMTFUNC_SCANF = _ida_typeinf.FMTFUNC_SCANF

FMTFUNC_STRFTIME = _ida_typeinf.FMTFUNC_STRFTIME

FMTFUNC_STRFMON = _ida_typeinf.FMTFUNC_STRFMON

class stkarg_area_info_t(object):
    r"""
    Proxy of C++ stkarg_area_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    cb: "size_t" = property(_ida_typeinf.stkarg_area_info_t_cb_get, _ida_typeinf.stkarg_area_info_t_cb_set, doc=r"""cb""")
    stkarg_offset: "sval_t" = property(_ida_typeinf.stkarg_area_info_t_stkarg_offset_get, _ida_typeinf.stkarg_area_info_t_stkarg_offset_set, doc=r"""stkarg_offset""")
    r"""
    Offset from the SP to the first stack argument (can include linkage area)
    examples: pc: 0, hppa: -0x34, ppc aix: 0x18
    """
    shadow_size: "sval_t" = property(_ida_typeinf.stkarg_area_info_t_shadow_size_get, _ida_typeinf.stkarg_area_info_t_shadow_size_set, doc=r"""shadow_size""")
    r"""
    Size of the shadow area. explanations at:
    \link{https://stackoverflow.com/questions/30190132/what-is-the-shadow-space-
    in-x64-assembly} examples: x64 Visual Studio C++: 0x20, x64 gcc: 0, ppc aix:
    0x20
    """
    linkage_area: "sval_t" = property(_ida_typeinf.stkarg_area_info_t_linkage_area_get, _ida_typeinf.stkarg_area_info_t_linkage_area_set, doc=r"""linkage_area""")
    r"""
    Size of the linkage area. explanations at: \link{https://www.ibm.com/docs/en/xl-
    fortran-aix/16.1.0?topic=conventions-linkage-area} examples: pc: 0, hppa: 0, ppc
    aix: 0x18 (equal to stkarg_offset)
    """

    def __init__(self):
        r"""
        __init__(self) -> stkarg_area_info_t
        """
        _ida_typeinf.stkarg_area_info_t_swiginit(self, _ida_typeinf.new_stkarg_area_info_t())
    __swig_destroy__ = _ida_typeinf.delete_stkarg_area_info_t

# Register stkarg_area_info_t in _ida_typeinf:
_ida_typeinf.stkarg_area_info_t_swigregister(stkarg_area_info_t)
class edm_t(object):
    r"""
    Proxy of C++ edm_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    name: "qstring" = property(_ida_typeinf.edm_t_name_get, _ida_typeinf.edm_t_name_set, doc=r"""name""")
    cmt: "qstring" = property(_ida_typeinf.edm_t_cmt_get, _ida_typeinf.edm_t_cmt_set, doc=r"""cmt""")
    value: "uint64" = property(_ida_typeinf.edm_t_value_get, _ida_typeinf.edm_t_value_set, doc=r"""value""")

    def __eq__(self, r: "edm_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: edm_t const &
        """
        return _ida_typeinf.edm_t___eq__(self, r)

    def __ne__(self, r: "edm_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: edm_t const &
        """
        return _ida_typeinf.edm_t___ne__(self, r)

    def swap(self, r: "edm_t") -> "void":
        r"""
        swap(self, r)

        @param r: edm_t &
        """
        return _ida_typeinf.edm_t_swap(self, r)

    def get_tid(self) -> "tid_t":
        r"""
        get_tid(self) -> tid_t
        """
        return _ida_typeinf.edm_t_get_tid(self)

    def __init__(self):
        r"""
        __init__(self) -> edm_t
        """
        _ida_typeinf.edm_t_swiginit(self, _ida_typeinf.new_edm_t())
    __swig_destroy__ = _ida_typeinf.delete_edm_t

# Register edm_t in _ida_typeinf:
_ida_typeinf.edm_t_swigregister(edm_t)
class enum_type_data_t(edmvec_t):
    r"""
    Proxy of C++ enum_type_data_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    group_sizes: "intvec_t" = property(_ida_typeinf.enum_type_data_t_group_sizes_get, _ida_typeinf.enum_type_data_t_group_sizes_set, doc=r"""group_sizes""")
    r"""
    if present, specifies bitmask group sizes each non-trivial group starts with a
    mask member
    """
    taenum_bits: "uint32" = property(_ida_typeinf.enum_type_data_t_taenum_bits_get, _ida_typeinf.enum_type_data_t_taenum_bits_set, doc=r"""taenum_bits""")
    r"""
    Type attributes for enums
    """
    bte: "bte_t" = property(_ida_typeinf.enum_type_data_t_bte_get, _ida_typeinf.enum_type_data_t_bte_set, doc=r"""bte""")
    r"""
    enum member sizes (shift amount) and style. do not manually set BTE_BITMASK, use
    set_enum_is_bitmask()
    """

    def __init__(self, *args):
        r"""
        __init__(self, _bte=BTE_ALWAYS|BTE_HEX) -> enum_type_data_t

        @param _bte: bte_t
        """
        _ida_typeinf.enum_type_data_t_swiginit(self, _ida_typeinf.new_enum_type_data_t(*args))

    def get_enum_radix(self) -> "int":
        r"""
        get_enum_radix(self) -> int
        Get enum constant radix

        @return: radix or 1 for BTE_CHAR
        """
        return _ida_typeinf.enum_type_data_t_get_enum_radix(self)

    def is_number_signed(self) -> "bool":
        r"""
        is_number_signed(self) -> bool
        """
        return _ida_typeinf.enum_type_data_t_is_number_signed(self)

    def set_enum_radix(self, radix: "int", sign: "bool") -> "void":
        r"""
        set_enum_radix(self, radix, sign)
        Set radix to display constants

        @param radix: (C++: int) radix with the special case 1 to display as character
        @param sign: (C++: bool)
        """
        return _ida_typeinf.enum_type_data_t_set_enum_radix(self, radix, sign)

    def is_char(self) -> "bool":
        r"""
        is_char(self) -> bool
        """
        return _ida_typeinf.enum_type_data_t_is_char(self)

    def is_dec(self) -> "bool":
        r"""
        is_dec(self) -> bool
        """
        return _ida_typeinf.enum_type_data_t_is_dec(self)

    def is_hex(self) -> "bool":
        r"""
        is_hex(self) -> bool
        """
        return _ida_typeinf.enum_type_data_t_is_hex(self)

    def is_oct(self) -> "bool":
        r"""
        is_oct(self) -> bool
        """
        return _ida_typeinf.enum_type_data_t_is_oct(self)

    def is_bin(self) -> "bool":
        r"""
        is_bin(self) -> bool
        """
        return _ida_typeinf.enum_type_data_t_is_bin(self)

    def is_udec(self) -> "bool":
        r"""
        is_udec(self) -> bool
        """
        return _ida_typeinf.enum_type_data_t_is_udec(self)

    def is_shex(self) -> "bool":
        r"""
        is_shex(self) -> bool
        """
        return _ida_typeinf.enum_type_data_t_is_shex(self)

    def is_soct(self) -> "bool":
        r"""
        is_soct(self) -> bool
        """
        return _ida_typeinf.enum_type_data_t_is_soct(self)

    def is_sbin(self) -> "bool":
        r"""
        is_sbin(self) -> bool
        """
        return _ida_typeinf.enum_type_data_t_is_sbin(self)

    def has_lzero(self) -> "bool":
        r"""
        has_lzero(self) -> bool
        """
        return _ida_typeinf.enum_type_data_t_has_lzero(self)

    def set_lzero(self, on: "bool") -> "void":
        r"""
        set_lzero(self, on)

        @param on: bool
        """
        return _ida_typeinf.enum_type_data_t_set_lzero(self, on)

    def calc_mask(self) -> "uint64":
        r"""
        calc_mask(self) -> uint64
        """
        return _ida_typeinf.enum_type_data_t_calc_mask(self)

    def store_64bit_values(self) -> "bool":
        r"""
        store_64bit_values(self) -> bool
        """
        return _ida_typeinf.enum_type_data_t_store_64bit_values(self)

    def is_bf(self) -> "bool":
        r"""
        is_bf(self) -> bool
        is bitmask or ordinary enum?
        """
        return _ida_typeinf.enum_type_data_t_is_bf(self)

    def calc_nbytes(self) -> "int":
        r"""
        calc_nbytes(self) -> int
        get the width of enum in bytes
        """
        return _ida_typeinf.enum_type_data_t_calc_nbytes(self)

    def set_nbytes(self, nbytes: "int") -> "bool":
        r"""
        set_nbytes(self, nbytes) -> bool
        set enum width (nbytes)

        @param nbytes: (C++: int)
        """
        return _ida_typeinf.enum_type_data_t_set_nbytes(self, nbytes)

    def is_group_mask_at(self, idx: "size_t") -> "bool":
        r"""
        is_group_mask_at(self, idx) -> bool
        is the enum member at IDX a non-trivial group mask? a trivial group consist of
        one bit and has just one member, which can be considered as a mask or a bitfield
        constant

        @param idx: (C++: size_t) index
        @return: success
        """
        return _ida_typeinf.enum_type_data_t_is_group_mask_at(self, idx)

    def is_valid_group_sizes(self) -> "bool":
        r"""
        is_valid_group_sizes(self) -> bool
        is valid group sizes
        """
        return _ida_typeinf.enum_type_data_t_is_valid_group_sizes(self)

    def find_member(self, *args) -> "ssize_t":
        r"""
        find_member(self, name, _from=0, to=size_t(-1)) -> ssize_t
        find member (constant or bmask) by value

        @param name: char const *
        @param from: (C++: size_t)
        @param to: (C++: size_t)

        find_member(self, value, serial, _from=0, to=size_t(-1), vmask=uint64(-1)) -> ssize_t

        @param value: uint64
        @param serial: uchar
        @param from: size_t
        @param to: size_t
        @param vmask: uint64
        """
        return _ida_typeinf.enum_type_data_t_find_member(self, *args)

    def swap(self, r: "enum_type_data_t") -> "void":
        r"""
        swap(self, r)
        swap two instances

        @param r: (C++: enum_type_data_t &)
        """
        return _ida_typeinf.enum_type_data_t_swap(self, r)

    def add_constant(self, name: "char const *", value: "uint64", cmt: "char const *"=None) -> "void":
        r"""
        add_constant(self, name, value, cmt=None)
        add constant for regular enum

        @param name: (C++: const char *) char const *
        @param value: (C++: uint64)
        @param cmt: (C++: const char *) char const *
        """
        return _ida_typeinf.enum_type_data_t_add_constant(self, name, value, cmt)

    def get_value_repr(self, repr: "value_repr_t") -> "tinfo_code_t":
        r"""
        get_value_repr(self, repr) -> tinfo_code_t
        get enum radix and other representation info

        @param repr: (C++: value_repr_t *) value display info
        """
        return _ida_typeinf.enum_type_data_t_get_value_repr(self, repr)

    def set_value_repr(self, repr: "value_repr_t") -> "tinfo_code_t":
        r"""
        set_value_repr(self, repr) -> tinfo_code_t
        set enum radix and other representation info

        @param repr: (C++: const value_repr_t &) value display info
        """
        return _ida_typeinf.enum_type_data_t_set_value_repr(self, repr)

    def get_serial(self, index: "size_t") -> "uchar":
        r"""
        get_serial(self, index) -> uchar
        returns serial for the constant

        @param index: (C++: size_t)
        """
        return _ida_typeinf.enum_type_data_t_get_serial(self, index)

    def get_max_serial(self, value: "uint64") -> "uchar":
        r"""
        get_max_serial(self, value) -> uchar
        return the maximum serial for the value

        @param value: (C++: uint64)
        """
        return _ida_typeinf.enum_type_data_t_get_max_serial(self, value)

    def get_constant_group(self, *args) -> "PyObject *":
        r"""
        get_constant_group(self, group_start_index, group_size, idx) -> bool
        get group parameters for the constant, valid for bitmask enum

        @param group_start_index: (C++: size_t *) index of the group mask
        @param group_size: (C++: size_t *) group size (>=1)
        @param idx: (C++: size_t) constant index
        @return: success
        get_constant_group(self, idx) -> PyObject *

        @param idx: size_t
        """
        return _ida_typeinf.enum_type_data_t_get_constant_group(self, *args)

    def all_groups(self, skip_trivial=False):
        r"""
        Generate tuples for bitmask enum groups.
        Each tupple is:
        [0] enum member index of group start
        [1] group size
        Tupples may include or not the group with 1 element.
        """
        if len(self.group_sizes) != 0 and self.is_valid_group_sizes():
            grp_start = 0
            for grp_size in self.group_sizes:
                if not skip_trivial or grp_size != 1:
                    yield (grp_start, grp_size)
                grp_start += grp_size
            return None


    def all_constants(self):
        r"""
        Generate tupples of all constants except of bitmasks.
        Each tupple is:
        [0] constant index
        [1] enum member index of group start
        [2] group size
        In case of regular enum the second element of tupple is 0 and the third element of tupple is the number of enum members.
        """
        if len(self.group_sizes) != 0:  # bitmask enum
            for (grp_start, grp_size) in self.all_groups():
                grp_end = grp_start + grp_size
                if grp_size != 1:
                    grp_start += 1
                for idx in range(grp_start, grp_end):
                    yield (idx, grp_start, grp_size)
        else: # regular enum
            sz = self.size()
            for idx in range(0, sz):
                yield (idx, 0, sz)
        return None

    __swig_destroy__ = _ida_typeinf.delete_enum_type_data_t

# Register enum_type_data_t in _ida_typeinf:
_ida_typeinf.enum_type_data_t_swigregister(enum_type_data_t)
class typedef_type_data_t(object):
    r"""
    Proxy of C++ typedef_type_data_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    til: "til_t const *" = property(_ida_typeinf.typedef_type_data_t_til_get, _ida_typeinf.typedef_type_data_t_til_set, doc=r"""til""")
    r"""
    type library to use when resolving
    """
    name: "char const *" = property(_ida_typeinf.typedef_type_data_t_name_get, _ida_typeinf.typedef_type_data_t_name_set, doc=r"""name""")
    r"""
    is_ordref=false: target type name. we do not own this pointer!
    """
    ordinal: "uint32" = property(_ida_typeinf.typedef_type_data_t_ordinal_get, _ida_typeinf.typedef_type_data_t_ordinal_set, doc=r"""ordinal""")
    r"""
    is_ordref=true: type ordinal number
    """
    is_ordref: "bool" = property(_ida_typeinf.typedef_type_data_t_is_ordref_get, _ida_typeinf.typedef_type_data_t_is_ordref_set, doc=r"""is_ordref""")
    r"""
    is reference by ordinal?
    """
    resolve: "bool" = property(_ida_typeinf.typedef_type_data_t_resolve_get, _ida_typeinf.typedef_type_data_t_resolve_set, doc=r"""resolve""")
    r"""
    should resolve immediately?
    """

    def __init__(self, *args):
        r"""
        __init__(self, _til, _name, _resolve=False) -> typedef_type_data_t

        @param _til: til_t const *
        @param _name: char const *
        @param _resolve: bool

        __init__(self, _til, ord, _resolve=False) -> typedef_type_data_t

        @param _til: til_t const *
        @param ord: uint32
        @param _resolve: bool
        """
        _ida_typeinf.typedef_type_data_t_swiginit(self, _ida_typeinf.new_typedef_type_data_t(*args))

    def swap(self, r: "typedef_type_data_t") -> "void":
        r"""
        swap(self, r)

        @param r: typedef_type_data_t &
        """
        return _ida_typeinf.typedef_type_data_t_swap(self, r)
    __swig_destroy__ = _ida_typeinf.delete_typedef_type_data_t

# Register typedef_type_data_t in _ida_typeinf:
_ida_typeinf.typedef_type_data_t_swigregister(typedef_type_data_t)
MAX_ENUM_SERIAL = cvar.MAX_ENUM_SERIAL
r"""
Max number of identical constants allowed for one enum type.
"""

class custom_data_type_info_t(object):
    r"""
    Proxy of C++ custom_data_type_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    dtid: "int16" = property(_ida_typeinf.custom_data_type_info_t_dtid_get, _ida_typeinf.custom_data_type_info_t_dtid_set, doc=r"""dtid""")
    r"""
    data type id
    """
    fid: "int16" = property(_ida_typeinf.custom_data_type_info_t_fid_get, _ida_typeinf.custom_data_type_info_t_fid_set, doc=r"""fid""")
    r"""
    data format ids
    """

    def __init__(self):
        r"""
        __init__(self) -> custom_data_type_info_t
        """
        _ida_typeinf.custom_data_type_info_t_swiginit(self, _ida_typeinf.new_custom_data_type_info_t())
    __swig_destroy__ = _ida_typeinf.delete_custom_data_type_info_t

# Register custom_data_type_info_t in _ida_typeinf:
_ida_typeinf.custom_data_type_info_t_swigregister(custom_data_type_info_t)
class value_repr_t(object):
    r"""
    Proxy of C++ value_repr_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    bits: "uint64" = property(_ida_typeinf.value_repr_t_bits_get, _ida_typeinf.value_repr_t_bits_set, doc=r"""bits""")
    ri: "refinfo_t" = property(_ida_typeinf.value_repr_t_ri_get, _ida_typeinf.value_repr_t_ri_set, doc=r"""ri""")
    r"""
    FRB_OFFSET.
    """
    strtype: "int32" = property(_ida_typeinf.value_repr_t_strtype_get, _ida_typeinf.value_repr_t_strtype_set, doc=r"""strtype""")
    r"""
    FRB_STRLIT.
    """
    delta: "adiff_t" = property(_ida_typeinf.value_repr_t_delta_get, _ida_typeinf.value_repr_t_delta_set, doc=r"""delta""")
    r"""
    FRB_STROFF.
    """
    type_ordinal: "uint32" = property(_ida_typeinf.value_repr_t_type_ordinal_get, _ida_typeinf.value_repr_t_type_ordinal_set, doc=r"""type_ordinal""")
    r"""
    FRB_STROFF, FRB_ENUM.
    """
    cd: "custom_data_type_info_t" = property(_ida_typeinf.value_repr_t_cd_get, _ida_typeinf.value_repr_t_cd_set, doc=r"""cd""")
    r"""
    FRB_CUSTOM.
    """
    ap: "array_parameters_t" = property(_ida_typeinf.value_repr_t_ap_get, _ida_typeinf.value_repr_t_ap_set, doc=r"""ap""")
    r"""
    FRB_TABFORM, AP_SIGNED is ignored, use FRB_SIGNED instead
    """

    def swap(self, r: "value_repr_t") -> "void":
        r"""
        swap(self, r)

        @param r: value_repr_t &
        """
        return _ida_typeinf.value_repr_t_swap(self, r)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_typeinf.value_repr_t_clear(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_typeinf.value_repr_t_empty(self)

    def is_enum(self) -> "bool":
        r"""
        is_enum(self) -> bool
        """
        return _ida_typeinf.value_repr_t_is_enum(self)

    def is_offset(self) -> "bool":
        r"""
        is_offset(self) -> bool
        """
        return _ida_typeinf.value_repr_t_is_offset(self)

    def is_strlit(self) -> "bool":
        r"""
        is_strlit(self) -> bool
        """
        return _ida_typeinf.value_repr_t_is_strlit(self)

    def is_custom(self) -> "bool":
        r"""
        is_custom(self) -> bool
        """
        return _ida_typeinf.value_repr_t_is_custom(self)

    def is_stroff(self) -> "bool":
        r"""
        is_stroff(self) -> bool
        """
        return _ida_typeinf.value_repr_t_is_stroff(self)

    def is_typref(self) -> "bool":
        r"""
        is_typref(self) -> bool
        """
        return _ida_typeinf.value_repr_t_is_typref(self)

    def is_signed(self) -> "bool":
        r"""
        is_signed(self) -> bool
        """
        return _ida_typeinf.value_repr_t_is_signed(self)

    def has_tabform(self) -> "bool":
        r"""
        has_tabform(self) -> bool
        """
        return _ida_typeinf.value_repr_t_has_tabform(self)

    def has_lzeroes(self) -> "bool":
        r"""
        has_lzeroes(self) -> bool
        """
        return _ida_typeinf.value_repr_t_has_lzeroes(self)

    def get_vtype(self) -> "uint64":
        r"""
        get_vtype(self) -> uint64
        """
        return _ida_typeinf.value_repr_t_get_vtype(self)

    def set_vtype(self, vt: "uint64") -> "void":
        r"""
        set_vtype(self, vt)

        @param vt: uint64
        """
        return _ida_typeinf.value_repr_t_set_vtype(self, vt)

    def set_signed(self, on: "bool") -> "void":
        r"""
        set_signed(self, on)

        @param on: bool
        """
        return _ida_typeinf.value_repr_t_set_signed(self, on)

    def set_tabform(self, on: "bool") -> "void":
        r"""
        set_tabform(self, on)

        @param on: bool
        """
        return _ida_typeinf.value_repr_t_set_tabform(self, on)

    def set_lzeroes(self, on: "bool") -> "void":
        r"""
        set_lzeroes(self, on)

        @param on: bool
        """
        return _ida_typeinf.value_repr_t_set_lzeroes(self, on)

    def set_ap(self, _ap: "array_parameters_t") -> "void":
        r"""
        set_ap(self, _ap)

        @param _ap: array_parameters_t const &
        """
        return _ida_typeinf.value_repr_t_set_ap(self, _ap)

    def init_ap(self, _ap: "array_parameters_t") -> "void":
        r"""
        init_ap(self, _ap)

        @param _ap: array_parameters_t *
        """
        return _ida_typeinf.value_repr_t_init_ap(self, _ap)

    def from_opinfo(self, flags: "flags64_t", afl: "aflags_t", opinfo: "opinfo_t", _ap: "array_parameters_t") -> "bool":
        r"""
        from_opinfo(self, flags, afl, opinfo, _ap) -> bool

        @param flags: flags64_t
        @param afl: aflags_t
        @param opinfo: opinfo_t const *
        @param _ap: array_parameters_t const *
        """
        return _ida_typeinf.value_repr_t_from_opinfo(self, flags, afl, opinfo, _ap)

    def _print(self, colored: "bool"=False) -> "size_t":
        r"""
        _print(self, colored=False) -> size_t

        Parameters
        ----------
        colored: bool

        """
        return _ida_typeinf.value_repr_t__print(self, colored)

    def parse_value_repr(self, *args) -> "bool":
        r"""
        parse_value_repr(self, attr, target_type=BTF_STRUCT) -> bool

        @param attr: qstring const &
        @param target_type: type_t
        """
        return _ida_typeinf.value_repr_t_parse_value_repr(self, *args)

    def __str__(self) -> "qstring":
        r"""
        __str__(self) -> qstring
        """
        return _ida_typeinf.value_repr_t___str__(self)

    def __init__(self):
        r"""
        __init__(self) -> value_repr_t
        """
        _ida_typeinf.value_repr_t_swiginit(self, _ida_typeinf.new_value_repr_t())
    __swig_destroy__ = _ida_typeinf.delete_value_repr_t

# Register value_repr_t in _ida_typeinf:
_ida_typeinf.value_repr_t_swigregister(value_repr_t)
FRB_MASK = _ida_typeinf.FRB_MASK
r"""
Mask for the value type (* means requires additional info):
"""

FRB_UNK = _ida_typeinf.FRB_UNK
r"""
Unknown.
"""

FRB_NUMB = _ida_typeinf.FRB_NUMB
r"""
Binary number.
"""

FRB_NUMO = _ida_typeinf.FRB_NUMO
r"""
Octal number.
"""

FRB_NUMH = _ida_typeinf.FRB_NUMH
r"""
Hexadecimal number.
"""

FRB_NUMD = _ida_typeinf.FRB_NUMD
r"""
Decimal number.
"""

FRB_FLOAT = _ida_typeinf.FRB_FLOAT
r"""
Floating point number (for interpreting an integer type as a floating value)
"""

FRB_CHAR = _ida_typeinf.FRB_CHAR
r"""
Char.
"""

FRB_SEG = _ida_typeinf.FRB_SEG
r"""
Segment.
"""

FRB_ENUM = _ida_typeinf.FRB_ENUM
r"""
*Enumeration
"""

FRB_OFFSET = _ida_typeinf.FRB_OFFSET
r"""
*Offset
"""

FRB_STRLIT = _ida_typeinf.FRB_STRLIT
r"""
*String literal (used for arrays)
"""

FRB_STROFF = _ida_typeinf.FRB_STROFF
r"""
*Struct offset
"""

FRB_CUSTOM = _ida_typeinf.FRB_CUSTOM
r"""
*Custom data type
"""

FRB_INVSIGN = _ida_typeinf.FRB_INVSIGN
r"""
Invert sign (0x01 is represented as -0xFF)
"""

FRB_INVBITS = _ida_typeinf.FRB_INVBITS
r"""
Invert bits (0x01 is represented as ~0xFE)
"""

FRB_SIGNED = _ida_typeinf.FRB_SIGNED
r"""
Force signed representation.
"""

FRB_LZERO = _ida_typeinf.FRB_LZERO
r"""
Toggle leading zeroes (used for integers)
"""

FRB_TABFORM = _ida_typeinf.FRB_TABFORM
r"""
has additional tabular parameters
"""


class udm_t(object):
    r"""
    Proxy of C++ udm_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    offset: "uint64" = property(_ida_typeinf.udm_t_offset_get, _ida_typeinf.udm_t_offset_set, doc=r"""offset""")
    r"""
    member offset in bits
    """
    size: "uint64" = property(_ida_typeinf.udm_t_size_get, _ida_typeinf.udm_t_size_set, doc=r"""size""")
    r"""
    size in bits
    """
    name: "qstring" = property(_ida_typeinf.udm_t_name_get, _ida_typeinf.udm_t_name_set, doc=r"""name""")
    r"""
    member name
    """
    cmt: "qstring" = property(_ida_typeinf.udm_t_cmt_get, _ida_typeinf.udm_t_cmt_set, doc=r"""cmt""")
    r"""
    member comment
    """
    type: "tinfo_t" = property(_ida_typeinf.udm_t_type_get, _ida_typeinf.udm_t_type_set, doc=r"""type""")
    r"""
    member type
    """
    repr: "value_repr_t" = property(_ida_typeinf.udm_t_repr_get, _ida_typeinf.udm_t_repr_set, doc=r"""repr""")
    r"""
    radix, refinfo, strpath, custom_id, strtype
    """
    effalign: "int" = property(_ida_typeinf.udm_t_effalign_get, _ida_typeinf.udm_t_effalign_set, doc=r"""effalign""")
    r"""
    effective field alignment (in bytes)
    """
    tafld_bits: "uint32" = property(_ida_typeinf.udm_t_tafld_bits_get, _ida_typeinf.udm_t_tafld_bits_set, doc=r"""tafld_bits""")
    r"""
    TAH bits.
    """
    fda: "uchar" = property(_ida_typeinf.udm_t_fda_get, _ida_typeinf.udm_t_fda_set, doc=r"""fda""")
    r"""
    field alignment (shift amount)
    """

    def is_bitfield(self) -> "bool":
        r"""
        is_bitfield(self) -> bool
        """
        return _ida_typeinf.udm_t_is_bitfield(self)

    def is_zero_bitfield(self) -> "bool":
        r"""
        is_zero_bitfield(self) -> bool
        """
        return _ida_typeinf.udm_t_is_zero_bitfield(self)

    def is_unaligned(self) -> "bool":
        r"""
        is_unaligned(self) -> bool
        """
        return _ida_typeinf.udm_t_is_unaligned(self)

    def is_baseclass(self) -> "bool":
        r"""
        is_baseclass(self) -> bool
        """
        return _ida_typeinf.udm_t_is_baseclass(self)

    def is_virtbase(self) -> "bool":
        r"""
        is_virtbase(self) -> bool
        """
        return _ida_typeinf.udm_t_is_virtbase(self)

    def is_vftable(self) -> "bool":
        r"""
        is_vftable(self) -> bool
        """
        return _ida_typeinf.udm_t_is_vftable(self)

    def is_method(self) -> "bool":
        r"""
        is_method(self) -> bool
        """
        return _ida_typeinf.udm_t_is_method(self)

    def is_gap(self) -> "bool":
        r"""
        is_gap(self) -> bool
        """
        return _ida_typeinf.udm_t_is_gap(self)

    def is_regcmt(self) -> "bool":
        r"""
        is_regcmt(self) -> bool
        """
        return _ida_typeinf.udm_t_is_regcmt(self)

    def is_retaddr(self) -> "bool":
        r"""
        is_retaddr(self) -> bool
        """
        return _ida_typeinf.udm_t_is_retaddr(self)

    def is_savregs(self) -> "bool":
        r"""
        is_savregs(self) -> bool
        """
        return _ida_typeinf.udm_t_is_savregs(self)

    def is_special_member(self) -> "bool":
        r"""
        is_special_member(self) -> bool
        """
        return _ida_typeinf.udm_t_is_special_member(self)

    def is_by_til(self) -> "bool":
        r"""
        is_by_til(self) -> bool
        """
        return _ida_typeinf.udm_t_is_by_til(self)

    def set_unaligned(self, on: "bool"=True) -> "void":
        r"""
        set_unaligned(self, on=True)

        @param on: bool
        """
        return _ida_typeinf.udm_t_set_unaligned(self, on)

    def set_baseclass(self, on: "bool"=True) -> "void":
        r"""
        set_baseclass(self, on=True)

        @param on: bool
        """
        return _ida_typeinf.udm_t_set_baseclass(self, on)

    def set_virtbase(self, on: "bool"=True) -> "void":
        r"""
        set_virtbase(self, on=True)

        @param on: bool
        """
        return _ida_typeinf.udm_t_set_virtbase(self, on)

    def set_vftable(self, on: "bool"=True) -> "void":
        r"""
        set_vftable(self, on=True)

        @param on: bool
        """
        return _ida_typeinf.udm_t_set_vftable(self, on)

    def set_method(self, on: "bool"=True) -> "void":
        r"""
        set_method(self, on=True)

        @param on: bool
        """
        return _ida_typeinf.udm_t_set_method(self, on)

    def set_regcmt(self, on: "bool"=True) -> "void":
        r"""
        set_regcmt(self, on=True)

        @param on: bool
        """
        return _ida_typeinf.udm_t_set_regcmt(self, on)

    def set_retaddr(self, on: "bool"=True) -> "void":
        r"""
        set_retaddr(self, on=True)

        @param on: bool
        """
        return _ida_typeinf.udm_t_set_retaddr(self, on)

    def set_savregs(self, on: "bool"=True) -> "void":
        r"""
        set_savregs(self, on=True)

        @param on: bool
        """
        return _ida_typeinf.udm_t_set_savregs(self, on)

    def set_by_til(self, on: "bool"=True) -> "void":
        r"""
        set_by_til(self, on=True)

        @param on: bool
        """
        return _ida_typeinf.udm_t_set_by_til(self, on)

    def clr_unaligned(self) -> "void":
        r"""
        clr_unaligned(self)
        """
        return _ida_typeinf.udm_t_clr_unaligned(self)

    def clr_baseclass(self) -> "void":
        r"""
        clr_baseclass(self)
        """
        return _ida_typeinf.udm_t_clr_baseclass(self)

    def clr_virtbase(self) -> "void":
        r"""
        clr_virtbase(self)
        """
        return _ida_typeinf.udm_t_clr_virtbase(self)

    def clr_vftable(self) -> "void":
        r"""
        clr_vftable(self)
        """
        return _ida_typeinf.udm_t_clr_vftable(self)

    def clr_method(self) -> "void":
        r"""
        clr_method(self)
        """
        return _ida_typeinf.udm_t_clr_method(self)

    def begin(self) -> "uint64":
        r"""
        begin(self) -> uint64
        """
        return _ida_typeinf.udm_t_begin(self)

    def end(self) -> "uint64":
        r"""
        end(self) -> uint64
        """
        return _ida_typeinf.udm_t_end(self)

    def __lt__(self, r: "udm_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: udm_t const &
        """
        return _ida_typeinf.udm_t___lt__(self, r)

    def __eq__(self, r: "udm_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: udm_t const &
        """
        return _ida_typeinf.udm_t___eq__(self, r)

    def __ne__(self, r: "udm_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: udm_t const &
        """
        return _ida_typeinf.udm_t___ne__(self, r)

    def swap(self, r: "udm_t") -> "void":
        r"""
        swap(self, r)

        @param r: udm_t &
        """
        return _ida_typeinf.udm_t_swap(self, r)

    def is_anonymous_udm(self) -> "bool":
        r"""
        is_anonymous_udm(self) -> bool
        """
        return _ida_typeinf.udm_t_is_anonymous_udm(self)

    def make_gap(self, byteoff: "uval_t", nbytes: "uval_t") -> "bool":
        r"""
        make_gap(self, byteoff, nbytes) -> bool

        @param byteoff: uval_t
        @param nbytes: uval_t
        """
        return _ida_typeinf.udm_t_make_gap(self, byteoff, nbytes)

    def set_value_repr(self, r: "value_repr_t") -> "void":
        r"""
        set_value_repr(self, r)

        @param r: value_repr_t const &
        """
        return _ida_typeinf.udm_t_set_value_repr(self, r)

    def can_be_dtor(self) -> "bool":
        r"""
        can_be_dtor(self) -> bool
        """
        return _ida_typeinf.udm_t_can_be_dtor(self)

    def can_rename(self) -> "bool":
        r"""
        can_rename(self) -> bool
        """
        return _ida_typeinf.udm_t_can_rename(self)

    def __init__(self):
        r"""
        __init__(self) -> udm_t
        """
        _ida_typeinf.udm_t_swiginit(self, _ida_typeinf.new_udm_t())
    __swig_destroy__ = _ida_typeinf.delete_udm_t

# Register udm_t in _ida_typeinf:
_ida_typeinf.udm_t_swigregister(udm_t)
class udtmembervec_t(udtmembervec_template_t):
    r"""
    Proxy of C++ udtmembervec_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> udtmembervec_t
        """
        _ida_typeinf.udtmembervec_t_swiginit(self, _ida_typeinf.new_udtmembervec_t())
    __swig_destroy__ = _ida_typeinf.delete_udtmembervec_t

# Register udtmembervec_t in _ida_typeinf:
_ida_typeinf.udtmembervec_t_swigregister(udtmembervec_t)
class udt_type_data_t(udtmembervec_t):
    r"""
    Proxy of C++ udt_type_data_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    total_size: "size_t" = property(_ida_typeinf.udt_type_data_t_total_size_get, _ida_typeinf.udt_type_data_t_total_size_set, doc=r"""total_size""")
    r"""
    total structure size in bytes
    """
    unpadded_size: "size_t" = property(_ida_typeinf.udt_type_data_t_unpadded_size_get, _ida_typeinf.udt_type_data_t_unpadded_size_set, doc=r"""unpadded_size""")
    r"""
    unpadded structure size in bytes
    """
    effalign: "uint32" = property(_ida_typeinf.udt_type_data_t_effalign_get, _ida_typeinf.udt_type_data_t_effalign_set, doc=r"""effalign""")
    r"""
    effective structure alignment (in bytes)
    """
    taudt_bits: "uint32" = property(_ida_typeinf.udt_type_data_t_taudt_bits_get, _ida_typeinf.udt_type_data_t_taudt_bits_set, doc=r"""taudt_bits""")
    r"""
    TA... and TAUDT... bits.
    """
    version: "uchar" = property(_ida_typeinf.udt_type_data_t_version_get, _ida_typeinf.udt_type_data_t_version_set, doc=r"""version""")
    r"""
    version of udt_type_data_t
    """
    sda: "uchar" = property(_ida_typeinf.udt_type_data_t_sda_get, _ida_typeinf.udt_type_data_t_sda_set, doc=r"""sda""")
    r"""
    declared structure alignment (shift amount+1). 0 - unspecified
    """
    pack: "uchar" = property(_ida_typeinf.udt_type_data_t_pack_get, _ida_typeinf.udt_type_data_t_pack_set, doc=r"""pack""")
    r"""
    #pragma pack() alignment (shift amount)
    """
    is_union: "bool" = property(_ida_typeinf.udt_type_data_t_is_union_get, _ida_typeinf.udt_type_data_t_is_union_set, doc=r"""is_union""")
    r"""
    is union or struct?
    """

    def swap(self, r: "udt_type_data_t") -> "void":
        r"""
        swap(self, r)

        @param r: udt_type_data_t &
        """
        return _ida_typeinf.udt_type_data_t_swap(self, r)

    def is_unaligned(self) -> "bool":
        r"""
        is_unaligned(self) -> bool
        """
        return _ida_typeinf.udt_type_data_t_is_unaligned(self)

    def is_msstruct(self) -> "bool":
        r"""
        is_msstruct(self) -> bool
        """
        return _ida_typeinf.udt_type_data_t_is_msstruct(self)

    def is_cppobj(self) -> "bool":
        r"""
        is_cppobj(self) -> bool
        """
        return _ida_typeinf.udt_type_data_t_is_cppobj(self)

    def is_vftable(self) -> "bool":
        r"""
        is_vftable(self) -> bool
        """
        return _ida_typeinf.udt_type_data_t_is_vftable(self)

    def is_fixed(self) -> "bool":
        r"""
        is_fixed(self) -> bool
        """
        return _ida_typeinf.udt_type_data_t_is_fixed(self)

    def set_vftable(self, on: "bool"=True) -> "void":
        r"""
        set_vftable(self, on=True)

        @param on: bool
        """
        return _ida_typeinf.udt_type_data_t_set_vftable(self, on)

    def set_fixed(self, on: "bool"=True) -> "void":
        r"""
        set_fixed(self, on=True)

        @param on: bool
        """
        return _ida_typeinf.udt_type_data_t_set_fixed(self, on)

    def is_last_baseclass(self, idx: "size_t") -> "bool":
        r"""
        is_last_baseclass(self, idx) -> bool

        @param idx: size_t
        """
        return _ida_typeinf.udt_type_data_t_is_last_baseclass(self, idx)

    def find_member(self, *args) -> "ssize_t":
        r"""
        find_member(self, pattern_udm, strmem_flags) -> ssize_t

        @param pattern_udm: udm_t *
        @param strmem_flags: int

        find_member(self, name) -> ssize_t

        @param name: char const *

        find_member(self, bit_offset) -> ssize_t

        @param bit_offset: uint64
        """
        return _ida_typeinf.udt_type_data_t_find_member(self, *args)

    def get_best_fit_member(self, disp: "asize_t") -> "ssize_t":
        r"""
        get_best_fit_member(self, disp) -> ssize_t
        Get member that is most likely referenced by the specified offset. Useful for
        offsets > sizeof(struct).

        @param disp: (C++: asize_t)
        """
        return _ida_typeinf.udt_type_data_t_get_best_fit_member(self, disp)
    __swig_destroy__ = _ida_typeinf.delete_udt_type_data_t

    def __init__(self):
        r"""
        __init__(self) -> udt_type_data_t
        """
        _ida_typeinf.udt_type_data_t_swiginit(self, _ida_typeinf.new_udt_type_data_t())

# Register udt_type_data_t in _ida_typeinf:
_ida_typeinf.udt_type_data_t_swigregister(udt_type_data_t)
STRUC_SEPARATOR = _ida_typeinf.STRUC_SEPARATOR
r"""
structname.fieldname
"""

VTBL_SUFFIX = _ida_typeinf.VTBL_SUFFIX

VTBL_MEMNAME = _ida_typeinf.VTBL_MEMNAME


def stroff_as_size(plen: "int", tif: "tinfo_t", value: "asize_t") -> "bool":
    r"""
    stroff_as_size(plen, tif, value) -> bool
    Should display a structure offset expression as the structure size?

    @param plen: (C++: int)
    @param tif: (C++: const tinfo_t &) tinfo_t const &
    @param value: (C++: asize_t)
    """
    return _ida_typeinf.stroff_as_size(plen, tif, value)
class udm_visitor_t(object):
    r"""
    Proxy of C++ udm_visitor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def visit_udm(self, tid: "tid_t", tif: "tinfo_t", udt: "udt_type_data_t", idx: "ssize_t") -> "int":
        r"""
        visit_udm(self, tid, tif, udt, idx) -> int

        @param tid: (C++: tid_t) udt tid
        @param tif: (C++: const tinfo_t *) udt type info (may be nullptr for corrupted idbs)
        @param udt: (C++: const udt_type_data_t *) udt type data (may be nullptr for corrupted idbs)
        @param idx: (C++: ssize_t) the index of udt the member (may be -1 if udm was not found)
        """
        return _ida_typeinf.udm_visitor_t_visit_udm(self, tid, tif, udt, idx)
    __swig_destroy__ = _ida_typeinf.delete_udm_visitor_t

    def __init__(self):
        r"""
        __init__(self) -> udm_visitor_t

        @param self: PyObject *
        """
        if self.__class__ == udm_visitor_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.udm_visitor_t_swiginit(self, _ida_typeinf.new_udm_visitor_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_udm_visitor_t(self)
        return weakref.proxy(self)

# Register udm_visitor_t in _ida_typeinf:
_ida_typeinf.udm_visitor_t_swigregister(udm_visitor_t)

def visit_stroff_udms(sfv: "udm_visitor_t", path: "tid_t const *", disp: "adiff_t *", appzero: "bool") -> "adiff_t *":
    r"""
    visit_stroff_udms(sfv, path, disp, appzero) -> int
    Visit structure fields in a stroff expression or in a reference to a struct data
    variable. This function can be used to enumerate all components of an expression
    like 'a.b.c'.

    @param sfv: (C++: udm_visitor_t &) visitor object
    @param path: (C++: const tid_t *) struct path (path[0] contains the initial struct id)
    @param disp: (C++: adiff_t *) offset into structure
    @param appzero: (C++: bool) should visit field at offset zero?
    @return: visitor result
    """
    return _ida_typeinf.visit_stroff_udms(sfv, path, disp, appzero)
class bitfield_type_data_t(object):
    r"""
    Proxy of C++ bitfield_type_data_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    nbytes: "uchar" = property(_ida_typeinf.bitfield_type_data_t_nbytes_get, _ida_typeinf.bitfield_type_data_t_nbytes_set, doc=r"""nbytes""")
    r"""
    enclosing type size (1,2,4,8 bytes)
    """
    width: "uchar" = property(_ida_typeinf.bitfield_type_data_t_width_get, _ida_typeinf.bitfield_type_data_t_width_set, doc=r"""width""")
    r"""
    number of bits
    """
    is_unsigned: "bool" = property(_ida_typeinf.bitfield_type_data_t_is_unsigned_get, _ida_typeinf.bitfield_type_data_t_is_unsigned_set, doc=r"""is_unsigned""")
    r"""
    is bitfield unsigned?
    """

    def __init__(self, _nbytes: "uchar"=0, _width: "uchar"=0, _is_unsigned: "bool"=False):
        r"""
        __init__(self, _nbytes=0, _width=0, _is_unsigned=False) -> bitfield_type_data_t

        @param _nbytes: uchar
        @param _width: uchar
        @param _is_unsigned: bool
        """
        _ida_typeinf.bitfield_type_data_t_swiginit(self, _ida_typeinf.new_bitfield_type_data_t(_nbytes, _width, _is_unsigned))

    def __eq__(self, r: "bitfield_type_data_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: bitfield_type_data_t const &
        """
        return _ida_typeinf.bitfield_type_data_t___eq__(self, r)

    def __ne__(self, r: "bitfield_type_data_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: bitfield_type_data_t const &
        """
        return _ida_typeinf.bitfield_type_data_t___ne__(self, r)

    def __lt__(self, r: "bitfield_type_data_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: bitfield_type_data_t const &
        """
        return _ida_typeinf.bitfield_type_data_t___lt__(self, r)

    def __gt__(self, r: "bitfield_type_data_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: bitfield_type_data_t const &
        """
        return _ida_typeinf.bitfield_type_data_t___gt__(self, r)

    def __le__(self, r: "bitfield_type_data_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: bitfield_type_data_t const &
        """
        return _ida_typeinf.bitfield_type_data_t___le__(self, r)

    def __ge__(self, r: "bitfield_type_data_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: bitfield_type_data_t const &
        """
        return _ida_typeinf.bitfield_type_data_t___ge__(self, r)

    def compare(self, r: "bitfield_type_data_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: bitfield_type_data_t const &
        """
        return _ida_typeinf.bitfield_type_data_t_compare(self, r)

    def swap(self, r: "bitfield_type_data_t") -> "void":
        r"""
        swap(self, r)

        @param r: bitfield_type_data_t &
        """
        return _ida_typeinf.bitfield_type_data_t_swap(self, r)

    def is_valid_bitfield(self) -> "bool":
        r"""
        is_valid_bitfield(self) -> bool
        """
        return _ida_typeinf.bitfield_type_data_t_is_valid_bitfield(self)
    __swig_destroy__ = _ida_typeinf.delete_bitfield_type_data_t

# Register bitfield_type_data_t in _ida_typeinf:
_ida_typeinf.bitfield_type_data_t_swigregister(bitfield_type_data_t)
TPOS_LNNUM = _ida_typeinf.TPOS_LNNUM

TPOS_REGCMT = _ida_typeinf.TPOS_REGCMT


def is_one_bit_mask(mask: "uval_t") -> "bool":
    r"""
    is_one_bit_mask(mask) -> bool
    Is bitmask one bit?

    @param mask: (C++: uval_t)
    """
    return _ida_typeinf.is_one_bit_mask(mask)

def inf_pack_stkargs(*args) -> "bool":
    r"""
    inf_pack_stkargs() -> bool
    inf_pack_stkargs(cc) -> bool

    @param cc: cm_t
    """
    return _ida_typeinf.inf_pack_stkargs(*args)

def inf_big_arg_align(*args) -> "bool":
    r"""
    inf_big_arg_align() -> bool
    inf_big_arg_align(cc) -> bool

    @param cc: cm_t
    """
    return _ida_typeinf.inf_big_arg_align(*args)

def inf_huge_arg_align(*args) -> "bool":
    r"""
    inf_huge_arg_align() -> bool
    inf_huge_arg_align(cc) -> bool

    @param cc: cm_t
    """
    return _ida_typeinf.inf_huge_arg_align(*args)
class type_mods_t(object):
    r"""
    Proxy of C++ type_mods_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    type: "tinfo_t" = property(_ida_typeinf.type_mods_t_type_get, _ida_typeinf.type_mods_t_type_set, doc=r"""type""")
    r"""
    current type
    """
    name: "qstring" = property(_ida_typeinf.type_mods_t_name_get, _ida_typeinf.type_mods_t_name_set, doc=r"""name""")
    r"""
    current type name
    """
    cmt: "qstring" = property(_ida_typeinf.type_mods_t_cmt_get, _ida_typeinf.type_mods_t_cmt_set, doc=r"""cmt""")
    r"""
    comment for current type
    """
    flags: "int" = property(_ida_typeinf.type_mods_t_flags_get, _ida_typeinf.type_mods_t_flags_set, doc=r"""flags""")
    r"""
    Type modification bits
    """

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_typeinf.type_mods_t_clear(self)

    def set_new_type(self, t: "tinfo_t") -> "void":
        r"""
        set_new_type(self, t)
        The visit_type() function may optionally save the modified type info. Use the
        following functions for that. The new name and comment will be applied only if
        the current tinfo element has storage for them.

        @param t: (C++: const tinfo_t &) tinfo_t const &
        """
        return _ida_typeinf.type_mods_t_set_new_type(self, t)

    def set_new_name(self, n: "qstring const &") -> "void":
        r"""
        set_new_name(self, n)

        @param n: qstring const &
        """
        return _ida_typeinf.type_mods_t_set_new_name(self, n)

    def set_new_cmt(self, c: "qstring const &", rptcmt: "bool") -> "void":
        r"""
        set_new_cmt(self, c, rptcmt)

        @param c: qstring const &
        @param rptcmt: bool
        """
        return _ida_typeinf.type_mods_t_set_new_cmt(self, c, rptcmt)

    def has_type(self) -> "bool":
        r"""
        has_type(self) -> bool
        """
        return _ida_typeinf.type_mods_t_has_type(self)

    def has_name(self) -> "bool":
        r"""
        has_name(self) -> bool
        """
        return _ida_typeinf.type_mods_t_has_name(self)

    def has_cmt(self) -> "bool":
        r"""
        has_cmt(self) -> bool
        """
        return _ida_typeinf.type_mods_t_has_cmt(self)

    def is_rptcmt(self) -> "bool":
        r"""
        is_rptcmt(self) -> bool
        """
        return _ida_typeinf.type_mods_t_is_rptcmt(self)

    def has_info(self) -> "bool":
        r"""
        has_info(self) -> bool
        """
        return _ida_typeinf.type_mods_t_has_info(self)

    def __init__(self):
        r"""
        __init__(self) -> type_mods_t
        """
        _ida_typeinf.type_mods_t_swiginit(self, _ida_typeinf.new_type_mods_t())
    __swig_destroy__ = _ida_typeinf.delete_type_mods_t

# Register type_mods_t in _ida_typeinf:
_ida_typeinf.type_mods_t_swigregister(type_mods_t)
TVIS_TYPE = _ida_typeinf.TVIS_TYPE
r"""
new type info is present
"""

TVIS_NAME = _ida_typeinf.TVIS_NAME
r"""
new name is present (only for funcargs and udt members)
"""

TVIS_CMT = _ida_typeinf.TVIS_CMT
r"""
new comment is present (only for udt members)
"""

TVIS_RPTCMT = _ida_typeinf.TVIS_RPTCMT
r"""
the new comment is repeatable
"""


class tinfo_visitor_t(object):
    r"""
    Proxy of C++ tinfo_visitor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    state: "int" = property(_ida_typeinf.tinfo_visitor_t_state_get, _ida_typeinf.tinfo_visitor_t_state_set, doc=r"""state""")
    r"""
    tinfo visitor states
    """

    def __init__(self, s: "int"=0):
        r"""
        __init__(self, s=0) -> tinfo_visitor_t

        @param s: int
        """
        if self.__class__ == tinfo_visitor_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.tinfo_visitor_t_swiginit(self, _ida_typeinf.new_tinfo_visitor_t(_self, s))
    __swig_destroy__ = _ida_typeinf.delete_tinfo_visitor_t

    def visit_type(self, out: "type_mods_t", tif: "tinfo_t", name: "char const *", cmt: "char const *") -> "int":
        r"""
        visit_type(self, out, tif, name, cmt) -> int
        Visit a subtype. this function must be implemented in the derived class. it may
        optionally fill out with the new type info. this can be used to modify types (in
        this case the 'out' argument of apply_to() may not be nullptr) return 0 to
        continue the traversal. return !=0 to stop the traversal.

        @param out: (C++: type_mods_t *)
        @param tif: (C++: const tinfo_t &) tinfo_t const &
        @param name: (C++: const char *) char const *
        @param cmt: (C++: const char *) char const *
        """
        return _ida_typeinf.tinfo_visitor_t_visit_type(self, out, tif, name, cmt)

    def prune_now(self) -> "void":
        r"""
        prune_now(self)
        To refuse to visit children of the current type, use this:
        """
        return _ida_typeinf.tinfo_visitor_t_prune_now(self)

    def apply_to(self, tif: "tinfo_t", out: "type_mods_t"=None, name: "char const *"=None, cmt: "char const *"=None) -> "int":
        r"""
        apply_to(self, tif, out=None, name=None, cmt=None) -> int
        Call this function to initiate the traversal.

        @param tif: (C++: const tinfo_t &) tinfo_t const &
        @param out: (C++: type_mods_t *)
        @param name: (C++: const char *) char const *
        @param cmt: (C++: const char *) char const *
        """
        return _ida_typeinf.tinfo_visitor_t_apply_to(self, tif, out, name, cmt)
    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_tinfo_visitor_t(self)
        return weakref.proxy(self)

# Register tinfo_visitor_t in _ida_typeinf:
_ida_typeinf.tinfo_visitor_t_swigregister(tinfo_visitor_t)
TVST_PRUNE = _ida_typeinf.TVST_PRUNE
r"""
don't visit children of current type
"""

TVST_DEF = _ida_typeinf.TVST_DEF
r"""
visit type definition (meaningful for typerefs)
"""

TVST_LEVEL = _ida_typeinf.TVST_LEVEL


class regobj_t(object):
    r"""
    Proxy of C++ regobj_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    regidx: "int" = property(_ida_typeinf.regobj_t_regidx_get, _ida_typeinf.regobj_t_regidx_set, doc=r"""regidx""")
    r"""
    index into dbg->registers
    """
    relocate: "int" = property(_ida_typeinf.regobj_t_relocate_get, _ida_typeinf.regobj_t_relocate_set, doc=r"""relocate""")
    r"""
    0-plain num, 1-must relocate
    """
    value: "bytevec_t" = property(_ida_typeinf.regobj_t_value_get, _ida_typeinf.regobj_t_value_set, doc=r"""value""")

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_typeinf.regobj_t_size(self)

    def __init__(self):
        r"""
        __init__(self) -> regobj_t
        """
        _ida_typeinf.regobj_t_swiginit(self, _ida_typeinf.new_regobj_t())
    __swig_destroy__ = _ida_typeinf.delete_regobj_t

# Register regobj_t in _ida_typeinf:
_ida_typeinf.regobj_t_swigregister(regobj_t)
class regobjs_t(regobjvec_t):
    r"""
    Proxy of C++ regobjs_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> regobjs_t
        """
        _ida_typeinf.regobjs_t_swiginit(self, _ida_typeinf.new_regobjs_t())
    __swig_destroy__ = _ida_typeinf.delete_regobjs_t

# Register regobjs_t in _ida_typeinf:
_ida_typeinf.regobjs_t_swigregister(regobjs_t)

def unpack_idcobj_from_idb(obj: "idc_value_t *", tif: "tinfo_t", ea: "ea_t", off0: "bytevec_t const *", pio_flags: "int"=0) -> "error_t":
    r"""
    unpack_idcobj_from_idb(obj, tif, ea, off0, pio_flags=0) -> error_t
    Collection of register objects.

    Read a typed idc object from the database

    @param obj: (C++: idc_value_t *)
    @param tif: (C++: const tinfo_t &) tinfo_t const &
    @param ea: (C++: ea_t)
    @param off0: (C++: const bytevec_t *) bytevec_t const *
    @param pio_flags: (C++: int)
    """
    return _ida_typeinf.unpack_idcobj_from_idb(obj, tif, ea, off0, pio_flags)
PIO_NOATTR_FAIL = _ida_typeinf.PIO_NOATTR_FAIL
r"""
missing attributes are not ok
"""

PIO_IGNORE_PTRS = _ida_typeinf.PIO_IGNORE_PTRS
r"""
do not follow pointers
"""


def unpack_idcobj_from_bv(obj: "idc_value_t *", tif: "tinfo_t", bytes: "bytevec_t const &", pio_flags: "int"=0) -> "error_t":
    r"""
    unpack_idcobj_from_bv(obj, tif, bytes, pio_flags=0) -> error_t
    Read a typed idc object from the byte vector.

    @param obj: (C++: idc_value_t *)
    @param tif: (C++: const tinfo_t &) tinfo_t const &
    @param bytes: (C++: const bytevec_t &) bytevec_t const &
    @param pio_flags: (C++: int)
    """
    return _ida_typeinf.unpack_idcobj_from_bv(obj, tif, bytes, pio_flags)

def pack_idcobj_to_idb(obj: "idc_value_t const *", tif: "tinfo_t", ea: "ea_t", pio_flags: "int"=0) -> "error_t":
    r"""
    pack_idcobj_to_idb(obj, tif, ea, pio_flags=0) -> error_t
    Write a typed idc object to the database.

    @param obj: (C++: const idc_value_t *) idc_value_t const *
    @param tif: (C++: const tinfo_t &) tinfo_t const &
    @param ea: (C++: ea_t)
    @param pio_flags: (C++: int)
    """
    return _ida_typeinf.pack_idcobj_to_idb(obj, tif, ea, pio_flags)

def pack_idcobj_to_bv(obj: "idc_value_t const *", tif: "tinfo_t", bytes: "relobj_t", objoff: "void *", pio_flags: "int"=0) -> "error_t":
    r"""
    pack_idcobj_to_bv(obj, tif, bytes, objoff, pio_flags=0) -> error_t
    Write a typed idc object to the byte vector. Byte vector may be non-empty, this
    function will append data to it

    @param obj: (C++: const idc_value_t *) idc_value_t const *
    @param tif: (C++: const tinfo_t &) tinfo_t const &
    @param bytes: (C++: relobj_t *)
    @param objoff: (C++: void *)
    @param pio_flags: (C++: int)
    """
    return _ida_typeinf.pack_idcobj_to_bv(obj, tif, bytes, objoff, pio_flags)

def apply_tinfo_to_stkarg(insn: "insn_t const &", x: "op_t const &", v: "uval_t", tif: "tinfo_t", name: "char const *") -> "bool":
    r"""
    apply_tinfo_to_stkarg(insn, x, v, tif, name) -> bool
    Helper function for the processor modules. to be called from
    processor_t::use_stkarg_type

    @param insn: (C++: const insn_t &) an ida_ua.insn_t, or an address (C++: const insn_t &)
    @param x: (C++: const op_t &) op_t const &
    @param v: (C++: uval_t)
    @param tif: (C++: const tinfo_t &) tinfo_t const &
    @param name: (C++: const char *) char const *
    """
    return _ida_typeinf.apply_tinfo_to_stkarg(insn, x, v, tif, name)
class argtinfo_helper_t(object):
    r"""
    Proxy of C++ argtinfo_helper_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    reserved: "size_t" = property(_ida_typeinf.argtinfo_helper_t_reserved_get, _ida_typeinf.argtinfo_helper_t_reserved_set, doc=r"""reserved""")
    __swig_destroy__ = _ida_typeinf.delete_argtinfo_helper_t

    def set_op_tinfo(self, insn: "insn_t const &", x: "op_t const &", tif: "tinfo_t", name: "char const *") -> "bool":
        r"""
        set_op_tinfo(self, insn, x, tif, name) -> bool
        Set the operand type as specified.

        @param insn: (C++: const insn_t &) an ida_ua.insn_t, or an address (C++: const insn_t &)
        @param x: (C++: const op_t &) op_t const &
        @param tif: (C++: const tinfo_t &) tinfo_t const &
        @param name: (C++: const char *) char const *
        """
        return _ida_typeinf.argtinfo_helper_t_set_op_tinfo(self, insn, x, tif, name)

    def is_stkarg_load(self, insn: "insn_t const &", src: "int *", dst: "int *") -> "bool":
        r"""
        is_stkarg_load(self, insn, src, dst) -> bool
        Is the current insn a stkarg load?. if yes:
        * src: index of the source operand in insn_t::ops
        * dst: index of the destination operand in insn_t::ops insn_t::ops[dst].addr is
        expected to have the stack offset

        @param insn: (C++: const insn_t &) an ida_ua.insn_t, or an address (C++: const insn_t &)
        @param src: (C++: int *)
        @param dst: (C++: int *)
        """
        return _ida_typeinf.argtinfo_helper_t_is_stkarg_load(self, insn, src, dst)

    def has_delay_slot(self, arg0: "ea_t") -> "bool":
        r"""
        has_delay_slot(self, arg0) -> bool
        The call instruction with a delay slot?.

        @param arg0: ea_t
        """
        return _ida_typeinf.argtinfo_helper_t_has_delay_slot(self, arg0)

    def use_arg_tinfos(self, caller: "ea_t", fti: "func_type_data_t", rargs: "funcargvec_t") -> "void":
        r"""
        use_arg_tinfos(self, caller, fti, rargs)
        This function is to be called by the processor module in response to
        ev_use_arg_types.

        @param caller: (C++: ea_t)
        @param fti: (C++: func_type_data_t *)
        @param rargs: (C++: funcargvec_t *)
        """
        return _ida_typeinf.argtinfo_helper_t_use_arg_tinfos(self, caller, fti, rargs)

    def __init__(self):
        r"""
        __init__(self) -> argtinfo_helper_t

        @param self: PyObject *
        """
        if self.__class__ == argtinfo_helper_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.argtinfo_helper_t_swiginit(self, _ida_typeinf.new_argtinfo_helper_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_argtinfo_helper_t(self)
        return weakref.proxy(self)

# Register argtinfo_helper_t in _ida_typeinf:
_ida_typeinf.argtinfo_helper_t_swigregister(argtinfo_helper_t)

def gen_use_arg_tinfos(_this: "argtinfo_helper_t", caller: "ea_t", fti: "func_type_data_t", rargs: "funcargvec_t") -> "void":
    r"""
    gen_use_arg_tinfos(_this, caller, fti, rargs)
    Do not call this function directly, use argtinfo_helper_t.

    @param _this: (C++: struct argtinfo_helper_t *) argtinfo_helper_t *
    @param caller: (C++: ea_t)
    @param fti: (C++: func_type_data_t *)
    @param rargs: (C++: funcargvec_t *)
    """
    return _ida_typeinf.gen_use_arg_tinfos(_this, caller, fti, rargs)

def func_has_stkframe_hole(ea: "ea_t", fti: "func_type_data_t") -> "bool":
    r"""
    func_has_stkframe_hole(ea, fti) -> bool
    Looks for a hole at the beginning of the stack arguments. Will make use of the
    IDB's func_t function at that place (if present) to help determine the presence
    of such a hole.

    @param ea: (C++: ea_t)
    @param fti: (C++: const func_type_data_t &) func_type_data_t const &
    """
    return _ida_typeinf.func_has_stkframe_hole(ea, fti)
class lowertype_helper_t(object):
    r"""
    Proxy of C++ lowertype_helper_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined - class is abstract")
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_typeinf.delete_lowertype_helper_t

    def func_has_stkframe_hole(self, candidate: "tinfo_t", candidate_data: "func_type_data_t") -> "bool":
        r"""
        func_has_stkframe_hole(self, candidate, candidate_data) -> bool

        @param candidate: tinfo_t const &
        @param candidate_data: func_type_data_t const &
        """
        return _ida_typeinf.lowertype_helper_t_func_has_stkframe_hole(self, candidate, candidate_data)

    def get_func_purged_bytes(self, candidate: "tinfo_t", candidate_data: "func_type_data_t") -> "int":
        r"""
        get_func_purged_bytes(self, candidate, candidate_data) -> int

        @param candidate: tinfo_t const &
        @param candidate_data: func_type_data_t const &
        """
        return _ida_typeinf.lowertype_helper_t_get_func_purged_bytes(self, candidate, candidate_data)

# Register lowertype_helper_t in _ida_typeinf:
_ida_typeinf.lowertype_helper_t_swigregister(lowertype_helper_t)
class ida_lowertype_helper_t(lowertype_helper_t):
    r"""
    Proxy of C++ ida_lowertype_helper_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, _tif: "tinfo_t", _ea: "ea_t", _pb: "int"):
        r"""
        __init__(self, _tif, _ea, _pb) -> ida_lowertype_helper_t

        @param _tif: tinfo_t const &
        @param _ea: ea_t
        @param _pb: int
        """
        _ida_typeinf.ida_lowertype_helper_t_swiginit(self, _ida_typeinf.new_ida_lowertype_helper_t(_tif, _ea, _pb))

    def func_has_stkframe_hole(self, candidate: "tinfo_t", candidate_data: "func_type_data_t") -> "bool":
        r"""
        func_has_stkframe_hole(self, candidate, candidate_data) -> bool

        @param candidate: tinfo_t const &
        @param candidate_data: func_type_data_t const &
        """
        return _ida_typeinf.ida_lowertype_helper_t_func_has_stkframe_hole(self, candidate, candidate_data)

    def get_func_purged_bytes(self, candidate: "tinfo_t", arg3: "func_type_data_t") -> "int":
        r"""
        get_func_purged_bytes(self, candidate, arg3) -> int

        @param candidate: tinfo_t const &
        @param arg3: func_type_data_t const &
        """
        return _ida_typeinf.ida_lowertype_helper_t_get_func_purged_bytes(self, candidate, arg3)
    __swig_destroy__ = _ida_typeinf.delete_ida_lowertype_helper_t

# Register ida_lowertype_helper_t in _ida_typeinf:
_ida_typeinf.ida_lowertype_helper_t_swigregister(ida_lowertype_helper_t)

def lower_type(til: "til_t", tif: "tinfo_t", name: "char const *"=None, _helper: "lowertype_helper_t"=None) -> "int":
    r"""
    lower_type(til, tif, name=None, _helper=None) -> int
    Lower type. Inspect the type and lower all function subtypes using
    lower_func_type().
    We call the prototypes usually encountered in source files "high level"
    They may have implicit arguments, array arguments, big structure retvals, etc
    We introduce explicit arguments (i.e. 'this' pointer) and call the result
    "low level prototype". See FTI_HIGH.

    In order to improve heuristics for recognition of big structure retvals,
    it is recommended to pass a helper that will be used to make decisions.
    That helper will be used only for lowering 'tif', and not for the children
    types walked through by recursion.
    @retval 1: removed FTI_HIGH,
    @retval 2: made substantial changes
    @retval -1: failure

    @param til: (C++: til_t *)
    @param tif: (C++: tinfo_t *)
    @param name: (C++: const char *) char const *
    @param _helper: (C++: lowertype_helper_t *)
    """
    return _ida_typeinf.lower_type(til, tif, name, _helper)

def replace_ordinal_typerefs(til: "til_t", tif: "tinfo_t") -> "int":
    r"""
    replace_ordinal_typerefs(til, tif) -> int
    Replace references to ordinal types by name references. This function 'unties'
    the type from the current local type library and makes it easier to export it.

    @param til: (C++: til_t *) type library to use. may be nullptr.
    @param tif: (C++: tinfo_t *) type to modify (in/out)
    @retval number: of replaced subtypes, -1 on failure
    """
    return _ida_typeinf.replace_ordinal_typerefs(til, tif)
UTP_ENUM = _ida_typeinf.UTP_ENUM

UTP_STRUCT = _ida_typeinf.UTP_STRUCT


def begin_type_updating(utp: "update_type_t") -> "void":
    r"""
    begin_type_updating(utp)
    Mark the beginning of a large update operation on the types. Can be used with
    add_enum_member(), add_struc_member, etc... Also see end_type_updating()

    @param utp: (C++: update_type_t) enum update_type_t
    """
    return _ida_typeinf.begin_type_updating(utp)

def end_type_updating(utp: "update_type_t") -> "void":
    r"""
    end_type_updating(utp)
    Mark the end of a large update operation on the types (see
    begin_type_updating())

    @param utp: (C++: update_type_t) enum update_type_t
    """
    return _ida_typeinf.end_type_updating(utp)

def get_named_type_tid(name: "char const *") -> "tid_t":
    r"""
    get_named_type_tid(name) -> tid_t
    Get named local type TID

    @param name: (C++: const char *) type name
    @return: TID or BADADDR
    """
    return _ida_typeinf.get_named_type_tid(name)

def get_tid_name(tid: "tid_t") -> "qstring *":
    r"""
    get_tid_name(tid) -> str
    Get a type name for the specified TID

    @param tid: (C++: tid_t) type TID
    @return: true if there is type with TID
    @note: this function is the inverse to get_named_type_tid
    """
    return _ida_typeinf.get_tid_name(tid)

def get_tid_ordinal(tid: "tid_t") -> "uint32":
    r"""
    get_tid_ordinal(tid) -> uint32
    Get type ordinal number for TID

    @param tid: (C++: tid_t) type/enum constant/udt member TID
    @return: type ordinal number or 0
    """
    return _ida_typeinf.get_tid_ordinal(tid)

def get_udm_by_fullname(udm: "udm_t", fullname: "char const *") -> "ssize_t":
    r"""
    get_udm_by_fullname(udm, fullname) -> ssize_t
    Get udt member by full name

    @param udm: (C++: udm_t *) member, can be NULL
    @param fullname: (C++: const char *) udt member name in format <udt name>.<member name>
    @return: member index into udt_type_data_t or -1
    """
    return _ida_typeinf.get_udm_by_fullname(udm, fullname)

def get_idainfo_by_udm(*args) -> "bool":
    r"""
    get_idainfo_by_udm(flags, ti, udm, refinfo_ea=BADADDR) -> bool
    Calculate IDA info from udt member

    @param flags: (C++: flags64_t *) [out]: flags (see bytes.hpp) for udt member
    @param ti: (C++: opinfo_t *) [out]: additional representation information, see set_opinfo()
    @param udm: (C++: const udm_t &) udt member
    @param refinfo_ea: (C++: ea_t) if specified will be used to adjust the refinfo_t data
    @note: any output argument may be nullptr
    """
    return _ida_typeinf.get_idainfo_by_udm(*args)

def create_enum_type(enum_name: "char const *", ei: "enum_type_data_t", enum_width: "int", sign: "type_sign_t", convert_to_bitmask: "bool", enum_cmt: "char const *"=None) -> "tid_t":
    r"""
    create_enum_type(enum_name, ei, enum_width, sign, convert_to_bitmask, enum_cmt=None) -> tid_t
    Create type enum

    @param enum_name: (C++: const char *) type name
    @param ei: (C++: enum_type_data_t &) enum type data
    @param enum_width: (C++: int) the width of an enum element allowed values: 0
                       (unspecified),1,2,4,8,16,32,64
    @param sign: (C++: type_sign_t) enum sign
    @param convert_to_bitmask: (C++: bool) try convert enum to bitmask enum
    @param enum_cmt: (C++: const char *) enum type comment
    @return: enum TID
    """
    return _ida_typeinf.create_enum_type(enum_name, ei, enum_width, sign, convert_to_bitmask, enum_cmt)
class valstr_t(object):
    r"""
    Proxy of C++ valstr_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    oneline: "qstring" = property(_ida_typeinf.valstr_t_oneline_get, _ida_typeinf.valstr_t_oneline_set, doc=r"""oneline""")
    r"""
    result if printed on one line in UTF-8 encoding
    """
    length: "size_t" = property(_ida_typeinf.valstr_t_length_get, _ida_typeinf.valstr_t_length_set, doc=r"""length""")
    r"""
    length if printed on one line
    """
    members: "valstrs_t *" = property(_ida_typeinf.valstr_t_members_get, _ida_typeinf.valstr_t_members_set, doc=r"""members""")
    r"""
    strings for members, each member separately
    """
    info: "valinfo_t *" = property(_ida_typeinf.valstr_t_info_get, _ida_typeinf.valstr_t_info_set, doc=r"""info""")
    r"""
    additional info
    """
    props: "int" = property(_ida_typeinf.valstr_t_props_get, _ida_typeinf.valstr_t_props_set, doc=r"""props""")
    r"""
    temporary properties, used internally
    """

    def __init__(self):
        r"""
        __init__(self) -> valstr_t
        """
        _ida_typeinf.valstr_t_swiginit(self, _ida_typeinf.new_valstr_t())
    __swig_destroy__ = _ida_typeinf.delete_valstr_t

# Register valstr_t in _ida_typeinf:
_ida_typeinf.valstr_t_swigregister(valstr_t)
VALSTR_OPEN = _ida_typeinf.VALSTR_OPEN
r"""
printed opening curly brace '{'
"""


class valstrs_t(valstrvec_t):
    r"""
    Proxy of C++ valstrs_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> valstrs_t
        """
        _ida_typeinf.valstrs_t_swiginit(self, _ida_typeinf.new_valstrs_t())
    __swig_destroy__ = _ida_typeinf.delete_valstrs_t

# Register valstrs_t in _ida_typeinf:
_ida_typeinf.valstrs_t_swigregister(valstrs_t)
class text_sink_t(object):
    r"""
    Proxy of C++ text_sink_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_typeinf.delete_text_sink_t

    def _print(self, str: "char const *") -> "int":
        r"""
        _print(self, str) -> int

        Parameters
        ----------
        str: char const *

        """
        return _ida_typeinf.text_sink_t__print(self, str)

    def __init__(self):
        r"""
        __init__(self) -> text_sink_t

        @param self: PyObject *
        """
        if self.__class__ == text_sink_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.text_sink_t_swiginit(self, _ida_typeinf.new_text_sink_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_text_sink_t(self)
        return weakref.proxy(self)

# Register text_sink_t in _ida_typeinf:
_ida_typeinf.text_sink_t_swigregister(text_sink_t)
PDF_INCL_DEPS = _ida_typeinf.PDF_INCL_DEPS
r"""
Include all type dependencies.
"""

PDF_DEF_FWD = _ida_typeinf.PDF_DEF_FWD
r"""
Allow forward declarations.
"""

PDF_DEF_BASE = _ida_typeinf.PDF_DEF_BASE
r"""
Include base types: __int8, __int16, etc..
"""

PDF_HEADER_CMT = _ida_typeinf.PDF_HEADER_CMT
r"""
Prepend output with a descriptive comment.
"""


def calc_number_of_children(loc: "argloc_t", tif: "tinfo_t", dont_deref_ptr: "bool"=False) -> "int":
    r"""
    calc_number_of_children(loc, tif, dont_deref_ptr=False) -> int
    Calculate max number of lines of a formatted c data, when expanded (PTV_EXPAND).

    @param loc: (C++: const argloc_t &) location of the data (ALOC_STATIC or ALOC_CUSTOM)
    @param tif: (C++: const tinfo_t &) type info
    @param dont_deref_ptr: (C++: bool) consider 'ea' as the ptr value
    @retval 0: data is not expandable
    @retval -1: error, see qerrno
    @retval else: the max number of lines
    """
    return _ida_typeinf.calc_number_of_children(loc, tif, dont_deref_ptr)

def get_enum_member_expr(tif: "tinfo_t", serial: "int", value: "uint64") -> "qstring *":
    r"""
    get_enum_member_expr(tif, serial, value) -> str
    Return a C expression that can be used to represent an enum member. If the value
    does not correspond to any single enum member, this function tries to find a
    bitwise combination of enum members that correspond to it. If more than half of
    value bits do not match any enum members, it fails.

    @param tif: (C++: const tinfo_t &) enumeration type
    @param serial: (C++: int) which enumeration member to use (0 means the first with the given
                   value)
    @param value: (C++: uint64) value to search in the enumeration type
    @return: success
    """
    return _ida_typeinf.get_enum_member_expr(tif, serial, value)
class til_symbol_t(object):
    r"""
    Proxy of C++ til_symbol_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    name: "char const *" = property(_ida_typeinf.til_symbol_t_name_get, _ida_typeinf.til_symbol_t_name_set, doc=r"""name""")
    r"""
    symbol name
    """
    til: "til_t const *" = property(_ida_typeinf.til_symbol_t_til_get, _ida_typeinf.til_symbol_t_til_set, doc=r"""til""")
    r"""
    pointer to til
    """

    def __init__(self, n: "char const *"=None, t: "til_t"=None):
        r"""
        __init__(self, n=None, t=None) -> til_symbol_t

        @param n: char const *
        @param t: til_t const *
        """
        _ida_typeinf.til_symbol_t_swiginit(self, _ida_typeinf.new_til_symbol_t(n, t))
    __swig_destroy__ = _ida_typeinf.delete_til_symbol_t

# Register til_symbol_t in _ida_typeinf:
_ida_typeinf.til_symbol_t_swigregister(til_symbol_t)
class predicate_t(object):
    r"""
    Proxy of C++ predicate_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def should_display(self, til: "til_t", name: "char const *", type: "type_t const *", fields: "p_list const *") -> "bool":
        r"""
        should_display(self, til, name, type, fields) -> bool

        @param til: til_t const *
        @param name: char const *
        @param type: type_t const *
        @param fields: p_list const *
        """
        return _ida_typeinf.predicate_t_should_display(self, til, name, type, fields)
    __swig_destroy__ = _ida_typeinf.delete_predicate_t

    def __init__(self):
        r"""
        __init__(self) -> predicate_t

        @param self: PyObject *
        """
        if self.__class__ == predicate_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.predicate_t_swiginit(self, _ida_typeinf.new_predicate_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_predicate_t(self)
        return weakref.proxy(self)

# Register predicate_t in _ida_typeinf:
_ida_typeinf.predicate_t_swigregister(predicate_t)

def choose_named_type(out_sym: "til_symbol_t", root_til: "til_t", title: "char const *", ntf_flags: "int", predicate: "predicate_t"=None) -> "bool":
    r"""
    choose_named_type(out_sym, root_til, title, ntf_flags, predicate=None) -> bool
    Choose a type from a type library.

    @param out_sym: (C++: til_symbol_t *) pointer to be filled with the chosen type
    @param root_til: (C++: const til_t *) pointer to starting til (the function will inspect the base
                     tils if allowed by flags)
    @param title: (C++: const char *) title of listbox to display
    @param ntf_flags: (C++: int) combination of Flags for named types
    @param predicate: (C++: predicate_t *) predicate to select types to display (maybe nullptr)
    @return: false if nothing is chosen, otherwise true
    """
    return _ida_typeinf.choose_named_type(out_sym, root_til, title, ntf_flags, predicate)

def choose_local_tinfo(ti: "til_t", title: "char const *", func: "local_tinfo_predicate_t *"=None, def_ord: "uint32"=0, ud: "void *"=None) -> "uint32":
    r"""
    choose_local_tinfo(ti, title, func=None, def_ord=0, ud=None) -> uint32
    Choose a type from the local type library.

    @param ti: (C++: const til_t *) pointer to til
    @param title: (C++: const char *) title of listbox to display
    @param func: (C++: local_tinfo_predicate_t *) predicate to select types to display (maybe nullptr)
    @param def_ord: (C++: uint32) ordinal to position cursor before choose
    @param ud: (C++: void *) user data
    @return: == 0 means nothing is chosen, otherwise an ordinal number
    """
    return _ida_typeinf.choose_local_tinfo(ti, title, func, def_ord, ud)

def choose_local_tinfo_and_delta(delta: "int32 *", ti: "til_t", title: "char const *", func: "local_tinfo_predicate_t *"=None, def_ord: "uint32"=0, ud: "void *"=None) -> "uint32":
    r"""
    choose_local_tinfo_and_delta(delta, ti, title, func=None, def_ord=0, ud=None) -> uint32
    Choose a type from the local type library and specify the pointer shift value.

    @param delta: (C++: int32 *) pointer shift value
    @param ti: (C++: const til_t *) pointer to til
    @param title: (C++: const char *) title of listbox to display
    @param func: (C++: local_tinfo_predicate_t *) predicate to select types to display (maybe nullptr)
    @param def_ord: (C++: uint32) ordinal to position cursor before choose
    @param ud: (C++: void *) user data
    @return: == 0 means nothing is chosen, otherwise an ordinal number
    """
    return _ida_typeinf.choose_local_tinfo_and_delta(delta, ti, title, func, def_ord, ud)
class til_type_ref_t(object):
    r"""
    Proxy of C++ til_type_ref_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    cb: "size_t" = property(_ida_typeinf.til_type_ref_t_cb_get, _ida_typeinf.til_type_ref_t_cb_set, doc=r"""cb""")
    tif: "tinfo_t" = property(_ida_typeinf.til_type_ref_t_tif_get, _ida_typeinf.til_type_ref_t_tif_set, doc=r"""tif""")
    cursor: "tif_cursor_t" = property(_ida_typeinf.til_type_ref_t_cursor_get, _ida_typeinf.til_type_ref_t_cursor_set, doc=r"""cursor""")
    ordinal: "uint32" = property(_ida_typeinf.til_type_ref_t_ordinal_get, _ida_typeinf.til_type_ref_t_ordinal_set, doc=r"""ordinal""")
    is_writable: "bool" = property(_ida_typeinf.til_type_ref_t_is_writable_get, _ida_typeinf.til_type_ref_t_is_writable_set, doc=r"""is_writable""")
    is_detached: "bool" = property(_ida_typeinf.til_type_ref_t_is_detached_get, _ida_typeinf.til_type_ref_t_is_detached_set, doc=r"""is_detached""")
    is_forward: "bool" = property(_ida_typeinf.til_type_ref_t_is_forward_get, _ida_typeinf.til_type_ref_t_is_forward_set, doc=r"""is_forward""")
    kind: "type_t" = property(_ida_typeinf.til_type_ref_t_kind_get, _ida_typeinf.til_type_ref_t_kind_set, doc=r"""kind""")
    memidx: "ssize_t" = property(_ida_typeinf.til_type_ref_t_memidx_get, _ida_typeinf.til_type_ref_t_memidx_set, doc=r"""memidx""")
    nmembers: "size_t" = property(_ida_typeinf.til_type_ref_t_nmembers_get, _ida_typeinf.til_type_ref_t_nmembers_set, doc=r"""nmembers""")
    udm: "udm_t" = property(_ida_typeinf.til_type_ref_t_udm_get, _ida_typeinf.til_type_ref_t_udm_set, doc=r"""udm""")
    r"""
    BTF_STRUCT or BTF_UNION: the current member.
    """
    total_size: "size_t" = property(_ida_typeinf.til_type_ref_t_total_size_get, _ida_typeinf.til_type_ref_t_total_size_set, doc=r"""total_size""")
    unpadded_size: "size_t" = property(_ida_typeinf.til_type_ref_t_unpadded_size_get, _ida_typeinf.til_type_ref_t_unpadded_size_set, doc=r"""unpadded_size""")
    last_udm_offset: "uint64" = property(_ida_typeinf.til_type_ref_t_last_udm_offset_get, _ida_typeinf.til_type_ref_t_last_udm_offset_set, doc=r"""last_udm_offset""")
    bucket_start: "uint64" = property(_ida_typeinf.til_type_ref_t_bucket_start_get, _ida_typeinf.til_type_ref_t_bucket_start_set, doc=r"""bucket_start""")
    bf_bitoff: "int" = property(_ida_typeinf.til_type_ref_t_bf_bitoff_get, _ida_typeinf.til_type_ref_t_bf_bitoff_set, doc=r"""bf_bitoff""")
    offset: "uint64" = property(_ida_typeinf.til_type_ref_t_offset_get, _ida_typeinf.til_type_ref_t_offset_set, doc=r"""offset""")
    edm: "edm_t" = property(_ida_typeinf.til_type_ref_t_edm_get, _ida_typeinf.til_type_ref_t_edm_set, doc=r"""edm""")
    r"""
    BTF_ENUM: the current enum member.
    """
    fa: "funcarg_t const *" = property(_ida_typeinf.til_type_ref_t_fa_get, _ida_typeinf.til_type_ref_t_fa_set, doc=r"""fa""")
    r"""
    BT_FUNC: the current argument, nullptr - ellipsis.
    """

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_typeinf.til_type_ref_t_clear(self)

    def on_member(self) -> "bool":
        r"""
        on_member(self) -> bool
        """
        return _ida_typeinf.til_type_ref_t_on_member(self)

    def is_typedef(self) -> "bool":
        r"""
        is_typedef(self) -> bool
        """
        return _ida_typeinf.til_type_ref_t_is_typedef(self)

    def is_struct(self) -> "bool":
        r"""
        is_struct(self) -> bool
        """
        return _ida_typeinf.til_type_ref_t_is_struct(self)

    def is_union(self) -> "bool":
        r"""
        is_union(self) -> bool
        """
        return _ida_typeinf.til_type_ref_t_is_union(self)

    def is_enum(self) -> "bool":
        r"""
        is_enum(self) -> bool
        """
        return _ida_typeinf.til_type_ref_t_is_enum(self)

    def is_func(self) -> "bool":
        r"""
        is_func(self) -> bool
        """
        return _ida_typeinf.til_type_ref_t_is_func(self)

    def is_udt(self) -> "bool":
        r"""
        is_udt(self) -> bool
        """
        return _ida_typeinf.til_type_ref_t_is_udt(self)

    def __init__(self):
        r"""
        __init__(self) -> til_type_ref_t
        """
        _ida_typeinf.til_type_ref_t_swiginit(self, _ida_typeinf.new_til_type_ref_t())
    __swig_destroy__ = _ida_typeinf.delete_til_type_ref_t

# Register til_type_ref_t in _ida_typeinf:
_ida_typeinf.til_type_ref_t_swigregister(til_type_ref_t)

def idc_parse_decl(ti: "til_t", decl: "char const *", flags: "int") -> "PyObject *":
    r"""
    idc_parse_decl(ti, decl, flags) -> (str, bytes, bytes) or None

    @param ti: til_t *
    @param decl: char const *
    @param flags: int
    """
    return _ida_typeinf.idc_parse_decl(ti, decl, flags)

def calc_type_size(ti: "til_t", tp: "PyObject *") -> "PyObject *":
    r"""
    calc_type_size(ti, tp) -> PyObject *
    Returns the size of a type

    @param ti: Type info library. 'None' can be passed.
    @param tp: serialized type byte string
    @return:     - None on failure
        - The size of the type
    """
    return _ida_typeinf.calc_type_size(ti, tp)

def apply_type(ti: "til_t", type: "type_t const *", fields: "p_list const *", ea: "ea_t", flags: "int") -> "bool":
    r"""
    apply_type(ti, type, fields, ea, flags) -> bool
    Apply the specified type to the address

    @param ti: Type info library. 'None' can be used.
    @param type: type_t const *
    @param fields: p_list const *
    @param ea: the address of the object
    @param flags: combination of TINFO_... constants or 0
    @return: Boolean
    """
    return _ida_typeinf.apply_type(ti, type, fields, ea, flags)

def get_arg_addrs(caller: "ea_t") -> "PyObject *":
    r"""
    get_arg_addrs(caller) -> PyObject *
    Retrieve addresses of argument initialization instructions

    @param caller: the address of the call instruction
    @return: list of instruction addresses
    """
    return _ida_typeinf.get_arg_addrs(caller)

def unpack_object_from_idb(ti: "til_t", type: "type_t const *", fields: "p_list const *", ea: "ea_t", pio_flags: "int"=0) -> "PyObject *":
    r"""
    unpack_object_from_idb(ti, type, fields, ea, pio_flags=0) -> PyObject

    @param ti: til_t *
    @param type: type_t const *
    @param fields: p_list const *
    @param ea: ea_t
    @param pio_flags: int
    """
    return _ida_typeinf.unpack_object_from_idb(ti, type, fields, ea, pio_flags)

def unpack_object_from_bv(ti: "til_t", type: "type_t const *", fields: "p_list const *", bytes: "bytevec_t const &", pio_flags: "int"=0) -> "PyObject *":
    r"""
    unpack_object_from_bv(ti, type, fields, bytes, pio_flags=0) -> PyObject
    Unpacks a buffer into an object.
    Returns the error_t returned by idaapi.pack_object_to_idb

    @param ti: Type info. 'None' can be passed.
    @param type: type_t const *
    @param fields: fields string (may be empty or None)
    @param bytes: the bytes to unpack
    @param pio_flags: flags used while unpacking
    @return:     - tuple(0, err) on failure
        - tuple(1, obj) on success
    """
    return _ida_typeinf.unpack_object_from_bv(ti, type, fields, bytes, pio_flags)

def pack_object_to_idb(py_obj: "PyObject *", ti: "til_t", type: "type_t const *", fields: "p_list const *", ea: "ea_t", pio_flags: "int"=0) -> "PyObject *":
    r"""
    pack_object_to_idb(py_obj, ti, type, fields, ea, pio_flags=0) -> PyObject
    Write a typed object to the database.
    Raises an exception if wrong parameters were passed or conversion fails
    Returns the error_t returned by idaapi.pack_object_to_idb

    @param py_obj: PyObject *
    @param ti: Type info. 'None' can be passed.
    @param type: type_t const *
    @param fields: fields string (may be empty or None)
    @param ea: ea to be used while packing
    @param pio_flags: flags used while unpacking
    """
    return _ida_typeinf.pack_object_to_idb(py_obj, ti, type, fields, ea, pio_flags)

def pack_object_to_bv(py_obj: "PyObject *", ti: "til_t", type: "type_t const *", fields: "p_list const *", base_ea: "ea_t", pio_flags: "int"=0) -> "PyObject *":
    r"""
    pack_object_to_bv(py_obj, ti, type, fields, base_ea, pio_flags=0) -> PyObject
    Packs a typed object to a string

    @param py_obj: PyObject *
    @param ti: Type info. 'None' can be passed.
    @param type: type_t const *
    @param fields: fields string (may be empty or None)
    @param base_ea: base ea used to relocate the pointers in the packed object
    @param pio_flags: flags used while unpacking
    @return:     tuple(0, err_code) on failure
        tuple(1, packed_buf) on success
    """
    return _ida_typeinf.pack_object_to_bv(py_obj, ti, type, fields, base_ea, pio_flags)
PT_FILE = _ida_typeinf.PT_FILE


def idc_parse_types(input: "char const *", flags: "int") -> "int":
    r"""
    idc_parse_types(input, flags) -> int

    @param input: char const *
    @param flags: int
    """
    return _ida_typeinf.idc_parse_types(input, flags)

def idc_get_type_raw(ea: "ea_t") -> "PyObject *":
    r"""
    idc_get_type_raw(ea) -> PyObject *

    @param ea: ea_t
    """
    return _ida_typeinf.idc_get_type_raw(ea)

def idc_get_local_type_raw(ordinal: "int") -> "PyObject *":
    r"""
    idc_get_local_type_raw(ordinal) -> (bytes, bytes)

    @param ordinal: int
    """
    return _ida_typeinf.idc_get_local_type_raw(ordinal)

def idc_guess_type(ea: "ea_t") -> "size_t":
    r"""
    idc_guess_type(ea) -> str

    @param ea: ea_t
    """
    return _ida_typeinf.idc_guess_type(ea)

def idc_get_type(ea: "ea_t") -> "size_t":
    r"""
    idc_get_type(ea) -> str

    @param ea: ea_t
    """
    return _ida_typeinf.idc_get_type(ea)

def idc_set_local_type(ordinal: "int", dcl: "char const *", flags: "int") -> "int":
    r"""
    idc_set_local_type(ordinal, dcl, flags) -> int

    @param ordinal: int
    @param dcl: char const *
    @param flags: int
    """
    return _ida_typeinf.idc_set_local_type(ordinal, dcl, flags)

def idc_get_local_type(ordinal: "int", flags: "int") -> "size_t":
    r"""
    idc_get_local_type(ordinal, flags) -> str

    @param ordinal: int
    @param flags: int
    """
    return _ida_typeinf.idc_get_local_type(ordinal, flags)

def idc_print_type(type: "type_t const *", fields: "p_list const *", name: "char const *", flags: "int") -> "PyObject *":
    r"""
    idc_print_type(type, fields, name, flags) -> str

    @param type: type_t const *
    @param fields: p_list const *
    @param name: char const *
    @param flags: int
    """
    return _ida_typeinf.idc_print_type(type, fields, name, flags)

def idc_get_local_type_name(ordinal: "int") -> "size_t":
    r"""
    idc_get_local_type_name(ordinal) -> str

    @param ordinal: int
    """
    return _ida_typeinf.idc_get_local_type_name(ordinal)

def get_named_type(til: "til_t", name: "char const *", ntf_flags: "int") -> "PyObject *":
    r"""
    get_named_type(til, name, ntf_flags) -> (int, bytes, bytes, NoneType, NoneType, int, int)
    Get a type data by its name.

    @param til: the type library
    @param name: the type name
    @param ntf_flags: a combination of NTF_* constants
    @return:     None on failure
        tuple(code, type_str, fields_str, cmt, field_cmts, sclass, value) on success
    """
    return _ida_typeinf.get_named_type(til, name, ntf_flags)

def get_named_type64(til: "til_t", name: "char const *", ntf_flags: "int") -> "PyObject *":
    r"""
    get_named_type64(til, name, ntf_flags) -> (int, bytes, NoneType, NoneType, NoneType, int, int)
    See get_named_type() above.
    @note: If the value in the 'ti' library is 32-bit, it will be sign-extended
           before being stored in the 'value' pointer.

    @param til: til_t const *
    @param name: (C++: const char *) char const *
    @param ntf_flags: (C++: int)
    """
    return _ida_typeinf.get_named_type64(til, name, ntf_flags)

def print_decls(printer: "text_sink_t", til: "til_t", py_ordinals: "PyObject *", flags: "uint32") -> "PyObject *":
    r"""
    print_decls(printer, til, py_ordinals, flags) -> int
    Print types (and possibly their dependencies) in a format suitable for using in
    a header file. This is the reverse parse_decls().

    @param printer: (C++: text_sink_t &) a handler for printing text
    @param til: (C++: const til_t *) the type library holding the ordinals
    @param py_ordinals: ordinals of types to export. nullptr means: all ordinals in til
    @param pdf_flags: (C++: uint32) flags for the algorithm. A combination of PDF_ constants
    @retval >0: the number of types exported
    @retval 0: an error occurred
    @retval <0: the negated number of types exported. There were minor errors and
                the resulting output might not be compilable.
    """
    return _ida_typeinf.print_decls(printer, til, py_ordinals, flags)

def remove_tinfo_pointer(tif: "tinfo_t", name: "char const *", til: "til_t") -> "PyObject *":
    r"""
    remove_tinfo_pointer(tif, name, til) -> (bool, NoneType), (bool, str)
    Remove pointer of a type. (i.e. convert "char *" into "char"). Optionally remove
    the "lp" (or similar) prefix of the input name. If the input type is not a
    pointer, then fail.

    @param tif: (C++: tinfo_t *)
    @param name: char const *
    @param til: (C++: const til_t *) til_t const *
    """
    return _ida_typeinf.remove_tinfo_pointer(tif, name, til)

def get_numbered_type(til: "til_t", ordinal: "uint32") -> "PyObject *":
    r"""
    get_numbered_type(til, ordinal) -> (bytes, NoneType, NoneType, NoneType, int), (bytes, bytes, NoneType, NoneType, int)
    Retrieve a type by its ordinal number.

    @param til: til_t const *
    @param ordinal: (C++: uint32)
    """
    return _ida_typeinf.get_numbered_type(til, ordinal)

def set_numbered_type(ti: "til_t", ordinal: "uint32", ntf_flags: "int", name: "char const *", type: "type_t const *", fields: "p_list const *"=None, cmt: "char const *"=None, fldcmts: "p_list const *"=None, sclass: "sclass_t const *"=None) -> "tinfo_code_t":
    r"""
    set_numbered_type(ti, ordinal, ntf_flags, name, type, fields=None, cmt=None, fldcmts=None, sclass=None) -> tinfo_code_t

    @param ti: til_t *
    @param ordinal: uint32
    @param ntf_flags: int
    @param name: char const *
    @param type: type_t const *
    @param fields: p_list const *
    @param cmt: char const *
    @param fldcmts: p_list const *
    @param sclass: sclass_t const *
    """
    return _ida_typeinf.set_numbered_type(ti, ordinal, ntf_flags, name, type, fields, cmt, fldcmts, sclass)

#<pycode(py_typeinf)>

import ida_idaapi
ida_idaapi._listify_types(
    reginfovec_t)

#
# When turning off BC695, 'idati' would still remain available
#
_real_cvar = cvar
_notify_idati = ida_idaapi._make_one_time_warning_message("idati", "get_idati()")

class _wrap_cvar(object):
    def __getattr__(self, attr):
        if attr == "idati":
            _notify_idati()
            return get_idati()
        return getattr(_real_cvar, attr)

    def __setattr__(self, attr, value):
        if attr != "idati":
            setattr(_real_cvar, attr, value)

cvar = _wrap_cvar()

# for compatilibity:
sc_auto   = SC_AUTO
sc_ext    = SC_EXT
sc_friend = SC_FRIEND
sc_reg    = SC_REG
sc_stat   = SC_STAT
sc_type   = SC_TYPE
sc_unk    = SC_UNK
sc_virt   = SC_VIRT

TERR_SAVE      = TERR_SAVE_ERROR
TERR_WRONGNAME = TERR_BAD_NAME

BADORD = 0xFFFFFFFF

enum_member_vec_t = edmvec_t
enum_member_t = edm_t
udt_member_t = udm_t
tinfo_t.find_udt_member = tinfo_t.find_udm

#</pycode(py_typeinf)>



