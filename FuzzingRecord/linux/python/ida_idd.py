r"""
Contains definition of the interface to IDD modules.

The interface consists of structures describing the target debugged processor
and a debugging API."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_idd
else:
    import _ida_idd

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

SWIG_PYTHON_LEGACY_BOOL = _ida_idd.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

import ida_range
class excvec_t(object):
    r"""
    Proxy of C++ qvector< exception_info_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> excvec_t
        __init__(self, x) -> excvec_t

        @param x: qvector< exception_info_t > const &
        """
        _ida_idd.excvec_t_swiginit(self, _ida_idd.new_excvec_t(*args))
    __swig_destroy__ = _ida_idd.delete_excvec_t

    def push_back(self, *args) -> "exception_info_t &":
        r"""
        push_back(self, x)

        @param x: exception_info_t const &

        push_back(self) -> exception_info_t
        """
        return _ida_idd.excvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_idd.excvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_idd.excvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_idd.excvec_t_empty(self)

    def at(self, _idx: "size_t") -> "exception_info_t const &":
        r"""
        at(self, _idx) -> exception_info_t

        @param _idx: size_t
        """
        return _ida_idd.excvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_idd.excvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_idd.excvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: exception_info_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_idd.excvec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=exception_info_t())

        @param x: exception_info_t const &
        """
        return _ida_idd.excvec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_idd.excvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_idd.excvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_idd.excvec_t_truncate(self)

    def swap(self, r: "excvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< exception_info_t > &
        """
        return _ida_idd.excvec_t_swap(self, r)

    def extract(self) -> "exception_info_t *":
        r"""
        extract(self) -> exception_info_t
        """
        return _ida_idd.excvec_t_extract(self)

    def inject(self, s: "exception_info_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: exception_info_t *
        @param len: size_t
        """
        return _ida_idd.excvec_t_inject(self, s, len)

    def begin(self, *args) -> "qvector< exception_info_t >::const_iterator":
        r"""
        begin(self) -> exception_info_t
        """
        return _ida_idd.excvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< exception_info_t >::const_iterator":
        r"""
        end(self) -> exception_info_t
        """
        return _ida_idd.excvec_t_end(self, *args)

    def insert(self, it: "exception_info_t", x: "exception_info_t") -> "qvector< exception_info_t >::iterator":
        r"""
        insert(self, it, x) -> exception_info_t

        @param it: qvector< exception_info_t >::iterator
        @param x: exception_info_t const &
        """
        return _ida_idd.excvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< exception_info_t >::iterator":
        r"""
        erase(self, it) -> exception_info_t

        @param it: qvector< exception_info_t >::iterator

        erase(self, first, last) -> exception_info_t

        @param first: qvector< exception_info_t >::iterator
        @param last: qvector< exception_info_t >::iterator
        """
        return _ida_idd.excvec_t_erase(self, *args)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_idd.excvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "exception_info_t const &":
        r"""
        __getitem__(self, i) -> exception_info_t

        @param i: size_t
        """
        return _ida_idd.excvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "exception_info_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: exception_info_t const &
        """
        return _ida_idd.excvec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register excvec_t in _ida_idd:
_ida_idd.excvec_t_swigregister(excvec_t)
class procinfo_vec_t(object):
    r"""
    Proxy of C++ qvector< process_info_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> procinfo_vec_t
        __init__(self, x) -> procinfo_vec_t

        @param x: qvector< process_info_t > const &
        """
        _ida_idd.procinfo_vec_t_swiginit(self, _ida_idd.new_procinfo_vec_t(*args))
    __swig_destroy__ = _ida_idd.delete_procinfo_vec_t

    def push_back(self, *args) -> "process_info_t &":
        r"""
        push_back(self, x)

        @param x: process_info_t const &

        push_back(self) -> process_info_t
        """
        return _ida_idd.procinfo_vec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_idd.procinfo_vec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_idd.procinfo_vec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_idd.procinfo_vec_t_empty(self)

    def at(self, _idx: "size_t") -> "process_info_t const &":
        r"""
        at(self, _idx) -> process_info_t

        @param _idx: size_t
        """
        return _ida_idd.procinfo_vec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_idd.procinfo_vec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_idd.procinfo_vec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: process_info_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_idd.procinfo_vec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=process_info_t())

        @param x: process_info_t const &
        """
        return _ida_idd.procinfo_vec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_idd.procinfo_vec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_idd.procinfo_vec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_idd.procinfo_vec_t_truncate(self)

    def swap(self, r: "procinfo_vec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< process_info_t > &
        """
        return _ida_idd.procinfo_vec_t_swap(self, r)

    def extract(self) -> "process_info_t *":
        r"""
        extract(self) -> process_info_t
        """
        return _ida_idd.procinfo_vec_t_extract(self)

    def inject(self, s: "process_info_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: process_info_t *
        @param len: size_t
        """
        return _ida_idd.procinfo_vec_t_inject(self, s, len)

    def begin(self, *args) -> "qvector< process_info_t >::const_iterator":
        r"""
        begin(self) -> process_info_t
        """
        return _ida_idd.procinfo_vec_t_begin(self, *args)

    def end(self, *args) -> "qvector< process_info_t >::const_iterator":
        r"""
        end(self) -> process_info_t
        """
        return _ida_idd.procinfo_vec_t_end(self, *args)

    def insert(self, it: "process_info_t", x: "process_info_t") -> "qvector< process_info_t >::iterator":
        r"""
        insert(self, it, x) -> process_info_t

        @param it: qvector< process_info_t >::iterator
        @param x: process_info_t const &
        """
        return _ida_idd.procinfo_vec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< process_info_t >::iterator":
        r"""
        erase(self, it) -> process_info_t

        @param it: qvector< process_info_t >::iterator

        erase(self, first, last) -> process_info_t

        @param first: qvector< process_info_t >::iterator
        @param last: qvector< process_info_t >::iterator
        """
        return _ida_idd.procinfo_vec_t_erase(self, *args)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_idd.procinfo_vec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "process_info_t const &":
        r"""
        __getitem__(self, i) -> process_info_t

        @param i: size_t
        """
        return _ida_idd.procinfo_vec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "process_info_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: process_info_t const &
        """
        return _ida_idd.procinfo_vec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register procinfo_vec_t in _ida_idd:
_ida_idd.procinfo_vec_t_swigregister(procinfo_vec_t)
class call_stack_info_vec_t(object):
    r"""
    Proxy of C++ qvector< call_stack_info_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> call_stack_info_vec_t
        __init__(self, x) -> call_stack_info_vec_t

        @param x: qvector< call_stack_info_t > const &
        """
        _ida_idd.call_stack_info_vec_t_swiginit(self, _ida_idd.new_call_stack_info_vec_t(*args))
    __swig_destroy__ = _ida_idd.delete_call_stack_info_vec_t

    def push_back(self, *args) -> "call_stack_info_t &":
        r"""
        push_back(self, x)

        @param x: call_stack_info_t const &

        push_back(self) -> call_stack_info_t
        """
        return _ida_idd.call_stack_info_vec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_idd.call_stack_info_vec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_idd.call_stack_info_vec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_idd.call_stack_info_vec_t_empty(self)

    def at(self, _idx: "size_t") -> "call_stack_info_t const &":
        r"""
        at(self, _idx) -> call_stack_info_t

        @param _idx: size_t
        """
        return _ida_idd.call_stack_info_vec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_idd.call_stack_info_vec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_idd.call_stack_info_vec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: call_stack_info_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_idd.call_stack_info_vec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=call_stack_info_t())

        @param x: call_stack_info_t const &
        """
        return _ida_idd.call_stack_info_vec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_idd.call_stack_info_vec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_idd.call_stack_info_vec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_idd.call_stack_info_vec_t_truncate(self)

    def swap(self, r: "call_stack_info_vec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< call_stack_info_t > &
        """
        return _ida_idd.call_stack_info_vec_t_swap(self, r)

    def extract(self) -> "call_stack_info_t *":
        r"""
        extract(self) -> call_stack_info_t
        """
        return _ida_idd.call_stack_info_vec_t_extract(self)

    def inject(self, s: "call_stack_info_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: call_stack_info_t *
        @param len: size_t
        """
        return _ida_idd.call_stack_info_vec_t_inject(self, s, len)

    def __eq__(self, r: "call_stack_info_vec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< call_stack_info_t > const &
        """
        return _ida_idd.call_stack_info_vec_t___eq__(self, r)

    def __ne__(self, r: "call_stack_info_vec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< call_stack_info_t > const &
        """
        return _ida_idd.call_stack_info_vec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< call_stack_info_t >::const_iterator":
        r"""
        begin(self) -> call_stack_info_t
        """
        return _ida_idd.call_stack_info_vec_t_begin(self, *args)

    def end(self, *args) -> "qvector< call_stack_info_t >::const_iterator":
        r"""
        end(self) -> call_stack_info_t
        """
        return _ida_idd.call_stack_info_vec_t_end(self, *args)

    def insert(self, it: "call_stack_info_t", x: "call_stack_info_t") -> "qvector< call_stack_info_t >::iterator":
        r"""
        insert(self, it, x) -> call_stack_info_t

        @param it: qvector< call_stack_info_t >::iterator
        @param x: call_stack_info_t const &
        """
        return _ida_idd.call_stack_info_vec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< call_stack_info_t >::iterator":
        r"""
        erase(self, it) -> call_stack_info_t

        @param it: qvector< call_stack_info_t >::iterator

        erase(self, first, last) -> call_stack_info_t

        @param first: qvector< call_stack_info_t >::iterator
        @param last: qvector< call_stack_info_t >::iterator
        """
        return _ida_idd.call_stack_info_vec_t_erase(self, *args)

    def find(self, *args) -> "qvector< call_stack_info_t >::const_iterator":
        r"""
        find(self, x) -> call_stack_info_t

        @param x: call_stack_info_t const &

        """
        return _ida_idd.call_stack_info_vec_t_find(self, *args)

    def has(self, x: "call_stack_info_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: call_stack_info_t const &
        """
        return _ida_idd.call_stack_info_vec_t_has(self, x)

    def add_unique(self, x: "call_stack_info_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: call_stack_info_t const &
        """
        return _ida_idd.call_stack_info_vec_t_add_unique(self, x)

    def _del(self, x: "call_stack_info_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: call_stack_info_t const &

        """
        return _ida_idd.call_stack_info_vec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_idd.call_stack_info_vec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "call_stack_info_t const &":
        r"""
        __getitem__(self, i) -> call_stack_info_t

        @param i: size_t
        """
        return _ida_idd.call_stack_info_vec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "call_stack_info_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: call_stack_info_t const &
        """
        return _ida_idd.call_stack_info_vec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register call_stack_info_vec_t in _ida_idd:
_ida_idd.call_stack_info_vec_t_swigregister(call_stack_info_vec_t)
class meminfo_vec_template_t(object):
    r"""
    Proxy of C++ qvector< memory_info_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> meminfo_vec_template_t
        __init__(self, x) -> meminfo_vec_template_t

        @param x: qvector< memory_info_t > const &
        """
        _ida_idd.meminfo_vec_template_t_swiginit(self, _ida_idd.new_meminfo_vec_template_t(*args))
    __swig_destroy__ = _ida_idd.delete_meminfo_vec_template_t

    def push_back(self, *args) -> "memory_info_t &":
        r"""
        push_back(self, x)

        @param x: memory_info_t const &

        push_back(self) -> memory_info_t
        """
        return _ida_idd.meminfo_vec_template_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_idd.meminfo_vec_template_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_idd.meminfo_vec_template_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_idd.meminfo_vec_template_t_empty(self)

    def at(self, _idx: "size_t") -> "memory_info_t const &":
        r"""
        at(self, _idx) -> memory_info_t

        @param _idx: size_t
        """
        return _ida_idd.meminfo_vec_template_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_idd.meminfo_vec_template_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_idd.meminfo_vec_template_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: memory_info_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_idd.meminfo_vec_template_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=memory_info_t())

        @param x: memory_info_t const &
        """
        return _ida_idd.meminfo_vec_template_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_idd.meminfo_vec_template_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_idd.meminfo_vec_template_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_idd.meminfo_vec_template_t_truncate(self)

    def swap(self, r: "meminfo_vec_template_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< memory_info_t > &
        """
        return _ida_idd.meminfo_vec_template_t_swap(self, r)

    def extract(self) -> "memory_info_t *":
        r"""
        extract(self) -> memory_info_t
        """
        return _ida_idd.meminfo_vec_template_t_extract(self)

    def inject(self, s: "memory_info_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: memory_info_t *
        @param len: size_t
        """
        return _ida_idd.meminfo_vec_template_t_inject(self, s, len)

    def __eq__(self, r: "meminfo_vec_template_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< memory_info_t > const &
        """
        return _ida_idd.meminfo_vec_template_t___eq__(self, r)

    def __ne__(self, r: "meminfo_vec_template_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< memory_info_t > const &
        """
        return _ida_idd.meminfo_vec_template_t___ne__(self, r)

    def begin(self, *args) -> "qvector< memory_info_t >::const_iterator":
        r"""
        begin(self) -> memory_info_t
        """
        return _ida_idd.meminfo_vec_template_t_begin(self, *args)

    def end(self, *args) -> "qvector< memory_info_t >::const_iterator":
        r"""
        end(self) -> memory_info_t
        """
        return _ida_idd.meminfo_vec_template_t_end(self, *args)

    def insert(self, it: "memory_info_t", x: "memory_info_t") -> "qvector< memory_info_t >::iterator":
        r"""
        insert(self, it, x) -> memory_info_t

        @param it: qvector< memory_info_t >::iterator
        @param x: memory_info_t const &
        """
        return _ida_idd.meminfo_vec_template_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< memory_info_t >::iterator":
        r"""
        erase(self, it) -> memory_info_t

        @param it: qvector< memory_info_t >::iterator

        erase(self, first, last) -> memory_info_t

        @param first: qvector< memory_info_t >::iterator
        @param last: qvector< memory_info_t >::iterator
        """
        return _ida_idd.meminfo_vec_template_t_erase(self, *args)

    def find(self, *args) -> "qvector< memory_info_t >::const_iterator":
        r"""
        find(self, x) -> memory_info_t

        @param x: memory_info_t const &

        """
        return _ida_idd.meminfo_vec_template_t_find(self, *args)

    def has(self, x: "memory_info_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: memory_info_t const &
        """
        return _ida_idd.meminfo_vec_template_t_has(self, x)

    def add_unique(self, x: "memory_info_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: memory_info_t const &
        """
        return _ida_idd.meminfo_vec_template_t_add_unique(self, x)

    def _del(self, x: "memory_info_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: memory_info_t const &

        """
        return _ida_idd.meminfo_vec_template_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_idd.meminfo_vec_template_t___len__(self)

    def __getitem__(self, i: "size_t") -> "memory_info_t const &":
        r"""
        __getitem__(self, i) -> memory_info_t

        @param i: size_t
        """
        return _ida_idd.meminfo_vec_template_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "memory_info_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: memory_info_t const &
        """
        return _ida_idd.meminfo_vec_template_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register meminfo_vec_template_t in _ida_idd:
_ida_idd.meminfo_vec_template_t_swigregister(meminfo_vec_template_t)
class regvals_t(object):
    r"""
    Proxy of C++ qvector< regval_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> regvals_t
        __init__(self, x) -> regvals_t

        @param x: qvector< regval_t > const &
        """
        _ida_idd.regvals_t_swiginit(self, _ida_idd.new_regvals_t(*args))
    __swig_destroy__ = _ida_idd.delete_regvals_t

    def push_back(self, *args) -> "regval_t &":
        r"""
        push_back(self, x)

        @param x: regval_t const &

        push_back(self) -> regval_t
        """
        return _ida_idd.regvals_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_idd.regvals_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_idd.regvals_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_idd.regvals_t_empty(self)

    def at(self, _idx: "size_t") -> "regval_t const &":
        r"""
        at(self, _idx) -> regval_t

        @param _idx: size_t
        """
        return _ida_idd.regvals_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_idd.regvals_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_idd.regvals_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: regval_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_idd.regvals_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=regval_t())

        @param x: regval_t const &
        """
        return _ida_idd.regvals_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_idd.regvals_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_idd.regvals_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_idd.regvals_t_truncate(self)

    def swap(self, r: "regvals_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< regval_t > &
        """
        return _ida_idd.regvals_t_swap(self, r)

    def extract(self) -> "regval_t *":
        r"""
        extract(self) -> regval_t
        """
        return _ida_idd.regvals_t_extract(self)

    def inject(self, s: "regval_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: regval_t *
        @param len: size_t
        """
        return _ida_idd.regvals_t_inject(self, s, len)

    def __eq__(self, r: "regvals_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< regval_t > const &
        """
        return _ida_idd.regvals_t___eq__(self, r)

    def __ne__(self, r: "regvals_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< regval_t > const &
        """
        return _ida_idd.regvals_t___ne__(self, r)

    def begin(self, *args) -> "qvector< regval_t >::const_iterator":
        r"""
        begin(self) -> regval_t
        """
        return _ida_idd.regvals_t_begin(self, *args)

    def end(self, *args) -> "qvector< regval_t >::const_iterator":
        r"""
        end(self) -> regval_t
        """
        return _ida_idd.regvals_t_end(self, *args)

    def insert(self, it: "regval_t", x: "regval_t") -> "qvector< regval_t >::iterator":
        r"""
        insert(self, it, x) -> regval_t

        @param it: qvector< regval_t >::iterator
        @param x: regval_t const &
        """
        return _ida_idd.regvals_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< regval_t >::iterator":
        r"""
        erase(self, it) -> regval_t

        @param it: qvector< regval_t >::iterator

        erase(self, first, last) -> regval_t

        @param first: qvector< regval_t >::iterator
        @param last: qvector< regval_t >::iterator
        """
        return _ida_idd.regvals_t_erase(self, *args)

    def find(self, *args) -> "qvector< regval_t >::const_iterator":
        r"""
        find(self, x) -> regval_t

        @param x: regval_t const &

        """
        return _ida_idd.regvals_t_find(self, *args)

    def has(self, x: "regval_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: regval_t const &
        """
        return _ida_idd.regvals_t_has(self, x)

    def add_unique(self, x: "regval_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: regval_t const &
        """
        return _ida_idd.regvals_t_add_unique(self, x)

    def _del(self, x: "regval_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: regval_t const &

        """
        return _ida_idd.regvals_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_idd.regvals_t___len__(self)

    def __getitem__(self, i: "size_t") -> "regval_t const &":
        r"""
        __getitem__(self, i) -> regval_t

        @param i: size_t
        """
        return _ida_idd.regvals_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "regval_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: regval_t const &
        """
        return _ida_idd.regvals_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register regvals_t in _ida_idd:
_ida_idd.regvals_t_swigregister(regvals_t)
IDD_INTERFACE_VERSION = _ida_idd.IDD_INTERFACE_VERSION
r"""
The IDD interface version number.
"""

NO_THREAD = _ida_idd.NO_THREAD
r"""
No thread. in PROCESS_STARTED this value can be used to specify that the main
thread has not been created. It will be initialized later by a THREAD_STARTED
event.
"""

class process_info_t(object):
    r"""
    Proxy of C++ process_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    pid: "pid_t" = property(_ida_idd.process_info_t_pid_get, _ida_idd.process_info_t_pid_set, doc=r"""pid""")
    r"""
    process id
    """
    name: "qstring" = property(_ida_idd.process_info_t_name_get, _ida_idd.process_info_t_name_set, doc=r"""name""")
    r"""
    process name
    """

    def __init__(self):
        r"""
        __init__(self) -> process_info_t
        """
        _ida_idd.process_info_t_swiginit(self, _ida_idd.new_process_info_t())
    __swig_destroy__ = _ida_idd.delete_process_info_t

# Register process_info_t in _ida_idd:
_ida_idd.process_info_t_swigregister(process_info_t)
class debapp_attrs_t(object):
    r"""
    Proxy of C++ debapp_attrs_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    cbsize: "int32" = property(_ida_idd.debapp_attrs_t_cbsize_get, _ida_idd.debapp_attrs_t_cbsize_set, doc=r"""cbsize""")
    r"""
    control field: size of this structure
    """
    addrsize: "int" = property(_ida_idd.debapp_attrs_t_addrsize_get, _ida_idd.debapp_attrs_t_addrsize_set, doc=r"""addrsize""")
    r"""
    address size of the process. Since 64-bit debuggers usually can debug 32-bit
    applications, we cannot rely on sizeof(ea_t) to detect the current address size.
    The following variable should be used instead. It is initialized with 8 for
    64-bit debuggers but they should adjust it as soon as they learn that a 32-bit
    application is being debugged. For 32-bit debuggers it is initialized with 4.
    """
    platform: "qstring" = property(_ida_idd.debapp_attrs_t_platform_get, _ida_idd.debapp_attrs_t_platform_set, doc=r"""platform""")
    r"""
    platform name process is running/debugging under. (is used as a key value in
    exceptions.cfg)
    """
    is_be: "int" = property(_ida_idd.debapp_attrs_t_is_be_get, _ida_idd.debapp_attrs_t_is_be_set, doc=r"""is_be""")

    def __init__(self):
        r"""
        __init__(self) -> debapp_attrs_t
        """
        _ida_idd.debapp_attrs_t_swiginit(self, _ida_idd.new_debapp_attrs_t())
    __swig_destroy__ = _ida_idd.delete_debapp_attrs_t

# Register debapp_attrs_t in _ida_idd:
_ida_idd.debapp_attrs_t_swigregister(debapp_attrs_t)
DEF_ADDRSIZE = _ida_idd.DEF_ADDRSIZE


class register_info_t(object):
    r"""
    Proxy of C++ register_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    name: "char const *" = property(_ida_idd.register_info_t_name_get, _ida_idd.register_info_t_name_set, doc=r"""name""")
    r"""
    Register name.
    """
    flags: "uint32" = property(_ida_idd.register_info_t_flags_get, _ida_idd.register_info_t_flags_set, doc=r"""flags""")
    r"""
    Register info attribute flags
    """
    register_class: "register_class_t" = property(_ida_idd.register_info_t_register_class_get, _ida_idd.register_info_t_register_class_set, doc=r"""register_class""")
    r"""
    segment, mmx, etc.
    """
    dtype: "op_dtype_t" = property(_ida_idd.register_info_t_dtype_get, _ida_idd.register_info_t_dtype_set, doc=r"""dtype""")
    r"""
    Register size (see Operand value types)
    """
    default_bit_strings_mask: "uval_t" = property(_ida_idd.register_info_t_default_bit_strings_mask_get, _ida_idd.register_info_t_default_bit_strings_mask_set, doc=r"""default_bit_strings_mask""")
    r"""
    mask of default bits
    """

    def __get_bit_strings(self) -> "PyObject *":
        r"""
        __get_bit_strings(self) -> PyObject *
        """
        return _ida_idd.register_info_t___get_bit_strings(self)

    bit_strings = property(__get_bit_strings)
    r"""
    strings corresponding to each bit of the register. (nullptr = no bit, same name
    = multi-bits mask)
    """


    def __init__(self):
        r"""
        __init__(self) -> register_info_t
        """
        _ida_idd.register_info_t_swiginit(self, _ida_idd.new_register_info_t())
    __swig_destroy__ = _ida_idd.delete_register_info_t

# Register register_info_t in _ida_idd:
_ida_idd.register_info_t_swigregister(register_info_t)
REGISTER_READONLY = _ida_idd.REGISTER_READONLY
r"""
the user can't modify the current value of this register
"""

REGISTER_IP = _ida_idd.REGISTER_IP
r"""
instruction pointer
"""

REGISTER_SP = _ida_idd.REGISTER_SP
r"""
stack pointer
"""

REGISTER_FP = _ida_idd.REGISTER_FP
r"""
frame pointer
"""

REGISTER_ADDRESS = _ida_idd.REGISTER_ADDRESS
r"""
may contain an address
"""

REGISTER_CS = _ida_idd.REGISTER_CS
r"""
code segment
"""

REGISTER_SS = _ida_idd.REGISTER_SS
r"""
stack segment
"""

REGISTER_NOLF = _ida_idd.REGISTER_NOLF
r"""
displays this register without returning to the next line, allowing the next
register to be displayed to its right (on the same line)
"""

REGISTER_CUSTFMT = _ida_idd.REGISTER_CUSTFMT
r"""
register should be displayed using a custom data format. the format name is in
bit_strings[0]; the corresponding regval_t will use bytevec_t
"""


class memory_info_t(ida_range.range_t):
    r"""
    Proxy of C++ memory_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    name: "qstring" = property(_ida_idd.memory_info_t_name_get, _ida_idd.memory_info_t_name_set, doc=r"""name""")
    r"""
    Memory range name.
    """
    sclass: "qstring" = property(_ida_idd.memory_info_t_sclass_get, _ida_idd.memory_info_t_sclass_set, doc=r"""sclass""")
    r"""
    Memory range class name.
    """
    sbase: "ea_t" = property(_ida_idd.memory_info_t_sbase_get, _ida_idd.memory_info_t_sbase_set, doc=r"""sbase""")
    r"""
    Segment base (meaningful only for segmented architectures, e.g. 16-bit x86) The
    base is specified in paragraphs (i.e. shifted to the right by 4)
    """
    bitness: "uchar" = property(_ida_idd.memory_info_t_bitness_get, _ida_idd.memory_info_t_bitness_set, doc=r"""bitness""")
    r"""
    Number of bits in segment addresses (0-16bit, 1-32bit, 2-64bit)
    """
    perm: "uchar" = property(_ida_idd.memory_info_t_perm_get, _ida_idd.memory_info_t_perm_set, doc=r"""perm""")
    r"""
    Memory range permissions (0-no information): see segment.hpp.
    """

    def __eq__(self, r: "memory_info_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: memory_info_t const &
        """
        return _ida_idd.memory_info_t___eq__(self, r)

    def __ne__(self, r: "memory_info_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: memory_info_t const &
        """
        return _ida_idd.memory_info_t___ne__(self, r)

    def __init__(self):
        r"""
        __init__(self) -> memory_info_t
        """
        _ida_idd.memory_info_t_swiginit(self, _ida_idd.new_memory_info_t())
    __swig_destroy__ = _ida_idd.delete_memory_info_t

# Register memory_info_t in _ida_idd:
_ida_idd.memory_info_t_swigregister(memory_info_t)
class meminfo_vec_t(meminfo_vec_template_t):
    r"""
    Proxy of C++ meminfo_vec_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> meminfo_vec_t
        """
        _ida_idd.meminfo_vec_t_swiginit(self, _ida_idd.new_meminfo_vec_t())
    __swig_destroy__ = _ida_idd.delete_meminfo_vec_t

# Register meminfo_vec_t in _ida_idd:
_ida_idd.meminfo_vec_t_swigregister(meminfo_vec_t)
class scattered_segm_t(ida_range.range_t):
    r"""
    Proxy of C++ scattered_segm_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    name: "qstring" = property(_ida_idd.scattered_segm_t_name_get, _ida_idd.scattered_segm_t_name_set, doc=r"""name""")
    r"""
    name of the segment
    """

    def __init__(self):
        r"""
        __init__(self) -> scattered_segm_t
        """
        _ida_idd.scattered_segm_t_swiginit(self, _ida_idd.new_scattered_segm_t())
    __swig_destroy__ = _ida_idd.delete_scattered_segm_t

# Register scattered_segm_t in _ida_idd:
_ida_idd.scattered_segm_t_swigregister(scattered_segm_t)
class launch_env_t(object):
    r"""
    Proxy of C++ launch_env_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    merge: "bool" = property(_ida_idd.launch_env_t_merge_get, _ida_idd.launch_env_t_merge_set, doc=r"""merge""")

    def __init__(self):
        r"""
        __init__(self) -> launch_env_t
        """
        _ida_idd.launch_env_t_swiginit(self, _ida_idd.new_launch_env_t())
    __swig_destroy__ = _ida_idd.delete_launch_env_t

# Register launch_env_t in _ida_idd:
_ida_idd.launch_env_t_swigregister(launch_env_t)
NO_EVENT = _ida_idd.NO_EVENT
r"""
Not an interesting event. This event can be used if the debugger module needs to
return an event but there are no valid events.
"""

PROCESS_STARTED = _ida_idd.PROCESS_STARTED
r"""
New process has been started.
"""

PROCESS_EXITED = _ida_idd.PROCESS_EXITED
r"""
Process has been stopped.
"""

THREAD_STARTED = _ida_idd.THREAD_STARTED
r"""
New thread has been started.
"""

THREAD_EXITED = _ida_idd.THREAD_EXITED
r"""
Thread has been stopped.
"""

BREAKPOINT = _ida_idd.BREAKPOINT
r"""
Breakpoint has been reached. IDA will complain about unknown breakpoints, they
should be reported as exceptions.
"""

STEP = _ida_idd.STEP
r"""
One instruction has been executed. Spurious events of this kind are silently
ignored by IDA.
"""

EXCEPTION = _ida_idd.EXCEPTION
r"""
Exception.
"""

LIB_LOADED = _ida_idd.LIB_LOADED
r"""
New library has been loaded.
"""

LIB_UNLOADED = _ida_idd.LIB_UNLOADED
r"""
Library has been unloaded.
"""

INFORMATION = _ida_idd.INFORMATION
r"""
User-defined information. This event can be used to return empty information
This will cause IDA to call get_debug_event() immediately once more.
"""

PROCESS_ATTACHED = _ida_idd.PROCESS_ATTACHED
r"""
Successfully attached to running process.
"""

PROCESS_DETACHED = _ida_idd.PROCESS_DETACHED
r"""
Successfully detached from process.
"""

PROCESS_SUSPENDED = _ida_idd.PROCESS_SUSPENDED
r"""
Process has been suspended. This event can be used by the debugger module to
signal if the process spontaneously gets suspended (not because of an exception,
breakpoint, or single step). IDA will silently switch to the 'suspended process'
mode without displaying any messages.
"""

TRACE_FULL = _ida_idd.TRACE_FULL
r"""
The trace buffer of the tracer module is full and IDA needs to read it before
continuing
"""


def set_debug_event_code(ev: "debug_event_t", id: "event_id_t") -> "void":
    r"""
    set_debug_event_code(ev, id)

    @param ev: debug_event_t *
    @param id: enum event_id_t
    """
    return _ida_idd.set_debug_event_code(ev, id)
class modinfo_t(object):
    r"""
    Proxy of C++ modinfo_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    name: "qstring" = property(_ida_idd.modinfo_t_name_get, _ida_idd.modinfo_t_name_set, doc=r"""name""")
    r"""
    full name of the module
    """
    base: "ea_t" = property(_ida_idd.modinfo_t_base_get, _ida_idd.modinfo_t_base_set, doc=r"""base""")
    r"""
    module base address. if unknown pass BADADDR
    """
    size: "asize_t" = property(_ida_idd.modinfo_t_size_get, _ida_idd.modinfo_t_size_set, doc=r"""size""")
    r"""
    module size. if unknown pass 0
    """
    rebase_to: "ea_t" = property(_ida_idd.modinfo_t_rebase_to_get, _ida_idd.modinfo_t_rebase_to_set, doc=r"""rebase_to""")
    r"""
    if not BADADDR, then rebase the program to the specified address
    """

    def __init__(self):
        r"""
        __init__(self) -> modinfo_t
        """
        _ida_idd.modinfo_t_swiginit(self, _ida_idd.new_modinfo_t())
    __swig_destroy__ = _ida_idd.delete_modinfo_t

# Register modinfo_t in _ida_idd:
_ida_idd.modinfo_t_swigregister(modinfo_t)
class bptaddr_t(object):
    r"""
    Proxy of C++ bptaddr_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    hea: "ea_t" = property(_ida_idd.bptaddr_t_hea_get, _ida_idd.bptaddr_t_hea_set, doc=r"""hea""")
    r"""
    Possible address referenced by hardware breakpoints.
    """
    kea: "ea_t" = property(_ida_idd.bptaddr_t_kea_get, _ida_idd.bptaddr_t_kea_set, doc=r"""kea""")
    r"""
    Address of the triggered bpt from the kernel's point of view. (for some systems
    with special memory mappings, the triggered ea might be different from event
    ea). Use to BADADDR for flat memory model.
    """

    def __init__(self):
        r"""
        __init__(self) -> bptaddr_t
        """
        _ida_idd.bptaddr_t_swiginit(self, _ida_idd.new_bptaddr_t())
    __swig_destroy__ = _ida_idd.delete_bptaddr_t

# Register bptaddr_t in _ida_idd:
_ida_idd.bptaddr_t_swigregister(bptaddr_t)
class excinfo_t(object):
    r"""
    Proxy of C++ excinfo_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    code: "uint32" = property(_ida_idd.excinfo_t_code_get, _ida_idd.excinfo_t_code_set, doc=r"""code""")
    r"""
    Exception code.
    """
    can_cont: "bool" = property(_ida_idd.excinfo_t_can_cont_get, _ida_idd.excinfo_t_can_cont_set, doc=r"""can_cont""")
    r"""
    Execution of the process can continue after this exception?
    """
    ea: "ea_t" = property(_ida_idd.excinfo_t_ea_get, _ida_idd.excinfo_t_ea_set, doc=r"""ea""")
    r"""
    Possible address referenced by the exception.
    """
    info: "qstring" = property(_ida_idd.excinfo_t_info_get, _ida_idd.excinfo_t_info_set, doc=r"""info""")
    r"""
    Exception message.
    """

    def __init__(self):
        r"""
        __init__(self) -> excinfo_t
        """
        _ida_idd.excinfo_t_swiginit(self, _ida_idd.new_excinfo_t())
    __swig_destroy__ = _ida_idd.delete_excinfo_t

# Register excinfo_t in _ida_idd:
_ida_idd.excinfo_t_swigregister(excinfo_t)
class debug_event_t(object):
    r"""
    Proxy of C++ debug_event_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    pid: "pid_t" = property(_ida_idd.debug_event_t_pid_get, _ida_idd.debug_event_t_pid_set, doc=r"""pid""")
    r"""
    Process where the event occurred.
    """
    tid: "thid_t" = property(_ida_idd.debug_event_t_tid_get, _ida_idd.debug_event_t_tid_set, doc=r"""tid""")
    r"""
    Thread where the event occurred.
    """
    ea: "ea_t" = property(_ida_idd.debug_event_t_ea_get, _ida_idd.debug_event_t_ea_set, doc=r"""ea""")
    r"""
    Address where the event occurred.
    """
    handled: "bool" = property(_ida_idd.debug_event_t_handled_get, _ida_idd.debug_event_t_handled_set, doc=r"""handled""")
    r"""
    Is event handled by the debugger?. (from the system's point of view) Meaningful
    for EXCEPTION events
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> debug_event_t
        __init__(self, r) -> debug_event_t

        @param r: debug_event_t const &
        """
        _ida_idd.debug_event_t_swiginit(self, _ida_idd.new_debug_event_t(*args))
    __swig_destroy__ = _ida_idd.delete_debug_event_t

    def copy(self, r: "debug_event_t") -> "debug_event_t &":
        r"""
        copy(self, r) -> debug_event_t

        @param r: debug_event_t const &
        """
        return _ida_idd.debug_event_t_copy(self, r)

    def clear(self) -> "void":
        r"""
        clear(self)
        clear the dependent information (see below), set event code to NO_EVENT
        """
        return _ida_idd.debug_event_t_clear(self)

    def clear_all(self) -> "void":
        r"""
        clear_all(self)
        """
        return _ida_idd.debug_event_t_clear_all(self)

    def eid(self) -> "event_id_t":
        r"""
        eid(self) -> event_id_t
        Event code.
        """
        return _ida_idd.debug_event_t_eid(self)

    def set_eid(self, id: "event_id_t") -> "void":
        r"""
        set_eid(self, id)
        Set event code. If the new event code is compatible with the old one then the
        dependent information (see below) will be preserved. Otherwise the event will be
        cleared and the new event code will be set.

        @param id: (C++: event_id_t) enum event_id_t
        """
        return _ida_idd.debug_event_t_set_eid(self, id)

    def modinfo(self, *args) -> "modinfo_t const &":
        r"""
        modinfo(self) -> modinfo_t
        """
        return _ida_idd.debug_event_t_modinfo(self, *args)

    def exit_code(self) -> "int const &":
        r"""
        exit_code(self) -> int const &
        """
        return _ida_idd.debug_event_t_exit_code(self)

    def info(self, *args) -> "qstring const &":
        r"""
        info(self) -> qstring
        info(self) -> qstring const &
        """
        return _ida_idd.debug_event_t_info(self, *args)

    def bpt(self, *args) -> "bptaddr_t const &":
        r"""
        bpt(self) -> bptaddr_t
        """
        return _ida_idd.debug_event_t_bpt(self, *args)

    def exc(self, *args) -> "excinfo_t const &":
        r"""
        exc(self) -> excinfo_t
        """
        return _ida_idd.debug_event_t_exc(self, *args)

    def set_modinfo(self, id: "event_id_t") -> "modinfo_t &":
        r"""
        set_modinfo(self, id) -> modinfo_t

        @param id: enum event_id_t
        """
        return _ida_idd.debug_event_t_set_modinfo(self, id)

    def set_exit_code(self, id: "event_id_t", code: "int") -> "void":
        r"""
        set_exit_code(self, id, code)

        @param id: enum event_id_t
        @param code: int
        """
        return _ida_idd.debug_event_t_set_exit_code(self, id, code)

    def set_info(self, id: "event_id_t") -> "qstring &":
        r"""
        set_info(self, id) -> qstring &

        @param id: enum event_id_t
        """
        return _ida_idd.debug_event_t_set_info(self, id)

    def set_bpt(self) -> "bptaddr_t &":
        r"""
        set_bpt(self) -> bptaddr_t
        """
        return _ida_idd.debug_event_t_set_bpt(self)

    def set_exception(self) -> "excinfo_t &":
        r"""
        set_exception(self) -> excinfo_t
        """
        return _ida_idd.debug_event_t_set_exception(self)

    def bpt_ea(self) -> "ea_t":
        r"""
        bpt_ea(self) -> ea_t
        On some systems with special memory mappings the triggered ea might be different
        from the actual ea. Calculate the address to use.
        """
        return _ida_idd.debug_event_t_bpt_ea(self)

# Register debug_event_t in _ida_idd:
_ida_idd.debug_event_t_swigregister(debug_event_t)
class exception_info_t(object):
    r"""
    Proxy of C++ exception_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    code: "uint" = property(_ida_idd.exception_info_t_code_get, _ida_idd.exception_info_t_code_set, doc=r"""code""")
    r"""
    exception code
    """
    flags: "uint32" = property(_ida_idd.exception_info_t_flags_get, _ida_idd.exception_info_t_flags_set, doc=r"""flags""")
    r"""
    Exception info flags
    """

    def break_on(self) -> "bool":
        r"""
        break_on(self) -> bool
        Should we break on the exception?
        """
        return _ida_idd.exception_info_t_break_on(self)

    def handle(self) -> "bool":
        r"""
        handle(self) -> bool
        Should we handle the exception?
        """
        return _ida_idd.exception_info_t_handle(self)
    name: "qstring" = property(_ida_idd.exception_info_t_name_get, _ida_idd.exception_info_t_name_set, doc=r"""name""")
    r"""
    Exception standard name.
    """
    desc: "qstring" = property(_ida_idd.exception_info_t_desc_get, _ida_idd.exception_info_t_desc_set, doc=r"""desc""")
    r"""
    Long message used to display info about the exception.
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> exception_info_t
        __init__(self, _code, _flags, _name, _desc) -> exception_info_t

        @param _code: uint
        @param _flags: uint32
        @param _name: char const *
        @param _desc: char const *
        """
        _ida_idd.exception_info_t_swiginit(self, _ida_idd.new_exception_info_t(*args))
    __swig_destroy__ = _ida_idd.delete_exception_info_t

# Register exception_info_t in _ida_idd:
_ida_idd.exception_info_t_swigregister(exception_info_t)
cvar = _ida_idd.cvar
BPT_WRITE = cvar.BPT_WRITE
r"""
Write access.
"""
BPT_READ = cvar.BPT_READ
r"""
Read access.
"""
BPT_RDWR = cvar.BPT_RDWR
r"""
Read/write access.
"""
BPT_SOFT = cvar.BPT_SOFT
r"""
Software breakpoint.
"""
BPT_EXEC = cvar.BPT_EXEC
r"""
Execute instruction.
"""
BPT_DEFAULT = cvar.BPT_DEFAULT
r"""
Choose bpt type automatically.
"""
EXC_BREAK = _ida_idd.EXC_BREAK
r"""
break on the exception
"""

EXC_HANDLE = _ida_idd.EXC_HANDLE
r"""
should be handled by the debugger?
"""

EXC_MSG = _ida_idd.EXC_MSG
r"""
instead of a warning, log the exception to the output window
"""

EXC_SILENT = _ida_idd.EXC_SILENT
r"""
do not warn or log to the output window
"""


class regval_t(object):
    r"""
    Proxy of C++ regval_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    rvtype: "int32" = property(_ida_idd.regval_t_rvtype_get, _ida_idd.regval_t_rvtype_set, doc=r"""rvtype""")
    r"""
    one of Register value types
    """
    ival: "uint64" = property(_ida_idd.regval_t_ival_get, _ida_idd.regval_t_ival_set, doc=r"""ival""")
    r"""
    RVT_INT.
    """

    def use_bytevec(self) -> "bool":
        r"""
        use_bytevec(self) -> bool
        """
        return _ida_idd.regval_t_use_bytevec(self)

    def __init__(self, *args):
        r"""
        __init__(self) -> regval_t
        __init__(self, r) -> regval_t

        @param r: regval_t const &
        """
        _ida_idd.regval_t_swiginit(self, _ida_idd.new_regval_t(*args))
    __swig_destroy__ = _ida_idd.delete_regval_t

    def clear(self) -> "void":
        r"""
        clear(self)
        Clear register value.
        """
        return _ida_idd.regval_t_clear(self)

    def __eq__(self, r: "regval_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: regval_t const &
        """
        return _ida_idd.regval_t___eq__(self, r)

    def __ne__(self, r: "regval_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: regval_t const &
        """
        return _ida_idd.regval_t___ne__(self, r)

    def swap(self, r: "regval_t") -> "void":
        r"""
        swap(self, r)
        Set this = r and r = this.

        @param r: (C++: regval_t &)
        """
        return _ida_idd.regval_t_swap(self, r)

    def set_int(self, x: "uint64") -> "void":
        r"""
        set_int(self, x)

        @param x: uint64
        """
        return _ida_idd.regval_t_set_int(self, x)

    def set_float(self, v: "bytevec_t const &") -> "void":
        r"""
        set_float(self, v)
        Set float value.

        @param v: (C++: const bytevec_t &) bytevec_t const &
        """
        return _ida_idd.regval_t_set_float(self, v)

    def set_bytes(self, *args) -> "bytevec_t &":
        r"""
        set_bytes(self, data, size, _rvtype=0)
        Initialize this regval to an empty custom value.

        @param data: uchar const *
        @param size: size_t
        @param _rvtype: (C++: int)

        set_bytes(self, v, _rvtype=0)

        @param v: bytevec_t const &
        @param _rvtype: int

        set_bytes(self, _rvtype) -> bytevec_t &

        @param _rvtype: int
        """
        return _ida_idd.regval_t_set_bytes(self, *args)

    def set_unavailable(self) -> "void":
        r"""
        set_unavailable(self)
        Mark as unavailable.
        """
        return _ida_idd.regval_t_set_unavailable(self)

    def bytes(self, *args) -> "bytevec_t const &":
        r"""
        bytes(self) -> bytevec_t
        Get const custom value.
        bytes(self) -> bytevec_t const &
        """
        return _ida_idd.regval_t_bytes(self, *args)

    def get_data(self, *args) -> "void const *":
        r"""
        get_data(self)
        Get const pointer to value.
        get_data(self) -> void const *
        """
        return _ida_idd.regval_t_get_data(self, *args)

    def get_data_size(self) -> "size_t":
        r"""
        get_data_size(self) -> size_t
        Get size of value.
        """
        return _ida_idd.regval_t_get_data_size(self)

    def set_pyval(self, o: "PyObject *", dtype: "op_dtype_t") -> "bool":
        r"""
        set_pyval(self, o, dtype) -> bool

        @param o: PyObject *
        @param dtype: op_dtype_t
        """
        return _ida_idd.regval_t_set_pyval(self, o, dtype)

    def pyval(self, dtype: "op_dtype_t") -> "PyObject *":
        r"""
        pyval(self, dtype) -> PyObject *

        @param dtype: op_dtype_t
        """
        return _ida_idd.regval_t_pyval(self, dtype)

# Register regval_t in _ida_idd:
_ida_idd.regval_t_swigregister(regval_t)
RVT_FLOAT = _ida_idd.RVT_FLOAT
r"""
floating point
"""

RVT_INT = _ida_idd.RVT_INT
r"""
integer
"""

RVT_UNAVAILABLE = _ida_idd.RVT_UNAVAILABLE
r"""
unavailable; other values mean custom data type
"""


class call_stack_info_t(object):
    r"""
    Proxy of C++ call_stack_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    callea: "ea_t" = property(_ida_idd.call_stack_info_t_callea_get, _ida_idd.call_stack_info_t_callea_set, doc=r"""callea""")
    r"""
    the address of the call instruction. for the 0th frame this is usually just the
    current value of EIP.
    """
    funcea: "ea_t" = property(_ida_idd.call_stack_info_t_funcea_get, _ida_idd.call_stack_info_t_funcea_set, doc=r"""funcea""")
    r"""
    the address of the called function
    """
    fp: "ea_t" = property(_ida_idd.call_stack_info_t_fp_get, _ida_idd.call_stack_info_t_fp_set, doc=r"""fp""")
    r"""
    the value of the frame pointer of the called function
    """
    funcok: "bool" = property(_ida_idd.call_stack_info_t_funcok_get, _ida_idd.call_stack_info_t_funcok_set, doc=r"""funcok""")
    r"""
    is the function present?
    """

    def __eq__(self, r: "call_stack_info_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: call_stack_info_t const &
        """
        return _ida_idd.call_stack_info_t___eq__(self, r)

    def __ne__(self, r: "call_stack_info_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: call_stack_info_t const &
        """
        return _ida_idd.call_stack_info_t___ne__(self, r)

    def __init__(self):
        r"""
        __init__(self) -> call_stack_info_t
        """
        _ida_idd.call_stack_info_t_swiginit(self, _ida_idd.new_call_stack_info_t())
    __swig_destroy__ = _ida_idd.delete_call_stack_info_t

# Register call_stack_info_t in _ida_idd:
_ida_idd.call_stack_info_t_swigregister(call_stack_info_t)
class call_stack_t(call_stack_info_vec_t):
    r"""
    Proxy of C++ call_stack_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> call_stack_t
        """
        _ida_idd.call_stack_t_swiginit(self, _ida_idd.new_call_stack_t())
    __swig_destroy__ = _ida_idd.delete_call_stack_t

# Register call_stack_t in _ida_idd:
_ida_idd.call_stack_t_swigregister(call_stack_t)

def dbg_appcall(retval: "idc_value_t *", func_ea: "ea_t", tid: "thid_t", ptif: "tinfo_t", argv: "idc_value_t *", argnum: "size_t") -> "error_t":
    r"""
    dbg_appcall(retval, func_ea, tid, ptif, argv, argnum) -> error_t
    Call a function from the debugged application.

    @param retval: (C++: idc_value_t *) function return value
    * for APPCALL_MANUAL, r will hold the new stack point value
    * for APPCALL_DEBEV, r will hold the exception information upon failure and the
    return code will be eExecThrow
    @param func_ea: (C++: ea_t) address to call
    @param tid: (C++: thid_t) thread to use. NO_THREAD means to use the current thread
    @param ptif: (C++: const tinfo_t *) pointer to type of the function to call
    @param argv: (C++: idc_value_t *) array of arguments
    @param argnum: (C++: size_t) number of actual arguments
    @return: eOk if successful, otherwise an error code
    """
    return _ida_idd.dbg_appcall(retval, func_ea, tid, ptif, argv, argnum)

def cleanup_appcall(tid: "thid_t") -> "error_t":
    r"""
    cleanup_appcall(tid) -> error_t
    Cleanup after manual appcall.

    @param tid: (C++: thid_t) thread to use. NO_THREAD means to use the current thread The
                application state is restored as it was before calling the last
                appcall(). Nested appcalls are supported.
    @return: eOk if successful, otherwise an error code
    """
    return _ida_idd.cleanup_appcall(tid)
class thread_name_t(object):
    r"""
    Proxy of C++ thread_name_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    tid: "thid_t" = property(_ida_idd.thread_name_t_tid_get, _ida_idd.thread_name_t_tid_set, doc=r"""tid""")
    r"""
    thread
    """
    name: "qstring" = property(_ida_idd.thread_name_t_name_get, _ida_idd.thread_name_t_name_set, doc=r"""name""")
    r"""
    new thread name
    """

    def __init__(self):
        r"""
        __init__(self) -> thread_name_t
        """
        _ida_idd.thread_name_t_swiginit(self, _ida_idd.new_thread_name_t())
    __swig_destroy__ = _ida_idd.delete_thread_name_t

# Register thread_name_t in _ida_idd:
_ida_idd.thread_name_t_swigregister(thread_name_t)
RESMOD_NONE = _ida_idd.RESMOD_NONE
r"""
no stepping, run freely
"""

RESMOD_INTO = _ida_idd.RESMOD_INTO
r"""
step into call (the most typical single stepping)
"""

RESMOD_OVER = _ida_idd.RESMOD_OVER
r"""
step over call
"""

RESMOD_OUT = _ida_idd.RESMOD_OUT
r"""
step out of the current function (run until return)
"""

RESMOD_SRCINTO = _ida_idd.RESMOD_SRCINTO
r"""
until control reaches a different source line
"""

RESMOD_SRCOVER = _ida_idd.RESMOD_SRCOVER
r"""
next source line in the current stack frame
"""

RESMOD_SRCOUT = _ida_idd.RESMOD_SRCOUT
r"""
next source line in the previous stack frame
"""

RESMOD_USER = _ida_idd.RESMOD_USER
r"""
step out to the user code
"""

RESMOD_HANDLE = _ida_idd.RESMOD_HANDLE
r"""
step into the exception handler
"""

RESMOD_MAX = _ida_idd.RESMOD_MAX

STEP_TRACE = _ida_idd.STEP_TRACE
r"""
lowest level trace. trace buffers are not maintained
"""

INSN_TRACE = _ida_idd.INSN_TRACE
r"""
instruction tracing
"""

FUNC_TRACE = _ida_idd.FUNC_TRACE
r"""
function tracing
"""

BBLK_TRACE = _ida_idd.BBLK_TRACE
r"""
basic block tracing
"""

DRC_EVENTS = _ida_idd.DRC_EVENTS
r"""
success, there are pending events
"""

DRC_CRC = _ida_idd.DRC_CRC
r"""
success, but the input file crc does not match
"""

DRC_OK = _ida_idd.DRC_OK
r"""
success
"""

DRC_NONE = _ida_idd.DRC_NONE
r"""
reaction to the event not implemented
"""

DRC_FAILED = _ida_idd.DRC_FAILED
r"""
failed or false
"""

DRC_NETERR = _ida_idd.DRC_NETERR
r"""
network error
"""

DRC_NOFILE = _ida_idd.DRC_NOFILE
r"""
file not found
"""

DRC_IDBSEG = _ida_idd.DRC_IDBSEG
r"""
use idb segmentation
"""

DRC_NOPROC = _ida_idd.DRC_NOPROC
r"""
the process does not exist anymore
"""

DRC_NOCHG = _ida_idd.DRC_NOCHG
r"""
no changes
"""

DRC_ERROR = _ida_idd.DRC_ERROR
r"""
unclassified error, may be complemented by errbuf
"""

class debugger_t(object):
    r"""
    Proxy of C++ debugger_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    version: "int" = property(_ida_idd.debugger_t_version_get, _ida_idd.debugger_t_version_set, doc=r"""version""")
    r"""
    Expected kernel version, should be IDD_INTERFACE_VERSION
    """
    name: "char const *" = property(_ida_idd.debugger_t_name_get, _ida_idd.debugger_t_name_set, doc=r"""name""")
    r"""
    Short debugger name like win32 or linux.
    """
    id: "int" = property(_ida_idd.debugger_t_id_get, _ida_idd.debugger_t_id_set, doc=r"""id""")
    r"""
    one of Debugger API module id
    """
    processor: "char const *" = property(_ida_idd.debugger_t_processor_get, _ida_idd.debugger_t_processor_set, doc=r"""processor""")
    r"""
    Required processor name. Used for instant debugging to load the correct
    processor module
    """
    flags: "uint32" = property(_ida_idd.debugger_t_flags_get, _ida_idd.debugger_t_flags_set, doc=r"""flags""")
    flags2: "uint32" = property(_ida_idd.debugger_t_flags2_get, _ida_idd.debugger_t_flags2_set, doc=r"""flags2""")
    r"""
    Debugger module features
    """

    def is_remote(self) -> "bool":
        r"""
        is_remote(self) -> bool
        """
        return _ida_idd.debugger_t_is_remote(self)

    def must_have_hostname(self) -> "bool":
        r"""
        must_have_hostname(self) -> bool
        """
        return _ida_idd.debugger_t_must_have_hostname(self)

    def can_continue_from_bpt(self) -> "bool":
        r"""
        can_continue_from_bpt(self) -> bool
        """
        return _ida_idd.debugger_t_can_continue_from_bpt(self)

    def may_disturb(self) -> "bool":
        r"""
        may_disturb(self) -> bool
        """
        return _ida_idd.debugger_t_may_disturb(self)

    def is_safe(self) -> "bool":
        r"""
        is_safe(self) -> bool
        """
        return _ida_idd.debugger_t_is_safe(self)

    def use_sregs(self) -> "bool":
        r"""
        use_sregs(self) -> bool
        """
        return _ida_idd.debugger_t_use_sregs(self)

    def cache_block_size(self) -> "size_t":
        r"""
        cache_block_size(self) -> size_t
        """
        return _ida_idd.debugger_t_cache_block_size(self)

    def use_memregs(self) -> "bool":
        r"""
        use_memregs(self) -> bool
        """
        return _ida_idd.debugger_t_use_memregs(self)

    def may_take_exit_snapshot(self) -> "bool":
        r"""
        may_take_exit_snapshot(self) -> bool
        """
        return _ida_idd.debugger_t_may_take_exit_snapshot(self)

    def virtual_threads(self) -> "bool":
        r"""
        virtual_threads(self) -> bool
        """
        return _ida_idd.debugger_t_virtual_threads(self)

    def supports_lowcnds(self) -> "bool":
        r"""
        supports_lowcnds(self) -> bool
        """
        return _ida_idd.debugger_t_supports_lowcnds(self)

    def supports_debthread(self) -> "bool":
        r"""
        supports_debthread(self) -> bool
        """
        return _ida_idd.debugger_t_supports_debthread(self)

    def can_debug_standalone_dlls(self) -> "bool":
        r"""
        can_debug_standalone_dlls(self) -> bool
        """
        return _ida_idd.debugger_t_can_debug_standalone_dlls(self)

    def fake_memory(self) -> "bool":
        r"""
        fake_memory(self) -> bool
        """
        return _ida_idd.debugger_t_fake_memory(self)

    def has_get_processes(self) -> "bool":
        r"""
        has_get_processes(self) -> bool
        """
        return _ida_idd.debugger_t_has_get_processes(self)

    def has_attach_process(self) -> "bool":
        r"""
        has_attach_process(self) -> bool
        """
        return _ida_idd.debugger_t_has_attach_process(self)

    def has_detach_process(self) -> "bool":
        r"""
        has_detach_process(self) -> bool
        """
        return _ida_idd.debugger_t_has_detach_process(self)

    def has_request_pause(self) -> "bool":
        r"""
        has_request_pause(self) -> bool
        """
        return _ida_idd.debugger_t_has_request_pause(self)

    def has_set_exception_info(self) -> "bool":
        r"""
        has_set_exception_info(self) -> bool
        """
        return _ida_idd.debugger_t_has_set_exception_info(self)

    def has_thread_suspend(self) -> "bool":
        r"""
        has_thread_suspend(self) -> bool
        """
        return _ida_idd.debugger_t_has_thread_suspend(self)

    def has_thread_continue(self) -> "bool":
        r"""
        has_thread_continue(self) -> bool
        """
        return _ida_idd.debugger_t_has_thread_continue(self)

    def has_set_resume_mode(self) -> "bool":
        r"""
        has_set_resume_mode(self) -> bool
        """
        return _ida_idd.debugger_t_has_set_resume_mode(self)

    def has_thread_get_sreg_base(self) -> "bool":
        r"""
        has_thread_get_sreg_base(self) -> bool
        """
        return _ida_idd.debugger_t_has_thread_get_sreg_base(self)

    def has_check_bpt(self) -> "bool":
        r"""
        has_check_bpt(self) -> bool
        """
        return _ida_idd.debugger_t_has_check_bpt(self)

    def has_open_file(self) -> "bool":
        r"""
        has_open_file(self) -> bool
        """
        return _ida_idd.debugger_t_has_open_file(self)

    def has_update_call_stack(self) -> "bool":
        r"""
        has_update_call_stack(self) -> bool
        """
        return _ida_idd.debugger_t_has_update_call_stack(self)

    def has_appcall(self) -> "bool":
        r"""
        has_appcall(self) -> bool
        """
        return _ida_idd.debugger_t_has_appcall(self)

    def has_rexec(self) -> "bool":
        r"""
        has_rexec(self) -> bool
        """
        return _ida_idd.debugger_t_has_rexec(self)

    def has_map_address(self) -> "bool":
        r"""
        has_map_address(self) -> bool
        """
        return _ida_idd.debugger_t_has_map_address(self)

    def has_soft_bpt(self) -> "bool":
        r"""
        has_soft_bpt(self) -> bool
        """
        return _ida_idd.debugger_t_has_soft_bpt(self)
    default_regclasses: "int" = property(_ida_idd.debugger_t_default_regclasses_get, _ida_idd.debugger_t_default_regclasses_set, doc=r"""default_regclasses""")
    r"""
    Mask of default printed register classes.
    """

    def regs(self, idx: "int") -> "register_info_t &":
        r"""
        regs(self, idx) -> register_info_t

        @param idx: int
        """
        return _ida_idd.debugger_t_regs(self, idx)
    memory_page_size: "int" = property(_ida_idd.debugger_t_memory_page_size_get, _ida_idd.debugger_t_memory_page_size_set, doc=r"""memory_page_size""")
    r"""
    Size of a memory page. Usually 4K.
    """
    bpt_size: "uchar" = property(_ida_idd.debugger_t_bpt_size_get, _ida_idd.debugger_t_bpt_size_set, doc=r"""bpt_size""")
    r"""
    Size of the software breakpoint instruction in bytes.
    """
    filetype: "uchar" = property(_ida_idd.debugger_t_filetype_get, _ida_idd.debugger_t_filetype_set, doc=r"""filetype""")
    r"""
    Input file type for the instant debugger. This value will be used after
    attaching to a new process.
    """
    resume_modes: "ushort" = property(_ida_idd.debugger_t_resume_modes_get, _ida_idd.debugger_t_resume_modes_set, doc=r"""resume_modes""")
    r"""
    Resume modes
    """

    def is_resmod_avail(self, resmod: "int") -> "bool":
        r"""
        is_resmod_avail(self, resmod) -> bool

        @param resmod: int
        """
        return _ida_idd.debugger_t_is_resmod_avail(self, resmod)
    ev_init_debugger = _ida_idd.debugger_t_ev_init_debugger
    r"""
    Initialize debugger. This event is generated in the main thread.
    @param hostname: (const char *)
    @param portnum: (int)
    @param password: (const char *)
    @param errbuf: (qstring *) may be nullptr
    @return: DRC_OK, DRC_FAILED
    """
    
    ev_term_debugger = _ida_idd.debugger_t_ev_term_debugger
    r"""
    Terminate debugger. This event is generated in the main thread.
    @return: DRC_OK, DRC_FAILED
    """
    
    ev_get_processes = _ida_idd.debugger_t_ev_get_processes
    r"""
    Return information about the running processes. This event is generated in the
    main thread. Available if DBG_HAS_GET_PROCESSES is set
    @param procs: (::procinfo_vec_t *)
    @param errbuf: (qstring *) may be nullptr
    @return: DRC_NONE, DRC_OK, DRC_FAILED, DRC_NETERR
    """
    
    ev_start_process = _ida_idd.debugger_t_ev_start_process
    r"""
    Start an executable to debug. This event is generated in debthread. Must be
    implemented.
    @param path: (const char *) path to executable
    @param args: (const char *) arguments to pass to executable
    @param startdir: (const char *) initial working directory of new process
    @param dbg_proc_flags: (uint32) Debug process flags
    @param input_path: (const char *) path to the file that was used to create the
                       idb file It is not always the same as 'path' - e.g. if we are
                       analyzing a dll and want to launch an executable that loads
                       it.
    @param input_file_crc32: (uint32) CRC value for 'input_path'
    @param errbuf: (qstring *) may be nullptr
    @param envs: (launch_env_t *) environment variables for debugged process
    @return: DRC_OK, DRC_CRC, DRC_FAILED, DRC_NETERR, DRC_NOFILE
    """
    
    ev_attach_process = _ida_idd.debugger_t_ev_attach_process
    r"""
    Attach to an existing running process. event_id should be equal to -1 if not
    attaching to a crashed process. This event is generated in debthread. Available
    if DBG_HAS_ATTACH_PROCESS is set
    @param pid: (pid_t) process id to attach
    @param event_id: (int) event to trigger upon attaching
    @param dbg_proc_flags: (uint32) Debug process flags
    @param errbuf: (qstring *) may be nullptr
    @return: DRC_NONE, DRC_OK, DRC_FAILED, DRC_NETERR
    """
    
    ev_detach_process = _ida_idd.debugger_t_ev_detach_process
    r"""
    Detach from the debugged process. May be generated while the process is running
    or suspended. Must detach from the process in any case. The kernel will
    repeatedly call get_debug_event() until PROCESS_DETACHED is received. In this
    mode, all other events will be automatically handled and process will be
    resumed. This event is generated from debthread. Available if
    DBG_HAS_DETACH_PROCESS is set
    @return: DRC_NONE, DRC_OK, DRC_FAILED, DRC_NETERR
    """
    
    ev_get_debapp_attrs = _ida_idd.debugger_t_ev_get_debapp_attrs
    r"""
    Retrieve process- and debugger-specific runtime attributes. This event is
    generated in the main thread.
    @param out_pattrs: (debapp_attrs_t *)
    @return: DRC_NONE, DRC_OK
    """
    
    ev_rebase_if_required_to = _ida_idd.debugger_t_ev_rebase_if_required_to
    r"""
    Rebase database if the debugged program has been rebased by the system. This
    event is generated in the main thread.
    @param new_base: (::ea_t)
    @return: DRC_NONE, DRC_OK
    """
    
    ev_request_pause = _ida_idd.debugger_t_ev_request_pause
    r"""
    Prepare to pause the process. Normally the next get_debug_event() will pause the
    process If the process is sleeping, then the pause will not occur until the
    process wakes up. If the debugger module does not react to this event, then it
    will be impossible to pause the program. This event is generated in debthread.
    Available if DBG_HAS_REQUEST_PAUSE is set
    @param errbuf: (qstring *) may be nullptr
    @return: DRC_NONE, DRC_OK, DRC_FAILED, DRC_NETERR
    """
    
    ev_exit_process = _ida_idd.debugger_t_ev_exit_process
    r"""
    Stop the process. May be generated while the process is running or suspended.
    Must terminate the process in any case. The kernel will repeatedly call
    get_debug_event() until PROCESS_EXITED is received. In this mode, all other
    events will be automatically handled and process will be resumed. This event is
    generated in debthread. Must be implemented.
    @param errbuf: (qstring *) may be nullptr
    @return: DRC_NONE, DRC_OK, DRC_FAILED, DRC_NETERR
    """
    
    ev_get_debug_event = _ida_idd.debugger_t_ev_get_debug_event
    r"""
    Get a pending debug event and suspend the process. This event will be generated
    regularly by IDA. This event is generated in debthread. IMPORTANT: the
    BREAKPOINT/EXCEPTION/STEP events must be reported only after reporting other
    pending events for a thread. Must be implemented.
    @param code: (gdecode_t *)
    @param event: (debug_event_t *)
    @param timeout_ms: (int)
    @retval ignored
    """
    
    ev_resume = _ida_idd.debugger_t_ev_resume
    r"""
    Continue after handling the event. This event is generated in debthread. Must be
    implemented.
    @param event: (debug_event_t *)
    @return: DRC_OK, DRC_FAILED, DRC_NETERR
    """
    
    ev_set_exception_info = _ida_idd.debugger_t_ev_set_exception_info
    r"""
    Set exception handling. This event is generated in debthread or the main thread.
    Available if DBG_HAS_SET_EXCEPTION_INFO is set
    @param info: (exception_info_t *)
    @param qty: (int)
    @return: DRC_NONE, DRC_OK
    """
    
    ev_suspended = _ida_idd.debugger_t_ev_suspended
    r"""
    This event will be generated by the kernel each time it has suspended the
    debuggee process and refreshed the database. The debugger module may add
    information to the database if necessary.

    The reason for introducing this event is that when an event like LOAD_DLL
    happens, the database does not reflect the memory state yet and therefore we
    can't add information about the dll into the database in the get_debug_event()
    function. Only when the kernel has adjusted the database we can do it. Example:
    for loaded PE DLLs we can add the exported function names to the list of debug
    names (see set_debug_names()).

    This event is generated in the main thread.
    @param dlls_added: (bool)
    @param thr_names: (thread_name_vec_t *) (for the kernel only, must be nullptr)
    @return: DRC_NONE, DRC_OK
    """
    
    ev_thread_suspend = _ida_idd.debugger_t_ev_thread_suspend
    r"""
    Suspend a running thread Available if DBG_HAS_THREAD_SUSPEND is set
    @param tid: (thid_t)
    """
    
    ev_thread_continue = _ida_idd.debugger_t_ev_thread_continue
    r"""
    Resume a suspended thread Available if DBG_HAS_THREAD_CONTINUE is set
    @param tid: (thid_t)
    """
    
    ev_set_resume_mode = _ida_idd.debugger_t_ev_set_resume_mode
    r"""
    Specify resume action Available if DBG_HAS_SET_RESUME_MODE is set
    @param tid: (thid_t)
    @param resmod: (resume_mode_t)
    """
    
    ev_read_registers = _ida_idd.debugger_t_ev_read_registers
    r"""
    Read thread registers. This event is generated in debthread. Must be
    implemented.
    @param tid: (thid_t) thread id
    @param clsmask: (int) bitmask of register classes to read
    @param values: (regval_t *) pointer to vector of regvals for all registers.
                   regval must have debugger_t::nregisters elements
    @param errbuf: (qstring *) may be nullptr
    @return: DRC_OK, DRC_FAILED, DRC_NETERR
    """
    
    ev_write_register = _ida_idd.debugger_t_ev_write_register
    r"""
    Write one thread register. This event is generated in debthread. Must be
    implemented.
    @param tid: (thid_t) thread id
    @param regidx: (int) register index
    @param value: (const regval_t *) new value of the register
    @param errbuf: (qstring *) may be nullptr
    @return: DRC_OK, DRC_FAILED, DRC_NETERR
    """
    
    ev_thread_get_sreg_base = _ida_idd.debugger_t_ev_thread_get_sreg_base
    r"""
    Get information about the base of a segment register. Currently used by the IBM
    PC module to resolve references like fs:0. This event is generated in debthread.
    Available if DBG_HAS_THREAD_GET_SREG_BASE is set
    @param answer: (::ea_t *) pointer to the answer. can't be nullptr.
    @param tid: (thid_t) thread id
    @param sreg_value: (int) value of the segment register (returned by
                       get_reg_val())
    @param errbuf: (qstring *) may be nullptr
    @return: DRC_NONE, DRC_OK, DRC_FAILED, DRC_NETERR
    """
    
    ev_get_memory_info = _ida_idd.debugger_t_ev_get_memory_info
    r"""
    Get information on the memory ranges. The debugger module fills 'ranges'. The
    returned vector must be sorted. This event is generated in debthread. Must be
    implemented.
    @param ranges: (meminfo_vec_t *)
    @param errbuf: (qstring *) may be nullptr
    @retval DRC_OK: new memory layout is returned
    @retval DRC_FAILED,DRC_NETERR,DRC_NOPROC,DRC_NOCHG,DRC_IDBSEG
    """
    
    ev_read_memory = _ida_idd.debugger_t_ev_read_memory
    r"""
    Read process memory. This event is generated in debthread.
    @param nbytes: (size_t *) number of read bytes
    @param ea: (::ea_t)
    @param buffer: (void *)
    @param size: (::size_t)
    @param errbuf: (qstring *) may be nullptr
    @return: DRC_OK, DRC_FAILED, DRC_NOPROC
    """
    
    ev_write_memory = _ida_idd.debugger_t_ev_write_memory
    r"""
    Write process memory. This event is generated in debthread.
    @param nbytes: (size_t *) number of written bytes
    @param ea: (::ea_t)
    @param buffer: (const void *)
    @param size: (::size_t)
    @param errbuf: (qstring *) may be nullptr
    @retval DRC_OK,DRC_FAILED,DRC_NOPROC
    """
    
    ev_check_bpt = _ida_idd.debugger_t_ev_check_bpt
    r"""
    Is it possible to set breakpoint? This event is generated in debthread or in the
    main thread if debthread is not running yet. It is generated to verify hardware
    breakpoints. Available if DBG_HAS_CHECK_BPT is set
    @param bptvc: (int *) breakpoint verification codes Breakpoint verification
                  codes
    @param type: (bpttype_t) Hardware breakpoint ids
    @param ea: (::ea_t)
    @param len: (int)
    @return: DRC_OK, DRC_NONE
    """
    
    ev_update_bpts = _ida_idd.debugger_t_ev_update_bpts
    r"""
    Add/del breakpoints. bpts array contains nadd bpts to add, followed by ndel bpts
    to del. This event is generated in debthread.
    @param nbpts: (int *) number of updated breakpoints
    @param bpts: (update_bpt_info_t *)
    @param nadd: (int)
    @param ndel: (int)
    @param errbuf: (qstring *) may be nullptr
    @return: DRC_OK, DRC_FAILED, DRC_NETERR
    """
    
    ev_update_lowcnds = _ida_idd.debugger_t_ev_update_lowcnds
    r"""
    Update low-level (server side) breakpoint conditions. This event is generated in
    debthread.
    @param nupdated: (int *) number of updated conditions
    @param lowcnds: (const lowcnd_t *)
    @param nlowcnds: (int)
    @param errbuf: (qstring *) may be nullptr
    @return: DRC_OK, DRC_NETERR
    """
    
    ev_open_file = _ida_idd.debugger_t_ev_open_file
    r"""
    @param file: (const char *)
    @param fsize: (::uint64 *)
    @param readonly: (bool)
    @param errbuf: (qstring *) may be nullptr
    @retval (int): handle
    @retval -1: error
    """
    
    ev_close_file = _ida_idd.debugger_t_ev_close_file
    r"""
    @param fn: (int) handle
    @return: ignored
    """
    
    ev_read_file = _ida_idd.debugger_t_ev_read_file
    r"""
    @param fn: (int) handle
    @param off: (qoff64_t)
    @param buf: (void *)
    @param size: (size_t)
    @param errbuf: (qstring *) may be nullptr
    @retval number: of read bytes
    """
    
    ev_write_file = _ida_idd.debugger_t_ev_write_file
    r"""
    @param fn: (int) handle
    @param off: (qoff64_t)
    @param buf: (const void *)
    @param size: (size_t)
    @param errbuf: (qstring *) may be nullptr
    @retval number: of written bytes
    """
    
    ev_map_address = _ida_idd.debugger_t_ev_map_address
    r"""
    Map process address. The debugger module may ignore this event. This event is
    generated in debthread. IDA will generate this event only if DBG_HAS_MAP_ADDRESS
    is set.
    @param mapped: (::ea_t *) mapped address or BADADDR
    @param off: (::ea_t) offset to map
    @param regs: (const regval_t *) current register values. if regs == nullptr,
                 then perform global mapping, which is independent on used registers
                 usually such a mapping is a trivial identity mapping
    @param regnum: (int) required mapping. May be specified as a segment register
                   number or a regular register number if the required mapping can
                   be deduced from it. For example, esp implies that ss should be
                   used.
    @return: DRC_NONE, DRC_OK see MAPPED
    """
    
    ev_get_debmod_extensions = _ida_idd.debugger_t_ev_get_debmod_extensions
    r"""
    Get pointer to debugger specific events. This event returns a pointer to a
    structure that holds pointers to debugger module specific events. For
    information on the structure layout, please check the corresponding debugger
    module. Most debugger modules return nullptr because they do not have any
    extensions. Available extensions may be generated from plugins. This event is
    generated in the main thread.
    @param ext: (void **)
    @return: DRC_NONE, DRC_OK see EXT
    """
    
    ev_update_call_stack = _ida_idd.debugger_t_ev_update_call_stack
    r"""
    Calculate the call stack trace for the given thread. This event is generated
    when the process is suspended and should fill the 'trace' object with the
    information about the current call stack. If this event returns DRC_NONE, IDA
    will try to invoke a processor-specific mechanism (see
    processor_t::ev_update_call_stack). If the current processor module does not
    implement stack tracing, then IDA will fall back to a generic algorithm (based
    on the frame pointer chain) to calculate the trace. This event is ideal if the
    debugging targets manage stack frames in a peculiar way, requiring special
    analysis. This event is generated in the main thread. Available if
    DBG_HAS_UPDATE_CALL_STACK is set
    @param tid: (thid_t)
    @param trace: (call_stack_t *)
    @retval DRC_NONE: false or not implemented
    @return: DRC_OK success
    """
    
    ev_appcall = _ida_idd.debugger_t_ev_appcall
    r"""
    Call application function. This event calls a function from the debugged
    application. This event is generated in debthread Available if HAS_APPCALL is
    set
    @param blob_ea: (::ea_t *) ea of stkargs blob, BADADDR if failed and errbuf is
                    filled
    @param func_ea: (::ea_t) address to call
    @param tid: (thid_t) thread to use
    @param fti: (const func_type_data_t *) type information for the generated event
    @param nargs: (int) number of actual arguments
    @param regargs: (const regobjs_t *) information about register arguments
    @param stkargs: (relobj_t *) memory blob to pass as stack arguments (usually
                    contains pointed data) it must be relocated by the callback but
                    not changed otherwise
    @param retregs: (regobjs_t *) event return registers.
    @param errbuf: (qstring *) the error message. if empty on failure, see EVENT.
                   should not be filled if an appcall exception happened but
                   APPCALL_DEBEV is set
    @param event: (debug_event_t *) the last debug event that occurred during
                  appcall execution filled only if the appcall execution fails and
                  APPCALL_DEBEV is set
    @param options: (int) appcall options, usually taken from
                    idainfo::appcall_options. possible values: combination of
                    Appcall options or 0
    @retval DRC_NONE
    @retval DRC_OK,see: BLOB_EA
    """
    
    ev_cleanup_appcall = _ida_idd.debugger_t_ev_cleanup_appcall
    r"""
    Cleanup after appcall(). The debugger module must keep the stack blob in the
    memory until this event is generated. It will be generated by the kernel for
    each successful appcall(). There is an exception: if APPCALL_MANUAL, IDA may not
    call cleanup_appcall. If the user selects to terminate a manual appcall, then
    cleanup_appcall will be generated. Otherwise, the debugger module should
    terminate the appcall when the generated event returns. This event is generated
    in debthread. Available if HAS_APPCALL is set
    @param tid: (thid_t)
    @retval DRC_EVENTS: success, there are pending events
    @retval DRC_OK: success
    @retval DRC_FAILED: failed
    @retval DRC_NETERR: network error
    """
    
    ev_eval_lowcnd = _ida_idd.debugger_t_ev_eval_lowcnd
    r"""
    Evaluate a low level breakpoint condition at 'ea'. Other evaluation errors are
    displayed in a dialog box. This call is used by IDA when the process has already
    been temporarily suspended for some reason and IDA has to decide whether the
    process should be resumed or definitely suspended because of a breakpoint with a
    low level condition. This event is generated in debthread.
    @param tid: (thid_t)
    @param ea: (::ea_t)
    @param errbuf: (qstring *) may be nullptr
    @retval DRC_OK: condition is satisfied
    @retval DRC_FAILED: not satisfied
    @retval DRC_NETERR: network error
    """
    
    ev_send_ioctl = _ida_idd.debugger_t_ev_send_ioctl
    r"""
    Perform a debugger-specific event. This event is generated in debthread
    @param fn: (int)
    @param buf: (const void *)
    @param size: (size_t)
    @param poutbuf: (void **)
    @param poutsize: (ssize_t *)
    @param errbuf: (qstring *) may be nullptr
    @retval DRC_...
    """
    
    ev_dbg_enable_trace = _ida_idd.debugger_t_ev_dbg_enable_trace
    r"""
    Enable/Disable tracing. The kernel will generated this event if the debugger
    plugin set DBG_FLAG_TRACER_MODULE. TRACE_FLAGS can be a set of STEP_TRACE,
    INSN_TRACE, BBLK_TRACE or FUNC_TRACE. This event is generated in the main
    thread.
    @param tid: (thid_t)
    @param enable: (bool)
    @param trace_flags: (int)
    @return: DRC_OK, DRC_FAILED, DRC_NONE
    """
    
    ev_is_tracing_enabled = _ida_idd.debugger_t_ev_is_tracing_enabled
    r"""
    Is tracing enabled? The kernel will generated this event if the debugger plugin
    set DBG_FLAG_TRACER_MODULE. TRACE_BIT can be one of the following: STEP_TRACE,
    INSN_TRACE, BBLK_TRACE or FUNC_TRACE
    @param tid: (thid_t)
    @param tracebit: (int)
    @retval DRC_OK: bit is set
    @retval DRC_NONE: bit is not set or not implemented
    """
    
    ev_rexec = _ida_idd.debugger_t_ev_rexec
    r"""
    Execute a command on the remote computer. Available if DBG_HAS_REXEC is set
    @param cmdline: (const char *)
    @return: (int) exit code
    """
    
    ev_get_srcinfo_path = _ida_idd.debugger_t_ev_get_srcinfo_path
    r"""
    Get the path to a file containing source debug info for the given module. This
    allows srcinfo providers to call into the debugger when looking for debug info.
    It is useful in certain cases like the iOS debugger, which is a remote debugger
    but the remote debugserver does not provide dwarf info. So, we allow the
    debugger client to decide where to look for debug info locally.
    @param path: (qstring *) output path (file might not exist)
    @param base: (::ea_t) base address of a module in the target process
    @return: DRC_NONE, DRC_OK result stored in PATH
    """
    
    ev_bin_search = _ida_idd.debugger_t_ev_bin_search
    r"""
    Search for a binary pattern in the program.
    @param out: (::ea_t *) binary pattern address
    @param start_ea: (::ea_t) linear address, start of range to search
    @param end_ea: (::ea_t) linear address, end of range to search (exclusive)
    @param data: (const ::compiled_binpat_vec_t *) the prepared data to search for
                 (see parse_binpat_str())
    @param srch_flags: (int) combination of Search flags
    @param errbuf: (qstring *) may be nullptr
    @return: DRC_OK EA contains the binary pattern address
    @retval DRC_FAILED: not found
    @retval DRC_NONE: not implemented
    @retval DRC_NETERR,DRC_ERROR
    """
    

    def init_debugger(self, hostname: "char const *", portnum: "int", password: "char const *") -> "bool":
        r"""
        init_debugger(self, hostname, portnum, password) -> bool

        @param hostname: char const *
        @param portnum: int
        @param password: char const *
        """
        return _ida_idd.debugger_t_init_debugger(self, hostname, portnum, password)

    def term_debugger(self) -> "bool":
        r"""
        term_debugger(self) -> bool
        """
        return _ida_idd.debugger_t_term_debugger(self)

    def get_processes(self, procs: "procinfo_vec_t") -> "drc_t":
        r"""
        get_processes(self, procs) -> drc_t

        @param procs: procinfo_vec_t *
        """
        return _ida_idd.debugger_t_get_processes(self, procs)

    def start_process(self, path: "char const *", args: "char const *", envs: "launch_env_t", startdir: "char const *", dbg_proc_flags: "uint32", input_path: "char const *", input_file_crc32: "uint32") -> "drc_t":
        r"""
        start_process(self, path, args, envs, startdir, dbg_proc_flags, input_path, input_file_crc32) -> drc_t

        @param path: char const *
        @param args: char const *
        @param envs: launch_env_t *
        @param startdir: char const *
        @param dbg_proc_flags: uint32
        @param input_path: char const *
        @param input_file_crc32: uint32
        """
        return _ida_idd.debugger_t_start_process(self, path, args, envs, startdir, dbg_proc_flags, input_path, input_file_crc32)

    def attach_process(self, pid: "pid_t", event_id: "int", dbg_proc_flags: "uint32") -> "drc_t":
        r"""
        attach_process(self, pid, event_id, dbg_proc_flags) -> drc_t

        @param pid: pid_t
        @param event_id: int
        @param dbg_proc_flags: uint32
        """
        return _ida_idd.debugger_t_attach_process(self, pid, event_id, dbg_proc_flags)

    def detach_process(self) -> "drc_t":
        r"""
        detach_process(self) -> drc_t
        """
        return _ida_idd.debugger_t_detach_process(self)

    def get_debapp_attrs(self, out_pattrs: "debapp_attrs_t") -> "bool":
        r"""
        get_debapp_attrs(self, out_pattrs) -> bool

        @param out_pattrs: debapp_attrs_t *
        """
        return _ida_idd.debugger_t_get_debapp_attrs(self, out_pattrs)

    def rebase_if_required_to(self, new_base: "ea_t") -> "void":
        r"""
        rebase_if_required_to(self, new_base)

        @param new_base: ea_t
        """
        return _ida_idd.debugger_t_rebase_if_required_to(self, new_base)

    def request_pause(self) -> "drc_t":
        r"""
        request_pause(self) -> drc_t
        """
        return _ida_idd.debugger_t_request_pause(self)

    def exit_process(self) -> "drc_t":
        r"""
        exit_process(self) -> drc_t
        """
        return _ida_idd.debugger_t_exit_process(self)

    def get_debug_event(self, event: "debug_event_t", timeout_ms: "int") -> "gdecode_t":
        r"""
        get_debug_event(self, event, timeout_ms) -> gdecode_t

        @param event: debug_event_t *
        @param timeout_ms: int
        """
        return _ida_idd.debugger_t_get_debug_event(self, event, timeout_ms)

    def resume(self, event: "debug_event_t") -> "drc_t":
        r"""
        resume(self, event) -> drc_t

        @param event: debug_event_t const *
        """
        return _ida_idd.debugger_t_resume(self, event)

    def set_exception_info(self, info: "exception_info_t", qty: "int") -> "void":
        r"""
        set_exception_info(self, info, qty)

        @param info: exception_info_t const *
        @param qty: int
        """
        return _ida_idd.debugger_t_set_exception_info(self, info, qty)

    def suspended(self, dlls_added: "bool", thr_names: "thread_name_vec_t *"=None) -> "void":
        r"""
        suspended(self, dlls_added, thr_names=None)

        @param dlls_added: bool
        @param thr_names: thread_name_vec_t *
        """
        return _ida_idd.debugger_t_suspended(self, dlls_added, thr_names)

    def thread_suspend(self, tid: "thid_t") -> "drc_t":
        r"""
        thread_suspend(self, tid) -> drc_t

        @param tid: thid_t
        """
        return _ida_idd.debugger_t_thread_suspend(self, tid)

    def thread_continue(self, tid: "thid_t") -> "drc_t":
        r"""
        thread_continue(self, tid) -> drc_t

        @param tid: thid_t
        """
        return _ida_idd.debugger_t_thread_continue(self, tid)

    def set_resume_mode(self, tid: "thid_t", resmod: "resume_mode_t") -> "drc_t":
        r"""
        set_resume_mode(self, tid, resmod) -> drc_t

        @param tid: thid_t
        @param resmod: enum resume_mode_t
        """
        return _ida_idd.debugger_t_set_resume_mode(self, tid, resmod)

    def read_registers(self, tid: "thid_t", clsmask: "int", values: "regval_t") -> "drc_t":
        r"""
        read_registers(self, tid, clsmask, values) -> drc_t

        @param tid: thid_t
        @param clsmask: int
        @param values: regval_t *
        """
        return _ida_idd.debugger_t_read_registers(self, tid, clsmask, values)

    def write_register(self, tid: "thid_t", regidx: "int", value: "regval_t") -> "drc_t":
        r"""
        write_register(self, tid, regidx, value) -> drc_t

        @param tid: thid_t
        @param regidx: int
        @param value: regval_t const *
        """
        return _ida_idd.debugger_t_write_register(self, tid, regidx, value)

    def thread_get_sreg_base(self, answer: "ea_t *", tid: "thid_t", sreg_value: "int") -> "drc_t":
        r"""
        thread_get_sreg_base(self, answer, tid, sreg_value) -> drc_t

        @param answer: ea_t *
        @param tid: thid_t
        @param sreg_value: int
        """
        return _ida_idd.debugger_t_thread_get_sreg_base(self, answer, tid, sreg_value)

    def get_memory_info(self, ranges: "meminfo_vec_t") -> "drc_t":
        r"""
        get_memory_info(self, ranges) -> drc_t

        @param ranges: meminfo_vec_t &
        """
        return _ida_idd.debugger_t_get_memory_info(self, ranges)

    def read_memory(self, nbytes: "size_t *", ea: "ea_t", buffer: "void *", size: "size_t") -> "drc_t":
        r"""
        read_memory(self, nbytes, ea, buffer, size) -> drc_t

        @param nbytes: size_t *
        @param ea: ea_t
        @param buffer: void *
        @param size: size_t
        """
        return _ida_idd.debugger_t_read_memory(self, nbytes, ea, buffer, size)

    def write_memory(self, nbytes: "size_t *", ea: "ea_t", buffer: "void const *", size: "size_t") -> "drc_t":
        r"""
        write_memory(self, nbytes, ea, buffer, size) -> drc_t

        @param nbytes: size_t *
        @param ea: ea_t
        @param buffer: void const *
        @param size: size_t
        """
        return _ida_idd.debugger_t_write_memory(self, nbytes, ea, buffer, size)

    def check_bpt(self, bptvc: "int *", type: "bpttype_t", ea: "ea_t", len: "int") -> "drc_t":
        r"""
        check_bpt(self, bptvc, type, ea, len) -> drc_t

        @param bptvc: int *
        @param type: bpttype_t
        @param ea: ea_t
        @param len: int
        """
        return _ida_idd.debugger_t_check_bpt(self, bptvc, type, ea, len)

    def update_bpts(self, nbpts: "int *", bpts: "update_bpt_info_t *", nadd: "int", ndel: "int") -> "drc_t":
        r"""
        update_bpts(self, nbpts, bpts, nadd, ndel) -> drc_t

        @param nbpts: int *
        @param bpts: update_bpt_info_t *
        @param nadd: int
        @param ndel: int
        """
        return _ida_idd.debugger_t_update_bpts(self, nbpts, bpts, nadd, ndel)

    def update_lowcnds(self, nupdated: "int *", lowcnds: "lowcnd_t const *", nlowcnds: "int") -> "drc_t":
        r"""
        update_lowcnds(self, nupdated, lowcnds, nlowcnds) -> drc_t

        @param nupdated: int *
        @param lowcnds: lowcnd_t const *
        @param nlowcnds: int
        """
        return _ida_idd.debugger_t_update_lowcnds(self, nupdated, lowcnds, nlowcnds)

    def open_file(self, file: "char const *", fsize: "uint64 *", readonly: "bool") -> "int":
        r"""
        open_file(self, file, fsize, readonly) -> int

        @param file: char const *
        @param fsize: uint64 *
        @param readonly: bool
        """
        return _ida_idd.debugger_t_open_file(self, file, fsize, readonly)

    def close_file(self, fn: "int") -> "void":
        r"""
        close_file(self, fn)

        @param fn: int
        """
        return _ida_idd.debugger_t_close_file(self, fn)

    def read_file(self, fn: "int", off: "qoff64_t", buf: "void *", size: "size_t") -> "ssize_t":
        r"""
        read_file(self, fn, off, buf, size) -> ssize_t

        @param fn: int
        @param off: qoff64_t
        @param buf: void *
        @param size: size_t
        """
        return _ida_idd.debugger_t_read_file(self, fn, off, buf, size)

    def write_file(self, fn: "int", off: "qoff64_t", buf: "void const *") -> "ssize_t":
        r"""
        write_file(self, fn, off, buf) -> ssize_t

        @param fn: int
        @param off: qoff64_t
        @param buf: void const *
        """
        return _ida_idd.debugger_t_write_file(self, fn, off, buf)

    def map_address(self, off: "ea_t", regs: "regval_t", regnum: "int") -> "ea_t":
        r"""
        map_address(self, off, regs, regnum) -> ea_t

        @param off: ea_t
        @param regs: regval_t const *
        @param regnum: int
        """
        return _ida_idd.debugger_t_map_address(self, off, regs, regnum)

    def get_debmod_extensions(self) -> "void const *":
        r"""
        get_debmod_extensions(self) -> void const *
        """
        return _ida_idd.debugger_t_get_debmod_extensions(self)

    def update_call_stack(self, tid: "thid_t", trace: "call_stack_t") -> "drc_t":
        r"""
        update_call_stack(self, tid, trace) -> drc_t

        @param tid: thid_t
        @param trace: call_stack_t *
        """
        return _ida_idd.debugger_t_update_call_stack(self, tid, trace)

    def cleanup_appcall(self, tid: "thid_t") -> "drc_t":
        r"""
        cleanup_appcall(self, tid) -> drc_t

        @param tid: thid_t
        """
        return _ida_idd.debugger_t_cleanup_appcall(self, tid)

    def eval_lowcnd(self, tid: "thid_t", ea: "ea_t") -> "drc_t":
        r"""
        eval_lowcnd(self, tid, ea) -> drc_t

        @param tid: thid_t
        @param ea: ea_t
        """
        return _ida_idd.debugger_t_eval_lowcnd(self, tid, ea)

    def send_ioctl(self, fn: "int", buf: "void const *", poutbuf: "void **", poutsize: "ssize_t *") -> "drc_t":
        r"""
        send_ioctl(self, fn, buf, poutbuf, poutsize) -> drc_t

        @param fn: int
        @param buf: void const *
        @param poutbuf: void **
        @param poutsize: ssize_t *
        """
        return _ida_idd.debugger_t_send_ioctl(self, fn, buf, poutbuf, poutsize)

    def dbg_enable_trace(self, tid: "thid_t", enable: "bool", trace_flags: "int") -> "bool":
        r"""
        dbg_enable_trace(self, tid, enable, trace_flags) -> bool

        @param tid: thid_t
        @param enable: bool
        @param trace_flags: int
        """
        return _ida_idd.debugger_t_dbg_enable_trace(self, tid, enable, trace_flags)

    def is_tracing_enabled(self, tid: "thid_t", tracebit: "int") -> "bool":
        r"""
        is_tracing_enabled(self, tid, tracebit) -> bool

        @param tid: thid_t
        @param tracebit: int
        """
        return _ida_idd.debugger_t_is_tracing_enabled(self, tid, tracebit)

    def rexec(self, cmdline: "char const *") -> "int":
        r"""
        rexec(self, cmdline) -> int

        @param cmdline: char const *
        """
        return _ida_idd.debugger_t_rexec(self, cmdline)

    def get_srcinfo_path(self, path: "qstring *", base: "ea_t") -> "bool":
        r"""
        get_srcinfo_path(self, path, base) -> bool

        @param path: qstring *
        @param base: ea_t
        """
        return _ida_idd.debugger_t_get_srcinfo_path(self, path, base)

    def bin_search(self, start_ea: "ea_t", end_ea: "ea_t", data: "compiled_binpat_vec_t const &", srch_flags: "int") -> "drc_t":
        r"""
        bin_search(self, start_ea, end_ea, data, srch_flags) -> drc_t

        @param start_ea: ea_t
        @param end_ea: ea_t
        @param data: compiled_binpat_vec_t const &
        @param srch_flags: int
        """
        return _ida_idd.debugger_t_bin_search(self, start_ea, end_ea, data, srch_flags)

    def __get_registers(self) -> "dynamic_wrapped_array_t< register_info_t >":
        r"""
        __get_registers(self) -> dyn_register_info_array
        """
        return _ida_idd.debugger_t___get_registers(self)

    def __get_nregisters(self) -> "int":
        r"""
        __get_nregisters(self) -> int
        """
        return _ida_idd.debugger_t___get_nregisters(self)

    def __get_regclasses(self) -> "PyObject *":
        r"""
        __get_regclasses(self) -> PyObject *
        """
        return _ida_idd.debugger_t___get_regclasses(self)

    def __get_bpt_bytes(self) -> "bytevec_t":
        r"""
        __get_bpt_bytes(self) -> bytevec_t
        """
        return _ida_idd.debugger_t___get_bpt_bytes(self)

    registers = property(__get_registers)
    r"""
    Array of registers. Use regs() to access it.
    """
    nregisters = property(__get_nregisters)
    r"""
    Number of registers.
    """
    regclasses = property(__get_regclasses)
    r"""
    Array of register class names.
    """
    bpt_bytes = property(__get_bpt_bytes)
    r"""
    A software breakpoint instruction.
    """


    def __init__(self):
        r"""
        __init__(self) -> debugger_t
        """
        _ida_idd.debugger_t_swiginit(self, _ida_idd.new_debugger_t())
    __swig_destroy__ = _ida_idd.delete_debugger_t

# Register debugger_t in _ida_idd:
_ida_idd.debugger_t_swigregister(debugger_t)
DEBUGGER_ID_X86_IA32_WIN32_USER = _ida_idd.DEBUGGER_ID_X86_IA32_WIN32_USER
r"""
Userland win32 processes (win32 debugging APIs)
"""

DEBUGGER_ID_X86_IA32_LINUX_USER = _ida_idd.DEBUGGER_ID_X86_IA32_LINUX_USER
r"""
Userland linux processes (ptrace())
"""

DEBUGGER_ID_X86_IA32_MACOSX_USER = _ida_idd.DEBUGGER_ID_X86_IA32_MACOSX_USER
r"""
Userland MAC OS X processes.
"""

DEBUGGER_ID_ARM_IPHONE_USER = _ida_idd.DEBUGGER_ID_ARM_IPHONE_USER
r"""
iPhone 1.x
"""

DEBUGGER_ID_X86_IA32_BOCHS = _ida_idd.DEBUGGER_ID_X86_IA32_BOCHS
r"""
BochsDbg.exe 32.
"""

DEBUGGER_ID_6811_EMULATOR = _ida_idd.DEBUGGER_ID_6811_EMULATOR
r"""
MC6812 emulator (beta)
"""

DEBUGGER_ID_GDB_USER = _ida_idd.DEBUGGER_ID_GDB_USER
r"""
GDB remote.
"""

DEBUGGER_ID_WINDBG = _ida_idd.DEBUGGER_ID_WINDBG
r"""
WinDBG using Microsoft Debug engine.
"""

DEBUGGER_ID_X86_DOSBOX_EMULATOR = _ida_idd.DEBUGGER_ID_X86_DOSBOX_EMULATOR
r"""
Dosbox MS-DOS emulator.
"""

DEBUGGER_ID_ARM_LINUX_USER = _ida_idd.DEBUGGER_ID_ARM_LINUX_USER
r"""
Userland arm linux.
"""

DEBUGGER_ID_TRACE_REPLAYER = _ida_idd.DEBUGGER_ID_TRACE_REPLAYER
r"""
Fake debugger to replay recorded traces.
"""

DEBUGGER_ID_X86_PIN_TRACER = _ida_idd.DEBUGGER_ID_X86_PIN_TRACER
r"""
PIN Tracer module.
"""

DEBUGGER_ID_DALVIK_USER = _ida_idd.DEBUGGER_ID_DALVIK_USER
r"""
Dalvik.
"""

DEBUGGER_ID_XNU_USER = _ida_idd.DEBUGGER_ID_XNU_USER
r"""
XNU Kernel.
"""

DEBUGGER_ID_ARM_MACOS_USER = _ida_idd.DEBUGGER_ID_ARM_MACOS_USER
r"""
Userland arm MAC OS.
"""

DBG_FLAG_REMOTE = _ida_idd.DBG_FLAG_REMOTE
r"""
Remote debugger (requires remote host name unless DBG_FLAG_NOHOST)
"""

DBG_FLAG_NOHOST = _ida_idd.DBG_FLAG_NOHOST
r"""
Remote debugger with does not require network params (host/port/pass). (a unique
device connected to the machine)
"""

DBG_FLAG_FAKE_ATTACH = _ida_idd.DBG_FLAG_FAKE_ATTACH
r"""
PROCESS_ATTACHED is a fake event and does not suspend the execution
"""

DBG_FLAG_HWDATBPT_ONE = _ida_idd.DBG_FLAG_HWDATBPT_ONE
r"""
Hardware data breakpoints are one byte size by default
"""

DBG_FLAG_CAN_CONT_BPT = _ida_idd.DBG_FLAG_CAN_CONT_BPT
r"""
Debugger knows to continue from a bpt. This flag also means that the debugger
module hides breakpoints from ida upon read_memory
"""

DBG_FLAG_NEEDPORT = _ida_idd.DBG_FLAG_NEEDPORT
r"""
Remote debugger requires port number (to be used with DBG_FLAG_NOHOST)
"""

DBG_FLAG_DONT_DISTURB = _ida_idd.DBG_FLAG_DONT_DISTURB
r"""
Debugger can handle only get_debug_event(), request_pause(), exit_process() when
the debugged process is running. The kernel may also call service functions
(file I/O, map_address, etc)
"""

DBG_FLAG_SAFE = _ida_idd.DBG_FLAG_SAFE
r"""
The debugger is safe (probably because it just emulates the application without
really running it)
"""

DBG_FLAG_CLEAN_EXIT = _ida_idd.DBG_FLAG_CLEAN_EXIT
r"""
IDA must suspend the application and remove all breakpoints before terminating
the application. Usually this is not required because the application memory
disappears upon termination.
"""

DBG_FLAG_USE_SREGS = _ida_idd.DBG_FLAG_USE_SREGS
r"""
Take segment register values into account (non flat memory)
"""

DBG_FLAG_NOSTARTDIR = _ida_idd.DBG_FLAG_NOSTARTDIR
r"""
Debugger module doesn't use startup directory.
"""

DBG_FLAG_NOPARAMETERS = _ida_idd.DBG_FLAG_NOPARAMETERS
r"""
Debugger module doesn't use commandline parameters.
"""

DBG_FLAG_NOPASSWORD = _ida_idd.DBG_FLAG_NOPASSWORD
r"""
Remote debugger doesn't use password.
"""

DBG_FLAG_CONNSTRING = _ida_idd.DBG_FLAG_CONNSTRING
r"""
Display "Connection string" instead of "Hostname" and hide the "Port" field.
"""

DBG_FLAG_SMALLBLKS = _ida_idd.DBG_FLAG_SMALLBLKS
r"""
If set, IDA uses 256-byte blocks for caching memory contents. Otherwise,
1024-byte blocks are used
"""

DBG_FLAG_MANMEMINFO = _ida_idd.DBG_FLAG_MANMEMINFO
r"""
If set, manual memory region manipulation commands will be available. Use this
bit for debugger modules that cannot return memory layout information
"""

DBG_FLAG_EXITSHOTOK = _ida_idd.DBG_FLAG_EXITSHOTOK
r"""
IDA may take a memory snapshot at PROCESS_EXITED event.
"""

DBG_FLAG_VIRTHREADS = _ida_idd.DBG_FLAG_VIRTHREADS
r"""
Thread IDs may be shuffled after each debug event. (to be used for virtual
threads that represent cpus for windbg kmode)
"""

DBG_FLAG_LOWCNDS = _ida_idd.DBG_FLAG_LOWCNDS
r"""
Low level breakpoint conditions are supported.
"""

DBG_FLAG_DEBTHREAD = _ida_idd.DBG_FLAG_DEBTHREAD
r"""
Supports creation of a separate thread in ida for the debugger (the debthread).
Most debugger functions will be called from debthread (exceptions are marked
below) The debugger module may directly call only THREAD_SAFE functions. To call
other functions please use execute_sync(). The debthread significantly increases
debugging speed, especially if debug events occur frequently.
"""

DBG_FLAG_DEBUG_DLL = _ida_idd.DBG_FLAG_DEBUG_DLL
r"""
Can debug standalone DLLs. For example, Bochs debugger can debug any snippet of
code
"""

DBG_FLAG_FAKE_MEMORY = _ida_idd.DBG_FLAG_FAKE_MEMORY
r"""
get_memory_info()/read_memory()/write_memory() work with the idb. (there is no
real process to read from, as for the replayer module) the kernel will not call
these functions if this flag is set. however, third party plugins may call them,
they must be implemented.
"""

DBG_FLAG_ANYSIZE_HWBPT = _ida_idd.DBG_FLAG_ANYSIZE_HWBPT
r"""
The debugger supports arbitrary size hardware breakpoints.
"""

DBG_FLAG_TRACER_MODULE = _ida_idd.DBG_FLAG_TRACER_MODULE
r"""
The module is a tracer, not a full featured debugger module.
"""

DBG_FLAG_PREFER_SWBPTS = _ida_idd.DBG_FLAG_PREFER_SWBPTS
r"""
Prefer to use software breakpoints.
"""

DBG_FLAG_LAZY_WATCHPTS = _ida_idd.DBG_FLAG_LAZY_WATCHPTS
r"""
Watchpoints are triggered before the offending instruction is executed. The
debugger must temporarily disable the watchpoint and single-step before
resuming.
"""

DBG_FLAG_FAST_STEP = _ida_idd.DBG_FLAG_FAST_STEP
r"""
Do not refresh memory layout info after single stepping.
"""

DBG_FLAG_ADD_ENVS = _ida_idd.DBG_FLAG_ADD_ENVS
r"""
The debugger supports launching processes with environment variables.
"""

DBG_FLAG_MERGE_ENVS = _ida_idd.DBG_FLAG_MERGE_ENVS
r"""
The debugger supports merge or replace setting for environment variables (only
makes sense if DBG_FLAG_ADD_ENVS is set)
"""

DBG_FLAG_DISABLE_ASLR = _ida_idd.DBG_FLAG_DISABLE_ASLR
r"""
The debugger support ASLR disabling (Address space layout randomization)
"""

DBG_HAS_GET_PROCESSES = _ida_idd.DBG_HAS_GET_PROCESSES
r"""
supports ev_get_processes
"""

DBG_HAS_ATTACH_PROCESS = _ida_idd.DBG_HAS_ATTACH_PROCESS
r"""
supports ev_attach_process
"""

DBG_HAS_DETACH_PROCESS = _ida_idd.DBG_HAS_DETACH_PROCESS
r"""
supports ev_detach_process
"""

DBG_HAS_REQUEST_PAUSE = _ida_idd.DBG_HAS_REQUEST_PAUSE
r"""
supports ev_request_pause
"""

DBG_HAS_SET_EXCEPTION_INFO = _ida_idd.DBG_HAS_SET_EXCEPTION_INFO
r"""
supports ev_set_exception_info
"""

DBG_HAS_THREAD_SUSPEND = _ida_idd.DBG_HAS_THREAD_SUSPEND
r"""
supports ev_thread_suspend
"""

DBG_HAS_THREAD_CONTINUE = _ida_idd.DBG_HAS_THREAD_CONTINUE
r"""
supports ev_thread_continue
"""

DBG_HAS_SET_RESUME_MODE = _ida_idd.DBG_HAS_SET_RESUME_MODE
r"""
supports ev_set_resume_mode. Cannot be set inside the
debugger_t::init_debugger()
"""

DBG_HAS_THREAD_GET_SREG_BASE = _ida_idd.DBG_HAS_THREAD_GET_SREG_BASE
r"""
supports ev_thread_get_sreg_base
"""

DBG_HAS_CHECK_BPT = _ida_idd.DBG_HAS_CHECK_BPT
r"""
supports ev_check_bpt
"""

DBG_HAS_OPEN_FILE = _ida_idd.DBG_HAS_OPEN_FILE
r"""
supports ev_open_file, ev_close_file, ev_read_file, ev_write_file
"""

DBG_HAS_UPDATE_CALL_STACK = _ida_idd.DBG_HAS_UPDATE_CALL_STACK
r"""
supports ev_update_call_stack
"""

DBG_HAS_APPCALL = _ida_idd.DBG_HAS_APPCALL
r"""
supports ev_appcall, ev_cleanup_appcall
"""

DBG_HAS_REXEC = _ida_idd.DBG_HAS_REXEC
r"""
supports ev_rexec
"""

DBG_HAS_MAP_ADDRESS = _ida_idd.DBG_HAS_MAP_ADDRESS
r"""
supports ev_map_address. Avoid using this bit, especially together with
DBG_FLAG_DEBTHREAD because it may cause big slow downs
"""

DBG_RESMOD_STEP_INTO = _ida_idd.DBG_RESMOD_STEP_INTO
r"""
RESMOD_INTO is available
"""

DBG_RESMOD_STEP_OVER = _ida_idd.DBG_RESMOD_STEP_OVER
r"""
RESMOD_OVER is available
"""

DBG_RESMOD_STEP_OUT = _ida_idd.DBG_RESMOD_STEP_OUT
r"""
RESMOD_OUT is available
"""

DBG_RESMOD_STEP_SRCINTO = _ida_idd.DBG_RESMOD_STEP_SRCINTO
r"""
RESMOD_SRCINTO is available
"""

DBG_RESMOD_STEP_SRCOVER = _ida_idd.DBG_RESMOD_STEP_SRCOVER
r"""
RESMOD_SRCOVER is available
"""

DBG_RESMOD_STEP_SRCOUT = _ida_idd.DBG_RESMOD_STEP_SRCOUT
r"""
RESMOD_SRCOUT is available
"""

DBG_RESMOD_STEP_USER = _ida_idd.DBG_RESMOD_STEP_USER
r"""
RESMOD_USER is available
"""

DBG_RESMOD_STEP_HANDLE = _ida_idd.DBG_RESMOD_STEP_HANDLE
r"""
RESMOD_HANDLE is available
"""

DBG_PROC_IS_DLL = _ida_idd.DBG_PROC_IS_DLL
r"""
database contains a dll (not exe)
"""

DBG_PROC_IS_GUI = _ida_idd.DBG_PROC_IS_GUI
r"""
using gui version of ida
"""

DBG_PROC_32BIT = _ida_idd.DBG_PROC_32BIT
r"""
application is 32-bit
"""

DBG_PROC_64BIT = _ida_idd.DBG_PROC_64BIT
r"""
application is 64-bit
"""

DBG_NO_TRACE = _ida_idd.DBG_NO_TRACE
r"""
do not trace the application (mac/linux)
"""

DBG_HIDE_WINDOW = _ida_idd.DBG_HIDE_WINDOW
r"""
application should be hidden on startup (windows)
"""

DBG_SUSPENDED = _ida_idd.DBG_SUSPENDED
r"""
application should be suspended on startup (mac)
"""

DBG_NO_ASLR = _ida_idd.DBG_NO_ASLR
r"""
disable ASLR (linux)
"""

BPT_OK = _ida_idd.BPT_OK
r"""
breakpoint can be set
"""

BPT_INTERNAL_ERR = _ida_idd.BPT_INTERNAL_ERR
r"""
interr occurred when verifying breakpoint
"""

BPT_BAD_TYPE = _ida_idd.BPT_BAD_TYPE
r"""
bpt type is not supported
"""

BPT_BAD_ALIGN = _ida_idd.BPT_BAD_ALIGN
r"""
alignment is invalid
"""

BPT_BAD_ADDR = _ida_idd.BPT_BAD_ADDR
r"""
ea is invalid
"""

BPT_BAD_LEN = _ida_idd.BPT_BAD_LEN
r"""
bpt len is invalid
"""

BPT_TOO_MANY = _ida_idd.BPT_TOO_MANY
r"""
reached max number of supported breakpoints
"""

BPT_READ_ERROR = _ida_idd.BPT_READ_ERROR
r"""
failed to read memory at bpt ea
"""

BPT_WRITE_ERROR = _ida_idd.BPT_WRITE_ERROR
r"""
failed to write memory at bpt ea
"""

BPT_SKIP = _ida_idd.BPT_SKIP
r"""
update_bpts(): do not process bpt
"""

BPT_PAGE_OK = _ida_idd.BPT_PAGE_OK
r"""
update_bpts(): ok, added a page bpt
"""

APPCALL_MANUAL = _ida_idd.APPCALL_MANUAL
r"""
Only set up the appcall, do not run. debugger_t::cleanup_appcall will not be
generated by ida!
"""

APPCALL_DEBEV = _ida_idd.APPCALL_DEBEV
r"""
Return debug event information.
"""

APPCALL_TIMEOUT = _ida_idd.APPCALL_TIMEOUT
r"""
Appcall with timeout. If timed out, errbuf will contain "timeout". See
SET_APPCALL_TIMEOUT and GET_APPCALL_TIMEOUT
"""


RQ_MASKING = _ida_idd.RQ_MASKING
r"""
masking step handler: unless errors, tmpbpt handlers won't be generated should
be used only with request_internal_step()
"""

RQ_SUSPEND = _ida_idd.RQ_SUSPEND
r"""
suspending step handler: suspends the app handle_debug_event: suspends the app
"""

RQ_NOSUSP = _ida_idd.RQ_NOSUSP
r"""
running step handler: continues the app
"""

RQ_IGNWERR = _ida_idd.RQ_IGNWERR
r"""
ignore breakpoint write failures
"""

RQ_SILENT = _ida_idd.RQ_SILENT
r"""
all: no dialog boxes
"""

RQ_VERBOSE = _ida_idd.RQ_VERBOSE
r"""
all: display dialog boxes
"""

RQ_SWSCREEN = _ida_idd.RQ_SWSCREEN
r"""
handle_debug_event: switch screens
"""

RQ__NOTHRRF = _ida_idd.RQ__NOTHRRF
r"""
handle_debug_event: do not refresh threads
"""

RQ_PROCEXIT = _ida_idd.RQ_PROCEXIT
r"""
snapshots: the process is exiting
"""

RQ_IDAIDLE = _ida_idd.RQ_IDAIDLE
r"""
handle_debug_event: ida is idle
"""

RQ_SUSPRUN = _ida_idd.RQ_SUSPRUN
r"""
handle_debug_event: suspend at PROCESS_STARTED
"""

RQ_RESUME = _ida_idd.RQ_RESUME
r"""
handle_debug_event: resume application
"""

RQ_RESMOD = _ida_idd.RQ_RESMOD
r"""
resume_mode_t
"""

RQ_RESMOD_SHIFT = _ida_idd.RQ_RESMOD_SHIFT


def cpu2ieee(ieee_out: "fpvalue_t *", cpu_fpval: "void const *", size: "int") -> "int":
    r"""
    cpu2ieee(ieee_out, cpu_fpval, size) -> int
    Convert a floating point number in CPU native format to IDA's internal format.

    @param ieee_out: (C++: fpvalue_t *) output buffer
    @param cpu_fpval: (C++: const void *) floating point number in CPU native format
    @param size: (C++: int) size of cpu_fpval in bytes (size of the input buffer)
    @return: Floating point/IEEE Conversion codes
    """
    return _ida_idd.cpu2ieee(ieee_out, cpu_fpval, size)

def ieee2cpu(cpu_fpval_out: "void *", ieee: "fpvalue_t const &", size: "int") -> "int":
    r"""
    ieee2cpu(cpu_fpval_out, ieee, size) -> int
    Convert a floating point number in IDA's internal format to CPU native format.

    @param cpu_fpval_out: (C++: void *) output buffer
    @param ieee: (C++: const fpvalue_t &) floating point number of IDA's internal format
    @param size: (C++: int) size of cpu_fpval in bytes (size of the output buffer)
    @return: Floating point/IEEE Conversion codes
    """
    return _ida_idd.ieee2cpu(cpu_fpval_out, ieee, size)
class dyn_register_info_array(object):
    r"""
    Proxy of C++ dynamic_wrapped_array_t< register_info_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    data: "register_info_t *" = property(_ida_idd.dyn_register_info_array_data_get, doc=r"""data""")
    count: "size_t" = property(_ida_idd.dyn_register_info_array_count_get, doc=r"""count""")

    def __init__(self, _data: "register_info_t", _count: "size_t"):
        r"""
        __init__(self, _data, _count) -> dyn_register_info_array

        @param _data: register_info_t *
        @param _count: size_t
        """
        _ida_idd.dyn_register_info_array_swiginit(self, _ida_idd.new_dyn_register_info_array(_data, _count))

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_idd.dyn_register_info_array___len__(self)

    def __getitem__(self, i: "size_t") -> "register_info_t const &":
        r"""
        __getitem__(self, i) -> register_info_t

        @param i: size_t
        """
        return _ida_idd.dyn_register_info_array___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "register_info_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: register_info_t const &
        """
        return _ida_idd.dyn_register_info_array___setitem__(self, i, v)

    __iter__ = ida_idaapi._bounded_getitem_iterator

    __swig_destroy__ = _ida_idd.delete_dyn_register_info_array

# Register dyn_register_info_array in _ida_idd:
_ida_idd.dyn_register_info_array_swigregister(dyn_register_info_array)

def get_dbg() -> "debugger_t *":
    r"""
    get_dbg() -> debugger_t
    """
    return _ida_idd.get_dbg()

def dbg_get_registers() -> "PyObject *":
    r"""
    dbg_get_registers() -> PyObject *
    This function returns the register definition from the currently loaded debugger.
    Basically, it returns an array of structure similar to to idd.hpp / register_info_t

    @return:     None if no debugger is loaded
        tuple(name, flags, class, dtype, bit_strings, default_bit_strings_mask)
        The bit_strings can be a tuple of strings or None (if the register does not have bit_strings)
    """
    return _ida_idd.dbg_get_registers()

def dbg_get_thread_sreg_base(tid: "thid_t", sreg_value: "int") -> "PyObject *":
    r"""
    dbg_get_thread_sreg_base(tid, sreg_value) -> PyObject *
    Returns the segment register base value

    @param tid: thread id
    @param sreg_value: segment register (selector) value
    @return:     - The base as an 'ea'
        - Or None on failure
    """
    return _ida_idd.dbg_get_thread_sreg_base(tid, sreg_value)

def dbg_read_memory(ea: "ea_t", sz: "size_t") -> "PyObject *":
    r"""
    dbg_read_memory(ea, sz) -> PyObject *
    Reads from the debugee's memory at the specified ea

    @param ea: ea_t
    @param sz: size_t
    @return:     - The read buffer (as bytes)
        - Or None on failure
    """
    return _ida_idd.dbg_read_memory(ea, sz)

def dbg_write_memory(ea: "ea_t", buf: "bytevec_t const &") -> "PyObject *":
    r"""
    dbg_write_memory(ea, buf) -> bool
    Writes a buffer to the debugee's memory

    @param ea: ea_t
    @param buf: bytevec_t const &
    @return: Boolean
    """
    return _ida_idd.dbg_write_memory(ea, buf)

def dbg_get_name() -> "PyObject *":
    r"""
    dbg_get_name() -> PyObject *
    This function returns the current debugger's name.

    @return: Debugger name or None if no debugger is active
    """
    return _ida_idd.dbg_get_name()

def dbg_get_memory_info() -> "PyObject *":
    r"""
    dbg_get_memory_info() -> PyObject *
    This function returns the memory configuration of a debugged process.

    @return:     None if no debugger is active
        tuple(start_ea, end_ea, name, sclass, sbase, bitness, perm)
    """
    return _ida_idd.dbg_get_memory_info()

def appcall(func_ea: "ea_t", tid: "thid_t", _type_or_none: "bytevec_t const &", _fields: "bytevec_t const &", arg_list: "PyObject *") -> "PyObject *":
    r"""
    appcall(func_ea, tid, _type_or_none, _fields, arg_list) -> PyObject *

    @param func_ea: ea_t
    @param tid: thid_t
    @param _type_or_none: bytevec_t const &
    @param _fields: bytevec_t const &
    @param arg_list: PyObject *
    """
    return _ida_idd.appcall(func_ea, tid, _type_or_none, _fields, arg_list)

def get_event_module_name(ev: "debug_event_t") -> "size_t":
    r"""
    get_event_module_name(ev) -> str

    @param ev: debug_event_t const *
    """
    return _ida_idd.get_event_module_name(ev)

def get_event_module_base(ev: "debug_event_t") -> "ea_t":
    r"""
    get_event_module_base(ev) -> ea_t

    @param ev: debug_event_t const *
    """
    return _ida_idd.get_event_module_base(ev)

def get_event_module_size(ev: "debug_event_t") -> "asize_t":
    r"""
    get_event_module_size(ev) -> asize_t

    @param ev: debug_event_t const *
    """
    return _ida_idd.get_event_module_size(ev)

def get_event_exc_info(ev: "debug_event_t") -> "size_t":
    r"""
    get_event_exc_info(ev) -> str

    @param ev: debug_event_t const *
    """
    return _ida_idd.get_event_exc_info(ev)

def get_event_info(ev: "debug_event_t") -> "size_t":
    r"""
    get_event_info(ev) -> str

    @param ev: debug_event_t const *
    """
    return _ida_idd.get_event_info(ev)

def get_event_bpt_hea(ev: "debug_event_t") -> "ea_t":
    r"""
    get_event_bpt_hea(ev) -> ea_t

    @param ev: debug_event_t const *
    """
    return _ida_idd.get_event_bpt_hea(ev)

def get_event_exc_code(ev: "debug_event_t") -> "uint":
    r"""
    get_event_exc_code(ev) -> uint

    @param ev: debug_event_t const *
    """
    return _ida_idd.get_event_exc_code(ev)

def get_event_exc_ea(ev: "debug_event_t") -> "ea_t":
    r"""
    get_event_exc_ea(ev) -> ea_t

    @param ev: debug_event_t const *
    """
    return _ida_idd.get_event_exc_ea(ev)

def can_exc_continue(ev: "debug_event_t") -> "bool":
    r"""
    can_exc_continue(ev) -> bool

    @param ev: debug_event_t const *
    """
    return _ida_idd.can_exc_continue(ev)

#<pycode(py_idd)>
NO_PROCESS = 0xFFFFFFFF
r"""
No process.
"""
NO_THREAD  = 0

import types
import _ida_idaapi
import _ida_dbg
import _ida_typeinf
import _ida_name
import _ida_bytes
import _ida_ida
import ida_idaapi
import ida_typeinf

dbg_can_query = _ida_dbg.dbg_can_query

# -----------------------------------------------------------------------
class Appcall_array__(object):
    r"""
    This class is used with Appcall.array() method
    """
    def __init__(self, tp):
        self.__type = tp

    def pack(self, L):
        r"""
        Packs a list or tuple into a byref buffer
        """
        t = type(L)
        if not (t == list or t == tuple):
            raise ValueError("Either a list or a tuple must be passed")
        self.__size = len(L)
        if self.__size == 1:
            self.__typedobj = Appcall__.typedobj(self.__type + ";")
        else:
            self.__typedobj = Appcall__.typedobj("%s x[%d];" % (self.__type, self.__size))
# Now store the object in a string buffer
        ok, buf = self.__typedobj.store(L)
        if ok:
            return Appcall__.byref(buf)
        else:
            return None

    def try_to_convert_to_list(self, obj):
        r"""
        Is this object a list? We check for the existance of attribute zero and attribute self.size-1
        """
        if not (hasattr(obj, "0") and hasattr(obj, str(self.__size-1))):
            return obj
# at this point, we are sure we have an "idc list"
# let us convert to a Python list
        return [getattr(obj, str(x)) for x in range(0, self.__size)]

    def unpack(self, buf, as_list=True):
        r"""
        Unpacks an array back into a list or an object
        """
# take the value from the special ref object
        if isinstance(buf, ida_idaapi.PyIdc_cvt_refclass__):
            buf = buf.value

# we can only unpack from strings
        if type(buf) != bytes:
            raise ValueError("Cannot unpack this type!")
# now unpack
        ok, obj = self.__typedobj.retrieve(buf)
        if not ok:
            raise ValueError("Failed while unpacking!")
        if not as_list:
            return obj
        return self.try_to_convert_to_list(obj)


# -----------------------------------------------------------------------
# Wrapper class for the appcall()
class Appcall_callable__(object):
    r"""
    Helper class to issue appcalls using a natural syntax:
      appcall.FunctionNameInTheDatabase(arguments, ....)
    or
      appcall["Function@8"](arguments, ...)
    or
      f8 = appcall["Function@8"]
      f8(arg1, arg2, ...)
    or
      o = appcall.obj()
      i = byref(5)
      appcall.funcname(arg1, i, "hello", o)
    """
    def __init__(self, ea, tinfo_or_typestr = None, fields = None):
        r"""
        Initializes an appcall with a given function ea
        """
        self.__ea      = ea
        self.__tif     = None
        self.__type    = None
        self.__fields  = None
        self.__options = None # Appcall options
        self.__timeout = None # Appcall timeout

        if tinfo_or_typestr:
          if isinstance(tinfo_or_typestr, ida_idaapi.string_types):
# a type string? assume (typestr, fields), try to deserialize
            tif = ida_typeinf.tinfo_t()
            if not tif.deserialize(None, tinfo_or_typestr, fields):
              raise ValueError("Could not deserialize type string")
          else:
            if not isinstance(tinfo_or_typestr, ida_typeinf.tinfo_t):
              raise ValueError("Invalid argument 'tinfo_or_typestr'")
            tif = tinfo_or_typestr
          self.__tif = tif
          (self.__type, self.__fields, _) = tif.serialize()

    def __get_timeout(self):
        return self.__timeout

    def __set_timeout(self, v):
        self.__timeout = v

    timeout = property(__get_timeout, __set_timeout)
    r"""
    An Appcall instance can change its timeout value with this attribute
    """

    def __get_options(self):
        return self.__options if self.__options != None else Appcall__.get_appcall_options()

    def __set_options(self, v):
        if self.timeout:
# If timeout value is set, then put the timeout flag and encode the timeout value
            v |= Appcall__.APPCALL_TIMEOUT | (self.timeout << 16)
        else:
# Timeout is not set, then clear the timeout flag
            v &= ~Appcall__.APPCALL_TIMEOUT

        self.__options = v

    options = property(__get_options, __set_options)
    r"""
    Sets the Appcall options locally to this Appcall instance
    """

    def __call__(self, *args):
        r"""
        Make object callable. We redirect execution to idaapi.appcall()
        """
        if self.ea is None:
            raise ValueError("Object not callable!")

# convert arguments to a list
        arg_list = list(args)

# Save appcall options and set new global options
        old_opt = Appcall__.get_appcall_options()
        Appcall__.set_appcall_options(self.options)

# Do the Appcall (use the wrapped version)
        try:
            return _ida_idd.appcall(
                self.ea,
                _ida_dbg.get_current_thread(),
                self.type,
                self.fields,
                arg_list)
        finally:
# Restore appcall options
            Appcall__.set_appcall_options(old_opt)

    def __get_ea(self):
        return self.__ea

    def __set_ea(self, val):
        self.__ea = val

    ea = property(__get_ea, __set_ea)
    r"""
    Returns or sets the EA associated with this object
    """

    def __get_tif(self):
        return self.__tif

    tif = property(__get_tif)
    r"""
    Returns the tinfo_t object
    """

    def __get_size(self):
        if self.__type == None:
            return -1
        r = _ida_typeinf.calc_type_size(None, self.__type)
        if not r:
            return -1
        return r

    size = property(__get_size)
    r"""
    Returns the size of the type
    """

    def __get_type(self):
        return self.__type

    type = property(__get_type)
    r"""
    Returns the typestring
    """

    def __get_fields(self):
        return self.__fields

    fields = property(__get_fields)
    r"""
    Returns the field names
    """


    def retrieve(self, src=None, flags=0):
        r"""
        Unpacks a typed object from the database if an ea is given or from a string if a string was passed
        @param src: the address of the object or a string
        @return: Returns a tuple of boolean and object or error number (Bool, Error | Object).
        """

# Nothing passed? Take the address and unpack from the database
        if src is None:
            src = self.ea

        if type(src) == bytes:
            return _ida_typeinf.unpack_object_from_bv(None, self.type, self.fields, src, flags)
        else:
            return _ida_typeinf.unpack_object_from_idb(None, self.type, self.fields, src, flags)

    def store(self, obj, dest_ea=None, base_ea=0, flags=0):
        r"""
        Packs an object into a given ea if provided or into a string if no address was passed.
        @param obj: The object to pack
        @param dest_ea: If packing to idb this will be the store location
        @param base_ea: If packing to a buffer, this will be the base that will be used to relocate the pointers

        @return:     - If packing to a string then a Tuple(Boolean, packed_string or error code)
            - If packing to the database then a return code is returned (0 is success)
        """

# no ea passed? thus pack to a string
        if dest_ea is None:
            return _ida_typeinf.pack_object_to_bv(obj,
                                             None,
                                             self.type,
                                             self.fields,
                                             base_ea,
                                             flags)
        else:
            return _ida_typeinf.pack_object_to_idb(obj,
                                              None,
                                              self.type,
                                              self.fields,
                                              dest_ea,
                                              flags)

# -----------------------------------------------------------------------
class Appcall_consts__(object):
    r"""
    Helper class used by Appcall.Consts attribute
    It is used to retrieve constants via attribute access
    """
    def __init__(self, default=None):
        self.__default = default

    def __getattr__(self, attr):
        v = Appcall__.valueof(attr, self.__default)
        if v is None:
            raise AttributeError("No constant with name " + attr)
        return v

# -----------------------------------------------------------------------
class Appcall__(object):
    APPCALL_MANUAL = 0x1
    r"""
    Only set up the appcall, do not run it.
    you should call CleanupAppcall() when finished
    """

    APPCALL_DEBEV  = 0x2
    r"""
    Return debug event information
    If this bit is set, exceptions during appcall
    will generate idc exceptions with full
    information about the exception
    """

    APPCALL_TIMEOUT = 0x4
    r"""
    Appcall with timeout
    The timeout value in milliseconds is specified
    in the high 2 bytes of the 'options' argument:
    If timed out, errbuf will contain "timeout".
    """

    __name__ = "Appcall__"

    def __init__(self):
        self.__consts = Appcall_consts__()

    def __get_consts(self):
        return self.__consts

    Consts = property(__get_consts)
    r"""
    Use Appcall.Consts.CONST_NAME to access constants
    """

    @staticmethod
    def __name_or_ea(name_or_ea):
        r"""
        Function that accepts a name or an ea and checks if the address is enabled.
        If a name is passed then idaapi.get_name_ea() is applied to retrieve the name
        @return:     - Returns the resolved EA or
            - Raises an exception if the address is not enabled
        """

# a string? try to resolve it
        if type(name_or_ea) in ida_idaapi.string_types:
            ea = _ida_name.get_name_ea(_ida_idaapi.BADADDR, name_or_ea)
        else:
            ea = name_or_ea
# could not resolve name or invalid address?
        if ea == _ida_idaapi.BADADDR or not _ida_bytes.is_mapped(ea):
            raise AttributeError("Undefined function " + name_or_ea)
        return ea

    @staticmethod
    def __typedecl_or_tinfo(typedecl_or_tinfo, flags = None):
        r"""
        Function that accepts a tinfo_t object or type declaration as a string
        If a type declaration is passed then ida_typeinf.parse_decl() is applied to prepare tinfo_t object
        @return:     - Returns the tinfo_t object
            - Raises an exception if the declaration cannot be parsed
        """

# a string? try to parse it
        if isinstance(typedecl_or_tinfo, ida_idaapi.string_types):
          if flags is None:
              flags = ida_typeinf.PT_SIL|ida_typeinf.PT_NDC|ida_typeinf.PT_TYP
          tif = ida_typeinf.tinfo_t()
          if ida_typeinf.parse_decl(tif, None, typedecl_or_tinfo, flags) == None:
            raise ValueError("Could not parse type: " + typedecl_or_tinfo)
        else:
            if not isinstance(typedecl_or_tinfo, ida_typeinf.tinfo_t):
              raise ValueError("Invalid argument 'typedecl_or_tinfo'")
            tif = typedecl_or_tinfo
        return tif

    @staticmethod
    def proto(name_or_ea, proto_or_tinfo, flags = None):
        r"""
        Allows you to instantiate an appcall (callable object) with the desired prototype
        @param name_or_ea: The name of the function (will be resolved with LocByName())
        @param proto_or_tinfo: function prototype as a string or type of the function as tinfo_t object
        @return:     - On failure it raises an exception if the prototype could not be parsed
              or the address is not resolvable
            - Returns a callbable Appcall instance with the given prototypes and flags
        """

# resolve and raise exception on error
        ea = Appcall__.__name_or_ea(name_or_ea)

# parse the type if it is given as (prototype, flags)
        tif = Appcall__.__typedecl_or_tinfo(proto_or_tinfo, flags)

# Return the callable method with type info
        return Appcall_callable__(ea, tif)

    def __getattr__(self, name_or_ea):
        r"""
        Allows you to call functions as if they were member functions (by returning a callable object)
        """
# resolve and raise exception on error
        ea = self.__name_or_ea(name_or_ea)
        if ea == _ida_idaapi.BADADDR:
            raise AttributeError("Undefined function " + name)
# Return the callable method
        return Appcall_callable__(ea)

    def __getitem__(self, idx):
        r"""
        Use self[func_name] syntax if the function name contains invalid characters for an attribute name
        See __getattr___
        """
        return self.__getattr__(idx)

    @staticmethod
    def valueof(name, default=0):
        r"""
        Returns the numeric value of a given name string.
        If the name could not be resolved then the default value will be returned
        """
        t, v = _ida_name.get_name_value(_ida_idaapi.BADADDR, name)
        if t == 0: # NT_NONE
          v = default
        return v

    @staticmethod
    def int64(v):
        r"""
        Whenever a 64bit number is needed use this method to construct an object
        """
        return ida_idaapi.PyIdc_cvt_int64__(v)

    @staticmethod
    def byref(val):
        r"""
        Method to create references to immutable objects
        Currently we support references to int/strings
        Objects need not be passed by reference (this will be done automatically)
        """
        return ida_idaapi.PyIdc_cvt_refclass__(val)

    @staticmethod
    def buffer(str = None, size = 0, fill="\x00"):
        r"""
        Creates a string buffer. The returned value (r) will be a byref object.
        Use r.value to get the contents and r.size to get the buffer's size
        """
        if str is None:
            str = ""
        left = size - len(str)
        if left > 0:
            str = str + (fill * left)
        r = Appcall__.byref(str)
        r.size = size
        return r

    @staticmethod
    def obj(**kwds):
        r"""
        Returns an empty object or objects with attributes as passed via its keywords arguments
        """
        return ida_idaapi.object_t(**kwds)

    @staticmethod
    def cstr(val):
        return ida_idaapi.as_cstr(val)

    @staticmethod
    def UTF16(s):
        return ida_idaapi.as_UTF16(s)
    unicode = UTF16

    @staticmethod
    def array(type_name):
        r"""
        Defines an array type. Later you need to pack() / unpack()
        """
        return Appcall_array__(type_name)

    @staticmethod
    def typedobj(typedecl_or_tinfo, ea=None):
        r"""
        Returns an appcall object for a type (can be given as tinfo_t object or
        as a string declaration)
        One can then use retrieve() member method
        @param ea: Optional parameter that later can be used to retrieve the type
        @return: Appcall object or raises ValueError exception
        """
# parse the type if it is given as string
        tif = Appcall__.__typedecl_or_tinfo(typedecl_or_tinfo)
# Return the callable method with type info
        return Appcall_callable__(ea, tif)

    @staticmethod
    def set_appcall_options(opt):
        r"""
        Method to change the Appcall options globally (not per Appcall)
        """
        old_opt = Appcall__.get_appcall_options()
        _ida_ida.inf_set_appcall_options(opt)
        return old_opt

    @staticmethod
    def get_appcall_options():
        r"""
        Return the global Appcall options
        """
        return _ida_ida.inf_get_appcall_options()

    @staticmethod
    def cleanup_appcall(tid = 0):
        r"""
        Equivalent to IDC's CleanupAppcall()
        """
        return _ida_idd.cleanup_appcall(tid)

Appcall = Appcall__()
#</pycode(py_idd)>



