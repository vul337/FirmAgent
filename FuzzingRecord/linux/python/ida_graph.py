r"""
Graph view management."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_graph
else:
    import _ida_graph

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

SWIG_PYTHON_LEGACY_BOOL = _ida_graph.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

import ida_gdl
class screen_graph_selection_base_t(object):
    r"""
    Proxy of C++ qvector< selection_item_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> screen_graph_selection_base_t
        __init__(self, x) -> screen_graph_selection_base_t

        @param x: qvector< selection_item_t > const &
        """
        _ida_graph.screen_graph_selection_base_t_swiginit(self, _ida_graph.new_screen_graph_selection_base_t(*args))
    __swig_destroy__ = _ida_graph.delete_screen_graph_selection_base_t

    def push_back(self, *args) -> "selection_item_t &":
        r"""
        push_back(self, x)

        @param x: selection_item_t const &

        push_back(self) -> selection_item_t
        """
        return _ida_graph.screen_graph_selection_base_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_graph.screen_graph_selection_base_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_graph.screen_graph_selection_base_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_graph.screen_graph_selection_base_t_empty(self)

    def at(self, _idx: "size_t") -> "selection_item_t const &":
        r"""
        at(self, _idx) -> selection_item_t

        @param _idx: size_t
        """
        return _ida_graph.screen_graph_selection_base_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_graph.screen_graph_selection_base_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_graph.screen_graph_selection_base_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: selection_item_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_graph.screen_graph_selection_base_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=selection_item_t())

        @param x: selection_item_t const &
        """
        return _ida_graph.screen_graph_selection_base_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_graph.screen_graph_selection_base_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_graph.screen_graph_selection_base_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_graph.screen_graph_selection_base_t_truncate(self)

    def swap(self, r: "screen_graph_selection_base_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< selection_item_t > &
        """
        return _ida_graph.screen_graph_selection_base_t_swap(self, r)

    def extract(self) -> "selection_item_t *":
        r"""
        extract(self) -> selection_item_t
        """
        return _ida_graph.screen_graph_selection_base_t_extract(self)

    def inject(self, s: "selection_item_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: selection_item_t *
        @param len: size_t
        """
        return _ida_graph.screen_graph_selection_base_t_inject(self, s, len)

    def __eq__(self, r: "screen_graph_selection_base_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< selection_item_t > const &
        """
        return _ida_graph.screen_graph_selection_base_t___eq__(self, r)

    def __ne__(self, r: "screen_graph_selection_base_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< selection_item_t > const &
        """
        return _ida_graph.screen_graph_selection_base_t___ne__(self, r)

    def begin(self, *args) -> "qvector< selection_item_t >::const_iterator":
        r"""
        begin(self) -> selection_item_t
        """
        return _ida_graph.screen_graph_selection_base_t_begin(self, *args)

    def end(self, *args) -> "qvector< selection_item_t >::const_iterator":
        r"""
        end(self) -> selection_item_t
        """
        return _ida_graph.screen_graph_selection_base_t_end(self, *args)

    def insert(self, it: "selection_item_t", x: "selection_item_t") -> "qvector< selection_item_t >::iterator":
        r"""
        insert(self, it, x) -> selection_item_t

        @param it: qvector< selection_item_t >::iterator
        @param x: selection_item_t const &
        """
        return _ida_graph.screen_graph_selection_base_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< selection_item_t >::iterator":
        r"""
        erase(self, it) -> selection_item_t

        @param it: qvector< selection_item_t >::iterator

        erase(self, first, last) -> selection_item_t

        @param first: qvector< selection_item_t >::iterator
        @param last: qvector< selection_item_t >::iterator
        """
        return _ida_graph.screen_graph_selection_base_t_erase(self, *args)

    def find(self, *args) -> "qvector< selection_item_t >::const_iterator":
        r"""
        find(self, x) -> selection_item_t

        @param x: selection_item_t const &

        """
        return _ida_graph.screen_graph_selection_base_t_find(self, *args)

    def has(self, x: "selection_item_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: selection_item_t const &
        """
        return _ida_graph.screen_graph_selection_base_t_has(self, x)

    def add_unique(self, x: "selection_item_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: selection_item_t const &
        """
        return _ida_graph.screen_graph_selection_base_t_add_unique(self, x)

    def _del(self, x: "selection_item_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: selection_item_t const &

        """
        return _ida_graph.screen_graph_selection_base_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_graph.screen_graph_selection_base_t___len__(self)

    def __getitem__(self, i: "size_t") -> "selection_item_t const &":
        r"""
        __getitem__(self, i) -> selection_item_t

        @param i: size_t
        """
        return _ida_graph.screen_graph_selection_base_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "selection_item_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: selection_item_t const &
        """
        return _ida_graph.screen_graph_selection_base_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register screen_graph_selection_base_t in _ida_graph:
_ida_graph.screen_graph_selection_base_t_swigregister(screen_graph_selection_base_t)
class node_layout_t(object):
    r"""
    Proxy of C++ qvector< rect_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> node_layout_t
        __init__(self, x) -> node_layout_t

        @param x: qvector< rect_t > const &
        """
        _ida_graph.node_layout_t_swiginit(self, _ida_graph.new_node_layout_t(*args))
    __swig_destroy__ = _ida_graph.delete_node_layout_t

    def push_back(self, *args) -> "rect_t &":
        r"""
        push_back(self, x)

        @param x: rect_t const &

        push_back(self) -> rect_t
        """
        return _ida_graph.node_layout_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_graph.node_layout_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_graph.node_layout_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_graph.node_layout_t_empty(self)

    def at(self, _idx: "size_t") -> "rect_t const &":
        r"""
        at(self, _idx) -> rect_t

        @param _idx: size_t
        """
        return _ida_graph.node_layout_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_graph.node_layout_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_graph.node_layout_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: rect_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_graph.node_layout_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=rect_t())

        @param x: rect_t const &
        """
        return _ida_graph.node_layout_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_graph.node_layout_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_graph.node_layout_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_graph.node_layout_t_truncate(self)

    def swap(self, r: "node_layout_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< rect_t > &
        """
        return _ida_graph.node_layout_t_swap(self, r)

    def extract(self) -> "rect_t *":
        r"""
        extract(self) -> rect_t
        """
        return _ida_graph.node_layout_t_extract(self)

    def inject(self, s: "rect_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: rect_t *
        @param len: size_t
        """
        return _ida_graph.node_layout_t_inject(self, s, len)

    def __eq__(self, r: "node_layout_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< rect_t > const &
        """
        return _ida_graph.node_layout_t___eq__(self, r)

    def __ne__(self, r: "node_layout_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< rect_t > const &
        """
        return _ida_graph.node_layout_t___ne__(self, r)

    def begin(self, *args) -> "qvector< rect_t >::const_iterator":
        r"""
        begin(self) -> rect_t
        """
        return _ida_graph.node_layout_t_begin(self, *args)

    def end(self, *args) -> "qvector< rect_t >::const_iterator":
        r"""
        end(self) -> rect_t
        """
        return _ida_graph.node_layout_t_end(self, *args)

    def insert(self, it: "rect_t", x: "rect_t") -> "qvector< rect_t >::iterator":
        r"""
        insert(self, it, x) -> rect_t

        @param it: qvector< rect_t >::iterator
        @param x: rect_t const &
        """
        return _ida_graph.node_layout_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< rect_t >::iterator":
        r"""
        erase(self, it) -> rect_t

        @param it: qvector< rect_t >::iterator

        erase(self, first, last) -> rect_t

        @param first: qvector< rect_t >::iterator
        @param last: qvector< rect_t >::iterator
        """
        return _ida_graph.node_layout_t_erase(self, *args)

    def find(self, *args) -> "qvector< rect_t >::const_iterator":
        r"""
        find(self, x) -> rect_t

        @param x: rect_t const &

        """
        return _ida_graph.node_layout_t_find(self, *args)

    def has(self, x: "rect_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: rect_t const &
        """
        return _ida_graph.node_layout_t_has(self, x)

    def add_unique(self, x: "rect_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: rect_t const &
        """
        return _ida_graph.node_layout_t_add_unique(self, x)

    def _del(self, x: "rect_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: rect_t const &

        """
        return _ida_graph.node_layout_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_graph.node_layout_t___len__(self)

    def __getitem__(self, i: "size_t") -> "rect_t const &":
        r"""
        __getitem__(self, i) -> rect_t

        @param i: size_t
        """
        return _ida_graph.node_layout_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "rect_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: rect_t const &
        """
        return _ida_graph.node_layout_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register node_layout_t in _ida_graph:
_ida_graph.node_layout_t_swigregister(node_layout_t)
class pointvec_t(object):
    r"""
    Proxy of C++ qvector< point_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> pointvec_t
        __init__(self, x) -> pointvec_t

        @param x: qvector< point_t > const &
        """
        _ida_graph.pointvec_t_swiginit(self, _ida_graph.new_pointvec_t(*args))
    __swig_destroy__ = _ida_graph.delete_pointvec_t

    def push_back(self, *args) -> "point_t &":
        r"""
        push_back(self, x)

        @param x: point_t const &

        push_back(self) -> point_t
        """
        return _ida_graph.pointvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_graph.pointvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_graph.pointvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_graph.pointvec_t_empty(self)

    def at(self, _idx: "size_t") -> "point_t const &":
        r"""
        at(self, _idx) -> point_t

        @param _idx: size_t
        """
        return _ida_graph.pointvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_graph.pointvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_graph.pointvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: point_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_graph.pointvec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=point_t())

        @param x: point_t const &
        """
        return _ida_graph.pointvec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_graph.pointvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_graph.pointvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_graph.pointvec_t_truncate(self)

    def swap(self, r: "pointvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< point_t > &
        """
        return _ida_graph.pointvec_t_swap(self, r)

    def extract(self) -> "point_t *":
        r"""
        extract(self) -> point_t
        """
        return _ida_graph.pointvec_t_extract(self)

    def inject(self, s: "point_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: point_t *
        @param len: size_t
        """
        return _ida_graph.pointvec_t_inject(self, s, len)

    def __eq__(self, r: "pointvec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< point_t > const &
        """
        return _ida_graph.pointvec_t___eq__(self, r)

    def __ne__(self, r: "pointvec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< point_t > const &
        """
        return _ida_graph.pointvec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< point_t >::const_iterator":
        r"""
        begin(self) -> point_t
        """
        return _ida_graph.pointvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< point_t >::const_iterator":
        r"""
        end(self) -> point_t
        """
        return _ida_graph.pointvec_t_end(self, *args)

    def insert(self, it: "point_t", x: "point_t") -> "qvector< point_t >::iterator":
        r"""
        insert(self, it, x) -> point_t

        @param it: qvector< point_t >::iterator
        @param x: point_t const &
        """
        return _ida_graph.pointvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< point_t >::iterator":
        r"""
        erase(self, it) -> point_t

        @param it: qvector< point_t >::iterator

        erase(self, first, last) -> point_t

        @param first: qvector< point_t >::iterator
        @param last: qvector< point_t >::iterator
        """
        return _ida_graph.pointvec_t_erase(self, *args)

    def find(self, *args) -> "qvector< point_t >::const_iterator":
        r"""
        find(self, x) -> point_t

        @param x: point_t const &

        """
        return _ida_graph.pointvec_t_find(self, *args)

    def has(self, x: "point_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: point_t const &
        """
        return _ida_graph.pointvec_t_has(self, x)

    def add_unique(self, x: "point_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: point_t const &
        """
        return _ida_graph.pointvec_t_add_unique(self, x)

    def _del(self, x: "point_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: point_t const &

        """
        return _ida_graph.pointvec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_graph.pointvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "point_t const &":
        r"""
        __getitem__(self, i) -> point_t

        @param i: size_t
        """
        return _ida_graph.pointvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "point_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: point_t const &
        """
        return _ida_graph.pointvec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register pointvec_t in _ida_graph:
_ida_graph.pointvec_t_swigregister(pointvec_t)
NIF_BG_COLOR = _ida_graph.NIF_BG_COLOR
r"""
node_info_t::bg_color
"""

NIF_FRAME_COLOR = _ida_graph.NIF_FRAME_COLOR
r"""
node_info_t::frame_color
"""

NIF_EA = _ida_graph.NIF_EA
r"""
node_info_t::ea
"""

NIF_TEXT = _ida_graph.NIF_TEXT
r"""
node_info_t::text
"""

NIF_FLAGS = _ida_graph.NIF_FLAGS
r"""
node_info_t::flags
"""

NIF_ALL = _ida_graph.NIF_ALL

GLICTL_CENTER = _ida_graph.GLICTL_CENTER
r"""
the gli should be set/get as center
"""

class node_info_t(object):
    r"""
    Proxy of C++ node_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    bg_color: "bgcolor_t" = property(_ida_graph.node_info_t_bg_color_get, _ida_graph.node_info_t_bg_color_set, doc=r"""bg_color""")
    r"""
    background color
    """
    frame_color: "bgcolor_t" = property(_ida_graph.node_info_t_frame_color_get, _ida_graph.node_info_t_frame_color_set, doc=r"""frame_color""")
    r"""
    color of enclosing frame
    """
    flags: "uint32" = property(_ida_graph.node_info_t_flags_get, _ida_graph.node_info_t_flags_set, doc=r"""flags""")
    r"""
    flags
    """
    ea: "ea_t" = property(_ida_graph.node_info_t_ea_get, _ida_graph.node_info_t_ea_set, doc=r"""ea""")
    r"""
    address
    """
    text: "qstring" = property(_ida_graph.node_info_t_text_get, _ida_graph.node_info_t_text_set, doc=r"""text""")
    r"""
    node contents
    """

    def valid_bg_color(self) -> "bool":
        r"""
        valid_bg_color(self) -> bool
        Has valid bg_color?
        """
        return _ida_graph.node_info_t_valid_bg_color(self)

    def valid_frame_color(self) -> "bool":
        r"""
        valid_frame_color(self) -> bool
        Has valid frame_color?
        """
        return _ida_graph.node_info_t_valid_frame_color(self)

    def valid_ea(self) -> "bool":
        r"""
        valid_ea(self) -> bool
        Has valid ea?
        """
        return _ida_graph.node_info_t_valid_ea(self)

    def valid_text(self) -> "bool":
        r"""
        valid_text(self) -> bool
        Has non-empty text?
        """
        return _ida_graph.node_info_t_valid_text(self)

    def valid_flags(self) -> "bool":
        r"""
        valid_flags(self) -> bool
        Has valid flags?
        """
        return _ida_graph.node_info_t_valid_flags(self)

    def get_flags_for_valid(self) -> "uint32":
        r"""
        get_flags_for_valid(self) -> uint32
        Get combination of Node info flags describing which attributes are valid.
        """
        return _ida_graph.node_info_t_get_flags_for_valid(self)

    def __init__(self):
        r"""
        __init__(self) -> node_info_t
        """
        _ida_graph.node_info_t_swiginit(self, _ida_graph.new_node_info_t())
    __swig_destroy__ = _ida_graph.delete_node_info_t

# Register node_info_t in _ida_graph:
_ida_graph.node_info_t_swigregister(node_info_t)
NIFF_SHOW_CONTENTS = _ida_graph.NIFF_SHOW_CONTENTS



def get_node_info(out: "node_info_t", gid: "graph_id_t", node: "int") -> "bool":
    r"""
    get_node_info(out, gid, node) -> bool
    Get node info.

    @param out: (C++: node_info_t *) result
    @param gid: (C++: graph_id_t) id of desired graph
    @param node: (C++: int) node number
    @return: success
    """
    return _ida_graph.get_node_info(out, gid, node)

def set_node_info(gid: "graph_id_t", node: "int", ni: "node_info_t", flags: "uint32") -> "void":
    r"""
    set_node_info(gid, node, ni, flags)
    Set node info.

    @param gid: (C++: graph_id_t) id of desired graph
    @param node: (C++: int) node number
    @param ni: (C++: const node_info_t &) node info to use
    @param flags: (C++: uint32) combination of Node info flags, identifying which fields of 'ni'
                  will be used
    """
    return _ida_graph.set_node_info(gid, node, ni, flags)

def del_node_info(gid: "graph_id_t", node: "int") -> "void":
    r"""
    del_node_info(gid, node)
    Delete the node_info_t for the given node.

    @param gid: (C++: graph_id_t)
    @param node: (C++: int)
    """
    return _ida_graph.del_node_info(gid, node)

def clr_node_info(gid: "graph_id_t", node: "int", flags: "uint32") -> "void":
    r"""
    clr_node_info(gid, node, flags)
    Clear node info for the given node.

    @param gid: (C++: graph_id_t) id of desired graph
    @param node: (C++: int) node number
    @param flags: (C++: uint32) combination of Node info flags, identifying which fields of
                  node_info_t will be cleared
    """
    return _ida_graph.clr_node_info(gid, node, flags)
class graph_node_visitor_t(object):
    r"""
    Proxy of C++ graph_node_visitor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def reinit(self) -> "void":
        r"""
        reinit(self)
        Reset visited nodes.
        """
        return _ida_graph.graph_node_visitor_t_reinit(self)

    def set_visited(self, n: "int") -> "void":
        r"""
        set_visited(self, n)
        Mark node as visited.

        @param n: (C++: int)
        """
        return _ida_graph.graph_node_visitor_t_set_visited(self, n)

    def is_visited(self, n: "int") -> "bool":
        r"""
        is_visited(self, n) -> bool
        Have we already visited the given node?

        @param n: (C++: int)
        """
        return _ida_graph.graph_node_visitor_t_is_visited(self, n)

    def visit_node(self, arg0: "int") -> "int":
        r"""
        visit_node(self, arg0) -> int
        Implements action to take when a node is visited.

        @param arg0: int
        """
        return _ida_graph.graph_node_visitor_t_visit_node(self, arg0)

    def is_forbidden_edge(self, arg0: "int", arg1: "int") -> "bool":
        r"""
        is_forbidden_edge(self, arg0, arg1) -> bool
        Should the edge between 'n' and 'm' be ignored?

        @param arg0: int
        @param arg1: int
        """
        return _ida_graph.graph_node_visitor_t_is_forbidden_edge(self, arg0, arg1)
    __swig_destroy__ = _ida_graph.delete_graph_node_visitor_t

    def __init__(self):
        r"""
        __init__(self) -> graph_node_visitor_t

        @param self: PyObject *
        """
        if self.__class__ == graph_node_visitor_t:
            _self = None
        else:
            _self = self
        _ida_graph.graph_node_visitor_t_swiginit(self, _ida_graph.new_graph_node_visitor_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_graph.disown_graph_node_visitor_t(self)
        return weakref.proxy(self)

# Register graph_node_visitor_t in _ida_graph:
_ida_graph.graph_node_visitor_t_swigregister(graph_node_visitor_t)
class graph_path_visitor_t(object):
    r"""
    Proxy of C++ graph_path_visitor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    path: "intvec_t" = property(_ida_graph.graph_path_visitor_t_path_get, _ida_graph.graph_path_visitor_t_path_set, doc=r"""path""")
    r"""
    current path
    """
    prune: "bool" = property(_ida_graph.graph_path_visitor_t_prune_get, _ida_graph.graph_path_visitor_t_prune_set, doc=r"""prune""")
    r"""
    walk_forward(): prune := true means to stop the current path
    """

    def walk_forward(self, arg0: "int") -> "int":
        r"""
        walk_forward(self, arg0) -> int

        @param arg0: int
        """
        return _ida_graph.graph_path_visitor_t_walk_forward(self, arg0)

    def walk_backward(self, arg0: "int") -> "int":
        r"""
        walk_backward(self, arg0) -> int

        @param arg0: int
        """
        return _ida_graph.graph_path_visitor_t_walk_backward(self, arg0)
    __swig_destroy__ = _ida_graph.delete_graph_path_visitor_t

    def __init__(self):
        r"""
        __init__(self) -> graph_path_visitor_t

        @param self: PyObject *
        """
        if self.__class__ == graph_path_visitor_t:
            _self = None
        else:
            _self = self
        _ida_graph.graph_path_visitor_t_swiginit(self, _ida_graph.new_graph_path_visitor_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_graph.disown_graph_path_visitor_t(self)
        return weakref.proxy(self)

# Register graph_path_visitor_t in _ida_graph:
_ida_graph.graph_path_visitor_t_swigregister(graph_path_visitor_t)
class point_t(object):
    r"""
    Proxy of C++ point_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    x: "int" = property(_ida_graph.point_t_x_get, _ida_graph.point_t_x_set, doc=r"""x""")
    y: "int" = property(_ida_graph.point_t_y_get, _ida_graph.point_t_y_set, doc=r"""y""")

    def __init__(self, *args):
        r"""
        __init__(self) -> point_t
        __init__(self, _x, _y) -> point_t

        @param _x: int
        @param _y: int
        """
        _ida_graph.point_t_swiginit(self, _ida_graph.new_point_t(*args))

    def add(self, r: "point_t") -> "point_t &":
        r"""
        add(self, r) -> point_t

        @param r: point_t const &
        """
        return _ida_graph.point_t_add(self, r)

    def sub(self, r: "point_t") -> "point_t &":
        r"""
        sub(self, r) -> point_t

        @param r: point_t const &
        """
        return _ida_graph.point_t_sub(self, r)

    def negate(self) -> "void":
        r"""
        negate(self)
        """
        return _ida_graph.point_t_negate(self)

    def __eq__(self, r: "point_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: point_t const &
        """
        return _ida_graph.point_t___eq__(self, r)

    def __ne__(self, r: "point_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: point_t const &
        """
        return _ida_graph.point_t___ne__(self, r)
    __swig_destroy__ = _ida_graph.delete_point_t

# Register point_t in _ida_graph:
_ida_graph.point_t_swigregister(point_t)

def calc_dist(p: "point_t", q: "point_t") -> "double":
    r"""
    calc_dist(p, q) -> double
    Calculate distance between p and q.

    @param p: (C++: point_t)
    @param q: (C++: point_t)
    """
    return _ida_graph.calc_dist(p, q)
class pointseq_t(pointvec_t):
    r"""
    Proxy of C++ pointseq_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> pointseq_t
        """
        _ida_graph.pointseq_t_swiginit(self, _ida_graph.new_pointseq_t())
    __swig_destroy__ = _ida_graph.delete_pointseq_t

# Register pointseq_t in _ida_graph:
_ida_graph.pointseq_t_swigregister(pointseq_t)
class rect_t(object):
    r"""
    Proxy of C++ rect_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    left: "int" = property(_ida_graph.rect_t_left_get, _ida_graph.rect_t_left_set, doc=r"""left""")
    top: "int" = property(_ida_graph.rect_t_top_get, _ida_graph.rect_t_top_set, doc=r"""top""")
    right: "int" = property(_ida_graph.rect_t_right_get, _ida_graph.rect_t_right_set, doc=r"""right""")
    bottom: "int" = property(_ida_graph.rect_t_bottom_get, _ida_graph.rect_t_bottom_set, doc=r"""bottom""")

    def __init__(self, *args):
        r"""
        __init__(self) -> rect_t
        __init__(self, l, t, r, b) -> rect_t

        @param l: int
        @param t: int
        @param r: int
        @param b: int

        __init__(self, p0, p1) -> rect_t

        @param p0: point_t const &
        @param p1: point_t const &
        """
        _ida_graph.rect_t_swiginit(self, _ida_graph.new_rect_t(*args))

    def verify(self) -> "void":
        r"""
        verify(self)
        """
        return _ida_graph.rect_t_verify(self)

    def width(self) -> "int":
        r"""
        width(self) -> int
        """
        return _ida_graph.rect_t_width(self)

    def height(self) -> "int":
        r"""
        height(self) -> int
        """
        return _ida_graph.rect_t_height(self)

    def move_to(self, p: "point_t") -> "void":
        r"""
        move_to(self, p)

        @param p: point_t const &
        """
        return _ida_graph.rect_t_move_to(self, p)

    def move_by(self, p: "point_t") -> "void":
        r"""
        move_by(self, p)

        @param p: point_t const &
        """
        return _ida_graph.rect_t_move_by(self, p)

    def center(self) -> "point_t":
        r"""
        center(self) -> point_t
        """
        return _ida_graph.rect_t_center(self)

    def topleft(self) -> "point_t":
        r"""
        topleft(self) -> point_t
        """
        return _ida_graph.rect_t_topleft(self)

    def bottomright(self) -> "point_t":
        r"""
        bottomright(self) -> point_t
        """
        return _ida_graph.rect_t_bottomright(self)

    def grow(self, delta: "int") -> "void":
        r"""
        grow(self, delta)

        @param delta: int
        """
        return _ida_graph.rect_t_grow(self, delta)

    def intersect(self, r: "rect_t") -> "void":
        r"""
        intersect(self, r)

        @param r: rect_t const &
        """
        return _ida_graph.rect_t_intersect(self, r)

    def make_union(self, r: "rect_t") -> "void":
        r"""
        make_union(self, r)

        @param r: rect_t const &
        """
        return _ida_graph.rect_t_make_union(self, r)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_graph.rect_t_empty(self)

    def is_intersection_empty(self, r: "rect_t") -> "bool":
        r"""
        is_intersection_empty(self, r) -> bool

        @param r: rect_t const &
        """
        return _ida_graph.rect_t_is_intersection_empty(self, r)

    def contains(self, p: "point_t") -> "bool":
        r"""
        contains(self, p) -> bool

        @param p: point_t const &
        """
        return _ida_graph.rect_t_contains(self, p)

    def area(self) -> "int":
        r"""
        area(self) -> int
        """
        return _ida_graph.rect_t_area(self)

    def __eq__(self, r: "rect_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: rect_t const &
        """
        return _ida_graph.rect_t___eq__(self, r)

    def __ne__(self, r: "rect_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: rect_t const &
        """
        return _ida_graph.rect_t___ne__(self, r)
    __swig_destroy__ = _ida_graph.delete_rect_t

# Register rect_t in _ida_graph:
_ida_graph.rect_t_swigregister(rect_t)
class TPointDouble(object):
    r"""
    Proxy of C++ TPointDouble class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    x: "double" = property(_ida_graph.TPointDouble_x_get, _ida_graph.TPointDouble_x_set, doc=r"""x""")
    y: "double" = property(_ida_graph.TPointDouble_y_get, _ida_graph.TPointDouble_y_set, doc=r"""y""")

    def __init__(self, *args):
        r"""
        __init__(self) -> TPointDouble
        __init__(self, a, b) -> TPointDouble

        @param a: double
        @param b: double

        __init__(self, r) -> TPointDouble

        @param r: point_t const &
        """
        _ida_graph.TPointDouble_swiginit(self, _ida_graph.new_TPointDouble(*args))

    def add(self, r: "TPointDouble") -> "void":
        r"""
        add(self, r)

        @param r: TPointDouble const &
        """
        return _ida_graph.TPointDouble_add(self, r)

    def sub(self, r: "TPointDouble") -> "void":
        r"""
        sub(self, r)

        @param r: TPointDouble const &
        """
        return _ida_graph.TPointDouble_sub(self, r)

    def negate(self) -> "void":
        r"""
        negate(self)
        """
        return _ida_graph.TPointDouble_negate(self)

    def __eq__(self, r: "TPointDouble") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: TPointDouble const &
        """
        return _ida_graph.TPointDouble___eq__(self, r)

    def __ne__(self, r: "TPointDouble") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: TPointDouble const &
        """
        return _ida_graph.TPointDouble___ne__(self, r)
    __swig_destroy__ = _ida_graph.delete_TPointDouble

# Register TPointDouble in _ida_graph:
_ida_graph.TPointDouble_swigregister(TPointDouble)
class edge_info_t(object):
    r"""
    Proxy of C++ edge_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    color: "bgcolor_t" = property(_ida_graph.edge_info_t_color_get, _ida_graph.edge_info_t_color_set, doc=r"""color""")
    r"""
    edge color
    """
    width: "int" = property(_ida_graph.edge_info_t_width_get, _ida_graph.edge_info_t_width_set, doc=r"""width""")
    r"""
    edge width
    """
    srcoff: "int" = property(_ida_graph.edge_info_t_srcoff_get, _ida_graph.edge_info_t_srcoff_set, doc=r"""srcoff""")
    r"""
    source: edge port offset from the left
    """
    dstoff: "int" = property(_ida_graph.edge_info_t_dstoff_get, _ida_graph.edge_info_t_dstoff_set, doc=r"""dstoff""")
    r"""
    destination: edge port offset from the left
    """
    layout: "pointseq_t" = property(_ida_graph.edge_info_t_layout_get, _ida_graph.edge_info_t_layout_set, doc=r"""layout""")
    r"""
    describes geometry of edge
    """

    def reverse_layout(self) -> "void":
        r"""
        reverse_layout(self)
        """
        return _ida_graph.edge_info_t_reverse_layout(self)

    def __init__(self):
        r"""
        __init__(self) -> edge_info_t
        """
        _ida_graph.edge_info_t_swiginit(self, _ida_graph.new_edge_info_t())
    __swig_destroy__ = _ida_graph.delete_edge_info_t

# Register edge_info_t in _ida_graph:
_ida_graph.edge_info_t_swigregister(edge_info_t)
cvar = _ida_graph.cvar
layout_none = cvar.layout_none
layout_digraph = cvar.layout_digraph
layout_tree = cvar.layout_tree
layout_circle = cvar.layout_circle
layout_polar_tree = cvar.layout_polar_tree
layout_orthogonal = cvar.layout_orthogonal
layout_radial_tree = cvar.layout_radial_tree

class edge_layout_point_t(object):
    r"""
    Proxy of C++ edge_layout_point_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    pidx: "int" = property(_ida_graph.edge_layout_point_t_pidx_get, _ida_graph.edge_layout_point_t_pidx_set, doc=r"""pidx""")
    r"""
    index into edge_info_t::layout
    """
    e: "edge_t" = property(_ida_graph.edge_layout_point_t_e_get, _ida_graph.edge_layout_point_t_e_set, doc=r"""e""")
    r"""
    parent edge
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> edge_layout_point_t
        __init__(self, _e, _pidx) -> edge_layout_point_t

        @param _e: edge_t const &
        @param _pidx: int
        """
        _ida_graph.edge_layout_point_t_swiginit(self, _ida_graph.new_edge_layout_point_t(*args))

    def compare(self, r: "edge_layout_point_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: edge_layout_point_t const &
        """
        return _ida_graph.edge_layout_point_t_compare(self, r)

    def __eq__(self, r: "edge_layout_point_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: edge_layout_point_t const &
        """
        return _ida_graph.edge_layout_point_t___eq__(self, r)

    def __ne__(self, r: "edge_layout_point_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: edge_layout_point_t const &
        """
        return _ida_graph.edge_layout_point_t___ne__(self, r)
    __swig_destroy__ = _ida_graph.delete_edge_layout_point_t

# Register edge_layout_point_t in _ida_graph:
_ida_graph.edge_layout_point_t_swigregister(edge_layout_point_t)
class selection_item_t(object):
    r"""
    Proxy of C++ selection_item_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    is_node: "bool" = property(_ida_graph.selection_item_t_is_node_get, _ida_graph.selection_item_t_is_node_set, doc=r"""is_node""")
    r"""
    represents a selected node?
    """
    node: "int" = property(_ida_graph.selection_item_t_node_get, _ida_graph.selection_item_t_node_set, doc=r"""node""")
    r"""
    node number (is_node = true)
    """
    elp: "edge_layout_point_t" = property(_ida_graph.selection_item_t_elp_get, _ida_graph.selection_item_t_elp_set, doc=r"""elp""")
    r"""
    edge layout point (is_node = false)
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> selection_item_t
        __init__(self, n) -> selection_item_t

        @param n: int

        __init__(self, _elp) -> selection_item_t

        @param _elp: edge_layout_point_t &

        __init__(self, e, idx) -> selection_item_t

        @param e: edge_t
        @param idx: int
        """
        _ida_graph.selection_item_t_swiginit(self, _ida_graph.new_selection_item_t(*args))

    def compare(self, r: "selection_item_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: selection_item_t const &
        """
        return _ida_graph.selection_item_t_compare(self, r)

    def __eq__(self, r: "selection_item_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: selection_item_t const &
        """
        return _ida_graph.selection_item_t___eq__(self, r)

    def __ne__(self, r: "selection_item_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: selection_item_t const &
        """
        return _ida_graph.selection_item_t___ne__(self, r)

    def __lt__(self, r: "selection_item_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: selection_item_t const &
        """
        return _ida_graph.selection_item_t___lt__(self, r)
    __swig_destroy__ = _ida_graph.delete_selection_item_t

# Register selection_item_t in _ida_graph:
_ida_graph.selection_item_t_swigregister(selection_item_t)
class screen_graph_selection_t(screen_graph_selection_base_t):
    r"""
    Proxy of C++ screen_graph_selection_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def has(self, item: "selection_item_t") -> "bool":
        r"""
        has(self, item) -> bool

        @param item: selection_item_t const &
        """
        return _ida_graph.screen_graph_selection_t_has(self, item)

    def add(self, s: "screen_graph_selection_t") -> "void":
        r"""
        add(self, s)

        @param s: screen_graph_selection_t const &
        """
        return _ida_graph.screen_graph_selection_t_add(self, s)

    def sub(self, s: "screen_graph_selection_t") -> "void":
        r"""
        sub(self, s)

        @param s: screen_graph_selection_t const &
        """
        return _ida_graph.screen_graph_selection_t_sub(self, s)

    def add_node(self, node: "int") -> "void":
        r"""
        add_node(self, node)

        @param node: int
        """
        return _ida_graph.screen_graph_selection_t_add_node(self, node)

    def del_node(self, node: "int") -> "void":
        r"""
        del_node(self, node)

        @param node: int
        """
        return _ida_graph.screen_graph_selection_t_del_node(self, node)

    def add_point(self, e: "edge_t", idx: "int") -> "void":
        r"""
        add_point(self, e, idx)

        @param e: edge_t
        @param idx: int
        """
        return _ida_graph.screen_graph_selection_t_add_point(self, e, idx)

    def del_point(self, e: "edge_t", idx: "int") -> "void":
        r"""
        del_point(self, e, idx)

        @param e: edge_t
        @param idx: int
        """
        return _ida_graph.screen_graph_selection_t_del_point(self, e, idx)

    def nodes_count(self) -> "size_t":
        r"""
        nodes_count(self) -> size_t
        """
        return _ida_graph.screen_graph_selection_t_nodes_count(self)

    def points_count(self) -> "size_t":
        r"""
        points_count(self) -> size_t
        """
        return _ida_graph.screen_graph_selection_t_points_count(self)

    def items_count(self, look_for_nodes: "bool") -> "size_t":
        r"""
        items_count(self, look_for_nodes) -> size_t

        @param look_for_nodes: bool
        """
        return _ida_graph.screen_graph_selection_t_items_count(self, look_for_nodes)

    def __init__(self):
        r"""
        __init__(self) -> screen_graph_selection_t
        """
        _ida_graph.screen_graph_selection_t_swiginit(self, _ida_graph.new_screen_graph_selection_t())
    __swig_destroy__ = _ida_graph.delete_screen_graph_selection_t

# Register screen_graph_selection_t in _ida_graph:
_ida_graph.screen_graph_selection_t_swigregister(screen_graph_selection_t)
class edge_segment_t(object):
    r"""
    Proxy of C++ edge_segment_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    e: "edge_t" = property(_ida_graph.edge_segment_t_e_get, _ida_graph.edge_segment_t_e_set, doc=r"""e""")
    nseg: "int" = property(_ida_graph.edge_segment_t_nseg_get, _ida_graph.edge_segment_t_nseg_set, doc=r"""nseg""")
    x0: "int" = property(_ida_graph.edge_segment_t_x0_get, _ida_graph.edge_segment_t_x0_set, doc=r"""x0""")
    x1: "int" = property(_ida_graph.edge_segment_t_x1_get, _ida_graph.edge_segment_t_x1_set, doc=r"""x1""")

    def length(self) -> "size_t":
        r"""
        length(self) -> size_t
        """
        return _ida_graph.edge_segment_t_length(self)

    def toright(self) -> "bool":
        r"""
        toright(self) -> bool
        """
        return _ida_graph.edge_segment_t_toright(self)

    def __lt__(self, r: "edge_segment_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: edge_segment_t const &
        """
        return _ida_graph.edge_segment_t___lt__(self, r)

    def __init__(self):
        r"""
        __init__(self) -> edge_segment_t
        """
        _ida_graph.edge_segment_t_swiginit(self, _ida_graph.new_edge_segment_t())
    __swig_destroy__ = _ida_graph.delete_edge_segment_t

# Register edge_segment_t in _ida_graph:
_ida_graph.edge_segment_t_swigregister(edge_segment_t)
git_none = _ida_graph.git_none
r"""
nothing
"""

git_edge = _ida_graph.git_edge
r"""
edge (graph_item_t::e, graph_item_t::n. n is farthest edge endpoint)
"""

git_node = _ida_graph.git_node
r"""
node title (graph_item_t::n)
"""

git_tool = _ida_graph.git_tool
r"""
node title button (graph_item_t::n, graph_item_t::b)
"""

git_text = _ida_graph.git_text
r"""
node text (graph_item_t::n, graph_item_t::p)
"""

git_elp = _ida_graph.git_elp
r"""
edge layout point (graph_item_t::elp)
"""

class graph_item_t(object):
    r"""
    Proxy of C++ graph_item_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    type: "graph_item_type_t" = property(_ida_graph.graph_item_t_type_get, _ida_graph.graph_item_t_type_set, doc=r"""type""")
    r"""
    type
    """
    e: "edge_t" = property(_ida_graph.graph_item_t_e_get, _ida_graph.graph_item_t_e_set, doc=r"""e""")
    r"""
    edge source and destination
    """
    n: "int" = property(_ida_graph.graph_item_t_n_get, _ida_graph.graph_item_t_n_set, doc=r"""n""")
    r"""
    node number
    """
    b: "int" = property(_ida_graph.graph_item_t_b_get, _ida_graph.graph_item_t_b_set, doc=r"""b""")
    r"""
    button number
    """
    p: "point_t" = property(_ida_graph.graph_item_t_p_get, _ida_graph.graph_item_t_p_set, doc=r"""p""")
    r"""
    text coordinates in the node
    """
    elp: "edge_layout_point_t" = property(_ida_graph.graph_item_t_elp_get, _ida_graph.graph_item_t_elp_set, doc=r"""elp""")
    r"""
    edge layout point
    """

    def is_node(self) -> "bool":
        r"""
        is_node(self) -> bool
        """
        return _ida_graph.graph_item_t_is_node(self)

    def is_edge(self) -> "bool":
        r"""
        is_edge(self) -> bool
        """
        return _ida_graph.graph_item_t_is_edge(self)

    def __init__(self):
        r"""
        __init__(self) -> graph_item_t
        """
        _ida_graph.graph_item_t_swiginit(self, _ida_graph.new_graph_item_t())
    __swig_destroy__ = _ida_graph.delete_graph_item_t

# Register graph_item_t in _ida_graph:
_ida_graph.graph_item_t_swigregister(graph_item_t)
class interval_t(object):
    r"""
    Proxy of C++ interval_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    x0: "int" = property(_ida_graph.interval_t_x0_get, _ida_graph.interval_t_x0_set, doc=r"""x0""")
    x1: "int" = property(_ida_graph.interval_t_x1_get, _ida_graph.interval_t_x1_set, doc=r"""x1""")

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_graph.interval_t_empty(self)

    def intersect(self, r: "interval_t") -> "void":
        r"""
        intersect(self, r)

        @param r: interval_t const &
        """
        return _ida_graph.interval_t_intersect(self, r)

    def make_union(self, r: "interval_t") -> "void":
        r"""
        make_union(self, r)

        @param r: interval_t const &
        """
        return _ida_graph.interval_t_make_union(self, r)

    def move_by(self, shift: "int") -> "void":
        r"""
        move_by(self, shift)

        @param shift: int
        """
        return _ida_graph.interval_t_move_by(self, shift)

    def __init__(self, *args):
        r"""
        __init__(self) -> interval_t
        __init__(self, y0, y1) -> interval_t

        @param y0: int
        @param y1: int

        __init__(self, s) -> interval_t

        @param s: edge_segment_t const &
        """
        _ida_graph.interval_t_swiginit(self, _ida_graph.new_interval_t(*args))

    def length(self) -> "int":
        r"""
        length(self) -> int
        """
        return _ida_graph.interval_t_length(self)

    def contains(self, x: "int") -> "bool":
        r"""
        contains(self, x) -> bool

        @param x: int
        """
        return _ida_graph.interval_t_contains(self, x)

    def __eq__(self, r: "interval_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: interval_t const &
        """
        return _ida_graph.interval_t___eq__(self, r)

    def __ne__(self, r: "interval_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: interval_t const &
        """
        return _ida_graph.interval_t___ne__(self, r)
    __swig_destroy__ = _ida_graph.delete_interval_t

# Register interval_t in _ida_graph:
_ida_graph.interval_t_swigregister(interval_t)
class row_info_t(object):
    r"""
    Proxy of C++ row_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    nodes: "intvec_t" = property(_ida_graph.row_info_t_nodes_get, _ida_graph.row_info_t_nodes_set, doc=r"""nodes""")
    r"""
    list of nodes at the row
    """
    top: "int" = property(_ida_graph.row_info_t_top_get, _ida_graph.row_info_t_top_set, doc=r"""top""")
    r"""
    top y coord of the row
    """
    bottom: "int" = property(_ida_graph.row_info_t_bottom_get, _ida_graph.row_info_t_bottom_set, doc=r"""bottom""")
    r"""
    bottom y coord of the row
    """

    def height(self) -> "int":
        r"""
        height(self) -> int
        """
        return _ida_graph.row_info_t_height(self)

    def __init__(self):
        r"""
        __init__(self) -> row_info_t
        """
        _ida_graph.row_info_t_swiginit(self, _ida_graph.new_row_info_t())
    __swig_destroy__ = _ida_graph.delete_row_info_t

# Register row_info_t in _ida_graph:
_ida_graph.row_info_t_swigregister(row_info_t)
class drawable_graph_t(ida_gdl.gdl_graph_t):
    r"""
    Proxy of C++ drawable_graph_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    title: "qstring" = property(_ida_graph.drawable_graph_t_title_get, _ida_graph.drawable_graph_t_title_set, doc=r"""title""")
    r"""
    graph title
    """
    rect_edges_made: "bool" = property(_ida_graph.drawable_graph_t_rect_edges_made_get, _ida_graph.drawable_graph_t_rect_edges_made_set, doc=r"""rect_edges_made""")
    r"""
    have create rectangular edges?
    """
    current_layout: "layout_type_t" = property(_ida_graph.drawable_graph_t_current_layout_get, _ida_graph.drawable_graph_t_current_layout_set, doc=r"""current_layout""")
    r"""
    see Proximity view layouts
    """
    circle_center: "point_t" = property(_ida_graph.drawable_graph_t_circle_center_get, _ida_graph.drawable_graph_t_circle_center_set, doc=r"""circle_center""")
    r"""
    for layout_circle
    """
    circle_radius: "int" = property(_ida_graph.drawable_graph_t_circle_radius_get, _ida_graph.drawable_graph_t_circle_radius_set, doc=r"""circle_radius""")
    r"""
    for layout_circle
    """
    callback_ud: "void *" = property(_ida_graph.drawable_graph_t_callback_ud_get, _ida_graph.drawable_graph_t_callback_ud_set, doc=r"""callback_ud""")
    r"""
    user data for callback
    """
    __swig_destroy__ = _ida_graph.delete_drawable_graph_t

    def create_tree_layout(self) -> "bool":
        r"""
        create_tree_layout(self) -> bool
        """
        return _ida_graph.drawable_graph_t_create_tree_layout(self)

    def create_circle_layout(self, p: "point_t", radius: "int") -> "bool":
        r"""
        create_circle_layout(self, p, radius) -> bool

        @param p: point_t
        @param radius: int
        """
        return _ida_graph.drawable_graph_t_create_circle_layout(self, p, radius)

    def set_callback(self, _callback: "hook_cb_t *", _ud: "void *") -> "void":
        r"""
        set_callback(self, _callback, _ud)

        @param _callback: hook_cb_t *
        @param _ud: void *
        """
        return _ida_graph.drawable_graph_t_set_callback(self, _callback, _ud)

    def grcall(self, code: "int") -> "ssize_t":
        r"""
        grcall(self, code) -> ssize_t

        @param code: int
        """
        return _ida_graph.drawable_graph_t_grcall(self, code)

    def get_edge(self, e: "edge_t") -> "edge_info_t *":
        r"""
        get_edge(self, e) -> edge_info_t

        @param e: edge_t
        """
        return _ida_graph.drawable_graph_t_get_edge(self, e)

    def nrect(self, n: "int") -> "rect_t":
        r"""
        nrect(self, n) -> rect_t

        @param n: int
        """
        return _ida_graph.drawable_graph_t_nrect(self, n)

    def __init__(self):
        r"""
        __init__(self) -> drawable_graph_t

        @param self: PyObject *
        """
        if self.__class__ == drawable_graph_t:
            _self = None
        else:
            _self = self
        _ida_graph.drawable_graph_t_swiginit(self, _ida_graph.new_drawable_graph_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_graph.disown_drawable_graph_t(self)
        return weakref.proxy(self)

# Register drawable_graph_t in _ida_graph:
_ida_graph.drawable_graph_t_swigregister(drawable_graph_t)
ygap = cvar.ygap
xgap = cvar.xgap
arrow_height = cvar.arrow_height
arrow_width = cvar.arrow_width

class edge_infos_wrapper_t(object):
    r"""
    Proxy of C++ edge_infos_wrapper_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_graph.edge_infos_wrapper_t_clear(self)
    ptr: "edge_infos_t *" = property(_ida_graph.edge_infos_wrapper_t_ptr_get, _ida_graph.edge_infos_wrapper_t_ptr_set, doc=r"""ptr""")

# Register edge_infos_wrapper_t in _ida_graph:
_ida_graph.edge_infos_wrapper_t_swigregister(edge_infos_wrapper_t)
class interactive_graph_t(drawable_graph_t):
    r"""
    Proxy of C++ interactive_graph_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined - class is abstract")
    __repr__ = _swig_repr
    gid: "uval_t" = property(_ida_graph.interactive_graph_t_gid_get, _ida_graph.interactive_graph_t_gid_set, doc=r"""gid""")
    r"""
    graph id - unique for the database for flowcharts it is equal to the function
    start_ea
    """
    belongs: "intvec_t" = property(_ida_graph.interactive_graph_t_belongs_get, _ida_graph.interactive_graph_t_belongs_set, doc=r"""belongs""")
    r"""
    the subgraph the node belongs to INT_MAX means that the node doesn't exist sign
    bit means collapsed node
    """
    node_flags: "bytevec_t" = property(_ida_graph.interactive_graph_t_node_flags_get, _ida_graph.interactive_graph_t_node_flags_set, doc=r"""node_flags""")
    r"""
    node flags
    """
    org_succs: "array_of_intvec_t" = property(_ida_graph.interactive_graph_t_org_succs_get, _ida_graph.interactive_graph_t_org_succs_set, doc=r"""org_succs""")
    org_preds: "array_of_intvec_t" = property(_ida_graph.interactive_graph_t_org_preds_get, _ida_graph.interactive_graph_t_org_preds_set, doc=r"""org_preds""")
    succs: "array_of_intvec_t" = property(_ida_graph.interactive_graph_t_succs_get, _ida_graph.interactive_graph_t_succs_set, doc=r"""succs""")
    preds: "array_of_intvec_t" = property(_ida_graph.interactive_graph_t_preds_get, _ida_graph.interactive_graph_t_preds_set, doc=r"""preds""")
    nodes: "interactive_graph_t::node_layout_t" = property(_ida_graph.interactive_graph_t_nodes_get, _ida_graph.interactive_graph_t_nodes_set, doc=r"""nodes""")
    edges: "edge_infos_wrapper_t" = property(_ida_graph.interactive_graph_t_edges_get, _ida_graph.interactive_graph_t_edges_set, doc=r"""edges""")
    __swig_destroy__ = _ida_graph.delete_interactive_graph_t

    def size(self) -> "int":
        r"""
        size(self) -> int
        Get the total number of nodes (including group nodes, and including hidden
        nodes.)

        See also node_qty()

        @return: the total number of nodes in the graph
        """
        return _ida_graph.interactive_graph_t_size(self)

    def node_qty(self) -> "int":
        r"""
        node_qty(self) -> int
        Get the number of visible nodes (the list can be retrieved using gdl.hpp's
        node_iterator)

        See also size()

        @return: the number of visible nodes
        """
        return _ida_graph.interactive_graph_t_node_qty(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        Is the graph (visually) empty?

        @return: true if there are no visible nodes
        """
        return _ida_graph.interactive_graph_t_empty(self)

    def exists(self, node: "int") -> "bool":
        r"""
        exists(self, node) -> bool
        Is the node visible?

        @param node: (C++: int) the node number
        @return: success
        """
        return _ida_graph.interactive_graph_t_exists(self, node)

    def get_node_representative(self, node: "int") -> "int":
        r"""
        get_node_representative(self, node) -> int
        Get the node that currently visually represents 'node'. This will find the
        "closest" parent group node that's visible, by attempting to walk up the group
        nodes that contain 'node', and will stop when it finds a node that is currently
        visible.

        See also get_group_node()

        @param node: (C++: int) the node
        @return: the node that represents 'node', or 'node' if it's not part of any
                 group
        """
        return _ida_graph.interactive_graph_t_get_node_representative(self, node)

    def get_node_group(self, node: "int") -> "int":
        r"""
        get_node_group(self, node) -> int

        @param node: int
        """
        return _ida_graph.interactive_graph_t_get_node_group(self, node)

    def set_node_group(self, node: "int", group: "int") -> "void":
        r"""
        set_node_group(self, node, group)

        @param node: int
        @param group: int
        """
        return _ida_graph.interactive_graph_t_set_node_group(self, node, group)

    def is_deleted_node(self, node: "int") -> "bool":
        r"""
        is_deleted_node(self, node) -> bool

        @param node: int
        """
        return _ida_graph.interactive_graph_t_is_deleted_node(self, node)

    def set_deleted_node(self, node: "int") -> "void":
        r"""
        set_deleted_node(self, node)

        @param node: int
        """
        return _ida_graph.interactive_graph_t_set_deleted_node(self, node)

    def is_subgraph_node(self, node: "int") -> "bool":
        r"""
        is_subgraph_node(self, node) -> bool

        @param node: int
        """
        return _ida_graph.interactive_graph_t_is_subgraph_node(self, node)

    def is_dot_node(self, node: "int") -> "bool":
        r"""
        is_dot_node(self, node) -> bool

        @param node: int
        """
        return _ida_graph.interactive_graph_t_is_dot_node(self, node)

    def is_group_node(self, node: "int") -> "bool":
        r"""
        is_group_node(self, node) -> bool

        @param node: int
        """
        return _ida_graph.interactive_graph_t_is_group_node(self, node)

    def is_displayable_node(self, node: "int") -> "bool":
        r"""
        is_displayable_node(self, node) -> bool

        @param node: int
        """
        return _ida_graph.interactive_graph_t_is_displayable_node(self, node)

    def is_simple_node(self, node: "int") -> "bool":
        r"""
        is_simple_node(self, node) -> bool

        @param node: int
        """
        return _ida_graph.interactive_graph_t_is_simple_node(self, node)

    def is_collapsed_node(self, node: "int") -> "bool":
        r"""
        is_collapsed_node(self, node) -> bool

        @param node: int
        """
        return _ida_graph.interactive_graph_t_is_collapsed_node(self, node)

    def is_uncollapsed_node(self, node: "int") -> "bool":
        r"""
        is_uncollapsed_node(self, node) -> bool

        @param node: int
        """
        return _ida_graph.interactive_graph_t_is_uncollapsed_node(self, node)

    def is_visible_node(self, node: "int") -> "bool":
        r"""
        is_visible_node(self, node) -> bool
        Is the node currently visible?

        An invisible node is a node that's part of a group that's currently collapsed.

        @param node: (C++: int) the node
        @return: success
        """
        return _ida_graph.interactive_graph_t_is_visible_node(self, node)

    def get_first_subgraph_node(self, group: "int") -> "int":
        r"""
        get_first_subgraph_node(self, group) -> int

        @param group: int
        """
        return _ida_graph.interactive_graph_t_get_first_subgraph_node(self, group)

    def get_next_subgraph_node(self, group: "int", current: "int") -> "int":
        r"""
        get_next_subgraph_node(self, group, current) -> int

        @param group: int
        @param current: int
        """
        return _ida_graph.interactive_graph_t_get_next_subgraph_node(self, group, current)

    def create_group(self, nodes: "intvec_t const &") -> "int":
        r"""
        create_group(self, nodes) -> int
        Create a new group node, that will contain all the nodes in 'nodes'.

        @param nodes: (C++: const intvec_t &) the nodes that will be part of the group
        @return: the group node, or -1 in case of error
        """
        return _ida_graph.interactive_graph_t_create_group(self, nodes)

    def delete_group(self, group: "int") -> "bool":
        r"""
        delete_group(self, group) -> bool
        Delete a group node.

        This deletes the group node only; it does not delete nodes that are part of the
        group.

        @param group: (C++: int) the group node
        @return: success
        """
        return _ida_graph.interactive_graph_t_delete_group(self, group)

    def change_group_visibility(self, group: "int", expand: "bool") -> "bool":
        r"""
        change_group_visibility(self, group, expand) -> bool
        Expand/collapse a group node

        @param group: (C++: int) the group node
        @param expand: (C++: bool) whether to expand or collapse
        @return: success
        """
        return _ida_graph.interactive_graph_t_change_group_visibility(self, group, expand)

    def nsucc(self, b: "int") -> "int":
        r"""
        nsucc(self, b) -> int

        @param b: int
        """
        return _ida_graph.interactive_graph_t_nsucc(self, b)

    def npred(self, b: "int") -> "int":
        r"""
        npred(self, b) -> int

        @param b: int
        """
        return _ida_graph.interactive_graph_t_npred(self, b)

    def succ(self, b: "int", i: "int") -> "int":
        r"""
        succ(self, b, i) -> int

        @param b: int
        @param i: int
        """
        return _ida_graph.interactive_graph_t_succ(self, b, i)

    def pred(self, b: "int", i: "int") -> "int":
        r"""
        pred(self, b, i) -> int

        @param b: int
        @param i: int
        """
        return _ida_graph.interactive_graph_t_pred(self, b, i)

    def succset(self, b: "int") -> "intvec_t const &":
        r"""
        succset(self, b) -> intvec_t const &

        @param b: int
        """
        return _ida_graph.interactive_graph_t_succset(self, b)

    def predset(self, b: "int") -> "intvec_t const &":
        r"""
        predset(self, b) -> intvec_t const &

        @param b: int
        """
        return _ida_graph.interactive_graph_t_predset(self, b)

    def reset(self) -> "void":
        r"""
        reset(self)
        """
        return _ida_graph.interactive_graph_t_reset(self)

    def redo_layout(self) -> "bool":
        r"""
        redo_layout(self) -> bool
        Recompute the layout, according to the value of 'current_layout'.

        @return: success
        """
        return _ida_graph.interactive_graph_t_redo_layout(self)

    def resize(self, n: "int") -> "void":
        r"""
        resize(self, n)
        Resize the graph to 'n' nodes

        @param n: (C++: int) the new size
        """
        return _ida_graph.interactive_graph_t_resize(self, n)

    def add_node(self, r: "rect_t") -> "int":
        r"""
        add_node(self, r) -> int
        Add a node, possibly with a specific geometry

        @param r: (C++: const rect_t *) the node geometry (can be nullptr)
        @return: the new node
        """
        return _ida_graph.interactive_graph_t_add_node(self, r)

    def del_node(self, n: "int") -> "ssize_t":
        r"""
        del_node(self, n) -> ssize_t
        Delete a node

        @param n: (C++: int) the node to delete
        @return: the number of deleted edges
        """
        return _ida_graph.interactive_graph_t_del_node(self, n)

    def add_edge(self, i: "int", j: "int", ei: "edge_info_t") -> "bool":
        r"""
        add_edge(self, i, j, ei) -> bool

        @param i: int
        @param j: int
        @param ei: edge_info_t const *
        """
        return _ida_graph.interactive_graph_t_add_edge(self, i, j, ei)

    def del_edge(self, i: "int", j: "int") -> "bool":
        r"""
        del_edge(self, i, j) -> bool

        @param i: int
        @param j: int
        """
        return _ida_graph.interactive_graph_t_del_edge(self, i, j)

    def replace_edge(self, i: "int", j: "int", x: "int", y: "int") -> "bool":
        r"""
        replace_edge(self, i, j, x, y) -> bool

        @param i: int
        @param j: int
        @param x: int
        @param y: int
        """
        return _ida_graph.interactive_graph_t_replace_edge(self, i, j, x, y)

    def refresh(self) -> "bool":
        r"""
        refresh(self) -> bool
        Refresh the graph

        A graph needs refreshing when it's "backing data". E.g., if the number (or
        contents) of the objects in the above example, change.

        Let's say the user's plugin ends up finding a 5th piece of scattered data. It
        should then add it to its internal list of known objects, and tell IDA that the
        graph needs to be refreshed, using refresh_viewer(). This will cause IDA to:
        * discard all its internal rendering information,
        * call interactive_graph_t::refresh() on the graph so that the user's plugin has
        a chance to "sync" the number of nodes & edges that this graph contains, to the
        information that the plugin has collected so far
        * re-create internal rendering information, and
        * repaint the view

        @return: success
        """
        return _ida_graph.interactive_graph_t_refresh(self)

    def set_nrect(self, n: "int", r: "rect_t") -> "bool":
        r"""
        set_nrect(self, n, r) -> bool

        @param n: int
        @param r: rect_t const &
        """
        return _ida_graph.interactive_graph_t_set_nrect(self, n, r)

    def set_edge(self, e: "edge_t", ei: "edge_info_t") -> "bool":
        r"""
        set_edge(self, e, ei) -> bool

        @param e: edge_t
        @param ei: edge_info_t const *
        """
        return _ida_graph.interactive_graph_t_set_edge(self, e, ei)

    def create_digraph_layout(self) -> "bool":
        r"""
        create_digraph_layout(self) -> bool
        """
        return _ida_graph.interactive_graph_t_create_digraph_layout(self)

    def del_custom_layout(self) -> "void":
        r"""
        del_custom_layout(self)
        """
        return _ida_graph.interactive_graph_t_del_custom_layout(self)

    def get_custom_layout(self) -> "bool":
        r"""
        get_custom_layout(self) -> bool
        """
        return _ida_graph.interactive_graph_t_get_custom_layout(self)

    def set_custom_layout(self) -> "void":
        r"""
        set_custom_layout(self)
        """
        return _ida_graph.interactive_graph_t_set_custom_layout(self)

    def get_graph_groups(self) -> "bool":
        r"""
        get_graph_groups(self) -> bool
        """
        return _ida_graph.interactive_graph_t_get_graph_groups(self)

    def set_graph_groups(self) -> "void":
        r"""
        set_graph_groups(self)
        """
        return _ida_graph.interactive_graph_t_set_graph_groups(self)

    def calc_group_ea(self, arg2: "intvec_t const &") -> "ea_t":
        r"""
        calc_group_ea(self, arg2) -> ea_t

        @param arg2: intvec_t const &
        """
        return _ida_graph.interactive_graph_t_calc_group_ea(self, arg2)

    def is_user_graph(self) -> "bool":
        r"""
        is_user_graph(self) -> bool
        """
        return _ida_graph.interactive_graph_t_is_user_graph(self)

# Register interactive_graph_t in _ida_graph:
_ida_graph.interactive_graph_t_swigregister(interactive_graph_t)
MTG_GROUP_NODE = _ida_graph.MTG_GROUP_NODE
r"""
is group node?
"""

MTG_DOT_NODE = _ida_graph.MTG_DOT_NODE
r"""
is dot node?
"""

MTG_NON_DISPLAYABLE_NODE = _ida_graph.MTG_NON_DISPLAYABLE_NODE
r"""
for disassembly graphs - non-displayable nodes have a visible area that is too
large to generate disassembly lines for without IDA slowing down significantly
(see MAX_VISIBLE_NODE_AREA)
"""

COLLAPSED_NODE = _ida_graph.COLLAPSED_NODE


class graph_visitor_t(object):
    r"""
    Proxy of C++ graph_visitor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_graph.delete_graph_visitor_t

    def visit_node(self, arg2: "int", arg3: "rect_t") -> "int":
        r"""
        visit_node(self, arg2, arg3) -> int

        @param arg2: int
        @param arg3: rect_t &
        """
        return _ida_graph.graph_visitor_t_visit_node(self, arg2, arg3)

    def visit_edge(self, arg2: "edge_t", arg3: "edge_info_t") -> "int":
        r"""
        visit_edge(self, arg2, arg3) -> int

        @param arg2: edge_t
        @param arg3: edge_info_t *
        """
        return _ida_graph.graph_visitor_t_visit_edge(self, arg2, arg3)

    def __init__(self):
        r"""
        __init__(self) -> graph_visitor_t

        @param self: PyObject *
        """
        if self.__class__ == graph_visitor_t:
            _self = None
        else:
            _self = self
        _ida_graph.graph_visitor_t_swiginit(self, _ida_graph.new_graph_visitor_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_graph.disown_graph_visitor_t(self)
        return weakref.proxy(self)

# Register graph_visitor_t in _ida_graph:
_ida_graph.graph_visitor_t_swigregister(graph_visitor_t)
grcode_calculating_layout = _ida_graph.grcode_calculating_layout
r"""
calculating user-defined graph layout.
@param g: (interactive_graph_t *)
@retval 0: not implemented
@retval 1: graph layout calculated by the plugin
"""

grcode_layout_calculated = _ida_graph.grcode_layout_calculated
r"""
graph layout calculated.
@param g: (interactive_graph_t *)
@param layout_succeeded: (bool)
@retval 0: must return 0
"""

grcode_changed_graph = _ida_graph.grcode_changed_graph
r"""
new graph has been set.
@param g: (interactive_graph_t *)
@retval 0: must return 0
"""

grcode_reserved = _ida_graph.grcode_reserved

grcode_clicked = _ida_graph.grcode_clicked
r"""
graph is being clicked. this callback allows you to ignore some clicks. it
occurs too early, internal graph variables are not updated yet. current_item1,
current_item2 point to the same thing. item2 has more information. see also:
custom_viewer_click_t
@param gv: (graph_viewer_t *)
@param current_item1: (selection_item_t *)
@param current_item2: (graph_item_t *)
@retval 0: ok
@retval 1: ignore click
"""

grcode_dblclicked = _ida_graph.grcode_dblclicked
r"""
a graph node has been double clicked.
@param gv: (graph_viewer_t *)
@param current_item: (selection_item_t *)
@retval 0: ok
@retval 1: ignore click
"""

grcode_creating_group = _ida_graph.grcode_creating_group
r"""
a group is being created. this provides an opportunity for the graph to forbid
creation of the group. Note that groups management is done by the
interactive_graph_t instance itself: there is no need to modify the graph in
this callback.
@param g: (interactive_graph_t *)
@param nodes: (intvec_t *)
@retval 0: ok
@retval 1: forbid group creation
"""

grcode_deleting_group = _ida_graph.grcode_deleting_group
r"""
a group is being deleted. this provides an opportunity for the graph to forbid
deletion of the group. Note that groups management is done by the
interactive_graph_t instance itself: there is no need to modify the graph in
this callback.
@param g: (interactive_graph_t *)
@param old_group: (int)
@retval 0: ok
@retval 1: forbid group deletion
"""

grcode_group_visibility = _ida_graph.grcode_group_visibility
r"""
a group is being collapsed/uncollapsed this provides an opportunity for the
graph to forbid changing the visibility of the group. Note that groups
management is done by the interactive_graph_t instance itself: there is no need
to modify the graph in this callback.
@param g: (interactive_graph_t *)
@param group: (int)
@param expand: (bool)
@retval 0: ok
@retval 1: forbid group modification
"""

grcode_gotfocus = _ida_graph.grcode_gotfocus
r"""
a graph viewer got focus.
@param gv: (graph_viewer_t *)
@retval 0: must return 0
"""

grcode_lostfocus = _ida_graph.grcode_lostfocus
r"""
a graph viewer lost focus.
@param gv: (graph_viewer_t *)
@retval 0: must return 0
"""

grcode_user_refresh = _ida_graph.grcode_user_refresh
r"""
refresh user-defined graph nodes and edges This is called when the UI considers
that it is necessary to recreate the graph layout, and thus has to ensure that
the 'interactive_graph_t' instance it is using, is up-to-date. For example:
* at graph creation-time
* if a refresh_viewer() call was made
@param g: (interactive_graph_t *)
@return: success
"""

grcode_reserved2 = _ida_graph.grcode_reserved2

grcode_user_text = _ida_graph.grcode_user_text
r"""
retrieve text for user-defined graph node. NB: do not use anything calling GDI!
@param g: (interactive_graph_t *)
@param node: (int)
@param result: (const char **)
@param bg_color: (bgcolor_t *) may be nullptr
@return: success, result must be filled
"""

grcode_user_size = _ida_graph.grcode_user_size
r"""
calculate node size for user-defined graph.
@param g: (interactive_graph_t *)
@param node: (int)
@param cx: (int *)
@param cy: (int *)
@retval 0: did not calculate. ida will use node text size
@retval 1: calculated. ida will add node title to the size
"""

grcode_user_title = _ida_graph.grcode_user_title
r"""
render node title of a user-defined graph.
@param g: (interactive_graph_t *)
@param node: (int)
@param title_rect: (rect_t *)
@param title_bg_color: (int)
@param dc: (HDC)
@retval 0: did not render, ida will fill it with title_bg_color
@retval 1: rendered node title
"""

grcode_user_draw = _ida_graph.grcode_user_draw
r"""
render node of a user-defined graph. NB: draw only on the specified DC and
nowhere else!
@param g: (interactive_graph_t *)
@param node: (int)
@param node_rect: (rect_t *)
@param dc: (HDC)
@retval 0: not rendered
@retval 1: rendered
"""

grcode_user_hint = _ida_graph.grcode_user_hint
r"""
retrieve hint for the user-defined graph.
@param g: (interactive_graph_t *)
@param mousenode: (int)
@param mouseedge_src: (int)
@param mouseedge_dst: (int)
@param hint: (char **) must be allocated by qalloc() or qstrdup()
@retval 0: use default hint
@retval 1: use proposed hint
"""

grcode_destroyed = _ida_graph.grcode_destroyed
r"""
graph is being destroyed. Note that this doesn't mean the graph viewer is being
destroyed; this only means that the graph that is being displayed by it is being
destroyed, and that, e.g., any possibly cached data should be invalidated (this
event can happen when, for example, the user decides to group nodes together:
that operation will effectively create a new graph, that will replace the old
one.) To be notified when the graph viewer itself is being destroyed, please see
notification 'view_close', in kernwin.hpp
@param g: (interactive_graph_t *)
@retval 0: must return 0
"""

grcode_create_graph_viewer = _ida_graph.grcode_create_graph_viewer
r"""
use create_graph_viewer()
"""

grcode_get_graph_viewer = _ida_graph.grcode_get_graph_viewer
r"""
use get_graph_viewer()
"""

grcode_get_viewer_graph = _ida_graph.grcode_get_viewer_graph
r"""
use get_viewer_graph()
"""

grcode_create_interactive_graph = _ida_graph.grcode_create_interactive_graph
r"""
use create_interactive_graph()
"""

grcode_set_viewer_graph = _ida_graph.grcode_set_viewer_graph
r"""
use set_viewer_graph()
"""

grcode_refresh_viewer = _ida_graph.grcode_refresh_viewer
r"""
use refresh_viewer()
"""

grcode_fit_window = _ida_graph.grcode_fit_window
r"""
use viewer_fit_window()
"""

grcode_get_curnode = _ida_graph.grcode_get_curnode
r"""
use viewer_get_curnode()
"""

grcode_center_on = _ida_graph.grcode_center_on
r"""
use viewer_center_on()
"""

grcode_get_selection = _ida_graph.grcode_get_selection
r"""
use viewer_get_selection()
"""

grcode_del_custom_layout = _ida_graph.grcode_del_custom_layout
r"""
use interactive_graph_t::del_custom_layout()
"""

grcode_set_custom_layout = _ida_graph.grcode_set_custom_layout
r"""
use interactive_graph_t::set_custom_layout()
"""

grcode_set_graph_groups = _ida_graph.grcode_set_graph_groups
r"""
use interactive_graph_t::set_graph_groups()
"""

grcode_clear = _ida_graph.grcode_clear
r"""
use interactive_graph_t::clear()
"""

grcode_create_digraph_layout = _ida_graph.grcode_create_digraph_layout
r"""
use interactive_graph_t::create_digraph_layout()
"""

grcode_create_tree_layout = _ida_graph.grcode_create_tree_layout
r"""
use drawable_graph_t::create_tree_layout()
"""

grcode_create_circle_layout = _ida_graph.grcode_create_circle_layout
r"""
use drawable_graph_t::create_circle_layout()
"""

grcode_get_node_representative = _ida_graph.grcode_get_node_representative
r"""
use interactive_graph_t::get_node_representative()
"""

grcode_find_subgraph_node = _ida_graph.grcode_find_subgraph_node
r"""
use interactive_graph_t::_find_subgraph_node()
"""

grcode_create_group = _ida_graph.grcode_create_group
r"""
use interactive_graph_t::create_group()
"""

grcode_get_custom_layout = _ida_graph.grcode_get_custom_layout
r"""
use interactive_graph_t::get_custom_layout()
"""

grcode_get_graph_groups = _ida_graph.grcode_get_graph_groups
r"""
use interactive_graph_t::get_graph_groups()
"""

grcode_empty = _ida_graph.grcode_empty
r"""
use interactive_graph_t::empty()
"""

grcode_is_visible_node = _ida_graph.grcode_is_visible_node
r"""
use interactive_graph_t::is_visible_node()
"""

grcode_delete_group = _ida_graph.grcode_delete_group
r"""
use interactive_graph_t::delete_group()
"""

grcode_change_group_visibility = _ida_graph.grcode_change_group_visibility
r"""
use interactive_graph_t::change_group_visibility()
"""

grcode_set_edge = _ida_graph.grcode_set_edge
r"""
use interactive_graph_t::set_edge()
"""

grcode_node_qty = _ida_graph.grcode_node_qty
r"""
use interactive_graph_t::node_qty()
"""

grcode_nrect = _ida_graph.grcode_nrect
r"""
use interactive_graph_t::nrect()
"""

grcode_set_titlebar_height = _ida_graph.grcode_set_titlebar_height
r"""
use viewer_set_titlebar_height()
"""

grcode_create_user_graph_place = _ida_graph.grcode_create_user_graph_place
r"""
use create_user_graph_place()
"""

grcode_create_disasm_graph1 = _ida_graph.grcode_create_disasm_graph1
r"""
use create_disasm_graph(ea_t ea)
"""

grcode_create_disasm_graph2 = _ida_graph.grcode_create_disasm_graph2
r"""
use create_disasm_graph(const rangevec_t &ranges)
"""

grcode_set_node_info = _ida_graph.grcode_set_node_info
r"""
use viewer_set_node_info()
"""

grcode_get_node_info = _ida_graph.grcode_get_node_info
r"""
use viewer_get_node_info()
"""

grcode_del_node_info = _ida_graph.grcode_del_node_info
r"""
use viewer_del_node_info()
"""

grcode_viewer_create_groups = _ida_graph.grcode_viewer_create_groups

grcode_viewer_delete_groups = _ida_graph.grcode_viewer_delete_groups

grcode_viewer_groups_visibility = _ida_graph.grcode_viewer_groups_visibility

grcode_viewer_create_groups_vec = _ida_graph.grcode_viewer_create_groups_vec
r"""
use viewer_create_groups()
"""

grcode_viewer_delete_groups_vec = _ida_graph.grcode_viewer_delete_groups_vec
r"""
use viewer_delete_groups()
"""

grcode_viewer_groups_visibility_vec = _ida_graph.grcode_viewer_groups_visibility_vec
r"""
use viewer_set_groups_visibility()
"""

grcode_delete_interactive_graph = _ida_graph.grcode_delete_interactive_graph
r"""
use delete_interactive_graph()
"""

grcode_edge_infos_wrapper_copy = _ida_graph.grcode_edge_infos_wrapper_copy
r"""
use edge_infos_wrapper_t::operator=()
"""

grcode_edge_infos_wrapper_clear = _ida_graph.grcode_edge_infos_wrapper_clear
r"""
use edge_infos_wrapper_t::clear()
"""

grcode_attach_menu_item = _ida_graph.grcode_attach_menu_item

grcode_set_gli = _ida_graph.grcode_set_gli
r"""
use viewer_set_gli()
"""

grcode_get_gli = _ida_graph.grcode_get_gli
r"""
use viewer_get_gli()
"""

class group_crinfo_t(object):
    r"""
    Proxy of C++ group_crinfo_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    nodes: "intvec_t" = property(_ida_graph.group_crinfo_t_nodes_get, _ida_graph.group_crinfo_t_nodes_set, doc=r"""nodes""")
    text: "qstring" = property(_ida_graph.group_crinfo_t_text_get, _ida_graph.group_crinfo_t_text_set, doc=r"""text""")

    def __init__(self):
        r"""
        __init__(self) -> group_crinfo_t
        """
        _ida_graph.group_crinfo_t_swiginit(self, _ida_graph.new_group_crinfo_t())
    __swig_destroy__ = _ida_graph.delete_group_crinfo_t

# Register group_crinfo_t in _ida_graph:
_ida_graph.group_crinfo_t_swigregister(group_crinfo_t)

def create_graph_viewer(title: "char const *", id: "uval_t", callback: "hook_cb_t *", ud: "void *", title_height: "int", parent: "TWidget *"=None) -> "graph_viewer_t *":
    r"""
    create_graph_viewer(title, id, callback, ud, title_height, parent=None) -> graph_viewer_t
    Create a custom graph viewer.

    @param title: (C++: const char *) the widget title
    @param id: (C++: uval_t) graph id
    @param callback: (C++: hook_cb_t *) callback to handle graph notifications (graph_notification_t)
    @param ud: (C++: void *) user data passed to callback
    @param title_height: (C++: int) node title height
    @param parent: (C++: TWidget *) the parent widget of the graph viewer
    @return: new viewer
    """
    return _ida_graph.create_graph_viewer(title, id, callback, ud, title_height, parent)

def get_graph_viewer(parent: "TWidget *") -> "graph_viewer_t *":
    r"""
    get_graph_viewer(parent) -> graph_viewer_t *
    Get custom graph viewer for given form.

    @param parent: (C++: TWidget *)
    """
    return _ida_graph.get_graph_viewer(parent)

def create_interactive_graph(id: "uval_t") -> "interactive_graph_t *":
    r"""
    create_interactive_graph(id) -> interactive_graph_t
    Create a new empty graph with given id.

    @param id: (C++: uval_t)
    """
    return _ida_graph.create_interactive_graph(id)

def create_disasm_graph(*args) -> "interactive_graph_t *":
    r"""
    create_disasm_graph(ea) -> interactive_graph_t
    Create a graph using an arbitrary set of ranges.

    @param ea: ea_t

    create_disasm_graph(ranges) -> interactive_graph_t

    @param ranges: rangevec_t const &
    """
    return _ida_graph.create_disasm_graph(*args)

def get_viewer_graph(gv: "graph_viewer_t *") -> "interactive_graph_t *":
    r"""
    get_viewer_graph(gv) -> interactive_graph_t
    Get graph object for given custom graph viewer.

    @param gv: (C++: graph_viewer_t *)
    """
    return _ida_graph.get_viewer_graph(gv)

def set_viewer_graph(gv: "graph_viewer_t *", g: "interactive_graph_t") -> "void":
    r"""
    set_viewer_graph(gv, g)
    Set the underlying graph object for the given viewer.

    @param gv: (C++: graph_viewer_t *)
    @param g: (C++: interactive_graph_t *)
    """
    return _ida_graph.set_viewer_graph(gv, g)

def refresh_viewer(gv: "graph_viewer_t *") -> "void":
    r"""
    refresh_viewer(gv)
    Redraw the graph in the given view.

    @param gv: (C++: graph_viewer_t *)
    """
    return _ida_graph.refresh_viewer(gv)

def viewer_fit_window(gv: "graph_viewer_t *") -> "void":
    r"""
    viewer_fit_window(gv)
    Fit graph viewer to its parent form.

    @param gv: (C++: graph_viewer_t *)
    """
    return _ida_graph.viewer_fit_window(gv)

def viewer_get_curnode(gv: "graph_viewer_t *") -> "int":
    r"""
    viewer_get_curnode(gv) -> int
    Get number of currently selected node (-1 if none)

    @param gv: (C++: graph_viewer_t *)
    """
    return _ida_graph.viewer_get_curnode(gv)

def viewer_center_on(gv: "graph_viewer_t *", node: "int") -> "void":
    r"""
    viewer_center_on(gv, node)
    Center the graph view on the given node.

    @param gv: (C++: graph_viewer_t *)
    @param node: (C++: int)
    """
    return _ida_graph.viewer_center_on(gv, node)

def viewer_set_gli(gv: "graph_viewer_t *", gli: "graph_location_info_t const *", flags: "uint32"=0) -> "void":
    r"""
    viewer_set_gli(gv, gli, flags=0)
    Set location info for given graph view If flags contains GLICTL_CENTER, then the
    gli will be set to be the center of the view. Otherwise it will be the top-left.

    @param gv: (C++: graph_viewer_t *)
    @param gli: (C++: const graph_location_info_t *) graph_location_info_t const *
    @param flags: (C++: uint32)
    """
    return _ida_graph.viewer_set_gli(gv, gli, flags)

def viewer_get_gli(out: "graph_location_info_t *", gv: "graph_viewer_t *", flags: "uint32"=0) -> "bool":
    r"""
    viewer_get_gli(out, gv, flags=0) -> bool
    Get location info for given graph view If flags contains GLICTL_CENTER, then the
    gli that will be retrieved, will be the one at the center of the view. Otherwise
    it will be the top-left.

    @param out: (C++: graph_location_info_t *)
    @param gv: (C++: graph_viewer_t *)
    @param flags: (C++: uint32)
    """
    return _ida_graph.viewer_get_gli(out, gv, flags)

def viewer_set_node_info(gv: "graph_viewer_t *", n: "int", ni: "node_info_t", flags: "uint32") -> "void":
    r"""
    viewer_set_node_info(gv, n, ni, flags)
    Set node info for node in given viewer (see set_node_info())

    @param gv: (C++: graph_viewer_t *)
    @param n: (C++: int)
    @param ni: (C++: const node_info_t &) node_info_t const &
    @param flags: (C++: uint32)
    """
    return _ida_graph.viewer_set_node_info(gv, n, ni, flags)

def viewer_get_node_info(gv: "graph_viewer_t *", out: "node_info_t", n: "int") -> "bool":
    r"""
    viewer_get_node_info(gv, out, n) -> bool
    Get node info for node in given viewer (see get_node_info())

    @param gv: (C++: graph_viewer_t *)
    @param out: (C++: node_info_t *)
    @param n: (C++: int)
    """
    return _ida_graph.viewer_get_node_info(gv, out, n)

def viewer_del_node_info(gv: "graph_viewer_t *", n: "int") -> "void":
    r"""
    viewer_del_node_info(gv, n)
    Delete node info for node in given viewer (see del_node_info())

    @param gv: (C++: graph_viewer_t *)
    @param n: (C++: int)
    """
    return _ida_graph.viewer_del_node_info(gv, n)

def viewer_create_groups(gv: "graph_viewer_t *", out_group_nodes: "intvec_t *", gi: "groups_crinfos_t const &") -> "bool":
    r"""
    viewer_create_groups(gv, out_group_nodes, gi) -> bool
    This will perform an operation similar to what happens when a user manually
    selects a set of nodes, right-clicks and selects "Create group". This is a
    wrapper around interactive_graph_t::create_group that will, in essence:
    * clone the current graph
    * for each group_crinfo_t, attempt creating group in that new graph
    * if all were successful, animate to that new graph.
    @note: this accepts parameters that allow creating of multiple groups at once;
           which means only one graph animation will be triggered.

    @param gv: (C++: graph_viewer_t *)
    @param out_group_nodes: (C++: intvec_t *)
    @param gi: (C++: const groups_crinfos_t &) groups_crinfos_t const &
    """
    return _ida_graph.viewer_create_groups(gv, out_group_nodes, gi)

def viewer_delete_groups(gv: "graph_viewer_t *", groups: "intvec_t const &", new_current: "int"=-1) -> "bool":
    r"""
    viewer_delete_groups(gv, groups, new_current=-1) -> bool
    Wrapper around interactive_graph_t::delete_group. This function will:
    * clone the current graph
    * attempt deleting the groups in that new graph
    * if successful, animate to that new graph.

    @param gv: (C++: graph_viewer_t *)
    @param groups: (C++: const intvec_t &) intvec_t const &
    @param new_current: (C++: int)
    """
    return _ida_graph.viewer_delete_groups(gv, groups, new_current)

def viewer_set_groups_visibility(gv: "graph_viewer_t *", groups: "intvec_t const &", expand: "bool", new_current: "int"=-1) -> "bool":
    r"""
    viewer_set_groups_visibility(gv, groups, expand, new_current=-1) -> bool
    Wrapper around interactive_graph_t::change_visibility. This function will:
    * clone the current graph
    * attempt changing visibility of the groups in that new graph
    * if successful, animate to that new graph.

    @param gv: (C++: graph_viewer_t *)
    @param groups: (C++: const intvec_t &) intvec_t const &
    @param expand: (C++: bool)
    @param new_current: (C++: int)
    """
    return _ida_graph.viewer_set_groups_visibility(gv, groups, expand, new_current)

def viewer_attach_menu_item(g: "graph_viewer_t *", name: "char const *") -> "bool":
    r"""
    viewer_attach_menu_item(g, name) -> bool
    Attach a previously-registered action to the view's context menu. See
    kernwin.hpp for how to register actions.

    @param g: (C++: graph_viewer_t *) graph viewer
    @param name: (C++: const char *) action name
    @return: success
    """
    return _ida_graph.viewer_attach_menu_item(g, name)

def viewer_get_selection(gv: "graph_viewer_t *", sgs: "screen_graph_selection_t") -> "bool":
    r"""
    viewer_get_selection(gv, sgs) -> bool
    Get currently selected items for graph viewer.

    @param gv: (C++: graph_viewer_t *)
    @param sgs: (C++: screen_graph_selection_t *)
    """
    return _ida_graph.viewer_get_selection(gv, sgs)

def viewer_set_titlebar_height(gv: "graph_viewer_t *", height: "int") -> "int":
    r"""
    viewer_set_titlebar_height(gv, height) -> int
    Set height of node title bars (grcode_set_titlebar_height)

    @param gv: (C++: graph_viewer_t *)
    @param height: (C++: int)
    """
    return _ida_graph.viewer_set_titlebar_height(gv, height)

def delete_interactive_graph(g: "interactive_graph_t") -> "void":
    r"""
    delete_interactive_graph(g)
    Delete graph object.
    @warning: use this only if you are dealing with interactive_graph_t instances
              that have not been used together with a graph_viewer_t. If you have
              called set_viewer_graph() with your graph, the graph's lifecycle will
              be managed by the viewer, and you shouldn't interfere with it

    @param g: (C++: interactive_graph_t *)
    """
    return _ida_graph.delete_interactive_graph(g)
class user_graph_place_t(object):
    r"""
    Proxy of C++ user_graph_place_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined - class is abstract")
    __repr__ = _swig_repr
    node: "int" = property(_ida_graph.user_graph_place_t_node_get, _ida_graph.user_graph_place_t_node_set, doc=r"""node""")

# Register user_graph_place_t in _ida_graph:
_ida_graph.user_graph_place_t_swigregister(user_graph_place_t)

def create_user_graph_place(node: "int", lnnum: "int") -> "user_graph_place_t *":
    r"""
    create_user_graph_place(node, lnnum) -> user_graph_place_t
    Get a copy of a user_graph_place_t (returns a pointer to static storage)

    @param node: (C++: int)
    @param lnnum: (C++: int)
    """
    return _ida_graph.create_user_graph_place(node, lnnum)

def pyg_close(_self: "PyObject *") -> "void":
    r"""
    pyg_close(_self)

    @param self: PyObject *
    """
    return _ida_graph.pyg_close(_self)

def pyg_select_node(_self: "PyObject *", nid: "int") -> "void":
    r"""
    pyg_select_node(_self, nid)

    @param self: PyObject *
    @param nid: int
    """
    return _ida_graph.pyg_select_node(_self, nid)

def pyg_show(_self: "PyObject *") -> "bool":
    r"""
    pyg_show(_self) -> bool

    @param self: PyObject *
    """
    return _ida_graph.pyg_show(_self)

#<pycode(py_graph)>
import ida_idaapi
import ida_kernwin
import ida_gdl

edge_t = ida_gdl.edge_t
node_ordering_t = ida_gdl.node_ordering_t
abstract_graph_t = drawable_graph_t
mutable_graph_t = interactive_graph_t

create_mutable_graph = create_interactive_graph
delete_mutable_graph = delete_interactive_graph
grcode_create_mutable_graph = grcode_create_interactive_graph
grcode_create_mutable_graph = grcode_create_interactive_graph

class GraphViewer(ida_kernwin.CustomIDAMemo):
    class UI_Hooks_Trampoline(ida_kernwin.UI_Hooks):
        def __init__(self, v):
            ida_kernwin.UI_Hooks.__init__(self)
            self.hook()
            import weakref
            self.v = weakref.ref(v)

        def populating_widget_popup(self, w, popup_handle):
            my_w = self.v().GetWidget()
            if w == my_w:
                self.v().OnPopup(my_w, popup_handle)

    """This class wraps the user graphing facility provided by the graph.hpp file"""
    def __init__(self, title, close_open = False):
        r"""
        Constructs the GraphView object.
        Please do not remove or rename the private fields

        @param title: The title of the graph window
        @param close_open: Should it attempt to close an existing graph (with same title) before creating this graph?
        """
        self._title = title
        self._nodes = []
        self._edges = []
        self._close_open = close_open
        def _qccb(ctx, cmd_id):
            return self.OnCommand(cmd_id)
        self._quick_commands = ida_kernwin.quick_widget_commands_t(_qccb)
        ida_kernwin.CustomIDAMemo.__init__(self)
        self.ui_hooks_trampoline = self.UI_Hooks_Trampoline(self)

    def AddNode(self, obj):
        r"""
        Creates a node associated with the given object and returns the node id
        """
        id = len(self._nodes)
        self._nodes.append(obj)
        return id

    def AddEdge(self, src_node, dest_node):
        r"""
        Creates an edge between two given node ids
        """
        assert src_node < len(self._nodes), "Source node %d is out of bounds" % src_node
        assert dest_node < len(self._nodes), "Destination node %d is out of bounds" % dest_node
        self._edges.append( (src_node, dest_node) )

    def Clear(self):
        r"""
        Clears all the nodes and edges
        """
        self._nodes = []
        self._edges = []

    def __iter__(self):
        return (self._nodes[index] for index in range(0, len(self._nodes)))

    def __getitem__(self, idx):
        r"""
        Returns a reference to the object associated with this node id
        """
        if idx >= len(self._nodes):
            raise KeyError
        else:
            return self._nodes[idx]

    def Count(self):
        r"""
        Returns the node count
        """
        return len(self._nodes)

    def Close(self):
        r"""
        Closes the graph.
        It is possible to call Show() again (which will recreate the graph)
        """
        _ida_graph.pyg_close(self)

    def Show(self):
        r"""
        Shows an existing graph or creates a new one

        @return: Boolean
        """
        if self._close_open:
            import ida_kernwin
            frm = ida_kernwin.find_widget(self._title)
            if frm:
                ida_kernwin.close_widget(frm, 0)
        return _ida_graph.pyg_show(self)

    def Select(self, node_id):
        r"""
        Selects a node on the graph
        """
        _ida_graph.pyg_select_node(self, node_id)

    def OnRefresh(self):
        r"""
        Event called when the graph is refreshed or first created.
        From this event you are supposed to create nodes and edges.
        This callback is mandatory.

        @note: ***It is important to clear previous nodes before adding nodes.***
        @return: Returning True tells the graph viewer to use the items. Otherwise old items will be used.
        """
        self.Clear()

        return True

    def AddCommand(self, title, shortcut):
        return self._quick_commands.add(
            caption=title,
            flags=ida_kernwin.CHOOSER_POPUP_MENU,
            menu_index=-1,
            icon=-1,
            emb=None,
            shortcut=shortcut)

    def OnPopup(self, widget, popup_handle):
        self._quick_commands.populate_popup(widget, popup_handle)

    def OnCommand(self, cmd_id):
        return 0

    def _OnBind(self, hook):
        if hook:
            self.ui_hooks_trampoline.hook()
        else:
            self.ui_hooks_trampoline.unhook()
        super()._OnBind(hook)

#<pydoc>
#    def OnGetText(self, node_id):
#        """
#        Triggered when the graph viewer wants the text and color for a given node.
#        This callback is triggered one time for a given node (the value will be cached and used later without calling Python).
#        When you call refresh then again this callback will be called for each node.
#
#        This callback is mandatory.
#
#        @return: Return a string to describe the node text or return a tuple (node_text, node_color) to describe both text and color
#        """
#        return str(self[node_id])
#
#    def OnActivate(self):
#        """
#        Triggered when the graph window gets the focus
#        @return: None
#        """
#        print("Activated....")
#
#    def OnDeactivate(self):
#        """Triggered when the graph window loses the focus
#        @return: None
#        """
#        print("Deactivated....")
#
#    def OnHint(self, node_id):
#        """
#        Triggered when the graph viewer wants to retrieve hint text associated with a given node
#
#        @return: None if no hint is avail or a string designating the hint
#        """
#        return "hint for " + str(node_id)
#
#    def OnEdgeHint(self, src, dst):
#        """
#        Triggered when the graph viewer wants to retrieve hint text associated with a edge
#
#        @return: None if no hint is avail or a string designating the hint
#        """
#        return "hint for edge %d -> %d" % (src, dst)
#
#    def OnClose(self):
#        """Triggered when the graph viewer window is being closed
#        @return: None
#        """
#        print("Closing.......")
#
#    def OnClick(self, node_id):
#        """
#        Triggered when a node is clicked
#        @return: False to ignore the click and True otherwise
#        """
#        print("clicked on", self[node_id])
#        return True
#
#    def OnDblClick(self, node_id):
#        """
#        Triggerd when a node is double-clicked.
#        @return: False to ignore the click and True otherwise
#        """
#        print("dblclicked on", self[node_id])
#        return True
#</pydoc>
#</pycode(py_graph)>



