r"""
"""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_moves
else:
    import _ida_moves

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

SWIG_PYTHON_LEGACY_BOOL = _ida_moves.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

class segm_move_info_vec_t(object):
    r"""
    Proxy of C++ qvector< segm_move_info_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> segm_move_info_vec_t
        __init__(self, x) -> segm_move_info_vec_t

        @param x: qvector< segm_move_info_t > const &
        """
        _ida_moves.segm_move_info_vec_t_swiginit(self, _ida_moves.new_segm_move_info_vec_t(*args))
    __swig_destroy__ = _ida_moves.delete_segm_move_info_vec_t

    def push_back(self, *args) -> "segm_move_info_t &":
        r"""
        push_back(self, x)

        @param x: segm_move_info_t const &

        push_back(self) -> segm_move_info_t
        """
        return _ida_moves.segm_move_info_vec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_moves.segm_move_info_vec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_moves.segm_move_info_vec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_moves.segm_move_info_vec_t_empty(self)

    def at(self, _idx: "size_t") -> "segm_move_info_t const &":
        r"""
        at(self, _idx) -> segm_move_info_t

        @param _idx: size_t
        """
        return _ida_moves.segm_move_info_vec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_moves.segm_move_info_vec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_moves.segm_move_info_vec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: segm_move_info_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_moves.segm_move_info_vec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=segm_move_info_t())

        @param x: segm_move_info_t const &
        """
        return _ida_moves.segm_move_info_vec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_moves.segm_move_info_vec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_moves.segm_move_info_vec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_moves.segm_move_info_vec_t_truncate(self)

    def swap(self, r: "segm_move_info_vec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< segm_move_info_t > &
        """
        return _ida_moves.segm_move_info_vec_t_swap(self, r)

    def extract(self) -> "segm_move_info_t *":
        r"""
        extract(self) -> segm_move_info_t
        """
        return _ida_moves.segm_move_info_vec_t_extract(self)

    def inject(self, s: "segm_move_info_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: segm_move_info_t *
        @param len: size_t
        """
        return _ida_moves.segm_move_info_vec_t_inject(self, s, len)

    def __eq__(self, r: "segm_move_info_vec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< segm_move_info_t > const &
        """
        return _ida_moves.segm_move_info_vec_t___eq__(self, r)

    def __ne__(self, r: "segm_move_info_vec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< segm_move_info_t > const &
        """
        return _ida_moves.segm_move_info_vec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< segm_move_info_t >::const_iterator":
        r"""
        begin(self) -> segm_move_info_t
        """
        return _ida_moves.segm_move_info_vec_t_begin(self, *args)

    def end(self, *args) -> "qvector< segm_move_info_t >::const_iterator":
        r"""
        end(self) -> segm_move_info_t
        """
        return _ida_moves.segm_move_info_vec_t_end(self, *args)

    def insert(self, it: "segm_move_info_t", x: "segm_move_info_t") -> "qvector< segm_move_info_t >::iterator":
        r"""
        insert(self, it, x) -> segm_move_info_t

        @param it: qvector< segm_move_info_t >::iterator
        @param x: segm_move_info_t const &
        """
        return _ida_moves.segm_move_info_vec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< segm_move_info_t >::iterator":
        r"""
        erase(self, it) -> segm_move_info_t

        @param it: qvector< segm_move_info_t >::iterator

        erase(self, first, last) -> segm_move_info_t

        @param first: qvector< segm_move_info_t >::iterator
        @param last: qvector< segm_move_info_t >::iterator
        """
        return _ida_moves.segm_move_info_vec_t_erase(self, *args)

    def find(self, *args) -> "qvector< segm_move_info_t >::const_iterator":
        r"""
        find(self, x) -> segm_move_info_t

        @param x: segm_move_info_t const &

        """
        return _ida_moves.segm_move_info_vec_t_find(self, *args)

    def has(self, x: "segm_move_info_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: segm_move_info_t const &
        """
        return _ida_moves.segm_move_info_vec_t_has(self, x)

    def add_unique(self, x: "segm_move_info_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: segm_move_info_t const &
        """
        return _ida_moves.segm_move_info_vec_t_add_unique(self, x)

    def _del(self, x: "segm_move_info_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: segm_move_info_t const &

        """
        return _ida_moves.segm_move_info_vec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_moves.segm_move_info_vec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "segm_move_info_t const &":
        r"""
        __getitem__(self, i) -> segm_move_info_t

        @param i: size_t
        """
        return _ida_moves.segm_move_info_vec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "segm_move_info_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: segm_move_info_t const &
        """
        return _ida_moves.segm_move_info_vec_t___setitem__(self, i, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register segm_move_info_vec_t in _ida_moves:
_ida_moves.segm_move_info_vec_t_swigregister(segm_move_info_vec_t)

#<pycode(py_moves)>
import ida_kernwin
#</pycode(py_moves)>

class graph_location_info_t(object):
    r"""
    Proxy of C++ graph_location_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    zoom: "double" = property(_ida_moves.graph_location_info_t_zoom_get, _ida_moves.graph_location_info_t_zoom_set, doc=r"""zoom""")
    orgx: "double" = property(_ida_moves.graph_location_info_t_orgx_get, _ida_moves.graph_location_info_t_orgx_set, doc=r"""orgx""")
    orgy: "double" = property(_ida_moves.graph_location_info_t_orgy_get, _ida_moves.graph_location_info_t_orgy_set, doc=r"""orgy""")

    def __init__(self):
        r"""
        __init__(self) -> graph_location_info_t
        """
        _ida_moves.graph_location_info_t_swiginit(self, _ida_moves.new_graph_location_info_t())

    def __eq__(self, r: "graph_location_info_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: graph_location_info_t const &
        """
        return _ida_moves.graph_location_info_t___eq__(self, r)

    def __ne__(self, r: "graph_location_info_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: graph_location_info_t const &
        """
        return _ida_moves.graph_location_info_t___ne__(self, r)
    __swig_destroy__ = _ida_moves.delete_graph_location_info_t

# Register graph_location_info_t in _ida_moves:
_ida_moves.graph_location_info_t_swigregister(graph_location_info_t)
class segm_move_info_t(object):
    r"""
    Proxy of C++ segm_move_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, _from: "ea_t"=0, _to: "ea_t"=0, _sz: "size_t"=0):
        r"""
        __init__(self, _from=0, _to=0, _sz=0) -> segm_move_info_t

        @param _from: ea_t
        @param _to: ea_t
        @param _sz: size_t
        """
        _ida_moves.segm_move_info_t_swiginit(self, _ida_moves.new_segm_move_info_t(_from, _to, _sz))
    _from: "ea_t" = property(_ida_moves.segm_move_info_t__from_get, _ida_moves.segm_move_info_t__from_set, doc=r"""_from""")
    to: "ea_t" = property(_ida_moves.segm_move_info_t_to_get, _ida_moves.segm_move_info_t_to_set, doc=r"""to""")
    size: "size_t" = property(_ida_moves.segm_move_info_t_size_get, _ida_moves.segm_move_info_t_size_set, doc=r"""size""")

    def __eq__(self, r: "segm_move_info_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: segm_move_info_t const &
        """
        return _ida_moves.segm_move_info_t___eq__(self, r)

    def __ne__(self, r: "segm_move_info_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: segm_move_info_t const &
        """
        return _ida_moves.segm_move_info_t___ne__(self, r)
    __swig_destroy__ = _ida_moves.delete_segm_move_info_t

# Register segm_move_info_t in _ida_moves:
_ida_moves.segm_move_info_t_swigregister(segm_move_info_t)
class segm_move_infos_t(segm_move_info_vec_t):
    r"""
    Proxy of C++ segm_move_infos_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def find(self, ea: "ea_t") -> "segm_move_info_t const *":
        r"""
        find(self, ea) -> segm_move_info_t

        @param ea: ea_t
        """
        return _ida_moves.segm_move_infos_t_find(self, ea)

    def __init__(self):
        r"""
        __init__(self) -> segm_move_infos_t
        """
        _ida_moves.segm_move_infos_t_swiginit(self, _ida_moves.new_segm_move_infos_t())
    __swig_destroy__ = _ida_moves.delete_segm_move_infos_t

# Register segm_move_infos_t in _ida_moves:
_ida_moves.segm_move_infos_t_swigregister(segm_move_infos_t)
class renderer_info_pos_t(object):
    r"""
    Proxy of C++ renderer_info_pos_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    node: "int" = property(_ida_moves.renderer_info_pos_t_node_get, _ida_moves.renderer_info_pos_t_node_set, doc=r"""node""")
    cx: "short" = property(_ida_moves.renderer_info_pos_t_cx_get, _ida_moves.renderer_info_pos_t_cx_set, doc=r"""cx""")
    cy: "short" = property(_ida_moves.renderer_info_pos_t_cy_get, _ida_moves.renderer_info_pos_t_cy_set, doc=r"""cy""")

    def __init__(self):
        r"""
        __init__(self) -> renderer_info_pos_t
        """
        _ida_moves.renderer_info_pos_t_swiginit(self, _ida_moves.new_renderer_info_pos_t())

    def __eq__(self, r: "renderer_info_pos_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: renderer_info_pos_t const &
        """
        return _ida_moves.renderer_info_pos_t___eq__(self, r)

    def __ne__(self, r: "renderer_info_pos_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: renderer_info_pos_t const &
        """
        return _ida_moves.renderer_info_pos_t___ne__(self, r)
    __swig_destroy__ = _ida_moves.delete_renderer_info_pos_t

# Register renderer_info_pos_t in _ida_moves:
_ida_moves.renderer_info_pos_t_swigregister(renderer_info_pos_t)
class renderer_info_t(object):
    r"""
    Proxy of C++ renderer_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    gli: "graph_location_info_t" = property(_ida_moves.renderer_info_t_gli_get, _ida_moves.renderer_info_t_gli_set, doc=r"""gli""")
    pos: "renderer_info_t::pos_t" = property(_ida_moves.renderer_info_t_pos_get, _ida_moves.renderer_info_t_pos_set, doc=r"""pos""")
    rtype: "tcc_renderer_type_t" = property(_ida_moves.renderer_info_t_rtype_get, _ida_moves.renderer_info_t_rtype_set, doc=r"""rtype""")

    def __init__(self, *args):
        r"""
        __init__(self) -> renderer_info_t
        __init__(self, _rtype, cx, cy) -> renderer_info_t

        @param _rtype: enum tcc_renderer_type_t
        @param cx: short
        @param cy: short
        """
        _ida_moves.renderer_info_t_swiginit(self, _ida_moves.new_renderer_info_t(*args))

    def __eq__(self, r: "renderer_info_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: renderer_info_t const &
        """
        return _ida_moves.renderer_info_t___eq__(self, r)

    def __ne__(self, r: "renderer_info_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: renderer_info_t const &
        """
        return _ida_moves.renderer_info_t___ne__(self, r)
    __swig_destroy__ = _ida_moves.delete_renderer_info_t

# Register renderer_info_t in _ida_moves:
_ida_moves.renderer_info_t_swigregister(renderer_info_t)
LSEF_PLACE = _ida_moves.LSEF_PLACE

LSEF_RINFO = _ida_moves.LSEF_RINFO

LSEF_PTYPE = _ida_moves.LSEF_PTYPE

LSEF_ALL = _ida_moves.LSEF_ALL

class lochist_entry_t(object):
    r"""
    Proxy of C++ lochist_entry_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    rinfo: "renderer_info_t" = property(_ida_moves.lochist_entry_t_rinfo_get, _ida_moves.lochist_entry_t_rinfo_set, doc=r"""rinfo""")
    plce: "place_t *" = property(_ida_moves.lochist_entry_t_plce_get, _ida_moves.lochist_entry_t_plce_set, doc=r"""plce""")

    def __init__(self, *args):
        r"""
        __init__(self) -> lochist_entry_t
        __init__(self, p, r) -> lochist_entry_t

        @param p: place_t const *
        @param r: renderer_info_t const &

        __init__(self, other) -> lochist_entry_t

        @param other: lochist_entry_t const &
        """
        _ida_moves.lochist_entry_t_swiginit(self, _ida_moves.new_lochist_entry_t(*args))
    __swig_destroy__ = _ida_moves.delete_lochist_entry_t

    def renderer_info(self, *args) -> "renderer_info_t &":
        r"""
        renderer_info(self) -> renderer_info_t
        """
        return _ida_moves.lochist_entry_t_renderer_info(self, *args)

    def place(self, *args) -> "place_t *":
        r"""
        place(self) -> place_t
        """
        return _ida_moves.lochist_entry_t_place(self, *args)

    def set_place(self, p: "place_t") -> "void":
        r"""
        set_place(self, p)

        @param p: place_t const *
        """
        return _ida_moves.lochist_entry_t_set_place(self, p)

    def is_valid(self) -> "bool":
        r"""
        is_valid(self) -> bool
        """
        return _ida_moves.lochist_entry_t_is_valid(self)

    def acquire_place(self, in_p: "place_t") -> "void":
        r"""
        acquire_place(self, in_p)

        @param in_p: place_t *
        """
        return _ida_moves.lochist_entry_t_acquire_place(self, in_p)

# Register lochist_entry_t in _ida_moves:
_ida_moves.lochist_entry_t_swigregister(lochist_entry_t)
UNHID_SEGM = _ida_moves.UNHID_SEGM
r"""
unhid a segment at 'target'
"""

UNHID_FUNC = _ida_moves.UNHID_FUNC
r"""
unhid a function at 'target'
"""

UNHID_RANGE = _ida_moves.UNHID_RANGE
r"""
unhid an range at 'target'
"""

DEFAULT_CURSOR_Y = _ida_moves.DEFAULT_CURSOR_Y

DEFAULT_LNNUM = _ida_moves.DEFAULT_LNNUM

CURLOC_LIST = _ida_moves.CURLOC_LIST

MAX_MARK_SLOT = _ida_moves.MAX_MARK_SLOT

class lochist_t(object):
    r"""
    Proxy of C++ lochist_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> lochist_t
        """
        _ida_moves.lochist_t_swiginit(self, _ida_moves.new_lochist_t())
    __swig_destroy__ = _ida_moves.delete_lochist_t

    def is_history_enabled(self) -> "bool":
        r"""
        is_history_enabled(self) -> bool
        """
        return _ida_moves.lochist_t_is_history_enabled(self)

    def get_place_id(self) -> "int":
        r"""
        get_place_id(self) -> int
        """
        return _ida_moves.lochist_t_get_place_id(self)

    def init(self, stream_name: "char const *", _defpos: "place_t", _ud: "void *", _flags: "uint32") -> "bool":
        r"""
        init(self, stream_name, _defpos, _ud, _flags) -> bool

        @param stream_name: char const *
        @param _defpos: place_t const *
        @param _ud: void *
        @param _flags: uint32
        """
        return _ida_moves.lochist_t_init(self, stream_name, _defpos, _ud, _flags)

    def netcode(self) -> "nodeidx_t":
        r"""
        netcode(self) -> nodeidx_t
        """
        return _ida_moves.lochist_t_netcode(self)

    def jump(self, try_to_unhide: "bool", e: "lochist_entry_t") -> "void":
        r"""
        jump(self, try_to_unhide, e)

        @param try_to_unhide: bool
        @param e: lochist_entry_t const &
        """
        return _ida_moves.lochist_t_jump(self, try_to_unhide, e)

    def current_index(self) -> "uint32":
        r"""
        current_index(self) -> uint32
        """
        return _ida_moves.lochist_t_current_index(self)

    def seek(self, index: "uint32", try_to_unhide: "bool") -> "bool":
        r"""
        seek(self, index, try_to_unhide) -> bool

        @param index: uint32
        @param try_to_unhide: bool
        """
        return _ida_moves.lochist_t_seek(self, index, try_to_unhide)

    def fwd(self, cnt: "uint32", try_to_unhide: "bool") -> "bool":
        r"""
        fwd(self, cnt, try_to_unhide) -> bool

        @param cnt: uint32
        @param try_to_unhide: bool
        """
        return _ida_moves.lochist_t_fwd(self, cnt, try_to_unhide)

    def back(self, cnt: "uint32", try_to_unhide: "bool") -> "bool":
        r"""
        back(self, cnt, try_to_unhide) -> bool

        @param cnt: uint32
        @param try_to_unhide: bool
        """
        return _ida_moves.lochist_t_back(self, cnt, try_to_unhide)

    def save(self) -> "void":
        r"""
        save(self)
        """
        return _ida_moves.lochist_t_save(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_moves.lochist_t_clear(self)

    def get_current(self) -> "lochist_entry_t const &":
        r"""
        get_current(self) -> lochist_entry_t
        """
        return _ida_moves.lochist_t_get_current(self)

    def set_current(self, e: "lochist_entry_t") -> "void":
        r"""
        set_current(self, e)

        @param e: lochist_entry_t const &
        """
        return _ida_moves.lochist_t_set_current(self, e)

    def set(self, index: "uint32", e: "lochist_entry_t") -> "void":
        r"""
        set(self, index, e)

        @param index: uint32
        @param e: lochist_entry_t const &
        """
        return _ida_moves.lochist_t_set(self, index, e)

    def get(self, out: "lochist_entry_t", index: "uint32") -> "bool":
        r"""
        get(self, out, index) -> bool

        @param out: lochist_entry_t *
        @param index: uint32
        """
        return _ida_moves.lochist_t_get(self, out, index)

    def size(self) -> "uint32":
        r"""
        size(self) -> uint32
        """
        return _ida_moves.lochist_t_size(self)

    def get_template_place(self) -> "place_t const *":
        r"""
        get_template_place(self) -> place_t
        """
        return _ida_moves.lochist_t_get_template_place(self)

# Register lochist_t in _ida_moves:
_ida_moves.lochist_t_swigregister(lochist_t)
class bookmarks_t(object):
    r"""
    Proxy of C++ bookmarks_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr

    @staticmethod
    def mark(e: "lochist_entry_t", index: "uint32", title: "char const *", desc: "char const *", ud: "void *") -> "uint32":
        r"""
        mark(e, index, title, desc, ud) -> uint32

        @param e: lochist_entry_t const &
        @param index: uint32
        @param title: char const *
        @param desc: char const *
        @param ud: void *
        """
        return _ida_moves.bookmarks_t_mark(e, index, title, desc, ud)

    @staticmethod
    def get_desc(e: "lochist_entry_t", index: "uint32", ud: "void *") -> "qstring *":
        r"""
        get_desc(e, index, ud) -> bool

        @param e: lochist_entry_t const &
        @param index: uint32
        @param ud: void *
        """
        return _ida_moves.bookmarks_t_get_desc(e, index, ud)

    @staticmethod
    def find_index(e: "lochist_entry_t", ud: "void *") -> "uint32":
        r"""
        find_index(e, ud) -> uint32

        @param e: lochist_entry_t const &
        @param ud: void *
        """
        return _ida_moves.bookmarks_t_find_index(e, ud)

    @staticmethod
    def size(e: "lochist_entry_t", ud: "void *") -> "uint32":
        r"""
        size(e, ud) -> uint32

        @param e: lochist_entry_t const &
        @param ud: void *
        """
        return _ida_moves.bookmarks_t_size(e, ud)

    @staticmethod
    def erase(e: "lochist_entry_t", index: "uint32", ud: "void *") -> "bool":
        r"""
        erase(e, index, ud) -> bool

        @param e: lochist_entry_t const &
        @param index: uint32
        @param ud: void *
        """
        return _ida_moves.bookmarks_t_erase(e, index, ud)

    @staticmethod
    def get_dirtree_id(e: "lochist_entry_t", ud: "void *") -> "dirtree_id_t":
        r"""
        get_dirtree_id(e, ud) -> dirtree_id_t

        @param e: lochist_entry_t const &
        @param ud: void *
        """
        return _ida_moves.bookmarks_t_get_dirtree_id(e, ud)

    @staticmethod
    def get(out: "lochist_entry_t", _index: "uint32", ud: "void *") -> "PyObject *":
        r"""
        get(out, _index, ud) -> PyObject *

        @param out: lochist_entry_t *
        @param _index: uint32
        @param ud: void *
        """
        return _ida_moves.bookmarks_t_get(out, _index, ud)

    def __init__(self, w):
        """
        Build an object suitable for iterating bookmarks
        associated with the specified widget.

        Note: all ea_t-based widgets (e.g., "IDA View-*",
        "Pseudocode-*", "Hex View-*", ...) share a common storage,
        so bookmarks can be re-used interchangeably between them
        """
        self.widget = w
        self.userdata = ida_kernwin.get_viewer_user_data(self.widget)
        self.template = lochist_entry_t()
        if ida_kernwin.get_custom_viewer_location(self.template, self.widget):
            p = self.template.place()
            if p is not None:
                p_id = ida_kernwin.get_place_class_id(p.name())
                if p_id > -1 and ida_kernwin.is_place_class_ea_capable(p_id):
                    idap_id = ida_kernwin.get_place_class_id("idaplace_t")
                    if idap_id > -1:
                        idap = ida_kernwin.get_place_class_template(idap_id)
                        if idap is not None:
                            self.template.set_place(idap)

    def __iter__(self):
        r"""
        Iterate on bookmarks present for the widget.
        """
        p = self.template.place()
        if p is not None:
            for idx in range(bookmarks_t.size(self.template, self.userdata)):
                yield self[idx]

    def __len__(self):
        r"""
        Get the number of bookmarks for the widget.
        """
        return bookmarks_t.size(self.template, self.userdata)

    def __getitem__(self, idx):
        r"""
        Get the n-th bookmark for the widget.
        """
        p = self.template.place()
        if p is not None:
            if isinstance(idx, int) and idx >= 0 and idx < len(self):
                loc = lochist_entry_t()
                loc.set_place(p)
                desc, _ = bookmarks_t.get(loc, idx, self.userdata)
                return loc, desc
            else:
                raise IndexError()


# Register bookmarks_t in _ida_moves:
_ida_moves.bookmarks_t_swigregister(bookmarks_t)
BOOKMARKS_PROMPT_WITH_HINT_PREFIX = _ida_moves.BOOKMARKS_PROMPT_WITH_HINT_PREFIX



#<pycode(py_moves_end)>
bookmarks_t_erase = bookmarks_t.erase
bookmarks_t_find_index = bookmarks_t.find_index
bookmarks_t_get = bookmarks_t.get
bookmarks_t_get_desc = bookmarks_t.get_desc
bookmarks_t_get_dirtree_id = bookmarks_t.get_dirtree_id
bookmarks_t_mark = bookmarks_t.mark
bookmarks_t_size = bookmarks_t.size
#</pycode(py_moves_end)>



