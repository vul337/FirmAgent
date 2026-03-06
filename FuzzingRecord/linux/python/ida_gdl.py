r"""
Low level graph drawing operations."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_gdl
else:
    import _ida_gdl

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

SWIG_PYTHON_LEGACY_BOOL = _ida_gdl.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

import ida_range
fcb_normal = _ida_gdl.fcb_normal
r"""
normal block
"""

fcb_indjump = _ida_gdl.fcb_indjump
r"""
block ends with indirect jump
"""

fcb_ret = _ida_gdl.fcb_ret
r"""
return block
"""

fcb_cndret = _ida_gdl.fcb_cndret
r"""
conditional return block
"""

fcb_noret = _ida_gdl.fcb_noret
r"""
noreturn block
"""

fcb_enoret = _ida_gdl.fcb_enoret
r"""
external noreturn block (does not belong to the function)
"""

fcb_extern = _ida_gdl.fcb_extern
r"""
external normal block
"""

fcb_error = _ida_gdl.fcb_error
r"""
block passes execution past the function end
"""

class edge_t(object):
    r"""
    Proxy of C++ edge_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    src: "int" = property(_ida_gdl.edge_t_src_get, _ida_gdl.edge_t_src_set, doc=r"""src""")
    r"""
    source node number
    """
    dst: "int" = property(_ida_gdl.edge_t_dst_get, _ida_gdl.edge_t_dst_set, doc=r"""dst""")
    r"""
    destination node number
    """

    def __init__(self, x: "int"=0, y: "int"=0):
        r"""
        __init__(self, x=0, y=0) -> edge_t

        @param x: int
        @param y: int
        """
        _ida_gdl.edge_t_swiginit(self, _ida_gdl.new_edge_t(x, y))

    def __lt__(self, y: "edge_t") -> "bool":
        r"""
        __lt__(self, y) -> bool

        @param y: edge_t const &
        """
        return _ida_gdl.edge_t___lt__(self, y)

    def __eq__(self, y: "edge_t") -> "bool":
        r"""
        __eq__(self, y) -> bool

        @param y: edge_t const &
        """
        return _ida_gdl.edge_t___eq__(self, y)

    def __ne__(self, y: "edge_t") -> "bool":
        r"""
        __ne__(self, y) -> bool

        @param y: edge_t const &
        """
        return _ida_gdl.edge_t___ne__(self, y)
    __swig_destroy__ = _ida_gdl.delete_edge_t

# Register edge_t in _ida_gdl:
_ida_gdl.edge_t_swigregister(edge_t)
class edgevec_t(object):
    r"""
    Proxy of C++ edgevec_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> edgevec_t
        """
        _ida_gdl.edgevec_t_swiginit(self, _ida_gdl.new_edgevec_t())
    __swig_destroy__ = _ida_gdl.delete_edgevec_t

# Register edgevec_t in _ida_gdl:
_ida_gdl.edgevec_t_swigregister(edgevec_t)
EDGE_NONE = _ida_gdl.EDGE_NONE

EDGE_TREE = _ida_gdl.EDGE_TREE

EDGE_FORWARD = _ida_gdl.EDGE_FORWARD

EDGE_BACK = _ida_gdl.EDGE_BACK

EDGE_CROSS = _ida_gdl.EDGE_CROSS

EDGE_SUBGRAPH = _ida_gdl.EDGE_SUBGRAPH

class node_ordering_t(object):
    r"""
    Proxy of C++ node_ordering_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_gdl.node_ordering_t_clear(self)

    def resize(self, n: "int") -> "void":
        r"""
        resize(self, n)

        @param n: int
        """
        return _ida_gdl.node_ordering_t_resize(self, n)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_gdl.node_ordering_t_size(self)

    def set(self, _node: "int", num: "int") -> "void":
        r"""
        set(self, _node, num)

        @param _node: int
        @param num: int
        """
        return _ida_gdl.node_ordering_t_set(self, _node, num)

    def clr(self, _node: "int") -> "bool":
        r"""
        clr(self, _node) -> bool

        @param _node: int
        """
        return _ida_gdl.node_ordering_t_clr(self, _node)

    def node(self, _order: "size_t") -> "int":
        r"""
        node(self, _order) -> int

        @param _order: size_t
        """
        return _ida_gdl.node_ordering_t_node(self, _order)

    def order(self, _node: "int") -> "int":
        r"""
        order(self, _node) -> int

        @param _node: int
        """
        return _ida_gdl.node_ordering_t_order(self, _node)

    def __init__(self):
        r"""
        __init__(self) -> node_ordering_t
        """
        _ida_gdl.node_ordering_t_swiginit(self, _ida_gdl.new_node_ordering_t())
    __swig_destroy__ = _ida_gdl.delete_node_ordering_t

# Register node_ordering_t in _ida_gdl:
_ida_gdl.node_ordering_t_swigregister(node_ordering_t)
class node_iterator(object):
    r"""
    Proxy of C++ node_iterator class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, _g: "gdl_graph_t", n: "int"):
        r"""
        __init__(self, _g, n) -> node_iterator

        @param _g: gdl_graph_t const *
        @param n: int
        """
        _ida_gdl.node_iterator_swiginit(self, _ida_gdl.new_node_iterator(_g, n))

    def __eq__(self, n: "node_iterator") -> "bool":
        r"""
        __eq__(self, n) -> bool

        @param n: node_iterator const &
        """
        return _ida_gdl.node_iterator___eq__(self, n)

    def __ne__(self, n: "node_iterator") -> "bool":
        r"""
        __ne__(self, n) -> bool

        @param n: node_iterator const &
        """
        return _ida_gdl.node_iterator___ne__(self, n)

    def __ref__(self) -> "int":
        r"""
        __ref__(self) -> int
        """
        return _ida_gdl.node_iterator___ref__(self)
    __swig_destroy__ = _ida_gdl.delete_node_iterator

# Register node_iterator in _ida_gdl:
_ida_gdl.node_iterator_swigregister(node_iterator)
class gdl_graph_t(object):
    r"""
    Proxy of C++ gdl_graph_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_gdl.delete_gdl_graph_t

    def get_node_label(self, n: "int") -> "char *":
        r"""
        get_node_label(self, n) -> char *

        @param n: int
        """
        return _ida_gdl.gdl_graph_t_get_node_label(self, n)

    def print_graph_attributes(self, fp: "FILE *") -> "void":
        r"""
        print_graph_attributes(self, fp)

        @param fp: FILE *
        """
        return _ida_gdl.gdl_graph_t_print_graph_attributes(self, fp)

    def print_node(self, fp: "FILE *", n: "int") -> "bool":
        r"""
        print_node(self, fp, n) -> bool

        @param fp: FILE *
        @param n: int
        """
        return _ida_gdl.gdl_graph_t_print_node(self, fp, n)

    def print_edge(self, fp: "FILE *", i: "int", j: "int") -> "bool":
        r"""
        print_edge(self, fp, i, j) -> bool

        @param fp: FILE *
        @param i: int
        @param j: int
        """
        return _ida_gdl.gdl_graph_t_print_edge(self, fp, i, j)

    def print_node_attributes(self, fp: "FILE *", n: "int") -> "void":
        r"""
        print_node_attributes(self, fp, n)

        @param fp: FILE *
        @param n: int
        """
        return _ida_gdl.gdl_graph_t_print_node_attributes(self, fp, n)

    def size(self) -> "int":
        r"""
        size(self) -> int
        """
        return _ida_gdl.gdl_graph_t_size(self)

    def node_qty(self) -> "int":
        r"""
        node_qty(self) -> int
        """
        return _ida_gdl.gdl_graph_t_node_qty(self)

    def exists(self, node: "int") -> "bool":
        r"""
        exists(self, node) -> bool

        @param node: int
        """
        return _ida_gdl.gdl_graph_t_exists(self, node)

    def entry(self) -> "int":
        r"""
        entry(self) -> int
        """
        return _ida_gdl.gdl_graph_t_entry(self)

    def exit(self) -> "int":
        r"""
        exit(self) -> int
        """
        return _ida_gdl.gdl_graph_t_exit(self)

    def nsucc(self, node: "int") -> "int":
        r"""
        nsucc(self, node) -> int

        @param node: int
        """
        return _ida_gdl.gdl_graph_t_nsucc(self, node)

    def npred(self, node: "int") -> "int":
        r"""
        npred(self, node) -> int

        @param node: int
        """
        return _ida_gdl.gdl_graph_t_npred(self, node)

    def succ(self, node: "int", i: "int") -> "int":
        r"""
        succ(self, node, i) -> int

        @param node: int
        @param i: int
        """
        return _ida_gdl.gdl_graph_t_succ(self, node, i)

    def pred(self, node: "int", i: "int") -> "int":
        r"""
        pred(self, node, i) -> int

        @param node: int
        @param i: int
        """
        return _ida_gdl.gdl_graph_t_pred(self, node, i)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_gdl.gdl_graph_t_empty(self)

    def get_node_color(self, n: "int") -> "bgcolor_t":
        r"""
        get_node_color(self, n) -> bgcolor_t

        @param n: int
        """
        return _ida_gdl.gdl_graph_t_get_node_color(self, n)

    def get_edge_color(self, i: "int", j: "int") -> "bgcolor_t":
        r"""
        get_edge_color(self, i, j) -> bgcolor_t

        @param i: int
        @param j: int
        """
        return _ida_gdl.gdl_graph_t_get_edge_color(self, i, j)

    def nedge(self, node: "int", ispred: "bool") -> "size_t":
        r"""
        nedge(self, node, ispred) -> size_t

        @param node: int
        @param ispred: bool
        """
        return _ida_gdl.gdl_graph_t_nedge(self, node, ispred)

    def edge(self, node: "int", i: "int", ispred: "bool") -> "int":
        r"""
        edge(self, node, i, ispred) -> int

        @param node: int
        @param i: int
        @param ispred: bool
        """
        return _ida_gdl.gdl_graph_t_edge(self, node, i, ispred)

    def front(self) -> "int":
        r"""
        front(self) -> int
        """
        return _ida_gdl.gdl_graph_t_front(self)

    def begin(self) -> "node_iterator":
        r"""
        begin(self) -> node_iterator
        """
        return _ida_gdl.gdl_graph_t_begin(self)

    def end(self) -> "node_iterator":
        r"""
        end(self) -> node_iterator
        """
        return _ida_gdl.gdl_graph_t_end(self)

    def __init__(self):
        r"""
        __init__(self) -> gdl_graph_t

        @param self: PyObject *
        """
        if self.__class__ == gdl_graph_t:
            _self = None
        else:
            _self = self
        _ida_gdl.gdl_graph_t_swiginit(self, _ida_gdl.new_gdl_graph_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_gdl.disown_gdl_graph_t(self)
        return weakref.proxy(self)

# Register gdl_graph_t in _ida_gdl:
_ida_gdl.gdl_graph_t_swigregister(gdl_graph_t)

def gen_gdl(g: "gdl_graph_t", fname: "char const *") -> "void":
    r"""
    gen_gdl(g, fname)
    Create GDL file for graph.

    @param g: (C++: const gdl_graph_t *) gdl_graph_t const *
    @param fname: (C++: const char *) char const *
    """
    return _ida_gdl.gen_gdl(g, fname)

def display_gdl(fname: "char const *") -> "int":
    r"""
    display_gdl(fname) -> int
    Display GDL file by calling wingraph32. The exact name of the grapher is taken
    from the configuration file and set up by setup_graph_subsystem(). The path
    should point to a temporary file: when wingraph32 succeeds showing the graph,
    the input file will be deleted.

    @param fname: (C++: const char *) char const *
    @return: error code from os, 0 if ok
    """
    return _ida_gdl.display_gdl(fname)

def gen_flow_graph(filename: "char const *", title: "char const *", pfn: "func_t *", ea1: "ea_t", ea2: "ea_t", gflags: "int") -> "bool":
    r"""
    gen_flow_graph(filename, title, pfn, ea1, ea2, gflags) -> bool
    Build and display a flow graph.

    @param filename: (C++: const char *) output file name. the file extension is not used. maybe
                     nullptr.
    @param title: (C++: const char *) graph title
    @param pfn: (C++: func_t *) function to graph
    @param ea1: (C++: ea_t) ,ea2: if pfn == nullptr, then the address range
    @param gflags: (C++: int) combination of Flow graph building flags. if none of
                   CHART_GEN_DOT, CHART_GEN_GDL, CHART_WINGRAPH is specified, the
                   function will return false
    @param gflags: (C++: int) combination of Flow graph building flags. if none of
                   CHART_GEN_DOT, CHART_GEN_GDL, CHART_WINGRAPH is specified, the
                   function will return false
    @return: success. if fails, a warning message is displayed on the screen
    """
    return _ida_gdl.gen_flow_graph(filename, title, pfn, ea1, ea2, gflags)
CHART_PRINT_NAMES = _ida_gdl.CHART_PRINT_NAMES
r"""
print labels for each block?
"""

CHART_GEN_DOT = _ida_gdl.CHART_GEN_DOT
r"""
generate .dot file (file extension is forced to .dot)
"""

CHART_GEN_GDL = _ida_gdl.CHART_GEN_GDL
r"""
generate .gdl file (file extension is forced to .gdl)
"""

CHART_WINGRAPH = _ida_gdl.CHART_WINGRAPH
r"""
call grapher to display the graph
"""


def gen_simple_call_chart(filename: "char const *", wait: "char const *", title: "char const *", gflags: "int") -> "bool":
    r"""
    gen_simple_call_chart(filename, wait, title, gflags) -> bool
    Build and display a simple function call graph.

    @param filename: (C++: const char *) output file name. the file extension is not used. maybe
                     nullptr.
    @param wait: (C++: const char *) message to display during graph building
    @param title: (C++: const char *) graph title
    @param gflags: (C++: int) combination of CHART_NOLIBFUNCS and Flow graph building flags. if
                   none of CHART_GEN_DOT, CHART_GEN_GDL, CHART_WINGRAPH is
                   specified, the function will return false.
    @return: success. if fails, a warning message is displayed on the screen
    """
    return _ida_gdl.gen_simple_call_chart(filename, wait, title, gflags)

def gen_complex_call_chart(filename: "char const *", wait: "char const *", title: "char const *", ea1: "ea_t", ea2: "ea_t", flags: "int", recursion_depth: "int32"=-1) -> "bool":
    r"""
    gen_complex_call_chart(filename, wait, title, ea1, ea2, flags, recursion_depth=-1) -> bool
    Build and display a complex xref graph.

    @param filename: (C++: const char *) output file name. the file extension is not used. maybe
                     nullptr.
    @param wait: (C++: const char *) message to display during graph building
    @param title: (C++: const char *) graph title
    @param ea1: (C++: ea_t) ,ea2: address range
    @param flags: (C++: int) combination of Call chart building flags and Flow graph building
                  flags. if none of CHART_GEN_DOT, CHART_GEN_GDL, CHART_WINGRAPH is
                  specified, the function will return false.
    @param flags: (C++: int) combination of Call chart building flags and Flow graph building
                  flags. if none of CHART_GEN_DOT, CHART_GEN_GDL, CHART_WINGRAPH is
                  specified, the function will return false.
    @param recursion_depth: (C++: int32) optional limit of recursion
    @return: success. if fails, a warning message is displayed on the screen
    """
    return _ida_gdl.gen_complex_call_chart(filename, wait, title, ea1, ea2, flags, recursion_depth)
CHART_NOLIBFUNCS = _ida_gdl.CHART_NOLIBFUNCS
r"""
don't include library functions in the graph
"""

CHART_REFERENCING = _ida_gdl.CHART_REFERENCING
r"""
references to the addresses in the list
"""

CHART_REFERENCED = _ida_gdl.CHART_REFERENCED
r"""
references from the addresses in the list
"""

CHART_RECURSIVE = _ida_gdl.CHART_RECURSIVE
r"""
analyze added blocks
"""

CHART_FOLLOW_DIRECTION = _ida_gdl.CHART_FOLLOW_DIRECTION
r"""
analyze references to added blocks only in the direction of the reference who
discovered the current block
"""

CHART_IGNORE_XTRN = _ida_gdl.CHART_IGNORE_XTRN

CHART_IGNORE_DATA_BSS = _ida_gdl.CHART_IGNORE_DATA_BSS

CHART_IGNORE_LIB_TO = _ida_gdl.CHART_IGNORE_LIB_TO
r"""
ignore references to library functions
"""

CHART_IGNORE_LIB_FROM = _ida_gdl.CHART_IGNORE_LIB_FROM
r"""
ignore references from library functions
"""

CHART_PRINT_COMMENTS = _ida_gdl.CHART_PRINT_COMMENTS

CHART_PRINT_DOTS = _ida_gdl.CHART_PRINT_DOTS
r"""
print dots if xrefs exist outside of the range recursion depth
"""

class cancellable_graph_t(gdl_graph_t):
    r"""
    Proxy of C++ cancellable_graph_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    cancelled: "bool" = property(_ida_gdl.cancellable_graph_t_cancelled_get, _ida_gdl.cancellable_graph_t_cancelled_set, doc=r"""cancelled""")
    __swig_destroy__ = _ida_gdl.delete_cancellable_graph_t

    def __init__(self):
        r"""
        __init__(self) -> cancellable_graph_t

        @param self: PyObject *
        """
        if self.__class__ == cancellable_graph_t:
            _self = None
        else:
            _self = self
        _ida_gdl.cancellable_graph_t_swiginit(self, _ida_gdl.new_cancellable_graph_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_gdl.disown_cancellable_graph_t(self)
        return weakref.proxy(self)

# Register cancellable_graph_t in _ida_gdl:
_ida_gdl.cancellable_graph_t_swigregister(cancellable_graph_t)
class qbasic_block_t(ida_range.range_t):
    r"""
    Proxy of C++ qbasic_block_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> qbasic_block_t
        """
        _ida_gdl.qbasic_block_t_swiginit(self, _ida_gdl.new_qbasic_block_t())
    __swig_destroy__ = _ida_gdl.delete_qbasic_block_t

# Register qbasic_block_t in _ida_gdl:
_ida_gdl.qbasic_block_t_swigregister(qbasic_block_t)

def is_noret_block(btype: "fc_block_type_t") -> "bool":
    r"""
    is_noret_block(btype) -> bool
    Does this block never return?

    @param btype: (C++: fc_block_type_t) enum fc_block_type_t
    """
    return _ida_gdl.is_noret_block(btype)

def is_ret_block(btype: "fc_block_type_t") -> "bool":
    r"""
    is_ret_block(btype) -> bool
    Does this block return?

    @param btype: (C++: fc_block_type_t) enum fc_block_type_t
    """
    return _ida_gdl.is_ret_block(btype)
FC_PRINT = _ida_gdl.FC_PRINT
r"""
print names (used only by display_flow_chart())
"""

FC_NOEXT = _ida_gdl.FC_NOEXT
r"""
do not compute external blocks. Use this to prevent jumps leaving the function
from appearing in the flow chart. Unless specified, the targets of those
outgoing jumps will be present in the flow chart under the form of one-
instruction blocks
"""

FC_RESERVED = _ida_gdl.FC_RESERVED
r"""
former FC_PREDS
"""

FC_APPND = _ida_gdl.FC_APPND
r"""
multirange flowchart (set by append_to_flowchart)
"""

FC_CHKBREAK = _ida_gdl.FC_CHKBREAK
r"""
build_qflow_chart() may be aborted by user
"""

FC_CALL_ENDS = _ida_gdl.FC_CALL_ENDS
r"""
call instructions terminate basic blocks
"""

FC_NOPREDS = _ida_gdl.FC_NOPREDS
r"""
do not compute predecessor lists
"""

FC_OUTLINES = _ida_gdl.FC_OUTLINES
r"""
include outlined code (with FUNC_OUTLINE)
"""

class qflow_chart_t(cancellable_graph_t):
    r"""
    Proxy of C++ qflow_chart_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    title: "qstring" = property(_ida_gdl.qflow_chart_t_title_get, _ida_gdl.qflow_chart_t_title_set, doc=r"""title""")
    bounds: "range_t" = property(_ida_gdl.qflow_chart_t_bounds_get, _ida_gdl.qflow_chart_t_bounds_set, doc=r"""bounds""")
    r"""
    overall bounds of the qflow_chart_t instance
    """
    pfn: "func_t *" = property(_ida_gdl.qflow_chart_t_pfn_get, _ida_gdl.qflow_chart_t_pfn_set, doc=r"""pfn""")
    r"""
    the function this instance was built upon
    """
    flags: "int" = property(_ida_gdl.qflow_chart_t_flags_get, _ida_gdl.qflow_chart_t_flags_set, doc=r"""flags""")
    r"""
    flags. See Flow chart flags
    """
    nproper: "int" = property(_ida_gdl.qflow_chart_t_nproper_get, _ida_gdl.qflow_chart_t_nproper_set, doc=r"""nproper""")
    r"""
    number of basic blocks belonging to the specified range
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> qflow_chart_t
        __init__(self, _title, _pfn, _ea1, _ea2, _flags) -> qflow_chart_t

        @param _title: char const *
        @param _pfn: func_t *
        @param _ea1: ea_t
        @param _ea2: ea_t
        @param _flags: int
        """
        _ida_gdl.qflow_chart_t_swiginit(self, _ida_gdl.new_qflow_chart_t(*args))
    __swig_destroy__ = _ida_gdl.delete_qflow_chart_t

    def create(self, *args) -> "void":
        r"""
        create(self, _title, _pfn, _ea1, _ea2, _flags)

        @param _title: char const *
        @param _pfn: func_t *
        @param _ea1: ea_t
        @param _ea2: ea_t
        @param _flags: int

        create(self, _title, ranges, _flags)

        @param _title: char const *
        @param ranges: rangevec_t const &
        @param _flags: int
        """
        return _ida_gdl.qflow_chart_t_create(self, *args)

    def append_to_flowchart(self, ea1: "ea_t", ea2: "ea_t") -> "void":
        r"""
        append_to_flowchart(self, ea1, ea2)

        @param ea1: ea_t
        @param ea2: ea_t
        """
        return _ida_gdl.qflow_chart_t_append_to_flowchart(self, ea1, ea2)

    def refresh(self) -> "void":
        r"""
        refresh(self)
        """
        return _ida_gdl.qflow_chart_t_refresh(self)

    def calc_block_type(self, blknum: "size_t") -> "fc_block_type_t":
        r"""
        calc_block_type(self, blknum) -> fc_block_type_t

        @param blknum: size_t
        """
        return _ida_gdl.qflow_chart_t_calc_block_type(self, blknum)

    def is_ret_block(self, blknum: "size_t") -> "bool":
        r"""
        is_ret_block(self, blknum) -> bool

        @param blknum: size_t
        """
        return _ida_gdl.qflow_chart_t_is_ret_block(self, blknum)

    def is_noret_block(self, blknum: "size_t") -> "bool":
        r"""
        is_noret_block(self, blknum) -> bool

        @param blknum: size_t
        """
        return _ida_gdl.qflow_chart_t_is_noret_block(self, blknum)

    def print_node_attributes(self, fp: "FILE *", n: "int") -> "void":
        r"""
        print_node_attributes(self, fp, n)

        @param fp: FILE *
        @param n: int
        """
        return _ida_gdl.qflow_chart_t_print_node_attributes(self, fp, n)

    def nsucc(self, node: "int") -> "int":
        r"""
        nsucc(self, node) -> int

        @param node: int
        """
        return _ida_gdl.qflow_chart_t_nsucc(self, node)

    def npred(self, node: "int") -> "int":
        r"""
        npred(self, node) -> int

        @param node: int
        """
        return _ida_gdl.qflow_chart_t_npred(self, node)

    def succ(self, node: "int", i: "int") -> "int":
        r"""
        succ(self, node, i) -> int

        @param node: int
        @param i: int
        """
        return _ida_gdl.qflow_chart_t_succ(self, node, i)

    def pred(self, node: "int", i: "int") -> "int":
        r"""
        pred(self, node, i) -> int

        @param node: int
        @param i: int
        """
        return _ida_gdl.qflow_chart_t_pred(self, node, i)

    def get_node_label(self, *args) -> "char *":
        r"""
        get_node_label(self, n) -> char *

        @param n: int
        """
        return _ida_gdl.qflow_chart_t_get_node_label(self, *args)

    def size(self) -> "int":
        r"""
        size(self) -> int
        """
        return _ida_gdl.qflow_chart_t_size(self)

    def print_names(self) -> "bool":
        r"""
        print_names(self) -> bool
        """
        return _ida_gdl.qflow_chart_t_print_names(self)

    def __getitem__(self, n: "int") -> "qbasic_block_t *":
        r"""
        __getitem__(self, n) -> qbasic_block_t

        @param n: int
        """
        return _ida_gdl.qflow_chart_t___getitem__(self, n)

# Register qflow_chart_t in _ida_gdl:
_ida_gdl.qflow_chart_t_swigregister(qflow_chart_t)

#<pycode(py_gdl)>
import types

import _ida_idaapi
import ida_idaapi
# -----------------------------------------------------------------------
class BasicBlock(object):
    r"""
    Basic block class. It is returned by the Flowchart class
    """
    def __init__(self, id, bb, fc):
        self._fc = fc

        self.id = id
        """Basic block ID"""

        self.start_ea = bb.start_ea
        """start_ea of basic block"""

        self.end_ea = bb.end_ea
        """end_ea of basic block"""

        self.type  = self._fc._q.calc_block_type(self.id)
        """Block type (check fc_block_type_t enum)"""


    def preds(self):
        r"""
        Iterates the predecessors list
        """
        q = self._fc._q
        for i in range(0, self._fc._q.npred(self.id)):
            yield self._fc[q.pred(self.id, i)]


    def succs(self):
        r"""
        Iterates the successors list
        """
        q = self._fc._q
        for i in range(0, q.nsucc(self.id)):
            yield self._fc[q.succ(self.id, i)]

# -----------------------------------------------------------------------
class FlowChart(object):
    r"""
    Flowchart class used to determine basic blocks.
    Check ex_gdl_qflow_chart.py for sample usage.
    """
    def __init__(self, f=None, bounds=None, flags=0):
        r"""
        Constructor
        @param f: A func_t type, use get_func(ea) to get a reference
        @param bounds: A tuple of the form (start, end). Used if "f" is None
        @param flags: one of the FC_xxxx flags.
        """
        if (f is None) and (bounds is None or type(bounds) != tuple):
            raise Exception("Please specifiy either a function or start/end pair")

        if bounds is None:
            bounds = (_ida_idaapi.BADADDR, _ida_idaapi.BADADDR)

# Create the flowchart
        self._q = qflow_chart_t("", f, bounds[0], bounds[1], flags)

    size = property(lambda self: self._q.size())
    r"""
    Number of blocks in the flow chart
    """


    def refresh(self):
        r"""
        Refreshes the flow chart
        """
        self._q.refresh()


    def _getitem(self, index):
        return BasicBlock(index, self._q[index], self)


    def __iter__(self):
        return (self._getitem(index) for index in range(0, self.size))


    def __getitem__(self, index):
        r"""
        Returns a basic block

        @return: BasicBlock
        """
        if index >= self.size:
            raise KeyError
        else:
            return self._getitem(index)

FC_PREDS = 0 # obsolete bit, do not use

#</pycode(py_gdl)>



