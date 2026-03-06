r"""
Merge functionality.

NOTE: this functionality is available in IDA Teams (not IDA Pro)

There are 3 databases involved in merging: base_idb, local_db, and remote_idb.
* base_idb: the common base ancestor of 'local_db' and 'remote_db'. in the UI
this database is located in the middle.
* local_idb: local database that will contain the result of the merging. in the
UI this database is located on the left.
* remote_idb: remote database that will merge into local_idb. It may reside
locally on the current computer, despite its name. in the UI this database is
located on the right. base_idb and remote_idb are opened for reading only.
base_idb may be absent, in this case a 2-way merging is performed.

Conflicts can be resolved automatically or interactively. The automatic
resolving scores the conflicting blocks and takes the better one. The
interactive resolving displays the full rendered contents side by side, and
expects the user to select the better side for each conflict.

Since IDB files contain various kinds of information, there are many merging
phases. The entire list can be found in merge.cpp. Below are just some selected
examples:
* merge global database settings (inf and other global vars)
* merge segmentation and changes to the database bytes
* merge various lists: exports, imports, loaded tils, etc
* merge names, functions, function frames
* merge debugger settings, breakpoints
* merge struct/enum views
* merge local type libraries
* merge the disassembly items (i.e. the segment contents) this includes operand
types, code/data separation, etc
* merge plugin specific info like decompiler types, dwarf mappings, etc

To unify UI elements of each merge phase, we use merger views:
* A view that consists of 2 or 3 panes: left (local_idb) and right (remote_idb).
The common base is in the middle, if present.
* Rendering of the panes depends on the phase, different phases show different
contents.
* The conflicts are highlighted by a colored background. Also, the detail pane
can be consulted for additional info.
* The user can select a conflict (or a bunch of conflicts) and say "use this
block".
* The user can browse the panes as he wishes. He will not be forced to handle
conflicts in any particular order. However, once he finishes working with a
merge handler and proceeds to the next one, he cannot go back.
* Scrolling the left pane will synchronously scroll the right pane and vice
versa.
* There are the navigation commands like "go to the prev/next conflict"
* The number of remaining conflicts to resolve is printed in the "Progress"
chooser.
* The user may manually modify local database inside the merger view. For that
he may use the regular hotkeys. However, editing the database may lead to new
conflicts, so we better restrict the available actions to some reasonable
minimum. Currently, this is not implemented.

IDA works in a new "merge" mode during merging. In this mode most events are not
generated. We forbid them to reduce the risk that a rogue third-party plugin
that is not aware of the "merge" mode would spoil something.

For example, normally renaming a function causes a cascade of events and may
lead to other database modifications. Some of them may be desired, some - not.
Since there are some undesired events, it is better to stop generating them.
However, some events are required to render the disassembly listing. For
example, ev_ana_insn, av_out_insn. This is why some events are still generated
in the "merge" mode.

To let processor modules and plugins merge their data, we introduce a new event:
ev_create_merge_handlers. It is generated immediately after opening all three
idbs. The interested modules should react to this event by creating new merge
handlers, if they need them.

While the kernel can create arbitrary merge handlers, modules can create only
the standard ones returned by:

create_nodeval_merge_handler() create_nodeval_merge_handlers()
create_std_modmerge_handlers()

We do not document merge_handler_t because once a merge handler is created, it
is used exclusively by the kernel.

See mergemod.hpp for more information about the merge mode for modules."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_merge
else:
    import _ida_merge

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

SWIG_PYTHON_LEGACY_BOOL = _ida_merge.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

MERGE_KIND_NETNODE = _ida_merge.MERGE_KIND_NETNODE
r"""
netnode (no merging, to be used in idbunits)
"""

MERGE_KIND_AUTOQ = _ida_merge.MERGE_KIND_AUTOQ
r"""
auto queues
"""

MERGE_KIND_INF = _ida_merge.MERGE_KIND_INF
r"""
merge the inf variable (global settings)
"""

MERGE_KIND_ENCODINGS = _ida_merge.MERGE_KIND_ENCODINGS
r"""
merge encodings
"""

MERGE_KIND_ENCODINGS2 = _ida_merge.MERGE_KIND_ENCODINGS2
r"""
merge default encodings
"""

MERGE_KIND_SCRIPTS2 = _ida_merge.MERGE_KIND_SCRIPTS2
r"""
merge scripts common info
"""

MERGE_KIND_SCRIPTS = _ida_merge.MERGE_KIND_SCRIPTS
r"""
merge scripts
"""

MERGE_KIND_CUSTDATA = _ida_merge.MERGE_KIND_CUSTDATA
r"""
merge custom data type and formats
"""

MERGE_KIND_ENUMS = _ida_merge.MERGE_KIND_ENUMS
r"""
merge enums
"""

MERGE_KIND_STRUCTS = _ida_merge.MERGE_KIND_STRUCTS
r"""
merge structs (globally: add/delete structs entirely)
"""

MERGE_KIND_TILS = _ida_merge.MERGE_KIND_TILS
r"""
merge type libraries
"""

MERGE_KIND_TINFO = _ida_merge.MERGE_KIND_TINFO
r"""
merge tinfo
"""

MERGE_KIND_STRMEM = _ida_merge.MERGE_KIND_STRMEM
r"""
merge struct members
"""

MERGE_KIND_UDTMEM = _ida_merge.MERGE_KIND_UDTMEM
r"""
merge UDT members (local types)
"""

MERGE_KIND_GHSTRCMT = _ida_merge.MERGE_KIND_GHSTRCMT
r"""
merge ghost structure comment
"""

MERGE_KIND_STRMEMCMT = _ida_merge.MERGE_KIND_STRMEMCMT
r"""
merge member comments for ghost struc
"""

MERGE_KIND_SELECTORS = _ida_merge.MERGE_KIND_SELECTORS
r"""
merge selectors
"""

MERGE_KIND_STT = _ida_merge.MERGE_KIND_STT
r"""
merge flag storage types
"""

MERGE_KIND_SEGMENTS = _ida_merge.MERGE_KIND_SEGMENTS
r"""
merge segments
"""

MERGE_KIND_SEGGRPS = _ida_merge.MERGE_KIND_SEGGRPS
r"""
merge segment groups
"""

MERGE_KIND_SEGREGS = _ida_merge.MERGE_KIND_SEGREGS
r"""
merge segment registers
"""

MERGE_KIND_ORPHANS = _ida_merge.MERGE_KIND_ORPHANS
r"""
merge orphan bytes
"""

MERGE_KIND_BYTEVAL = _ida_merge.MERGE_KIND_BYTEVAL
r"""
merge byte values
"""

MERGE_KIND_FIXUPS = _ida_merge.MERGE_KIND_FIXUPS
r"""
merge fixups
"""

MERGE_KIND_MAPPING = _ida_merge.MERGE_KIND_MAPPING
r"""
merge manual memory mapping
"""

MERGE_KIND_EXPORTS = _ida_merge.MERGE_KIND_EXPORTS
r"""
merge exports
"""

MERGE_KIND_IMPORTS = _ida_merge.MERGE_KIND_IMPORTS
r"""
merge imports
"""

MERGE_KIND_PATCHES = _ida_merge.MERGE_KIND_PATCHES
r"""
merge patched bytes
"""

MERGE_KIND_FLAGS = _ida_merge.MERGE_KIND_FLAGS
r"""
merge flags64_t
"""

MERGE_KIND_EXTRACMT = _ida_merge.MERGE_KIND_EXTRACMT
r"""
merge extra next or prev lines
"""

MERGE_KIND_AFLAGS_EA = _ida_merge.MERGE_KIND_AFLAGS_EA
r"""
merge aflags for mapped EA
"""

MERGE_KIND_IGNOREMICRO = _ida_merge.MERGE_KIND_IGNOREMICRO
r"""
IM ("$ ignore micro") flags.
"""

MERGE_KIND_FILEREGIONS = _ida_merge.MERGE_KIND_FILEREGIONS
r"""
merge fileregions
"""

MERGE_KIND_HIDDENRANGES = _ida_merge.MERGE_KIND_HIDDENRANGES
r"""
merge hidden ranges
"""

MERGE_KIND_SOURCEFILES = _ida_merge.MERGE_KIND_SOURCEFILES
r"""
merge source files ranges
"""

MERGE_KIND_FUNC = _ida_merge.MERGE_KIND_FUNC
r"""
merge func info
"""

MERGE_KIND_FRAMEMGR = _ida_merge.MERGE_KIND_FRAMEMGR
r"""
merge frames (globally: add/delete frames entirely)
"""

MERGE_KIND_FRAME = _ida_merge.MERGE_KIND_FRAME
r"""
merge function frame info (frame members)
"""

MERGE_KIND_STKPNTS = _ida_merge.MERGE_KIND_STKPNTS
r"""
merge SP change points
"""

MERGE_KIND_FLOWS = _ida_merge.MERGE_KIND_FLOWS
r"""
merge flows
"""

MERGE_KIND_CREFS = _ida_merge.MERGE_KIND_CREFS
r"""
merge crefs
"""

MERGE_KIND_DREFS = _ida_merge.MERGE_KIND_DREFS
r"""
merge drefs
"""

MERGE_KIND_BPTS = _ida_merge.MERGE_KIND_BPTS
r"""
merge breakpoints
"""

MERGE_KIND_WATCHPOINTS = _ida_merge.MERGE_KIND_WATCHPOINTS
r"""
merge watchpoints
"""

MERGE_KIND_BOOKMARKS = _ida_merge.MERGE_KIND_BOOKMARKS
r"""
merge bookmarks
"""

MERGE_KIND_TRYBLKS = _ida_merge.MERGE_KIND_TRYBLKS
r"""
merge try blocks
"""

MERGE_KIND_DIRTREE = _ida_merge.MERGE_KIND_DIRTREE
r"""
merge std dirtrees
"""

MERGE_KIND_VFTABLES = _ida_merge.MERGE_KIND_VFTABLES
r"""
merge vftables
"""

MERGE_KIND_SIGNATURES = _ida_merge.MERGE_KIND_SIGNATURES
r"""
signatures
"""

MERGE_KIND_PROBLEMS = _ida_merge.MERGE_KIND_PROBLEMS
r"""
problems
"""

MERGE_KIND_UI = _ida_merge.MERGE_KIND_UI
r"""
UI.
"""

MERGE_KIND_DEKSTOPS = _ida_merge.MERGE_KIND_DEKSTOPS
r"""
dekstops
"""

MERGE_KIND_NOTEPAD = _ida_merge.MERGE_KIND_NOTEPAD
r"""
notepad
"""

MERGE_KIND_LOADER = _ida_merge.MERGE_KIND_LOADER
r"""
loader data
"""

MERGE_KIND_DEBUGGER = _ida_merge.MERGE_KIND_DEBUGGER
r"""
debugger data
"""

MERGE_KIND_DBG_MEMREGS = _ida_merge.MERGE_KIND_DBG_MEMREGS
r"""
manual memory regions (debugger)
"""

MERGE_KIND_LUMINA = _ida_merge.MERGE_KIND_LUMINA
r"""
lumina function metadata
"""

MERGE_KIND_LAST = _ida_merge.MERGE_KIND_LAST
r"""
last predefined merge handler type. please note that there can be more merge
handler types, registered by plugins and processor modules.
"""

MERGE_KIND_END = _ida_merge.MERGE_KIND_END
r"""
insert to the end of handler list, valid for
merge_handler_params_t::insert_after
"""

MERGE_KIND_NONE = _ida_merge.MERGE_KIND_NONE


def is_diff_merge_mode() -> "bool":
    r"""
    is_diff_merge_mode() -> bool
    Return TRUE if IDA is running in diff mode
    (MERGE_POLICY_MDIFF/MERGE_POLICY_VDIFF)
    """
    return _ida_merge.is_diff_merge_mode()
class merge_data_t(object):
    r"""
    Proxy of C++ merge_data_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    dbctx_ids: "int [3]" = property(_ida_merge.merge_data_t_dbctx_ids_get, _ida_merge.merge_data_t_dbctx_ids_set, doc=r"""dbctx_ids""")
    r"""
    local, remote, base ids
    """
    nbases: "int" = property(_ida_merge.merge_data_t_nbases_get, _ida_merge.merge_data_t_nbases_set, doc=r"""nbases""")
    r"""
    number of database participating in merge process, maybe 2 or 3
    """
    ev_handlers: "merge_handlers_t" = property(_ida_merge.merge_data_t_ev_handlers_get, _ida_merge.merge_data_t_ev_handlers_set, doc=r"""ev_handlers""")
    r"""
    event handlers
    """
    item_block_locator: "merge_data_t::item_block_locator_t *" = property(_ida_merge.merge_data_t_item_block_locator_get, _ida_merge.merge_data_t_item_block_locator_set, doc=r"""item_block_locator""")
    last_udt_related_merger: "merge_handler_t *" = property(_ida_merge.merge_data_t_last_udt_related_merger_get, _ida_merge.merge_data_t_last_udt_related_merger_set, doc=r"""last_udt_related_merger""")

    def set_dbctx_ids(self, local: "int", remote: "int", base: "int") -> "void":
        r"""
        set_dbctx_ids(self, local, remote, base)

        @param local: int
        @param remote: int
        @param base: int
        """
        return _ida_merge.merge_data_t_set_dbctx_ids(self, local, remote, base)

    def local_id(self) -> "int":
        r"""
        local_id(self) -> int
        """
        return _ida_merge.merge_data_t_local_id(self)

    def remote_id(self) -> "int":
        r"""
        remote_id(self) -> int
        """
        return _ida_merge.merge_data_t_remote_id(self)

    def base_id(self) -> "int":
        r"""
        base_id(self) -> int
        """
        return _ida_merge.merge_data_t_base_id(self)

    def add_event_handler(self, handler: "merge_handler_t *") -> "void":
        r"""
        add_event_handler(self, handler)

        @param handler: merge_handler_t *
        """
        return _ida_merge.merge_data_t_add_event_handler(self, handler)

    def remove_event_handler(self, handler: "merge_handler_t *") -> "void":
        r"""
        remove_event_handler(self, handler)

        @param handler: merge_handler_t *
        """
        return _ida_merge.merge_data_t_remove_event_handler(self, handler)

    def get_block_head(self, idx: "diff_source_idx_t", item_head: "ea_t") -> "ea_t":
        r"""
        get_block_head(self, idx, item_head) -> ea_t

        @param idx: diff_source_idx_t
        @param item_head: ea_t
        """
        return _ida_merge.merge_data_t_get_block_head(self, idx, item_head)

    def setup_blocks(self, dst_idx: "diff_source_idx_t", src_idx: "diff_source_idx_t", region: "diff_range_t const &") -> "bool":
        r"""
        setup_blocks(self, dst_idx, src_idx, region) -> bool

        @param dst_idx: diff_source_idx_t
        @param src_idx: diff_source_idx_t
        @param region: diff_range_t const &
        """
        return _ida_merge.merge_data_t_setup_blocks(self, dst_idx, src_idx, region)

    def has_existing_node(self, nodename: "char const *") -> "bool":
        r"""
        has_existing_node(self, nodename) -> bool
        check that node exists in any of databases

        @param nodename: (C++: const char *) char const *
        """
        return _ida_merge.merge_data_t_has_existing_node(self, nodename)

    def map_privrange_id(self, tid: "tid_t *", ea: "ea_t", _from: "diff_source_idx_t", to: "diff_source_idx_t", strict: "bool"=True) -> "bool":
        r"""
        map_privrange_id(self, tid, ea, _from, to, strict=True) -> bool
        map IDs of structures, enumerations and their members

        @param tid: (C++: tid_t *) item ID in TO database
        @param ea: (C++: ea_t) item ID to find counterpart
        @param from: (C++: diff_source_idx_t) source database index, diff_source_idx_t
        @param to: (C++: diff_source_idx_t) destination database index, diff_source_idx_t
        @param strict: (C++: bool) raise interr if could not map
        @return: success
        """
        return _ida_merge.merge_data_t_map_privrange_id(self, tid, ea, _from, to, strict)

    def map_tinfo(self, tif: "tinfo_t", _from: "diff_source_idx_t", to: "diff_source_idx_t", strict: "bool"=True) -> "bool":
        r"""
        map_tinfo(self, tif, _from, to, strict=True) -> bool
        migrate type, replaces type references into FROM database to references into TO
        database

        @param tif: (C++: tinfo_t *) type to migrate, will be cleared in case of fail
        @param from: (C++: diff_source_idx_t) source database index, diff_source_idx_t
        @param to: (C++: diff_source_idx_t) destination database index, diff_source_idx_t
        @param strict: (C++: bool) raise interr if could not map
        @return: success
        """
        return _ida_merge.merge_data_t_map_tinfo(self, tif, _from, to, strict)

    def compare_merging_tifs(self, tif1: "tinfo_t", diffidx1: "diff_source_idx_t", tif2: "tinfo_t", diffidx2: "diff_source_idx_t") -> "int":
        r"""
        compare_merging_tifs(self, tif1, diffidx1, tif2, diffidx2) -> int
        compare types from two databases

        @param tif1: (C++: const tinfo_t &) type
        @param diffidx1: (C++: diff_source_idx_t) database index, diff_source_idx_t
        @param tif2: (C++: const tinfo_t &) type
        @param diffidx2: (C++: diff_source_idx_t) database index, diff_source_idx_t
        @return: -1, 0, 1
        """
        return _ida_merge.merge_data_t_compare_merging_tifs(self, tif1, diffidx1, tif2, diffidx2)

# Register merge_data_t in _ida_merge:
_ida_merge.merge_data_t_swigregister(merge_data_t)
class item_block_locator_t(object):
    r"""
    Proxy of C++ merge_data_t::item_block_locator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def get_block_head(self, md: "merge_data_t", idx: "diff_source_idx_t", item_head: "ea_t") -> "ea_t":
        r"""
        get_block_head(self, md, idx, item_head) -> ea_t

        @param md: merge_data_t &
        @param idx: diff_source_idx_t
        @param item_head: ea_t
        """
        return _ida_merge.item_block_locator_t_get_block_head(self, md, idx, item_head)

    def setup_blocks(self, md: "merge_data_t", _from: "diff_source_idx_t", to: "diff_source_idx_t", region: "diff_range_t const &") -> "bool":
        r"""
        setup_blocks(self, md, _from, to, region) -> bool

        @param md: merge_data_t &
        @param from: diff_source_idx_t
        @param to: diff_source_idx_t
        @param region: diff_range_t const &
        """
        return _ida_merge.item_block_locator_t_setup_blocks(self, md, _from, to, region)
    __swig_destroy__ = _ida_merge.delete_item_block_locator_t

    def __init__(self):
        r"""
        __init__(self) -> item_block_locator_t

        @param self: PyObject *
        """
        if self.__class__ == item_block_locator_t:
            _self = None
        else:
            _self = self
        _ida_merge.item_block_locator_t_swiginit(self, _ida_merge.new_item_block_locator_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_merge.disown_item_block_locator_t(self)
        return weakref.proxy(self)

# Register item_block_locator_t in _ida_merge:
_ida_merge.item_block_locator_t_swigregister(item_block_locator_t)
class merge_handler_params_t(object):
    r"""
    Proxy of C++ merge_handler_params_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    md: "merge_data_t &" = property(_ida_merge.merge_handler_params_t_md_get, doc=r"""md""")
    label: "qstring" = property(_ida_merge.merge_handler_params_t_label_get, _ida_merge.merge_handler_params_t_label_set, doc=r"""label""")
    kind: "merge_kind_t" = property(_ida_merge.merge_handler_params_t_kind_get, _ida_merge.merge_handler_params_t_kind_set, doc=r"""kind""")
    r"""
    merge handler kind merge_kind_t
    """
    insert_after: "merge_kind_t" = property(_ida_merge.merge_handler_params_t_insert_after_get, _ida_merge.merge_handler_params_t_insert_after_set, doc=r"""insert_after""")
    r"""
    desired position inside 'handlers' merge_kind_t
    """
    mh_flags: "uint32" = property(_ida_merge.merge_handler_params_t_mh_flags_get, _ida_merge.merge_handler_params_t_mh_flags_set, doc=r"""mh_flags""")

    def __init__(self, _md: "merge_data_t", _label: "qstring const &", _kind: "merge_kind_t", _insert_after: "merge_kind_t", _mh_flags: "uint32"):
        r"""
        __init__(self, _md, _label, _kind, _insert_after, _mh_flags) -> merge_handler_params_t

        @param _md: merge_data_t &
        @param _label: qstring const &
        @param _kind: enum merge_kind_t
        @param _insert_after: enum merge_kind_t
        @param _mh_flags: uint32
        """
        _ida_merge.merge_handler_params_t_swiginit(self, _ida_merge.new_merge_handler_params_t(_md, _label, _kind, _insert_after, _mh_flags))

    def ui_has_details(self, *args) -> "bool":
        r"""
        ui_has_details(self, _mh_flags) -> bool
        Should IDA display the diffpos detail pane?

        @param _mh_flags: (C++: uint32)

        ui_has_details(self) -> bool
        """
        return _ida_merge.merge_handler_params_t_ui_has_details(self, *args)

    def ui_complex_details(self, *args) -> "bool":
        r"""
        ui_complex_details(self, _mh_flags) -> bool
        Do not display the diffpos details in the chooser. For example, the
        MERGE_KIND_SCRIPTS handler puts the script body as the diffpos detail. It would
        not be great to show them as part of the chooser.

        @param _mh_flags: (C++: uint32)

        ui_complex_details(self) -> bool
        """
        return _ida_merge.merge_handler_params_t_ui_complex_details(self, *args)

    def ui_complex_name(self, *args) -> "bool":
        r"""
        ui_complex_name(self, _mh_flags) -> bool
        It customary to create long diffpos names having many components that are
        separated by any 7-bit ASCII character (besides of '\0'). In this case it is
        possible to instruct IDA to use this separator to create a multi-column chooser.
        For example the MERGE_KIND_ENUMS handler has the following diffpos name:
        enum_1,enum_2 If MH_UI_COMMANAME is specified, IDA will create 2 columns for
        these names.

        @param _mh_flags: (C++: uint32)

        ui_complex_name(self) -> bool
        """
        return _ida_merge.merge_handler_params_t_ui_complex_name(self, *args)

    def ui_split_char(self, *args) -> "char":
        r"""
        ui_split_char(self, _mh_flags) -> char

        @param _mh_flags: uint32

        ui_split_char(self) -> char
        """
        return _ida_merge.merge_handler_params_t_ui_split_char(self, *args)

    def ui_split_str(self, *args) -> "qstring":
        r"""
        ui_split_str(self, _mh_flags) -> qstring

        @param _mh_flags: uint32

        ui_split_str(self) -> qstring
        """
        return _ida_merge.merge_handler_params_t_ui_split_str(self, *args)

    def ui_dp_shortname(self, *args) -> "bool":
        r"""
        ui_dp_shortname(self, _mh_flags) -> bool
        The detail pane shows the diffpos details for the current diffpos range as a
        tree-like view. In this pane the diffpos names are used as tree node names and
        the diffpos details as their children. Sometimes, for complex diffpos names, the
        first part of the name looks better than the entire name. For example, the
        MERGE_KIND_SEGMENTS handler has the following diffpos name:
        <range>,<segm1>,<segm2>,<segm3> if MH_UI_DP_SHORTNAME is specified, IDA will use
        <range> as a tree node name

        @param _mh_flags: (C++: uint32)

        ui_dp_shortname(self) -> bool
        """
        return _ida_merge.merge_handler_params_t_ui_dp_shortname(self, *args)

    def ui_linediff(self, *args) -> "bool":
        r"""
        ui_linediff(self, _mh_flags) -> bool
        In detail pane IDA shows difference between diffpos details. IDA marks added or
        deleted detail by color. In the modified detail the changes are marked. Use this
        UI hint if you do not want to show the differences inside detail.

        @param _mh_flags: (C++: uint32)

        ui_linediff(self) -> bool
        """
        return _ida_merge.merge_handler_params_t_ui_linediff(self, *args)

    def ui_indent(self, *args) -> "bool":
        r"""
        ui_indent(self, _mh_flags) -> bool
        In the ordinary situation the spaces from the both sides of diffpos name are
        trimmed. Use this UI hint to preserve the leading spaces.

        @param _mh_flags: (C++: uint32)

        ui_indent(self) -> bool
        """
        return _ida_merge.merge_handler_params_t_ui_indent(self, *args)
    __swig_destroy__ = _ida_merge.delete_merge_handler_params_t

# Register merge_handler_params_t in _ida_merge:
_ida_merge.merge_handler_params_t_swigregister(merge_handler_params_t)
MH_LISTEN = _ida_merge.MH_LISTEN
r"""
merge handler will receive merge events
"""

MH_TERSE = _ida_merge.MH_TERSE
r"""
do not display equal lines in the merge results table
"""

MH_UI_NODETAILS = _ida_merge.MH_UI_NODETAILS
r"""
ida will not show the diffpos details
"""

MH_UI_COMPLEX = _ida_merge.MH_UI_COMPLEX
r"""
diffpos details won't be displayed in the diffpos chooser
"""

MH_UI_DP_NOLINEDIFF = _ida_merge.MH_UI_DP_NOLINEDIFF
r"""
Detail pane: do not show differences inside the line.
"""

MH_UI_DP_SHORTNAME = _ida_merge.MH_UI_DP_SHORTNAME
r"""
Detail pane: use the first part of a complex diffpos name as the tree node name.
"""

MH_UI_INDENT = _ida_merge.MH_UI_INDENT
r"""
preserve indent for diffpos name in diffpos chooser
"""

MH_UI_SPLITNAME = _ida_merge.MH_UI_SPLITNAME
r"""
ida will split the diffpos name by 7-bit ASCII char to create chooser columns
"""

MH_UI_CHAR_MASK = _ida_merge.MH_UI_CHAR_MASK
r"""
7-bit ASCII split character
"""

MH_UI_COMMANAME = _ida_merge.MH_UI_COMMANAME
r"""
ida will split the diffpos name by ',' to create chooser columns
"""

MH_UI_COLONNAME = _ida_merge.MH_UI_COLONNAME
r"""
ida will split the diffpos name by ':' to create chooser columns
"""


class moddata_diff_helper_t(object):
    r"""
    Proxy of C++ moddata_diff_helper_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    module_name: "char const *" = property(_ida_merge.moddata_diff_helper_t_module_name_get, _ida_merge.moddata_diff_helper_t_module_name_set, doc=r"""module_name""")
    r"""
    will be used as a prefix for field desc
    """
    netnode_name: "char const *" = property(_ida_merge.moddata_diff_helper_t_netnode_name_get, _ida_merge.moddata_diff_helper_t_netnode_name_set, doc=r"""netnode_name""")
    r"""
    name of netnode with module data attributes
    """
    fields: "idbattr_info_t const *" = property(_ida_merge.moddata_diff_helper_t_fields_get, _ida_merge.moddata_diff_helper_t_fields_set, doc=r"""fields""")
    r"""
    module data attribute descriptions
    """
    nfields: "size_t" = property(_ida_merge.moddata_diff_helper_t_nfields_get, _ida_merge.moddata_diff_helper_t_nfields_set, doc=r"""nfields""")
    r"""
    number of descriptions
    """
    additional_mh_flags: "uint32" = property(_ida_merge.moddata_diff_helper_t_additional_mh_flags_get, _ida_merge.moddata_diff_helper_t_additional_mh_flags_set, doc=r"""additional_mh_flags""")
    r"""
    additional merge handler flags
    """

    def __init__(self, _module_name: "char const *", _netnode_name: "char const *", _fields: "idbattr_info_t"):
        r"""
        __init__(self, _module_name, _netnode_name, _fields) -> moddata_diff_helper_t

        @param _module_name: char const *
        @param _netnode_name: char const *
        @param _fields: idbattr_info_t const *
        """
        if self.__class__ == moddata_diff_helper_t:
            _self = None
        else:
            _self = self
        _ida_merge.moddata_diff_helper_t_swiginit(self, _ida_merge.new_moddata_diff_helper_t(_self, _module_name, _netnode_name, _fields))
    __swig_destroy__ = _ida_merge.delete_moddata_diff_helper_t

    def merge_starting(self, arg0: "diff_source_idx_t", arg1: "void *") -> "void":
        r"""
        merge_starting(self, arg0, arg1)

        @param arg0: diff_source_idx_t
        @param arg1: void *
        """
        return _ida_merge.moddata_diff_helper_t_merge_starting(self, arg0, arg1)

    def merge_ending(self, arg0: "diff_source_idx_t", arg1: "void *") -> "void":
        r"""
        merge_ending(self, arg0, arg1)

        @param arg0: diff_source_idx_t
        @param arg1: void *
        """
        return _ida_merge.moddata_diff_helper_t_merge_ending(self, arg0, arg1)

    def get_struc_ptr(self, arg0: "merge_data_t", arg1: "diff_source_idx_t", arg2: "idbattr_info_t") -> "void *":
        r"""
        get_struc_ptr(self, arg0, arg1, arg2) -> void *

        @param arg0: merge_data_t &
        @param arg1: diff_source_idx_t
        @param arg2: idbattr_info_t const &
        """
        return _ida_merge.moddata_diff_helper_t_get_struc_ptr(self, arg0, arg1, arg2)

    def print_diffpos_details(self, arg0: "qstrvec_t *", arg1: "idbattr_info_t") -> "void":
        r"""
        print_diffpos_details(self, arg0, arg1)

        @param arg0: qstrvec_t *
        @param arg1: idbattr_info_t const &
        """
        return _ida_merge.moddata_diff_helper_t_print_diffpos_details(self, arg0, arg1)

    def val2str(self, arg0: "qstring *", arg1: "idbattr_info_t", arg2: "uint64") -> "bool":
        r"""
        val2str(self, arg0, arg1, arg2) -> bool

        @param arg0: qstring *
        @param arg1: idbattr_info_t const &
        @param arg2: uint64
        """
        return _ida_merge.moddata_diff_helper_t_val2str(self, arg0, arg1, arg2)

    def str2val(self, arg0: "uint64 *", arg1: "idbattr_info_t", arg2: "char const *") -> "bool":
        r"""
        str2val(self, arg0, arg1, arg2) -> bool

        @param arg0: uint64 *
        @param arg1: idbattr_info_t const &
        @param arg2: char const *
        """
        return _ida_merge.moddata_diff_helper_t_str2val(self, arg0, arg1, arg2)
    def __disown__(self):
        self.this.disown()
        _ida_merge.disown_moddata_diff_helper_t(self)
        return weakref.proxy(self)

# Register moddata_diff_helper_t in _ida_merge:
_ida_merge.moddata_diff_helper_t_swigregister(moddata_diff_helper_t)
NDS_IS_BOOL = _ida_merge.NDS_IS_BOOL
r"""
boolean value
"""

NDS_IS_EA = _ida_merge.NDS_IS_EA
r"""
EA value.
"""

NDS_IS_RELATIVE = _ida_merge.NDS_IS_RELATIVE
r"""
value is relative to index (stored as delta)
"""

NDS_IS_STR = _ida_merge.NDS_IS_STR
r"""
string value
"""

NDS_SUPVAL = _ida_merge.NDS_SUPVAL
r"""
stored as netnode supvals (not scalar)
"""

NDS_BLOB = _ida_merge.NDS_BLOB
r"""
stored as netnode blobs
"""

NDS_EV_RANGE = _ida_merge.NDS_EV_RANGE
r"""
enable default handling of mev_modified_ranges, mev_deleting_segm
"""

NDS_EV_FUNC = _ida_merge.NDS_EV_FUNC
r"""
enable default handling of mev_added_func/mev_deleting_func
"""

NDS_MAP_IDX = _ida_merge.NDS_MAP_IDX
r"""
apply ea2node() to index (==NETMAP_IDX)
"""

NDS_MAP_VAL = _ida_merge.NDS_MAP_VAL
r"""
apply ea2node() to value. Along with NDS_INC it gives effect of NETMAP_VAL,
examples: altval_ea : NDS_MAP_IDX charval : NDS_VAL8 charval_ea:
NDS_MAP_IDX|NDS_VAL8 eaget : NDS_MAP_IDX|NDS_MAP_VAL|NDS_INC
"""

NDS_VAL8 = _ida_merge.NDS_VAL8
r"""
use 8-bit values (==NETMAP_V8)
"""

NDS_INC = _ida_merge.NDS_INC
r"""
stored value is incremented (scalars only)
"""

NDS_UI_ND = _ida_merge.NDS_UI_ND
r"""
UI: no need to show diffpos detail pane, MH_UI_NODETAILS, make sense if
merge_node_helper_t is used
"""

class merge_node_helper_t(object):
    r"""
    Proxy of C++ merge_node_helper_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_merge.delete_merge_node_helper_t

    def print_entry_name(self, arg0: "uchar", arg1: "nodeidx_t", arg2: "void *") -> "qstring":
        r"""
        print_entry_name(self, arg0, arg1, arg2) -> qstring
        print the name of the specified entry (to be used in print_diffpos_name)

        @param arg0: uchar
        @param arg1: nodeidx_t
        @param arg2: void *
        """
        return _ida_merge.merge_node_helper_t_print_entry_name(self, arg0, arg1, arg2)

    def print_entry_details(self, arg0: "qstrvec_t *", arg1: "uchar", arg2: "nodeidx_t", arg3: "void *") -> "void":
        r"""
        print_entry_details(self, arg0, arg1, arg2, arg3)
        print the details of the specified entry usually contains multiple lines, one
        for each attribute or detail. (to be used in print_diffpos_details)

        @param arg0: qstrvec_t *
        @param arg1: uchar
        @param arg2: nodeidx_t
        @param arg3: void *
        """
        return _ida_merge.merge_node_helper_t_print_entry_details(self, arg0, arg1, arg2, arg3)

    def get_column_headers(self, arg0: "qstrvec_t *", arg1: "uchar", arg2: "void *") -> "void":
        r"""
        get_column_headers(self, arg0, arg1, arg2)
        get column headers for chooser (to be used in
        linear_diff_source_t::get_column_headers)

        @param arg0: qstrvec_t *
        @param arg1: uchar
        @param arg2: void *
        """
        return _ida_merge.merge_node_helper_t_get_column_headers(self, arg0, arg1, arg2)

    def is_mergeable(self, arg0: "uchar", arg1: "nodeidx_t") -> "bool":
        r"""
        is_mergeable(self, arg0, arg1) -> bool

        @param filter: check if we should perform merging for given record
        @param arg1: nodeidx_t
        """
        return _ida_merge.merge_node_helper_t_is_mergeable(self, arg0, arg1)

    def get_netnode(self) -> "netnode":
        r"""
        get_netnode(self) -> netnode
        return netnode to be used as source. If this function returns BADNODE netnode
        will be created using netnode name passed to create_nodeval_diff_source
        """
        return _ida_merge.merge_node_helper_t_get_netnode(self)

    def map_scalar(self, arg0: "nodeidx_t *", arg1: "void *", arg2: "diff_source_idx_t", arg3: "diff_source_idx_t") -> "void":
        r"""
        map_scalar(self, arg0, arg1, arg2, arg3)
        map scalar/string/buffered value

        @param arg0: nodeidx_t *
        @param arg1: void *
        @param arg2: diff_source_idx_t
        @param arg3: diff_source_idx_t
        """
        return _ida_merge.merge_node_helper_t_map_scalar(self, arg0, arg1, arg2, arg3)

    def map_string(self, arg0: "qstring *", arg1: "void *", arg2: "diff_source_idx_t", arg3: "diff_source_idx_t") -> "void":
        r"""
        map_string(self, arg0, arg1, arg2, arg3)

        @param arg0: qstring *
        @param arg1: void *
        @param arg2: diff_source_idx_t
        @param arg3: diff_source_idx_t
        """
        return _ida_merge.merge_node_helper_t_map_string(self, arg0, arg1, arg2, arg3)

    def refresh(self, arg0: "uchar", arg1: "void *") -> "void":
        r"""
        refresh(self, arg0, arg1)
        notify helper that some data was changed in the database and internal structures
        (e.g. caches) should be refreshed

        @param arg0: uchar
        @param arg1: void *
        """
        return _ida_merge.merge_node_helper_t_refresh(self, arg0, arg1)

    @staticmethod
    def append_eavec(s: "qstring *", prefix: "char const *", eas: "eavec_t const &") -> "void":
        r"""
        append_eavec(s, prefix, eas)
        can be used by derived classes

        @param s: (C++: qstring *)
        @param prefix: (C++: const char *) char const *
        @param eas: (C++: const eavec_t &) eavec_t const &
        """
        return _ida_merge.merge_node_helper_t_append_eavec(s, prefix, eas)

    def __init__(self):
        r"""
        __init__(self) -> merge_node_helper_t

        @param self: PyObject *
        """
        if self.__class__ == merge_node_helper_t:
            _self = None
        else:
            _self = self
        _ida_merge.merge_node_helper_t_swiginit(self, _ida_merge.new_merge_node_helper_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_merge.disown_merge_node_helper_t(self)
        return weakref.proxy(self)

# Register merge_node_helper_t in _ida_merge:
_ida_merge.merge_node_helper_t_swigregister(merge_node_helper_t)
class merge_node_info_t(object):
    r"""
    Proxy of C++ merge_node_info2_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    name: "char const *" = property(_ida_merge.merge_node_info_t_name_get, _ida_merge.merge_node_info_t_name_set, doc=r"""name""")
    r"""
    name of the array (label)
    """
    tag: "uchar" = property(_ida_merge.merge_node_info_t_tag_get, _ida_merge.merge_node_info_t_tag_set, doc=r"""tag""")
    r"""
    a tag used to access values in the netnode
    """
    nds_flags: "uint32" = property(_ida_merge.merge_node_info_t_nds_flags_get, _ida_merge.merge_node_info_t_nds_flags_set, doc=r"""nds_flags""")
    r"""
    node value attributes (a combination of nds_flags_t)
    """
    node_helper: "merge_node_helper_t *" = property(_ida_merge.merge_node_info_t_node_helper_get, _ida_merge.merge_node_info_t_node_helper_set, doc=r"""node_helper""")

    def __init__(self, name: "char const *", tag: "uchar", nds_flags: "uint32", node_helper: "merge_node_helper_t"=None):
        r"""
        __init__(self, name, tag, nds_flags, node_helper=None) -> merge_node_info_t

        @param name: char const *
        @param tag: uchar
        @param nds_flags: uint32
        @param node_helper: merge_node_helper_t *
        """
        _ida_merge.merge_node_info_t_swiginit(self, _ida_merge.new_merge_node_info_t(name, tag, nds_flags, node_helper))
    __swig_destroy__ = _ida_merge.delete_merge_node_info_t

# Register merge_node_info_t in _ida_merge:
_ida_merge.merge_node_info_t_swigregister(merge_node_info_t)

def create_nodeval_merge_handler(mhp: "merge_handler_params_t", label: "char const *", nodename: "char const *", tag: "uchar", nds_flags: "uint32", node_helper: "merge_node_helper_t"=None, skip_empty_nodes: "bool"=True) -> "merge_handler_t *":
    r"""
    create_nodeval_merge_handler(mhp, label, nodename, tag, nds_flags, node_helper=None, skip_empty_nodes=True) -> merge_handler_t
    Create a merge handler for netnode scalar/string values

    @param mhp: (C++: const merge_handler_params_t &) merging parameters
    @param label: (C++: const char *) handler short name (to be be appended to mhp.label)
    @param nodename: (C++: const char *) netnode name
    @param tag: (C++: uchar) a tag used to access values in the netnode
    @param nds_flags: (C++: uint32) netnode value attributes (a combination of nds_flags_t)
    @param node_helper: merge_node_helper_t *
    @param skip_empty_nodes: (C++: bool) do not create handler in case of empty netnode
    @return: diff source object (normally should be attahced to a merge handler)
    """
    return _ida_merge.create_nodeval_merge_handler(mhp, label, nodename, tag, nds_flags, node_helper, skip_empty_nodes)

def create_nodeval_merge_handlers(out: "merge_handlers_t *", mhp: "merge_handler_params_t", nodename: "char const *", valdesc: "merge_node_info_t", skip_empty_nodes: "bool"=True) -> "void":
    r"""
    create_nodeval_merge_handlers(out, mhp, nodename, valdesc, skip_empty_nodes=True)
    Create a serie of merge handlers for netnode scalar/string values (call
    create_nodeval_merge_handler() for each member of VALDESC)

    @param out: (C++: merge_handlers_t *) [out] created handlers will be placed here
    @param mhp: (C++: const merge_handler_params_t &) merging parameters
    @param nodename: (C++: const char *) netnode name
    @param valdesc: (C++: const merge_node_info_t *) array of handler descriptions
    @param skip_empty_nodes: (C++: bool) do not create handlers for empty netnodes
    @return: diff source object (normally should be attahced to a merge handler)
    """
    return _ida_merge.create_nodeval_merge_handlers(out, mhp, nodename, valdesc, skip_empty_nodes)

def destroy_moddata_merge_handlers(data_id: "int") -> "void":
    r"""
    destroy_moddata_merge_handlers(data_id)

    @param data_id: int
    """
    return _ida_merge.destroy_moddata_merge_handlers(data_id)

def get_ea_diffpos_name(ea: "ea_t") -> "qstring *":
    r"""
    get_ea_diffpos_name(ea) -> str
    Get nice name for EA diffpos

    @param ea: (C++: ea_t) diffpos
    @note
    @see: get_nice_colored_name
    """
    return _ida_merge.get_ea_diffpos_name(ea)


