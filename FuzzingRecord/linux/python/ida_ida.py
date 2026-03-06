r"""
Contains the ::inf structure definition and some functions common to the whole
IDA project.

The ::inf structure is saved in the database and contains information specific
to the current program being disassembled. Initially it is filled with values
from ida.cfg.

Although it is not a good idea to change values in ::inf structure (because you
will overwrite values taken from ida.cfg), you are allowed to do it if you feel
it necessary."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_ida
else:
    import _ida_ida

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

SWIG_PYTHON_LEGACY_BOOL = _ida_ida.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

AF_FINAL = _ida_ida.AF_FINAL
r"""
Final pass of analysis.
"""

f_EXE_old = _ida_ida.f_EXE_old
r"""
MS DOS EXE File.
"""

f_COM_old = _ida_ida.f_COM_old
r"""
MS DOS COM File.
"""

f_BIN = _ida_ida.f_BIN
r"""
Binary File.
"""

f_DRV = _ida_ida.f_DRV
r"""
MS DOS Driver.
"""

f_WIN = _ida_ida.f_WIN
r"""
New Executable (NE)
"""

f_HEX = _ida_ida.f_HEX
r"""
Intel Hex Object File.
"""

f_MEX = _ida_ida.f_MEX
r"""
MOS Technology Hex Object File.
"""

f_LX = _ida_ida.f_LX
r"""
Linear Executable (LX)
"""

f_LE = _ida_ida.f_LE
r"""
Linear Executable (LE)
"""

f_NLM = _ida_ida.f_NLM
r"""
Netware Loadable Module (NLM)
"""

f_COFF = _ida_ida.f_COFF
r"""
Common Object File Format (COFF)
"""

f_PE = _ida_ida.f_PE
r"""
Portable Executable (PE)
"""

f_OMF = _ida_ida.f_OMF
r"""
Object Module Format.
"""

f_SREC = _ida_ida.f_SREC
r"""
Motorola SREC (S-record)
"""

f_ZIP = _ida_ida.f_ZIP
r"""
ZIP file (this file is never loaded to IDA database)
"""

f_OMFLIB = _ida_ida.f_OMFLIB
r"""
Library of OMF Modules.
"""

f_AR = _ida_ida.f_AR
r"""
ar library
"""

f_LOADER = _ida_ida.f_LOADER
r"""
file is loaded using LOADER DLL
"""

f_ELF = _ida_ida.f_ELF
r"""
Executable and Linkable Format (ELF)
"""

f_W32RUN = _ida_ida.f_W32RUN
r"""
Watcom DOS32 Extender (W32RUN)
"""

f_AOUT = _ida_ida.f_AOUT
r"""
Linux a.out (AOUT)
"""

f_PRC = _ida_ida.f_PRC
r"""
PalmPilot program file.
"""

f_EXE = _ida_ida.f_EXE
r"""
MS DOS EXE File.
"""

f_COM = _ida_ida.f_COM
r"""
MS DOS COM File.
"""

f_AIXAR = _ida_ida.f_AIXAR
r"""
AIX ar library.
"""

f_MACHO = _ida_ida.f_MACHO
r"""
Mac OS X Mach-O.
"""

f_PSXOBJ = _ida_ida.f_PSXOBJ
r"""
Sony Playstation PSX object file.
"""

f_MD1IMG = _ida_ida.f_MD1IMG
r"""
Mediatek Firmware Image.
"""


def is_filetype_like_binary(ft: "filetype_t") -> "bool":
    r"""
    is_filetype_like_binary(ft) -> bool
    Is unstructured input file?

    @param ft: (C++: filetype_t) enum filetype_t
    """
    return _ida_ida.is_filetype_like_binary(ft)
class compiler_info_t(object):
    r"""
    Proxy of C++ compiler_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    id: "comp_t" = property(_ida_ida.compiler_info_t_id_get, _ida_ida.compiler_info_t_id_set, doc=r"""id""")
    r"""
    compiler id (see Compiler IDs)
    """
    cm: "cm_t" = property(_ida_ida.compiler_info_t_cm_get, _ida_ida.compiler_info_t_cm_set, doc=r"""cm""")
    r"""
    memory model and calling convention (see CM)
    """
    size_i: "uchar" = property(_ida_ida.compiler_info_t_size_i_get, _ida_ida.compiler_info_t_size_i_set, doc=r"""size_i""")
    r"""
    sizeof(int)
    """
    size_b: "uchar" = property(_ida_ida.compiler_info_t_size_b_get, _ida_ida.compiler_info_t_size_b_set, doc=r"""size_b""")
    r"""
    sizeof(bool)
    """
    size_e: "uchar" = property(_ida_ida.compiler_info_t_size_e_get, _ida_ida.compiler_info_t_size_e_set, doc=r"""size_e""")
    r"""
    sizeof(enum)
    """
    defalign: "uchar" = property(_ida_ida.compiler_info_t_defalign_get, _ida_ida.compiler_info_t_defalign_set, doc=r"""defalign""")
    r"""
    default alignment for structures
    """
    size_s: "uchar" = property(_ida_ida.compiler_info_t_size_s_get, _ida_ida.compiler_info_t_size_s_set, doc=r"""size_s""")
    r"""
    short
    """
    size_l: "uchar" = property(_ida_ida.compiler_info_t_size_l_get, _ida_ida.compiler_info_t_size_l_set, doc=r"""size_l""")
    r"""
    long
    """
    size_ll: "uchar" = property(_ida_ida.compiler_info_t_size_ll_get, _ida_ida.compiler_info_t_size_ll_set, doc=r"""size_ll""")
    r"""
    longlong
    """
    size_ldbl: "uchar" = property(_ida_ida.compiler_info_t_size_ldbl_get, _ida_ida.compiler_info_t_size_ldbl_set, doc=r"""size_ldbl""")
    r"""
    longdouble (if different from processor_t::tbyte_size)
    """

    def __init__(self):
        r"""
        __init__(self) -> compiler_info_t
        """
        _ida_ida.compiler_info_t_swiginit(self, _ida_ida.new_compiler_info_t())
    __swig_destroy__ = _ida_ida.delete_compiler_info_t

# Register compiler_info_t in _ida_ida:
_ida_ida.compiler_info_t_swigregister(compiler_info_t)
STT_CUR = _ida_ida.STT_CUR
r"""
use current storage type (may be used only as a function argument)
"""

STT_VA = _ida_ida.STT_VA
r"""
regular storage: virtual arrays, an explicit flag for each byte
"""

STT_MM = _ida_ida.STT_MM
r"""
memory map: sparse storage. useful for huge objects
"""

STT_DBG = _ida_ida.STT_DBG
r"""
memory map: temporary debugger storage. used internally
"""

IDAINFO_TAG_SIZE = _ida_ida.IDAINFO_TAG_SIZE
r"""
The database parameters. This structure is kept in the ida database. It contains
the essential parameters for the current program
"""

IDAINFO_PROCNAME_SIZE = _ida_ida.IDAINFO_PROCNAME_SIZE

IDAINFO_STRLIT_PREF_SIZE = _ida_ida.IDAINFO_STRLIT_PREF_SIZE

class idainfo(object):
    r"""
    Proxy of C++ idainfo class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    tag: "char [3]" = property(_ida_ida.idainfo_tag_get, _ida_ida.idainfo_tag_set, doc=r"""tag""")
    r"""
    'IDA'
    """
    version: "ushort" = property(_ida_ida.idainfo_version_get, _ida_ida.idainfo_version_set, doc=r"""version""")
    r"""
    Version of database.
    """
    procname: "char [16]" = property(_ida_ida.idainfo_procname_get, _ida_ida.idainfo_procname_set, doc=r"""procname""")
    r"""
    Name of the current processor (with \0)
    """
    s_genflags: "ushort" = property(_ida_ida.idainfo_s_genflags_get, _ida_ida.idainfo_s_genflags_set, doc=r"""s_genflags""")
    r"""
    General idainfo flags
    """
    database_change_count: "uint32" = property(_ida_ida.idainfo_database_change_count_get, _ida_ida.idainfo_database_change_count_set, doc=r"""database_change_count""")
    r"""
    incremented after each byte and regular segment modifications
    """
    filetype: "ushort" = property(_ida_ida.idainfo_filetype_get, _ida_ida.idainfo_filetype_set, doc=r"""filetype""")
    r"""
    The input file type.
    """
    ostype: "ushort" = property(_ida_ida.idainfo_ostype_get, _ida_ida.idainfo_ostype_set, doc=r"""ostype""")
    r"""
    OS type the program is for bit definitions in libfuncs.hpp
    """
    apptype: "ushort" = property(_ida_ida.idainfo_apptype_get, _ida_ida.idainfo_apptype_set, doc=r"""apptype""")
    r"""
    Application type bit definitions in libfuncs.hpp
    """
    asmtype: "uchar" = property(_ida_ida.idainfo_asmtype_get, _ida_ida.idainfo_asmtype_set, doc=r"""asmtype""")
    r"""
    target assembler number
    """
    specsegs: "uchar" = property(_ida_ida.idainfo_specsegs_get, _ida_ida.idainfo_specsegs_set, doc=r"""specsegs""")
    r"""
    What format do special segments use? 0-unspecified, 4-entries are 4 bytes, 8-
    entries are 8 bytes.
    """
    af: "uint32" = property(_ida_ida.idainfo_af_get, _ida_ida.idainfo_af_set, doc=r"""af""")
    r"""
    Analysis flags
    """
    af2: "uint32" = property(_ida_ida.idainfo_af2_get, _ida_ida.idainfo_af2_set, doc=r"""af2""")
    r"""
    Analysis flags 2
    """
    baseaddr: "uval_t" = property(_ida_ida.idainfo_baseaddr_get, _ida_ida.idainfo_baseaddr_set, doc=r"""baseaddr""")
    r"""
    remaining 28 bits are reserved

    base address of the program (paragraphs)
    """
    start_ss: "sel_t" = property(_ida_ida.idainfo_start_ss_get, _ida_ida.idainfo_start_ss_set, doc=r"""start_ss""")
    r"""
    selector of the initial stack segment
    """
    start_cs: "sel_t" = property(_ida_ida.idainfo_start_cs_get, _ida_ida.idainfo_start_cs_set, doc=r"""start_cs""")
    r"""
    selector of the segment with the main entry point
    """
    start_ip: "ea_t" = property(_ida_ida.idainfo_start_ip_get, _ida_ida.idainfo_start_ip_set, doc=r"""start_ip""")
    r"""
    IP register value at the start of program execution
    """
    start_ea: "ea_t" = property(_ida_ida.idainfo_start_ea_get, _ida_ida.idainfo_start_ea_set, doc=r"""start_ea""")
    r"""
    Linear address of program entry point.
    """
    start_sp: "ea_t" = property(_ida_ida.idainfo_start_sp_get, _ida_ida.idainfo_start_sp_set, doc=r"""start_sp""")
    r"""
    SP register value at the start of program execution
    """
    main: "ea_t" = property(_ida_ida.idainfo_main_get, _ida_ida.idainfo_main_set, doc=r"""main""")
    r"""
    address of main()
    """
    min_ea: "ea_t" = property(_ida_ida.idainfo_min_ea_get, _ida_ida.idainfo_min_ea_set, doc=r"""min_ea""")
    r"""
    current limits of program
    """
    max_ea: "ea_t" = property(_ida_ida.idainfo_max_ea_get, _ida_ida.idainfo_max_ea_set, doc=r"""max_ea""")
    r"""
    maxEA is excluded
    """
    omin_ea: "ea_t" = property(_ida_ida.idainfo_omin_ea_get, _ida_ida.idainfo_omin_ea_set, doc=r"""omin_ea""")
    r"""
    original minEA (is set after loading the input file)
    """
    omax_ea: "ea_t" = property(_ida_ida.idainfo_omax_ea_get, _ida_ida.idainfo_omax_ea_set, doc=r"""omax_ea""")
    r"""
    original maxEA (is set after loading the input file)
    """
    lowoff: "ea_t" = property(_ida_ida.idainfo_lowoff_get, _ida_ida.idainfo_lowoff_set, doc=r"""lowoff""")
    r"""
    Low limit for offsets (used in calculation of 'void' operands)
    """
    highoff: "ea_t" = property(_ida_ida.idainfo_highoff_get, _ida_ida.idainfo_highoff_set, doc=r"""highoff""")
    r"""
    High limit for offsets (used in calculation of 'void' operands)
    """
    maxref: "uval_t" = property(_ida_ida.idainfo_maxref_get, _ida_ida.idainfo_maxref_set, doc=r"""maxref""")
    r"""
    Max tail for references.
    """
    xrefnum: "uchar" = property(_ida_ida.idainfo_xrefnum_get, _ida_ida.idainfo_xrefnum_set, doc=r"""xrefnum""")
    r"""
    CROSS REFERENCES.

    Number of references to generate in the disassembly listing 0 - xrefs won't be
    generated at all
    """
    type_xrefnum: "uchar" = property(_ida_ida.idainfo_type_xrefnum_get, _ida_ida.idainfo_type_xrefnum_set, doc=r"""type_xrefnum""")
    r"""
    Number of references to generate in the struct & enum windows 0 - xrefs won't be
    generated at all
    """
    refcmtnum: "uchar" = property(_ida_ida.idainfo_refcmtnum_get, _ida_ida.idainfo_refcmtnum_set, doc=r"""refcmtnum""")
    r"""
    Number of comment lines to generate for refs to string literals or demangled
    names 0 - such comments won't be generated at all
    """
    s_xrefflag: "uchar" = property(_ida_ida.idainfo_s_xrefflag_get, _ida_ida.idainfo_s_xrefflag_set, doc=r"""s_xrefflag""")
    r"""
    Xref options
    """
    max_autoname_len: "ushort" = property(_ida_ida.idainfo_max_autoname_len_get, _ida_ida.idainfo_max_autoname_len_set, doc=r"""max_autoname_len""")
    r"""
    NAMES.

    max autogenerated name length (without zero byte)
    """
    nametype: "char" = property(_ida_ida.idainfo_nametype_get, _ida_ida.idainfo_nametype_set, doc=r"""nametype""")
    r"""
    Dummy names representation types
    """
    short_demnames: "uint32" = property(_ida_ida.idainfo_short_demnames_get, _ida_ida.idainfo_short_demnames_set, doc=r"""short_demnames""")
    r"""
    short form of demangled names
    """
    long_demnames: "uint32" = property(_ida_ida.idainfo_long_demnames_get, _ida_ida.idainfo_long_demnames_set, doc=r"""long_demnames""")
    r"""
    long form of demangled names see demangle.h for definitions
    """
    demnames: "uchar" = property(_ida_ida.idainfo_demnames_get, _ida_ida.idainfo_demnames_set, doc=r"""demnames""")
    r"""
    Demangled name flags
    """
    listnames: "uchar" = property(_ida_ida.idainfo_listnames_get, _ida_ida.idainfo_listnames_set, doc=r"""listnames""")
    r"""
    Name list options
    """
    indent: "uchar" = property(_ida_ida.idainfo_indent_get, _ida_ida.idainfo_indent_set, doc=r"""indent""")
    r"""
    DISASSEMBLY LISTING DETAILS.

    Indentation for instructions
    """
    cmt_indent: "uchar" = property(_ida_ida.idainfo_cmt_indent_get, _ida_ida.idainfo_cmt_indent_set, doc=r"""cmt_indent""")
    r"""
    Indentation for comments.
    """
    margin: "ushort" = property(_ida_ida.idainfo_margin_get, _ida_ida.idainfo_margin_set, doc=r"""margin""")
    r"""
    max length of data lines
    """
    lenxref: "ushort" = property(_ida_ida.idainfo_lenxref_get, _ida_ida.idainfo_lenxref_set, doc=r"""lenxref""")
    r"""
    max length of line with xrefs
    """
    outflags: "uint32" = property(_ida_ida.idainfo_outflags_get, _ida_ida.idainfo_outflags_set, doc=r"""outflags""")
    r"""
    output flags
    """
    s_cmtflg: "uchar" = property(_ida_ida.idainfo_s_cmtflg_get, _ida_ida.idainfo_s_cmtflg_set, doc=r"""s_cmtflg""")
    r"""
    Comment options
    """
    s_limiter: "uchar" = property(_ida_ida.idainfo_s_limiter_get, _ida_ida.idainfo_s_limiter_set, doc=r"""s_limiter""")
    r"""
    Delimiter options
    """
    bin_prefix_size: "short" = property(_ida_ida.idainfo_bin_prefix_size_get, _ida_ida.idainfo_bin_prefix_size_set, doc=r"""bin_prefix_size""")
    r"""
    Number of instruction bytes (opcodes) to show in line prefix.
    """
    s_prefflag: "uchar" = property(_ida_ida.idainfo_s_prefflag_get, _ida_ida.idainfo_s_prefflag_set, doc=r"""s_prefflag""")
    r"""
    Line prefix options
    """
    strlit_flags: "uchar" = property(_ida_ida.idainfo_strlit_flags_get, _ida_ida.idainfo_strlit_flags_set, doc=r"""strlit_flags""")
    r"""
    STRING LITERALS.

    string literal flags
    """
    strlit_break: "uchar" = property(_ida_ida.idainfo_strlit_break_get, _ida_ida.idainfo_strlit_break_set, doc=r"""strlit_break""")
    r"""
    string literal line break symbol
    """
    strlit_zeroes: "char" = property(_ida_ida.idainfo_strlit_zeroes_get, _ida_ida.idainfo_strlit_zeroes_set, doc=r"""strlit_zeroes""")
    r"""
    leading zeroes
    """
    strtype: "int32" = property(_ida_ida.idainfo_strtype_get, _ida_ida.idainfo_strtype_set, doc=r"""strtype""")
    r"""
    current ascii string type see nalt.hpp for string types
    """
    strlit_pref: "char [16]" = property(_ida_ida.idainfo_strlit_pref_get, _ida_ida.idainfo_strlit_pref_set, doc=r"""strlit_pref""")
    r"""
    prefix for string literal names
    """
    strlit_sernum: "uval_t" = property(_ida_ida.idainfo_strlit_sernum_get, _ida_ida.idainfo_strlit_sernum_set, doc=r"""strlit_sernum""")
    r"""
    serial number
    """
    datatypes: "uval_t" = property(_ida_ida.idainfo_datatypes_get, _ida_ida.idainfo_datatypes_set, doc=r"""datatypes""")
    r"""
    data types allowed in data carousel
    """
    cc: "compiler_info_t" = property(_ida_ida.idainfo_cc_get, _ida_ida.idainfo_cc_set, doc=r"""cc""")
    r"""
    COMPILER.

    Target compiler
    """
    abibits: "uint32" = property(_ida_ida.idainfo_abibits_get, _ida_ida.idainfo_abibits_set, doc=r"""abibits""")
    r"""
    ABI features. Depends on info returned by get_abi_name() Processor modules may
    modify them in set_compiler
    """
    appcall_options: "uint32" = property(_ida_ida.idainfo_appcall_options_get, _ida_ida.idainfo_appcall_options_set, doc=r"""appcall_options""")
    r"""
    appcall options, see idd.hpp
    """

    def get_abiname(self) -> "qstring":
        r"""
        get_abiname(self) -> qstring
        """
        return _ida_ida.idainfo_get_abiname(self)

    def _get_lflags(self) -> "uint32":
        r"""_get_lflags(self) -> uint32"""
        return _ida_ida.idainfo__get_lflags(self)

    def _set_lflags(self, _f: "uint32") -> "void":
        r"""
        _set_lflags(self, _f)

        Parameters
        ----------
        _f: uint32

        """
        return _ida_ida.idainfo__set_lflags(self, _f)

    abiname = property(get_abiname)
    lflags = property(_get_lflags, _set_lflags)
    r"""
    Misc. database flags
    """

    minEA = ida_idaapi._make_missed_695bwcompat_property("minEA", "min_ea", has_setter=True)
    maxEA = ida_idaapi._make_missed_695bwcompat_property("maxEA", "max_ea", has_setter=True)
    procName = ida_idaapi._make_missed_695bwcompat_property("procName", "procname", has_setter=False)



# Register idainfo in _ida_ida:
_ida_ida.idainfo_swigregister(idainfo)
INFFL_AUTO = _ida_ida.INFFL_AUTO
r"""
Autoanalysis is enabled?
"""

INFFL_ALLASM = _ida_ida.INFFL_ALLASM
r"""
may use constructs not supported by the target assembler
"""

INFFL_LOADIDC = _ida_ida.INFFL_LOADIDC
r"""
loading an idc file that contains database info
"""

INFFL_NOUSER = _ida_ida.INFFL_NOUSER
r"""
do not store user info in the database
"""

INFFL_READONLY = _ida_ida.INFFL_READONLY
r"""
(internal) temporary interdiction to modify the database
"""

INFFL_CHKOPS = _ida_ida.INFFL_CHKOPS
r"""
check manual operands? (unused)
"""

INFFL_NMOPS = _ida_ida.INFFL_NMOPS
r"""
allow non-matched operands? (unused)
"""

INFFL_GRAPH_VIEW = _ida_ida.INFFL_GRAPH_VIEW
r"""
currently using graph options ( text_options_t::graph)
"""

LFLG_PC_FPP = _ida_ida.LFLG_PC_FPP
r"""
decode floating point processor instructions?
"""

LFLG_PC_FLAT = _ida_ida.LFLG_PC_FLAT
r"""
32-bit program (or higher)?
"""

LFLG_64BIT = _ida_ida.LFLG_64BIT
r"""
64-bit program?
"""

LFLG_IS_DLL = _ida_ida.LFLG_IS_DLL
r"""
Is dynamic library?
"""

LFLG_FLAT_OFF32 = _ida_ida.LFLG_FLAT_OFF32
r"""
treat REF_OFF32 as 32-bit offset for 16bit segments (otherwise try SEG16:OFF16)
"""

LFLG_MSF = _ida_ida.LFLG_MSF
r"""
Byte order: is MSB first?
"""

LFLG_WIDE_HBF = _ida_ida.LFLG_WIDE_HBF
r"""
Bit order of wide bytes: high byte first? (wide bytes: processor_t::dnbits > 8)
"""

LFLG_DBG_NOPATH = _ida_ida.LFLG_DBG_NOPATH
r"""
do not store input full path in debugger process options
"""

LFLG_SNAPSHOT = _ida_ida.LFLG_SNAPSHOT
r"""
memory snapshot was taken?
"""

LFLG_PACK = _ida_ida.LFLG_PACK
r"""
pack the database?
"""

LFLG_COMPRESS = _ida_ida.LFLG_COMPRESS
r"""
compress the database?
"""

LFLG_KERNMODE = _ida_ida.LFLG_KERNMODE
r"""
is kernel mode binary?
"""

IDB_UNPACKED = _ida_ida.IDB_UNPACKED
r"""
leave database components unpacked
"""

IDB_PACKED = _ida_ida.IDB_PACKED
r"""
pack database components into .idb
"""

IDB_COMPRESSED = _ida_ida.IDB_COMPRESSED
r"""
compress & pack database components
"""

AF_CODE = _ida_ida.AF_CODE
r"""
Trace execution flow.
"""

AF_MARKCODE = _ida_ida.AF_MARKCODE
r"""
Mark typical code sequences as code.
"""

AF_JUMPTBL = _ida_ida.AF_JUMPTBL
r"""
Locate and create jump tables.
"""

AF_PURDAT = _ida_ida.AF_PURDAT
r"""
Control flow to data segment is ignored.
"""

AF_USED = _ida_ida.AF_USED
r"""
Analyze and create all xrefs.
"""

AF_UNK = _ida_ida.AF_UNK
r"""
Delete instructions with no xrefs.
"""

AF_PROCPTR = _ida_ida.AF_PROCPTR
r"""
Create function if data xref data->code32 exists.
"""

AF_PROC = _ida_ida.AF_PROC
r"""
Create functions if call is present.
"""

AF_FTAIL = _ida_ida.AF_FTAIL
r"""
Create function tails.
"""

AF_LVAR = _ida_ida.AF_LVAR
r"""
Create stack variables.
"""

AF_STKARG = _ida_ida.AF_STKARG
r"""
Propagate stack argument information.
"""

AF_REGARG = _ida_ida.AF_REGARG
r"""
Propagate register argument information.
"""

AF_TRACE = _ida_ida.AF_TRACE
r"""
Trace stack pointer.
"""

AF_VERSP = _ida_ida.AF_VERSP
r"""
Perform full SP-analysis. ( processor_t::verify_sp)
"""

AF_ANORET = _ida_ida.AF_ANORET
r"""
Perform 'no-return' analysis.
"""

AF_MEMFUNC = _ida_ida.AF_MEMFUNC
r"""
Try to guess member function types.
"""

AF_TRFUNC = _ida_ida.AF_TRFUNC
r"""
Truncate functions upon code deletion.
"""

AF_STRLIT = _ida_ida.AF_STRLIT
r"""
Create string literal if data xref exists.
"""

AF_CHKUNI = _ida_ida.AF_CHKUNI
r"""
Check for unicode strings.
"""

AF_FIXUP = _ida_ida.AF_FIXUP
r"""
Create offsets and segments using fixup info.
"""

AF_DREFOFF = _ida_ida.AF_DREFOFF
r"""
Create offset if data xref to seg32 exists.
"""

AF_IMMOFF = _ida_ida.AF_IMMOFF
r"""
Convert 32bit instruction operand to offset.
"""

AF_DATOFF = _ida_ida.AF_DATOFF
r"""
Automatically convert data to offsets.
"""

AF_FLIRT = _ida_ida.AF_FLIRT
r"""
Use flirt signatures.
"""

AF_SIGCMT = _ida_ida.AF_SIGCMT
r"""
Append a signature name comment for recognized anonymous library functions.
"""

AF_SIGMLT = _ida_ida.AF_SIGMLT
r"""
Allow recognition of several copies of the same function.
"""

AF_HFLIRT = _ida_ida.AF_HFLIRT
r"""
Automatically hide library functions.
"""

AF_JFUNC = _ida_ida.AF_JFUNC
r"""
Rename jump functions as j_...
"""

AF_NULLSUB = _ida_ida.AF_NULLSUB
r"""
Rename empty functions as nullsub_...
"""

AF_DODATA = _ida_ida.AF_DODATA
r"""
Coagulate data segs at the final pass.
"""

AF_DOCODE = _ida_ida.AF_DOCODE
r"""
Coagulate code segs at the final pass.
"""

AF2_DOEH = _ida_ida.AF2_DOEH
r"""
Handle EH information.
"""

AF2_DORTTI = _ida_ida.AF2_DORTTI
r"""
Handle RTTI information.
"""

AF2_MACRO = _ida_ida.AF2_MACRO
r"""
Try to combine several instructions into a macro instruction
"""

AF2_MERGESTR = _ida_ida.AF2_MERGESTR
r"""
Merge string literals created using data xrefs
"""

SW_SEGXRF = _ida_ida.SW_SEGXRF
r"""
show segments in xrefs?
"""

SW_XRFMRK = _ida_ida.SW_XRFMRK
r"""
show xref type marks?
"""

SW_XRFFNC = _ida_ida.SW_XRFFNC
r"""
show function offsets?
"""

SW_XRFVAL = _ida_ida.SW_XRFVAL
r"""
show xref values? (otherwise-"...")
"""

NM_REL_OFF = _ida_ida.NM_REL_OFF

NM_PTR_OFF = _ida_ida.NM_PTR_OFF

NM_NAM_OFF = _ida_ida.NM_NAM_OFF

NM_REL_EA = _ida_ida.NM_REL_EA

NM_PTR_EA = _ida_ida.NM_PTR_EA

NM_NAM_EA = _ida_ida.NM_NAM_EA

NM_EA = _ida_ida.NM_EA

NM_EA4 = _ida_ida.NM_EA4

NM_EA8 = _ida_ida.NM_EA8

NM_SHORT = _ida_ida.NM_SHORT

NM_SERIAL = _ida_ida.NM_SERIAL

DEMNAM_MASK = _ida_ida.DEMNAM_MASK
r"""
mask for name form
"""

DEMNAM_CMNT = _ida_ida.DEMNAM_CMNT
r"""
display demangled names as comments
"""

DEMNAM_NAME = _ida_ida.DEMNAM_NAME
r"""
display demangled names as regular names
"""

DEMNAM_NONE = _ida_ida.DEMNAM_NONE
r"""
don't display demangled names
"""

DEMNAM_GCC3 = _ida_ida.DEMNAM_GCC3
r"""
assume gcc3 names (valid for gnu compiler)
"""

DEMNAM_FIRST = _ida_ida.DEMNAM_FIRST
r"""
override type info
"""

LN_NORMAL = _ida_ida.LN_NORMAL
r"""
include normal names
"""

LN_PUBLIC = _ida_ida.LN_PUBLIC
r"""
include public names
"""

LN_AUTO = _ida_ida.LN_AUTO
r"""
include autogenerated names
"""

LN_WEAK = _ida_ida.LN_WEAK
r"""
include weak names
"""

OFLG_SHOW_VOID = _ida_ida.OFLG_SHOW_VOID
r"""
Display void marks?
"""

OFLG_SHOW_AUTO = _ida_ida.OFLG_SHOW_AUTO
r"""
Display autoanalysis indicator?
"""

OFLG_GEN_NULL = _ida_ida.OFLG_GEN_NULL
r"""
Generate empty lines?
"""

OFLG_SHOW_PREF = _ida_ida.OFLG_SHOW_PREF
r"""
Show line prefixes?
"""

OFLG_PREF_SEG = _ida_ida.OFLG_PREF_SEG
r"""
line prefixes with segment name?
"""

OFLG_LZERO = _ida_ida.OFLG_LZERO
r"""
generate leading zeroes in numbers
"""

OFLG_GEN_ORG = _ida_ida.OFLG_GEN_ORG
r"""
Generate 'org' directives?
"""

OFLG_GEN_ASSUME = _ida_ida.OFLG_GEN_ASSUME
r"""
Generate 'assume' directives?
"""

OFLG_GEN_TRYBLKS = _ida_ida.OFLG_GEN_TRYBLKS
r"""
Generate try/catch directives?
"""

SCF_RPTCMT = _ida_ida.SCF_RPTCMT
r"""
show repeatable comments?
"""

SCF_ALLCMT = _ida_ida.SCF_ALLCMT
r"""
comment all lines?
"""

SCF_NOCMT = _ida_ida.SCF_NOCMT
r"""
no comments at all
"""

SCF_LINNUM = _ida_ida.SCF_LINNUM
r"""
show source line numbers
"""

SCF_TESTMODE = _ida_ida.SCF_TESTMODE
r"""
testida.idc is running
"""

SCF_SHHID_ITEM = _ida_ida.SCF_SHHID_ITEM
r"""
show hidden instructions
"""

SCF_SHHID_FUNC = _ida_ida.SCF_SHHID_FUNC
r"""
show hidden functions
"""

SCF_SHHID_SEGM = _ida_ida.SCF_SHHID_SEGM
r"""
show hidden segments
"""

LMT_THIN = _ida_ida.LMT_THIN
r"""
thin borders
"""

LMT_THICK = _ida_ida.LMT_THICK
r"""
thick borders
"""

LMT_EMPTY = _ida_ida.LMT_EMPTY
r"""
empty lines at the end of basic blocks
"""

PREF_SEGADR = _ida_ida.PREF_SEGADR
r"""
show segment addresses?
"""

PREF_FNCOFF = _ida_ida.PREF_FNCOFF
r"""
show function offsets?
"""

PREF_STACK = _ida_ida.PREF_STACK
r"""
show stack pointer?
"""

PREF_PFXTRUNC = _ida_ida.PREF_PFXTRUNC
r"""
truncate instruction bytes if they would need more than 1 line
"""

STRF_GEN = _ida_ida.STRF_GEN
r"""
generate names?
"""

STRF_AUTO = _ida_ida.STRF_AUTO
r"""
names have 'autogenerated' bit?
"""

STRF_SERIAL = _ida_ida.STRF_SERIAL
r"""
generate serial names?
"""

STRF_UNICODE = _ida_ida.STRF_UNICODE
r"""
unicode strings are present?
"""

STRF_COMMENT = _ida_ida.STRF_COMMENT
r"""
generate auto comment for string references?
"""

STRF_SAVECASE = _ida_ida.STRF_SAVECASE
r"""
preserve case of strings for identifiers
"""

ABI_8ALIGN4 = _ida_ida.ABI_8ALIGN4
r"""
4 byte alignment for 8byte scalars (__int64/double) inside structures?
"""

ABI_PACK_STKARGS = _ida_ida.ABI_PACK_STKARGS
r"""
do not align stack arguments to stack slots
"""

ABI_BIGARG_ALIGN = _ida_ida.ABI_BIGARG_ALIGN
r"""
use natural type alignment for argument if the alignment exceeds native word
size. (e.g. __int64 argument should be 8byte aligned on some 32bit platforms)
"""

ABI_STACK_LDBL = _ida_ida.ABI_STACK_LDBL
r"""
long double arguments are passed on stack
"""

ABI_STACK_VARARGS = _ida_ida.ABI_STACK_VARARGS
r"""
varargs are always passed on stack (even when there are free registers)
"""

ABI_HARD_FLOAT = _ida_ida.ABI_HARD_FLOAT
r"""
use the floating-point register set
"""

ABI_SET_BY_USER = _ida_ida.ABI_SET_BY_USER
r"""
compiler/abi were set by user flag and require SETCOMP_BY_USER flag to be
changed
"""

ABI_GCC_LAYOUT = _ida_ida.ABI_GCC_LAYOUT
r"""
use gcc layout for udts (used for mingw)
"""

ABI_MAP_STKARGS = _ida_ida.ABI_MAP_STKARGS
r"""
register arguments are mapped to stack area (and consume stack slots)
"""

ABI_HUGEARG_ALIGN = _ida_ida.ABI_HUGEARG_ALIGN
r"""
use natural type alignment for an argument even if its alignment exceeds double
native word size (the default is to use double word max). e.g. if this bit is
set, __int128 has 16-byte alignment. this bit is not used by ida yet
"""


INF_VERSION = _ida_ida.INF_VERSION

INF_PROCNAME = _ida_ida.INF_PROCNAME

INF_GENFLAGS = _ida_ida.INF_GENFLAGS

INF_LFLAGS = _ida_ida.INF_LFLAGS

INF_DATABASE_CHANGE_COUNT = _ida_ida.INF_DATABASE_CHANGE_COUNT

INF_FILETYPE = _ida_ida.INF_FILETYPE

INF_OSTYPE = _ida_ida.INF_OSTYPE

INF_APPTYPE = _ida_ida.INF_APPTYPE

INF_ASMTYPE = _ida_ida.INF_ASMTYPE

INF_SPECSEGS = _ida_ida.INF_SPECSEGS

INF_AF = _ida_ida.INF_AF

INF_AF2 = _ida_ida.INF_AF2

INF_BASEADDR = _ida_ida.INF_BASEADDR

INF_START_SS = _ida_ida.INF_START_SS

INF_START_CS = _ida_ida.INF_START_CS

INF_START_IP = _ida_ida.INF_START_IP

INF_START_EA = _ida_ida.INF_START_EA

INF_START_SP = _ida_ida.INF_START_SP

INF_MAIN = _ida_ida.INF_MAIN

INF_MIN_EA = _ida_ida.INF_MIN_EA

INF_MAX_EA = _ida_ida.INF_MAX_EA

INF_OMIN_EA = _ida_ida.INF_OMIN_EA

INF_OMAX_EA = _ida_ida.INF_OMAX_EA

INF_LOWOFF = _ida_ida.INF_LOWOFF

INF_HIGHOFF = _ida_ida.INF_HIGHOFF

INF_MAXREF = _ida_ida.INF_MAXREF

INF_PRIVRANGE = _ida_ida.INF_PRIVRANGE

INF_PRIVRANGE_START_EA = _ida_ida.INF_PRIVRANGE_START_EA

INF_PRIVRANGE_END_EA = _ida_ida.INF_PRIVRANGE_END_EA

INF_NETDELTA = _ida_ida.INF_NETDELTA

INF_XREFNUM = _ida_ida.INF_XREFNUM

INF_TYPE_XREFNUM = _ida_ida.INF_TYPE_XREFNUM

INF_REFCMTNUM = _ida_ida.INF_REFCMTNUM

INF_XREFFLAG = _ida_ida.INF_XREFFLAG

INF_MAX_AUTONAME_LEN = _ida_ida.INF_MAX_AUTONAME_LEN

INF_NAMETYPE = _ida_ida.INF_NAMETYPE

INF_SHORT_DEMNAMES = _ida_ida.INF_SHORT_DEMNAMES

INF_LONG_DEMNAMES = _ida_ida.INF_LONG_DEMNAMES

INF_DEMNAMES = _ida_ida.INF_DEMNAMES

INF_LISTNAMES = _ida_ida.INF_LISTNAMES

INF_INDENT = _ida_ida.INF_INDENT

INF_CMT_INDENT = _ida_ida.INF_CMT_INDENT

INF_MARGIN = _ida_ida.INF_MARGIN

INF_LENXREF = _ida_ida.INF_LENXREF

INF_OUTFLAGS = _ida_ida.INF_OUTFLAGS

INF_CMTFLG = _ida_ida.INF_CMTFLG

INF_LIMITER = _ida_ida.INF_LIMITER

INF_BIN_PREFIX_SIZE = _ida_ida.INF_BIN_PREFIX_SIZE

INF_PREFFLAG = _ida_ida.INF_PREFFLAG

INF_STRLIT_FLAGS = _ida_ida.INF_STRLIT_FLAGS

INF_STRLIT_BREAK = _ida_ida.INF_STRLIT_BREAK

INF_STRLIT_ZEROES = _ida_ida.INF_STRLIT_ZEROES

INF_STRTYPE = _ida_ida.INF_STRTYPE

INF_STRLIT_PREF = _ida_ida.INF_STRLIT_PREF

INF_STRLIT_SERNUM = _ida_ida.INF_STRLIT_SERNUM

INF_DATATYPES = _ida_ida.INF_DATATYPES

INF_CC = _ida_ida.INF_CC

INF_CC_ID = _ida_ida.INF_CC_ID

INF_CC_CM = _ida_ida.INF_CC_CM

INF_CC_SIZE_I = _ida_ida.INF_CC_SIZE_I

INF_CC_SIZE_B = _ida_ida.INF_CC_SIZE_B

INF_CC_SIZE_E = _ida_ida.INF_CC_SIZE_E

INF_CC_DEFALIGN = _ida_ida.INF_CC_DEFALIGN

INF_CC_SIZE_S = _ida_ida.INF_CC_SIZE_S

INF_CC_SIZE_L = _ida_ida.INF_CC_SIZE_L

INF_CC_SIZE_LL = _ida_ida.INF_CC_SIZE_LL

INF_CC_SIZE_LDBL = _ida_ida.INF_CC_SIZE_LDBL

INF_ABIBITS = _ida_ida.INF_ABIBITS

INF_APPCALL_OPTIONS = _ida_ida.INF_APPCALL_OPTIONS

INF_FILE_FORMAT_NAME = _ida_ida.INF_FILE_FORMAT_NAME
r"""
file format name for loader modules
"""

INF_GROUPS = _ida_ida.INF_GROUPS
r"""
segment group information (see init_groups())
"""

INF_H_PATH = _ida_ida.INF_H_PATH
r"""
C header path.
"""

INF_C_MACROS = _ida_ida.INF_C_MACROS
r"""
C predefined macros.
"""

INF_INCLUDE = _ida_ida.INF_INCLUDE
r"""
assembler include file name
"""

INF_DUALOP_GRAPH = _ida_ida.INF_DUALOP_GRAPH
r"""
Graph text representation options.
"""

INF_DUALOP_TEXT = _ida_ida.INF_DUALOP_TEXT
r"""
Text text representation options.
"""

INF_MD5 = _ida_ida.INF_MD5
r"""
MD5 of the input file.
"""

INF_IDA_VERSION = _ida_ida.INF_IDA_VERSION
r"""
version of ida which created the database
"""

INF_STR_ENCODINGS = _ida_ida.INF_STR_ENCODINGS
r"""
a list of encodings for the program strings
"""

INF_DBG_BINPATHS = _ida_ida.INF_DBG_BINPATHS
r"""
unused (20 indexes)
"""

INF_SHA256 = _ida_ida.INF_SHA256
r"""
SHA256 of the input file.
"""

INF_ABINAME = _ida_ida.INF_ABINAME
r"""
ABI name (processor specific)
"""

INF_ARCHIVE_PATH = _ida_ida.INF_ARCHIVE_PATH
r"""
archive file path
"""

INF_PROBLEMS = _ida_ida.INF_PROBLEMS
r"""
problem lists
"""

INF_SELECTORS = _ida_ida.INF_SELECTORS
r"""
2..63 are for selector_t blob (see init_selectors())
"""

INF_NOTEPAD = _ida_ida.INF_NOTEPAD
r"""
notepad blob, occupies 1000 indexes (1MB of text)
"""

INF_SRCDBG_PATHS = _ida_ida.INF_SRCDBG_PATHS
r"""
source debug paths, occupies 20 indexes
"""

INF_SRCDBG_UNDESIRED = _ida_ida.INF_SRCDBG_UNDESIRED
r"""
user-closed source files, occupies 20 indexes
"""

INF_INITIAL_VERSION = _ida_ida.INF_INITIAL_VERSION
r"""
initial version of database
"""

INF_CTIME = _ida_ida.INF_CTIME
r"""
database creation timestamp
"""

INF_ELAPSED = _ida_ida.INF_ELAPSED
r"""
seconds database stayed open
"""

INF_NOPENS = _ida_ida.INF_NOPENS
r"""
how many times the database is opened
"""

INF_CRC32 = _ida_ida.INF_CRC32
r"""
input file crc32
"""

INF_IMAGEBASE = _ida_ida.INF_IMAGEBASE
r"""
image base
"""

INF_IDSNODE = _ida_ida.INF_IDSNODE
r"""
ids modnode id (for import_module)
"""

INF_FSIZE = _ida_ida.INF_FSIZE
r"""
input file size
"""

INF_OUTFILEENC = _ida_ida.INF_OUTFILEENC
r"""
output file encoding index
"""

INF_INPUT_FILE_PATH = _ida_ida.INF_INPUT_FILE_PATH

INF_LAST = _ida_ida.INF_LAST


def getinf_str(tag: "inftag_t") -> "qstring *":
    r"""
    getinf_str(tag) -> str
    Get program specific information (a non-scalar value)

    @param tag: (C++: inftag_t) one of inftag_t constants
    @return: number of bytes stored in the buffer (<0 - not defined)
    """
    return _ida_ida.getinf_str(tag)

def delinf(tag: "inftag_t") -> "bool":
    r"""
    delinf(tag) -> bool
    Undefine a program specific information

    @param tag: (C++: inftag_t) one of inftag_t constants
    @return: success
    """
    return _ida_ida.delinf(tag)

def inf_get_version() -> "ushort":
    r"""
    inf_get_version() -> ushort
    """
    return _ida_ida.inf_get_version()

def inf_set_version(_v: "ushort") -> "bool":
    r"""
    inf_set_version(_v) -> bool

    @param _v: ushort
    """
    return _ida_ida.inf_set_version(_v)

def inf_get_genflags() -> "ushort":
    r"""
    inf_get_genflags() -> ushort
    """
    return _ida_ida.inf_get_genflags()

def inf_set_genflags(_v: "ushort") -> "bool":
    r"""
    inf_set_genflags(_v) -> bool

    @param _v: ushort
    """
    return _ida_ida.inf_set_genflags(_v)

def inf_is_auto_enabled() -> "bool":
    r"""
    inf_is_auto_enabled() -> bool
    """
    return _ida_ida.inf_is_auto_enabled()

def inf_set_auto_enabled(_v: "bool"=True) -> "bool":
    r"""
    inf_set_auto_enabled(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_auto_enabled(_v)

def inf_use_allasm() -> "bool":
    r"""
    inf_use_allasm() -> bool
    """
    return _ida_ida.inf_use_allasm()

def inf_set_use_allasm(_v: "bool"=True) -> "bool":
    r"""
    inf_set_use_allasm(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_use_allasm(_v)

def inf_loading_idc() -> "bool":
    r"""
    inf_loading_idc() -> bool
    """
    return _ida_ida.inf_loading_idc()

def inf_set_loading_idc(_v: "bool"=True) -> "bool":
    r"""
    inf_set_loading_idc(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_loading_idc(_v)

def inf_no_store_user_info() -> "bool":
    r"""
    inf_no_store_user_info() -> bool
    """
    return _ida_ida.inf_no_store_user_info()

def inf_set_no_store_user_info(_v: "bool"=True) -> "bool":
    r"""
    inf_set_no_store_user_info(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_no_store_user_info(_v)

def inf_readonly_idb() -> "bool":
    r"""
    inf_readonly_idb() -> bool
    """
    return _ida_ida.inf_readonly_idb()

def inf_set_readonly_idb(_v: "bool"=True) -> "bool":
    r"""
    inf_set_readonly_idb(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_readonly_idb(_v)

def inf_check_manual_ops() -> "bool":
    r"""
    inf_check_manual_ops() -> bool
    """
    return _ida_ida.inf_check_manual_ops()

def inf_set_check_manual_ops(_v: "bool"=True) -> "bool":
    r"""
    inf_set_check_manual_ops(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_check_manual_ops(_v)

def inf_allow_non_matched_ops() -> "bool":
    r"""
    inf_allow_non_matched_ops() -> bool
    """
    return _ida_ida.inf_allow_non_matched_ops()

def inf_set_allow_non_matched_ops(_v: "bool"=True) -> "bool":
    r"""
    inf_set_allow_non_matched_ops(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_allow_non_matched_ops(_v)

def inf_is_graph_view() -> "bool":
    r"""
    inf_is_graph_view() -> bool
    """
    return _ida_ida.inf_is_graph_view()

def inf_set_graph_view(_v: "bool"=True) -> "bool":
    r"""
    inf_set_graph_view(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_graph_view(_v)

def inf_get_lflags() -> "uint32":
    r"""
    inf_get_lflags() -> uint32
    """
    return _ida_ida.inf_get_lflags()

def inf_set_lflags(_v: "uint32") -> "bool":
    r"""
    inf_set_lflags(_v) -> bool

    @param _v: uint32
    """
    return _ida_ida.inf_set_lflags(_v)

def inf_decode_fpp() -> "bool":
    r"""
    inf_decode_fpp() -> bool
    """
    return _ida_ida.inf_decode_fpp()

def inf_set_decode_fpp(_v: "bool"=True) -> "bool":
    r"""
    inf_set_decode_fpp(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_decode_fpp(_v)

def inf_is_32bit_or_higher() -> "bool":
    r"""
    inf_is_32bit_or_higher() -> bool
    """
    return _ida_ida.inf_is_32bit_or_higher()

def inf_is_32bit_exactly() -> "bool":
    r"""
    inf_is_32bit_exactly() -> bool
    """
    return _ida_ida.inf_is_32bit_exactly()

def inf_set_32bit(_v: "bool"=True) -> "bool":
    r"""
    inf_set_32bit(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_32bit(_v)

def inf_is_16bit() -> "bool":
    r"""
    inf_is_16bit() -> bool
    """
    return _ida_ida.inf_is_16bit()

def inf_is_64bit() -> "bool":
    r"""
    inf_is_64bit() -> bool
    """
    return _ida_ida.inf_is_64bit()

def inf_set_64bit(_v: "bool"=True) -> "bool":
    r"""
    inf_set_64bit(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_64bit(_v)

def inf_is_dll() -> "bool":
    r"""
    inf_is_dll() -> bool
    """
    return _ida_ida.inf_is_dll()

def inf_set_dll(_v: "bool"=True) -> "bool":
    r"""
    inf_set_dll(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_dll(_v)

def inf_is_flat_off32() -> "bool":
    r"""
    inf_is_flat_off32() -> bool
    """
    return _ida_ida.inf_is_flat_off32()

def inf_set_flat_off32(_v: "bool"=True) -> "bool":
    r"""
    inf_set_flat_off32(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_flat_off32(_v)

def inf_is_be() -> "bool":
    r"""
    inf_is_be() -> bool
    """
    return _ida_ida.inf_is_be()

def inf_set_be(_v: "bool"=True) -> "bool":
    r"""
    inf_set_be(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_be(_v)

def inf_is_wide_high_byte_first() -> "bool":
    r"""
    inf_is_wide_high_byte_first() -> bool
    """
    return _ida_ida.inf_is_wide_high_byte_first()

def inf_set_wide_high_byte_first(_v: "bool"=True) -> "bool":
    r"""
    inf_set_wide_high_byte_first(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_wide_high_byte_first(_v)

def inf_dbg_no_store_path() -> "bool":
    r"""
    inf_dbg_no_store_path() -> bool
    """
    return _ida_ida.inf_dbg_no_store_path()

def inf_set_dbg_no_store_path(_v: "bool"=True) -> "bool":
    r"""
    inf_set_dbg_no_store_path(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_dbg_no_store_path(_v)

def inf_is_snapshot() -> "bool":
    r"""
    inf_is_snapshot() -> bool
    """
    return _ida_ida.inf_is_snapshot()

def inf_set_snapshot(_v: "bool"=True) -> "bool":
    r"""
    inf_set_snapshot(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_snapshot(_v)

def inf_pack_idb() -> "bool":
    r"""
    inf_pack_idb() -> bool
    """
    return _ida_ida.inf_pack_idb()

def inf_set_pack_idb(_v: "bool"=True) -> "bool":
    r"""
    inf_set_pack_idb(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_pack_idb(_v)

def inf_compress_idb() -> "bool":
    r"""
    inf_compress_idb() -> bool
    """
    return _ida_ida.inf_compress_idb()

def inf_set_compress_idb(_v: "bool"=True) -> "bool":
    r"""
    inf_set_compress_idb(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_compress_idb(_v)

def inf_is_kernel_mode() -> "bool":
    r"""
    inf_is_kernel_mode() -> bool
    """
    return _ida_ida.inf_is_kernel_mode()

def inf_set_kernel_mode(_v: "bool"=True) -> "bool":
    r"""
    inf_set_kernel_mode(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_kernel_mode(_v)

def inf_get_app_bitness() -> "uint":
    r"""
    inf_get_app_bitness() -> uint
    """
    return _ida_ida.inf_get_app_bitness()

def inf_set_app_bitness(bitness: "uint") -> "void":
    r"""
    inf_set_app_bitness(bitness)

    @param bitness: uint
    """
    return _ida_ida.inf_set_app_bitness(bitness)

def inf_get_database_change_count() -> "uint32":
    r"""
    inf_get_database_change_count() -> uint32
    """
    return _ida_ida.inf_get_database_change_count()

def inf_set_database_change_count(_v: "uint32") -> "bool":
    r"""
    inf_set_database_change_count(_v) -> bool

    @param _v: uint32
    """
    return _ida_ida.inf_set_database_change_count(_v)

def inf_get_filetype() -> "filetype_t":
    r"""
    inf_get_filetype() -> filetype_t
    """
    return _ida_ida.inf_get_filetype()

def inf_set_filetype(_v: "filetype_t") -> "bool":
    r"""
    inf_set_filetype(_v) -> bool

    @param _v: enum filetype_t
    """
    return _ida_ida.inf_set_filetype(_v)

def inf_get_ostype() -> "ushort":
    r"""
    inf_get_ostype() -> ushort
    """
    return _ida_ida.inf_get_ostype()

def inf_set_ostype(_v: "ushort") -> "bool":
    r"""
    inf_set_ostype(_v) -> bool

    @param _v: ushort
    """
    return _ida_ida.inf_set_ostype(_v)

def inf_get_apptype() -> "ushort":
    r"""
    inf_get_apptype() -> ushort
    """
    return _ida_ida.inf_get_apptype()

def inf_set_apptype(_v: "ushort") -> "bool":
    r"""
    inf_set_apptype(_v) -> bool

    @param _v: ushort
    """
    return _ida_ida.inf_set_apptype(_v)

def inf_get_asmtype() -> "uchar":
    r"""
    inf_get_asmtype() -> uchar
    """
    return _ida_ida.inf_get_asmtype()

def inf_set_asmtype(_v: "uchar") -> "bool":
    r"""
    inf_set_asmtype(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_asmtype(_v)

def inf_get_specsegs() -> "uchar":
    r"""
    inf_get_specsegs() -> uchar
    """
    return _ida_ida.inf_get_specsegs()

def inf_set_specsegs(_v: "uchar") -> "bool":
    r"""
    inf_set_specsegs(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_specsegs(_v)

def inf_get_af() -> "uint32":
    r"""
    inf_get_af() -> uint32
    """
    return _ida_ida.inf_get_af()

def inf_set_af(_v: "uint32") -> "bool":
    r"""
    inf_set_af(_v) -> bool

    @param _v: uint32
    """
    return _ida_ida.inf_set_af(_v)

def inf_trace_flow() -> "bool":
    r"""
    inf_trace_flow() -> bool
    """
    return _ida_ida.inf_trace_flow()

def inf_set_trace_flow(_v: "bool"=True) -> "bool":
    r"""
    inf_set_trace_flow(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_trace_flow(_v)

def inf_mark_code() -> "bool":
    r"""
    inf_mark_code() -> bool
    """
    return _ida_ida.inf_mark_code()

def inf_set_mark_code(_v: "bool"=True) -> "bool":
    r"""
    inf_set_mark_code(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_mark_code(_v)

def inf_create_jump_tables() -> "bool":
    r"""
    inf_create_jump_tables() -> bool
    """
    return _ida_ida.inf_create_jump_tables()

def inf_set_create_jump_tables(_v: "bool"=True) -> "bool":
    r"""
    inf_set_create_jump_tables(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_create_jump_tables(_v)

def inf_noflow_to_data() -> "bool":
    r"""
    inf_noflow_to_data() -> bool
    """
    return _ida_ida.inf_noflow_to_data()

def inf_set_noflow_to_data(_v: "bool"=True) -> "bool":
    r"""
    inf_set_noflow_to_data(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_noflow_to_data(_v)

def inf_create_all_xrefs() -> "bool":
    r"""
    inf_create_all_xrefs() -> bool
    """
    return _ida_ida.inf_create_all_xrefs()

def inf_set_create_all_xrefs(_v: "bool"=True) -> "bool":
    r"""
    inf_set_create_all_xrefs(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_create_all_xrefs(_v)

def inf_del_no_xref_insns() -> "bool":
    r"""
    inf_del_no_xref_insns() -> bool
    """
    return _ida_ida.inf_del_no_xref_insns()

def inf_set_del_no_xref_insns(_v: "bool"=True) -> "bool":
    r"""
    inf_set_del_no_xref_insns(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_del_no_xref_insns(_v)

def inf_create_func_from_ptr() -> "bool":
    r"""
    inf_create_func_from_ptr() -> bool
    """
    return _ida_ida.inf_create_func_from_ptr()

def inf_set_create_func_from_ptr(_v: "bool"=True) -> "bool":
    r"""
    inf_set_create_func_from_ptr(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_create_func_from_ptr(_v)

def inf_create_func_from_call() -> "bool":
    r"""
    inf_create_func_from_call() -> bool
    """
    return _ida_ida.inf_create_func_from_call()

def inf_set_create_func_from_call(_v: "bool"=True) -> "bool":
    r"""
    inf_set_create_func_from_call(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_create_func_from_call(_v)

def inf_create_func_tails() -> "bool":
    r"""
    inf_create_func_tails() -> bool
    """
    return _ida_ida.inf_create_func_tails()

def inf_set_create_func_tails(_v: "bool"=True) -> "bool":
    r"""
    inf_set_create_func_tails(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_create_func_tails(_v)

def inf_should_create_stkvars() -> "bool":
    r"""
    inf_should_create_stkvars() -> bool
    """
    return _ida_ida.inf_should_create_stkvars()

def inf_set_should_create_stkvars(_v: "bool"=True) -> "bool":
    r"""
    inf_set_should_create_stkvars(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_should_create_stkvars(_v)

def inf_propagate_stkargs() -> "bool":
    r"""
    inf_propagate_stkargs() -> bool
    """
    return _ida_ida.inf_propagate_stkargs()

def inf_set_propagate_stkargs(_v: "bool"=True) -> "bool":
    r"""
    inf_set_propagate_stkargs(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_propagate_stkargs(_v)

def inf_propagate_regargs() -> "bool":
    r"""
    inf_propagate_regargs() -> bool
    """
    return _ida_ida.inf_propagate_regargs()

def inf_set_propagate_regargs(_v: "bool"=True) -> "bool":
    r"""
    inf_set_propagate_regargs(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_propagate_regargs(_v)

def inf_should_trace_sp() -> "bool":
    r"""
    inf_should_trace_sp() -> bool
    """
    return _ida_ida.inf_should_trace_sp()

def inf_set_should_trace_sp(_v: "bool"=True) -> "bool":
    r"""
    inf_set_should_trace_sp(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_should_trace_sp(_v)

def inf_full_sp_ana() -> "bool":
    r"""
    inf_full_sp_ana() -> bool
    """
    return _ida_ida.inf_full_sp_ana()

def inf_set_full_sp_ana(_v: "bool"=True) -> "bool":
    r"""
    inf_set_full_sp_ana(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_full_sp_ana(_v)

def inf_noret_ana() -> "bool":
    r"""
    inf_noret_ana() -> bool
    """
    return _ida_ida.inf_noret_ana()

def inf_set_noret_ana(_v: "bool"=True) -> "bool":
    r"""
    inf_set_noret_ana(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_noret_ana(_v)

def inf_guess_func_type() -> "bool":
    r"""
    inf_guess_func_type() -> bool
    """
    return _ida_ida.inf_guess_func_type()

def inf_set_guess_func_type(_v: "bool"=True) -> "bool":
    r"""
    inf_set_guess_func_type(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_guess_func_type(_v)

def inf_truncate_on_del() -> "bool":
    r"""
    inf_truncate_on_del() -> bool
    """
    return _ida_ida.inf_truncate_on_del()

def inf_set_truncate_on_del(_v: "bool"=True) -> "bool":
    r"""
    inf_set_truncate_on_del(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_truncate_on_del(_v)

def inf_create_strlit_on_xref() -> "bool":
    r"""
    inf_create_strlit_on_xref() -> bool
    """
    return _ida_ida.inf_create_strlit_on_xref()

def inf_set_create_strlit_on_xref(_v: "bool"=True) -> "bool":
    r"""
    inf_set_create_strlit_on_xref(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_create_strlit_on_xref(_v)

def inf_check_unicode_strlits() -> "bool":
    r"""
    inf_check_unicode_strlits() -> bool
    """
    return _ida_ida.inf_check_unicode_strlits()

def inf_set_check_unicode_strlits(_v: "bool"=True) -> "bool":
    r"""
    inf_set_check_unicode_strlits(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_check_unicode_strlits(_v)

def inf_create_off_using_fixup() -> "bool":
    r"""
    inf_create_off_using_fixup() -> bool
    """
    return _ida_ida.inf_create_off_using_fixup()

def inf_set_create_off_using_fixup(_v: "bool"=True) -> "bool":
    r"""
    inf_set_create_off_using_fixup(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_create_off_using_fixup(_v)

def inf_create_off_on_dref() -> "bool":
    r"""
    inf_create_off_on_dref() -> bool
    """
    return _ida_ida.inf_create_off_on_dref()

def inf_set_create_off_on_dref(_v: "bool"=True) -> "bool":
    r"""
    inf_set_create_off_on_dref(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_create_off_on_dref(_v)

def inf_op_offset() -> "bool":
    r"""
    inf_op_offset() -> bool
    """
    return _ida_ida.inf_op_offset()

def inf_set_op_offset(_v: "bool"=True) -> "bool":
    r"""
    inf_set_op_offset(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_op_offset(_v)

def inf_data_offset() -> "bool":
    r"""
    inf_data_offset() -> bool
    """
    return _ida_ida.inf_data_offset()

def inf_set_data_offset(_v: "bool"=True) -> "bool":
    r"""
    inf_set_data_offset(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_data_offset(_v)

def inf_use_flirt() -> "bool":
    r"""
    inf_use_flirt() -> bool
    """
    return _ida_ida.inf_use_flirt()

def inf_set_use_flirt(_v: "bool"=True) -> "bool":
    r"""
    inf_set_use_flirt(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_use_flirt(_v)

def inf_append_sigcmt() -> "bool":
    r"""
    inf_append_sigcmt() -> bool
    """
    return _ida_ida.inf_append_sigcmt()

def inf_set_append_sigcmt(_v: "bool"=True) -> "bool":
    r"""
    inf_set_append_sigcmt(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_append_sigcmt(_v)

def inf_allow_sigmulti() -> "bool":
    r"""
    inf_allow_sigmulti() -> bool
    """
    return _ida_ida.inf_allow_sigmulti()

def inf_set_allow_sigmulti(_v: "bool"=True) -> "bool":
    r"""
    inf_set_allow_sigmulti(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_allow_sigmulti(_v)

def inf_hide_libfuncs() -> "bool":
    r"""
    inf_hide_libfuncs() -> bool
    """
    return _ida_ida.inf_hide_libfuncs()

def inf_set_hide_libfuncs(_v: "bool"=True) -> "bool":
    r"""
    inf_set_hide_libfuncs(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_hide_libfuncs(_v)

def inf_rename_jumpfunc() -> "bool":
    r"""
    inf_rename_jumpfunc() -> bool
    """
    return _ida_ida.inf_rename_jumpfunc()

def inf_set_rename_jumpfunc(_v: "bool"=True) -> "bool":
    r"""
    inf_set_rename_jumpfunc(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_rename_jumpfunc(_v)

def inf_rename_nullsub() -> "bool":
    r"""
    inf_rename_nullsub() -> bool
    """
    return _ida_ida.inf_rename_nullsub()

def inf_set_rename_nullsub(_v: "bool"=True) -> "bool":
    r"""
    inf_set_rename_nullsub(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_rename_nullsub(_v)

def inf_coagulate_data() -> "bool":
    r"""
    inf_coagulate_data() -> bool
    """
    return _ida_ida.inf_coagulate_data()

def inf_set_coagulate_data(_v: "bool"=True) -> "bool":
    r"""
    inf_set_coagulate_data(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_coagulate_data(_v)

def inf_coagulate_code() -> "bool":
    r"""
    inf_coagulate_code() -> bool
    """
    return _ida_ida.inf_coagulate_code()

def inf_set_coagulate_code(_v: "bool"=True) -> "bool":
    r"""
    inf_set_coagulate_code(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_coagulate_code(_v)

def inf_final_pass() -> "bool":
    r"""
    inf_final_pass() -> bool
    """
    return _ida_ida.inf_final_pass()

def inf_set_final_pass(_v: "bool"=True) -> "bool":
    r"""
    inf_set_final_pass(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_final_pass(_v)

def inf_get_af2() -> "uint32":
    r"""
    inf_get_af2() -> uint32
    """
    return _ida_ida.inf_get_af2()

def inf_set_af2(_v: "uint32") -> "bool":
    r"""
    inf_set_af2(_v) -> bool

    @param _v: uint32
    """
    return _ida_ida.inf_set_af2(_v)

def inf_handle_eh() -> "bool":
    r"""
    inf_handle_eh() -> bool
    """
    return _ida_ida.inf_handle_eh()

def inf_set_handle_eh(_v: "bool"=True) -> "bool":
    r"""
    inf_set_handle_eh(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_handle_eh(_v)

def inf_handle_rtti() -> "bool":
    r"""
    inf_handle_rtti() -> bool
    """
    return _ida_ida.inf_handle_rtti()

def inf_set_handle_rtti(_v: "bool"=True) -> "bool":
    r"""
    inf_set_handle_rtti(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_handle_rtti(_v)

def inf_macros_enabled() -> "bool":
    r"""
    inf_macros_enabled() -> bool
    """
    return _ida_ida.inf_macros_enabled()

def inf_set_macros_enabled(_v: "bool"=True) -> "bool":
    r"""
    inf_set_macros_enabled(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_macros_enabled(_v)

def inf_merge_strlits() -> "bool":
    r"""
    inf_merge_strlits() -> bool
    """
    return _ida_ida.inf_merge_strlits()

def inf_set_merge_strlits(_v: "bool"=True) -> "bool":
    r"""
    inf_set_merge_strlits(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_merge_strlits(_v)

def inf_get_baseaddr() -> "uval_t":
    r"""
    inf_get_baseaddr() -> uval_t
    """
    return _ida_ida.inf_get_baseaddr()

def inf_set_baseaddr(_v: "uval_t") -> "bool":
    r"""
    inf_set_baseaddr(_v) -> bool

    @param _v: uval_t
    """
    return _ida_ida.inf_set_baseaddr(_v)

def inf_get_start_ss() -> "sel_t":
    r"""
    inf_get_start_ss() -> sel_t
    """
    return _ida_ida.inf_get_start_ss()

def inf_set_start_ss(_v: "sel_t") -> "bool":
    r"""
    inf_set_start_ss(_v) -> bool

    @param _v: sel_t
    """
    return _ida_ida.inf_set_start_ss(_v)

def inf_get_start_cs() -> "sel_t":
    r"""
    inf_get_start_cs() -> sel_t
    """
    return _ida_ida.inf_get_start_cs()

def inf_set_start_cs(_v: "sel_t") -> "bool":
    r"""
    inf_set_start_cs(_v) -> bool

    @param _v: sel_t
    """
    return _ida_ida.inf_set_start_cs(_v)

def inf_get_start_ip() -> "ea_t":
    r"""
    inf_get_start_ip() -> ea_t
    """
    return _ida_ida.inf_get_start_ip()

def inf_set_start_ip(_v: "ea_t") -> "bool":
    r"""
    inf_set_start_ip(_v) -> bool

    @param _v: ea_t
    """
    return _ida_ida.inf_set_start_ip(_v)

def inf_get_start_ea() -> "ea_t":
    r"""
    inf_get_start_ea() -> ea_t
    """
    return _ida_ida.inf_get_start_ea()

def inf_set_start_ea(_v: "ea_t") -> "bool":
    r"""
    inf_set_start_ea(_v) -> bool

    @param _v: ea_t
    """
    return _ida_ida.inf_set_start_ea(_v)

def inf_get_start_sp() -> "ea_t":
    r"""
    inf_get_start_sp() -> ea_t
    """
    return _ida_ida.inf_get_start_sp()

def inf_set_start_sp(_v: "ea_t") -> "bool":
    r"""
    inf_set_start_sp(_v) -> bool

    @param _v: ea_t
    """
    return _ida_ida.inf_set_start_sp(_v)

def inf_get_main() -> "ea_t":
    r"""
    inf_get_main() -> ea_t
    """
    return _ida_ida.inf_get_main()

def inf_set_main(_v: "ea_t") -> "bool":
    r"""
    inf_set_main(_v) -> bool

    @param _v: ea_t
    """
    return _ida_ida.inf_set_main(_v)

def inf_get_min_ea() -> "ea_t":
    r"""
    inf_get_min_ea() -> ea_t
    """
    return _ida_ida.inf_get_min_ea()

def inf_set_min_ea(_v: "ea_t") -> "bool":
    r"""
    inf_set_min_ea(_v) -> bool

    @param _v: ea_t
    """
    return _ida_ida.inf_set_min_ea(_v)

def inf_get_max_ea() -> "ea_t":
    r"""
    inf_get_max_ea() -> ea_t
    """
    return _ida_ida.inf_get_max_ea()

def inf_set_max_ea(_v: "ea_t") -> "bool":
    r"""
    inf_set_max_ea(_v) -> bool

    @param _v: ea_t
    """
    return _ida_ida.inf_set_max_ea(_v)

def inf_get_omin_ea() -> "ea_t":
    r"""
    inf_get_omin_ea() -> ea_t
    """
    return _ida_ida.inf_get_omin_ea()

def inf_set_omin_ea(_v: "ea_t") -> "bool":
    r"""
    inf_set_omin_ea(_v) -> bool

    @param _v: ea_t
    """
    return _ida_ida.inf_set_omin_ea(_v)

def inf_get_omax_ea() -> "ea_t":
    r"""
    inf_get_omax_ea() -> ea_t
    """
    return _ida_ida.inf_get_omax_ea()

def inf_set_omax_ea(_v: "ea_t") -> "bool":
    r"""
    inf_set_omax_ea(_v) -> bool

    @param _v: ea_t
    """
    return _ida_ida.inf_set_omax_ea(_v)

def inf_get_lowoff() -> "ea_t":
    r"""
    inf_get_lowoff() -> ea_t
    """
    return _ida_ida.inf_get_lowoff()

def inf_set_lowoff(_v: "ea_t") -> "bool":
    r"""
    inf_set_lowoff(_v) -> bool

    @param _v: ea_t
    """
    return _ida_ida.inf_set_lowoff(_v)

def inf_get_highoff() -> "ea_t":
    r"""
    inf_get_highoff() -> ea_t
    """
    return _ida_ida.inf_get_highoff()

def inf_set_highoff(_v: "ea_t") -> "bool":
    r"""
    inf_set_highoff(_v) -> bool

    @param _v: ea_t
    """
    return _ida_ida.inf_set_highoff(_v)

def inf_get_maxref() -> "uval_t":
    r"""
    inf_get_maxref() -> uval_t
    """
    return _ida_ida.inf_get_maxref()

def inf_set_maxref(_v: "uval_t") -> "bool":
    r"""
    inf_set_maxref(_v) -> bool

    @param _v: uval_t
    """
    return _ida_ida.inf_set_maxref(_v)

def inf_get_netdelta() -> "sval_t":
    r"""
    inf_get_netdelta() -> sval_t
    """
    return _ida_ida.inf_get_netdelta()

def inf_set_netdelta(_v: "sval_t") -> "bool":
    r"""
    inf_set_netdelta(_v) -> bool

    @param _v: sval_t
    """
    return _ida_ida.inf_set_netdelta(_v)

def inf_get_xrefnum() -> "uchar":
    r"""
    inf_get_xrefnum() -> uchar
    """
    return _ida_ida.inf_get_xrefnum()

def inf_set_xrefnum(_v: "uchar") -> "bool":
    r"""
    inf_set_xrefnum(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_xrefnum(_v)

def inf_get_type_xrefnum() -> "uchar":
    r"""
    inf_get_type_xrefnum() -> uchar
    """
    return _ida_ida.inf_get_type_xrefnum()

def inf_set_type_xrefnum(_v: "uchar") -> "bool":
    r"""
    inf_set_type_xrefnum(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_type_xrefnum(_v)

def inf_get_refcmtnum() -> "uchar":
    r"""
    inf_get_refcmtnum() -> uchar
    """
    return _ida_ida.inf_get_refcmtnum()

def inf_set_refcmtnum(_v: "uchar") -> "bool":
    r"""
    inf_set_refcmtnum(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_refcmtnum(_v)

def inf_get_xrefflag() -> "uchar":
    r"""
    inf_get_xrefflag() -> uchar
    """
    return _ida_ida.inf_get_xrefflag()

def inf_set_xrefflag(_v: "uchar") -> "bool":
    r"""
    inf_set_xrefflag(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_xrefflag(_v)

def inf_show_xref_seg() -> "bool":
    r"""
    inf_show_xref_seg() -> bool
    """
    return _ida_ida.inf_show_xref_seg()

def inf_set_show_xref_seg(_v: "bool"=True) -> "bool":
    r"""
    inf_set_show_xref_seg(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_show_xref_seg(_v)

def inf_show_xref_tmarks() -> "bool":
    r"""
    inf_show_xref_tmarks() -> bool
    """
    return _ida_ida.inf_show_xref_tmarks()

def inf_set_show_xref_tmarks(_v: "bool"=True) -> "bool":
    r"""
    inf_set_show_xref_tmarks(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_show_xref_tmarks(_v)

def inf_show_xref_fncoff() -> "bool":
    r"""
    inf_show_xref_fncoff() -> bool
    """
    return _ida_ida.inf_show_xref_fncoff()

def inf_set_show_xref_fncoff(_v: "bool"=True) -> "bool":
    r"""
    inf_set_show_xref_fncoff(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_show_xref_fncoff(_v)

def inf_show_xref_val() -> "bool":
    r"""
    inf_show_xref_val() -> bool
    """
    return _ida_ida.inf_show_xref_val()

def inf_set_show_xref_val(_v: "bool"=True) -> "bool":
    r"""
    inf_set_show_xref_val(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_show_xref_val(_v)

def inf_get_max_autoname_len() -> "ushort":
    r"""
    inf_get_max_autoname_len() -> ushort
    """
    return _ida_ida.inf_get_max_autoname_len()

def inf_set_max_autoname_len(_v: "ushort") -> "bool":
    r"""
    inf_set_max_autoname_len(_v) -> bool

    @param _v: ushort
    """
    return _ida_ida.inf_set_max_autoname_len(_v)

def inf_get_nametype() -> "char":
    r"""
    inf_get_nametype() -> char
    """
    return _ida_ida.inf_get_nametype()

def inf_set_nametype(_v: "char") -> "bool":
    r"""
    inf_set_nametype(_v) -> bool

    @param _v: char
    """
    return _ida_ida.inf_set_nametype(_v)

def inf_get_short_demnames() -> "uint32":
    r"""
    inf_get_short_demnames() -> uint32
    """
    return _ida_ida.inf_get_short_demnames()

def inf_set_short_demnames(_v: "uint32") -> "bool":
    r"""
    inf_set_short_demnames(_v) -> bool

    @param _v: uint32
    """
    return _ida_ida.inf_set_short_demnames(_v)

def inf_get_long_demnames() -> "uint32":
    r"""
    inf_get_long_demnames() -> uint32
    """
    return _ida_ida.inf_get_long_demnames()

def inf_set_long_demnames(_v: "uint32") -> "bool":
    r"""
    inf_set_long_demnames(_v) -> bool

    @param _v: uint32
    """
    return _ida_ida.inf_set_long_demnames(_v)

def inf_get_demnames() -> "uchar":
    r"""
    inf_get_demnames() -> uchar
    """
    return _ida_ida.inf_get_demnames()

def inf_set_demnames(_v: "uchar") -> "bool":
    r"""
    inf_set_demnames(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_demnames(_v)

def inf_get_listnames() -> "uchar":
    r"""
    inf_get_listnames() -> uchar
    """
    return _ida_ida.inf_get_listnames()

def inf_set_listnames(_v: "uchar") -> "bool":
    r"""
    inf_set_listnames(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_listnames(_v)

def inf_get_indent() -> "uchar":
    r"""
    inf_get_indent() -> uchar
    """
    return _ida_ida.inf_get_indent()

def inf_set_indent(_v: "uchar") -> "bool":
    r"""
    inf_set_indent(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_indent(_v)

def inf_get_cmt_indent() -> "uchar":
    r"""
    inf_get_cmt_indent() -> uchar
    """
    return _ida_ida.inf_get_cmt_indent()

def inf_set_cmt_indent(_v: "uchar") -> "bool":
    r"""
    inf_set_cmt_indent(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_cmt_indent(_v)

def inf_get_margin() -> "ushort":
    r"""
    inf_get_margin() -> ushort
    """
    return _ida_ida.inf_get_margin()

def inf_set_margin(_v: "ushort") -> "bool":
    r"""
    inf_set_margin(_v) -> bool

    @param _v: ushort
    """
    return _ida_ida.inf_set_margin(_v)

def inf_get_lenxref() -> "ushort":
    r"""
    inf_get_lenxref() -> ushort
    """
    return _ida_ida.inf_get_lenxref()

def inf_set_lenxref(_v: "ushort") -> "bool":
    r"""
    inf_set_lenxref(_v) -> bool

    @param _v: ushort
    """
    return _ida_ida.inf_set_lenxref(_v)

def inf_get_outflags() -> "uint32":
    r"""
    inf_get_outflags() -> uint32
    """
    return _ida_ida.inf_get_outflags()

def inf_set_outflags(_v: "uint32") -> "bool":
    r"""
    inf_set_outflags(_v) -> bool

    @param _v: uint32
    """
    return _ida_ida.inf_set_outflags(_v)

def inf_show_void() -> "bool":
    r"""
    inf_show_void() -> bool
    """
    return _ida_ida.inf_show_void()

def inf_set_show_void(_v: "bool"=True) -> "bool":
    r"""
    inf_set_show_void(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_show_void(_v)

def inf_show_auto() -> "bool":
    r"""
    inf_show_auto() -> bool
    """
    return _ida_ida.inf_show_auto()

def inf_set_show_auto(_v: "bool"=True) -> "bool":
    r"""
    inf_set_show_auto(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_show_auto(_v)

def inf_gen_null() -> "bool":
    r"""
    inf_gen_null() -> bool
    """
    return _ida_ida.inf_gen_null()

def inf_set_gen_null(_v: "bool"=True) -> "bool":
    r"""
    inf_set_gen_null(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_gen_null(_v)

def inf_show_line_pref() -> "bool":
    r"""
    inf_show_line_pref() -> bool
    """
    return _ida_ida.inf_show_line_pref()

def inf_set_show_line_pref(_v: "bool"=True) -> "bool":
    r"""
    inf_set_show_line_pref(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_show_line_pref(_v)

def inf_line_pref_with_seg() -> "bool":
    r"""
    inf_line_pref_with_seg() -> bool
    """
    return _ida_ida.inf_line_pref_with_seg()

def inf_set_line_pref_with_seg(_v: "bool"=True) -> "bool":
    r"""
    inf_set_line_pref_with_seg(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_line_pref_with_seg(_v)

def inf_gen_lzero() -> "bool":
    r"""
    inf_gen_lzero() -> bool
    """
    return _ida_ida.inf_gen_lzero()

def inf_set_gen_lzero(_v: "bool"=True) -> "bool":
    r"""
    inf_set_gen_lzero(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_gen_lzero(_v)

def inf_gen_org() -> "bool":
    r"""
    inf_gen_org() -> bool
    """
    return _ida_ida.inf_gen_org()

def inf_set_gen_org(_v: "bool"=True) -> "bool":
    r"""
    inf_set_gen_org(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_gen_org(_v)

def inf_gen_assume() -> "bool":
    r"""
    inf_gen_assume() -> bool
    """
    return _ida_ida.inf_gen_assume()

def inf_set_gen_assume(_v: "bool"=True) -> "bool":
    r"""
    inf_set_gen_assume(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_gen_assume(_v)

def inf_gen_tryblks() -> "bool":
    r"""
    inf_gen_tryblks() -> bool
    """
    return _ida_ida.inf_gen_tryblks()

def inf_set_gen_tryblks(_v: "bool"=True) -> "bool":
    r"""
    inf_set_gen_tryblks(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_gen_tryblks(_v)

def inf_get_cmtflg() -> "uchar":
    r"""
    inf_get_cmtflg() -> uchar
    """
    return _ida_ida.inf_get_cmtflg()

def inf_set_cmtflg(_v: "uchar") -> "bool":
    r"""
    inf_set_cmtflg(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_cmtflg(_v)

def inf_show_repeatables() -> "bool":
    r"""
    inf_show_repeatables() -> bool
    """
    return _ida_ida.inf_show_repeatables()

def inf_set_show_repeatables(_v: "bool"=True) -> "bool":
    r"""
    inf_set_show_repeatables(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_show_repeatables(_v)

def inf_show_all_comments() -> "bool":
    r"""
    inf_show_all_comments() -> bool
    """
    return _ida_ida.inf_show_all_comments()

def inf_set_show_all_comments(_v: "bool"=True) -> "bool":
    r"""
    inf_set_show_all_comments(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_show_all_comments(_v)

def inf_hide_comments() -> "bool":
    r"""
    inf_hide_comments() -> bool
    """
    return _ida_ida.inf_hide_comments()

def inf_set_hide_comments(_v: "bool"=True) -> "bool":
    r"""
    inf_set_hide_comments(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_hide_comments(_v)

def inf_show_src_linnum() -> "bool":
    r"""
    inf_show_src_linnum() -> bool
    """
    return _ida_ida.inf_show_src_linnum()

def inf_set_show_src_linnum(_v: "bool"=True) -> "bool":
    r"""
    inf_set_show_src_linnum(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_show_src_linnum(_v)

def inf_test_mode() -> "bool":
    r"""
    inf_test_mode() -> bool
    """
    return _ida_ida.inf_test_mode()

def inf_show_hidden_insns() -> "bool":
    r"""
    inf_show_hidden_insns() -> bool
    """
    return _ida_ida.inf_show_hidden_insns()

def inf_set_show_hidden_insns(_v: "bool"=True) -> "bool":
    r"""
    inf_set_show_hidden_insns(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_show_hidden_insns(_v)

def inf_show_hidden_funcs() -> "bool":
    r"""
    inf_show_hidden_funcs() -> bool
    """
    return _ida_ida.inf_show_hidden_funcs()

def inf_set_show_hidden_funcs(_v: "bool"=True) -> "bool":
    r"""
    inf_set_show_hidden_funcs(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_show_hidden_funcs(_v)

def inf_show_hidden_segms() -> "bool":
    r"""
    inf_show_hidden_segms() -> bool
    """
    return _ida_ida.inf_show_hidden_segms()

def inf_set_show_hidden_segms(_v: "bool"=True) -> "bool":
    r"""
    inf_set_show_hidden_segms(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_show_hidden_segms(_v)

def inf_get_limiter() -> "uchar":
    r"""
    inf_get_limiter() -> uchar
    """
    return _ida_ida.inf_get_limiter()

def inf_set_limiter(_v: "uchar") -> "bool":
    r"""
    inf_set_limiter(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_limiter(_v)

def inf_is_limiter_thin() -> "bool":
    r"""
    inf_is_limiter_thin() -> bool
    """
    return _ida_ida.inf_is_limiter_thin()

def inf_set_limiter_thin(_v: "bool"=True) -> "bool":
    r"""
    inf_set_limiter_thin(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_limiter_thin(_v)

def inf_is_limiter_thick() -> "bool":
    r"""
    inf_is_limiter_thick() -> bool
    """
    return _ida_ida.inf_is_limiter_thick()

def inf_set_limiter_thick(_v: "bool"=True) -> "bool":
    r"""
    inf_set_limiter_thick(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_limiter_thick(_v)

def inf_is_limiter_empty() -> "bool":
    r"""
    inf_is_limiter_empty() -> bool
    """
    return _ida_ida.inf_is_limiter_empty()

def inf_set_limiter_empty(_v: "bool"=True) -> "bool":
    r"""
    inf_set_limiter_empty(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_limiter_empty(_v)

def inf_get_bin_prefix_size() -> "short":
    r"""
    inf_get_bin_prefix_size() -> short
    """
    return _ida_ida.inf_get_bin_prefix_size()

def inf_set_bin_prefix_size(_v: "short") -> "bool":
    r"""
    inf_set_bin_prefix_size(_v) -> bool

    @param _v: short
    """
    return _ida_ida.inf_set_bin_prefix_size(_v)

def inf_get_prefflag() -> "uchar":
    r"""
    inf_get_prefflag() -> uchar
    """
    return _ida_ida.inf_get_prefflag()

def inf_set_prefflag(_v: "uchar") -> "bool":
    r"""
    inf_set_prefflag(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_prefflag(_v)

def inf_prefix_show_segaddr() -> "bool":
    r"""
    inf_prefix_show_segaddr() -> bool
    """
    return _ida_ida.inf_prefix_show_segaddr()

def inf_set_prefix_show_segaddr(_v: "bool"=True) -> "bool":
    r"""
    inf_set_prefix_show_segaddr(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_prefix_show_segaddr(_v)

def inf_prefix_show_funcoff() -> "bool":
    r"""
    inf_prefix_show_funcoff() -> bool
    """
    return _ida_ida.inf_prefix_show_funcoff()

def inf_set_prefix_show_funcoff(_v: "bool"=True) -> "bool":
    r"""
    inf_set_prefix_show_funcoff(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_prefix_show_funcoff(_v)

def inf_prefix_show_stack() -> "bool":
    r"""
    inf_prefix_show_stack() -> bool
    """
    return _ida_ida.inf_prefix_show_stack()

def inf_set_prefix_show_stack(_v: "bool"=True) -> "bool":
    r"""
    inf_set_prefix_show_stack(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_prefix_show_stack(_v)

def inf_prefix_truncate_opcode_bytes() -> "bool":
    r"""
    inf_prefix_truncate_opcode_bytes() -> bool
    """
    return _ida_ida.inf_prefix_truncate_opcode_bytes()

def inf_set_prefix_truncate_opcode_bytes(_v: "bool"=True) -> "bool":
    r"""
    inf_set_prefix_truncate_opcode_bytes(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_prefix_truncate_opcode_bytes(_v)

def inf_get_strlit_flags() -> "uchar":
    r"""
    inf_get_strlit_flags() -> uchar
    """
    return _ida_ida.inf_get_strlit_flags()

def inf_set_strlit_flags(_v: "uchar") -> "bool":
    r"""
    inf_set_strlit_flags(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_strlit_flags(_v)

def inf_strlit_names() -> "bool":
    r"""
    inf_strlit_names() -> bool
    """
    return _ida_ida.inf_strlit_names()

def inf_set_strlit_names(_v: "bool"=True) -> "bool":
    r"""
    inf_set_strlit_names(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_strlit_names(_v)

def inf_strlit_name_bit() -> "bool":
    r"""
    inf_strlit_name_bit() -> bool
    """
    return _ida_ida.inf_strlit_name_bit()

def inf_set_strlit_name_bit(_v: "bool"=True) -> "bool":
    r"""
    inf_set_strlit_name_bit(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_strlit_name_bit(_v)

def inf_strlit_serial_names() -> "bool":
    r"""
    inf_strlit_serial_names() -> bool
    """
    return _ida_ida.inf_strlit_serial_names()

def inf_set_strlit_serial_names(_v: "bool"=True) -> "bool":
    r"""
    inf_set_strlit_serial_names(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_strlit_serial_names(_v)

def inf_unicode_strlits() -> "bool":
    r"""
    inf_unicode_strlits() -> bool
    """
    return _ida_ida.inf_unicode_strlits()

def inf_set_unicode_strlits(_v: "bool"=True) -> "bool":
    r"""
    inf_set_unicode_strlits(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_unicode_strlits(_v)

def inf_strlit_autocmt() -> "bool":
    r"""
    inf_strlit_autocmt() -> bool
    """
    return _ida_ida.inf_strlit_autocmt()

def inf_set_strlit_autocmt(_v: "bool"=True) -> "bool":
    r"""
    inf_set_strlit_autocmt(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_strlit_autocmt(_v)

def inf_strlit_savecase() -> "bool":
    r"""
    inf_strlit_savecase() -> bool
    """
    return _ida_ida.inf_strlit_savecase()

def inf_set_strlit_savecase(_v: "bool"=True) -> "bool":
    r"""
    inf_set_strlit_savecase(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_strlit_savecase(_v)

def inf_get_strlit_break() -> "uchar":
    r"""
    inf_get_strlit_break() -> uchar
    """
    return _ida_ida.inf_get_strlit_break()

def inf_set_strlit_break(_v: "uchar") -> "bool":
    r"""
    inf_set_strlit_break(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_strlit_break(_v)

def inf_get_strlit_zeroes() -> "char":
    r"""
    inf_get_strlit_zeroes() -> char
    """
    return _ida_ida.inf_get_strlit_zeroes()

def inf_set_strlit_zeroes(_v: "char") -> "bool":
    r"""
    inf_set_strlit_zeroes(_v) -> bool

    @param _v: char
    """
    return _ida_ida.inf_set_strlit_zeroes(_v)

def inf_get_strtype() -> "int32":
    r"""
    inf_get_strtype() -> int32
    """
    return _ida_ida.inf_get_strtype()

def inf_set_strtype(_v: "int32") -> "bool":
    r"""
    inf_set_strtype(_v) -> bool

    @param _v: int32
    """
    return _ida_ida.inf_set_strtype(_v)

def inf_get_strlit_sernum() -> "uval_t":
    r"""
    inf_get_strlit_sernum() -> uval_t
    """
    return _ida_ida.inf_get_strlit_sernum()

def inf_set_strlit_sernum(_v: "uval_t") -> "bool":
    r"""
    inf_set_strlit_sernum(_v) -> bool

    @param _v: uval_t
    """
    return _ida_ida.inf_set_strlit_sernum(_v)

def inf_get_datatypes() -> "uval_t":
    r"""
    inf_get_datatypes() -> uval_t
    """
    return _ida_ida.inf_get_datatypes()

def inf_set_datatypes(_v: "uval_t") -> "bool":
    r"""
    inf_set_datatypes(_v) -> bool

    @param _v: uval_t
    """
    return _ida_ida.inf_set_datatypes(_v)

def inf_get_abibits() -> "uint32":
    r"""
    inf_get_abibits() -> uint32
    """
    return _ida_ida.inf_get_abibits()

def inf_set_abibits(_v: "uint32") -> "bool":
    r"""
    inf_set_abibits(_v) -> bool

    @param _v: uint32
    """
    return _ida_ida.inf_set_abibits(_v)

def inf_is_mem_aligned4() -> "bool":
    r"""
    inf_is_mem_aligned4() -> bool
    """
    return _ida_ida.inf_is_mem_aligned4()

def inf_set_mem_aligned4(_v: "bool"=True) -> "bool":
    r"""
    inf_set_mem_aligned4(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_mem_aligned4(_v)

def inf_pack_stkargs(*args) -> "bool":
    r"""
    inf_pack_stkargs(cc) -> bool

    @param cc: cm_t

    inf_pack_stkargs() -> bool
    """
    return _ida_ida.inf_pack_stkargs(*args)

def inf_set_pack_stkargs(_v: "bool"=True) -> "bool":
    r"""
    inf_set_pack_stkargs(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_pack_stkargs(_v)

def inf_big_arg_align(*args) -> "bool":
    r"""
    inf_big_arg_align(cc) -> bool

    @param cc: cm_t

    inf_big_arg_align() -> bool
    """
    return _ida_ida.inf_big_arg_align(*args)

def inf_set_big_arg_align(_v: "bool"=True) -> "bool":
    r"""
    inf_set_big_arg_align(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_big_arg_align(_v)

def inf_stack_ldbl() -> "bool":
    r"""
    inf_stack_ldbl() -> bool
    """
    return _ida_ida.inf_stack_ldbl()

def inf_set_stack_ldbl(_v: "bool"=True) -> "bool":
    r"""
    inf_set_stack_ldbl(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_stack_ldbl(_v)

def inf_stack_varargs() -> "bool":
    r"""
    inf_stack_varargs() -> bool
    """
    return _ida_ida.inf_stack_varargs()

def inf_set_stack_varargs(_v: "bool"=True) -> "bool":
    r"""
    inf_set_stack_varargs(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_stack_varargs(_v)

def inf_is_hard_float() -> "bool":
    r"""
    inf_is_hard_float() -> bool
    """
    return _ida_ida.inf_is_hard_float()

def inf_set_hard_float(_v: "bool"=True) -> "bool":
    r"""
    inf_set_hard_float(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_hard_float(_v)

def inf_abi_set_by_user() -> "bool":
    r"""
    inf_abi_set_by_user() -> bool
    """
    return _ida_ida.inf_abi_set_by_user()

def inf_set_abi_set_by_user(_v: "bool"=True) -> "bool":
    r"""
    inf_set_abi_set_by_user(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_abi_set_by_user(_v)

def inf_use_gcc_layout() -> "bool":
    r"""
    inf_use_gcc_layout() -> bool
    """
    return _ida_ida.inf_use_gcc_layout()

def inf_set_use_gcc_layout(_v: "bool"=True) -> "bool":
    r"""
    inf_set_use_gcc_layout(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_use_gcc_layout(_v)

def inf_map_stkargs() -> "bool":
    r"""
    inf_map_stkargs() -> bool
    """
    return _ida_ida.inf_map_stkargs()

def inf_set_map_stkargs(_v: "bool"=True) -> "bool":
    r"""
    inf_set_map_stkargs(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_map_stkargs(_v)

def inf_huge_arg_align(*args) -> "bool":
    r"""
    inf_huge_arg_align(cc) -> bool

    @param cc: cm_t

    inf_huge_arg_align() -> bool
    """
    return _ida_ida.inf_huge_arg_align(*args)

def inf_set_huge_arg_align(_v: "bool"=True) -> "bool":
    r"""
    inf_set_huge_arg_align(_v=True) -> bool

    @param _v: bool
    """
    return _ida_ida.inf_set_huge_arg_align(_v)

def inf_get_appcall_options() -> "uint32":
    r"""
    inf_get_appcall_options() -> uint32
    """
    return _ida_ida.inf_get_appcall_options()

def inf_set_appcall_options(_v: "uint32") -> "bool":
    r"""
    inf_set_appcall_options(_v) -> bool

    @param _v: uint32
    """
    return _ida_ida.inf_set_appcall_options(_v)

def inf_get_privrange_start_ea() -> "ea_t":
    r"""
    inf_get_privrange_start_ea() -> ea_t
    """
    return _ida_ida.inf_get_privrange_start_ea()

def inf_set_privrange_start_ea(_v: "ea_t") -> "bool":
    r"""
    inf_set_privrange_start_ea(_v) -> bool

    @param _v: ea_t
    """
    return _ida_ida.inf_set_privrange_start_ea(_v)

def inf_get_privrange_end_ea() -> "ea_t":
    r"""
    inf_get_privrange_end_ea() -> ea_t
    """
    return _ida_ida.inf_get_privrange_end_ea()

def inf_set_privrange_end_ea(_v: "ea_t") -> "bool":
    r"""
    inf_set_privrange_end_ea(_v) -> bool

    @param _v: ea_t
    """
    return _ida_ida.inf_set_privrange_end_ea(_v)

def inf_get_cc_id() -> "comp_t":
    r"""
    inf_get_cc_id() -> comp_t
    """
    return _ida_ida.inf_get_cc_id()

def inf_set_cc_id(_v: "comp_t") -> "bool":
    r"""
    inf_set_cc_id(_v) -> bool

    @param _v: comp_t
    """
    return _ida_ida.inf_set_cc_id(_v)

def inf_get_cc_cm() -> "cm_t":
    r"""
    inf_get_cc_cm() -> cm_t
    """
    return _ida_ida.inf_get_cc_cm()

def inf_set_cc_cm(_v: "cm_t") -> "bool":
    r"""
    inf_set_cc_cm(_v) -> bool

    @param _v: cm_t
    """
    return _ida_ida.inf_set_cc_cm(_v)

def inf_get_cc_size_i() -> "uchar":
    r"""
    inf_get_cc_size_i() -> uchar
    """
    return _ida_ida.inf_get_cc_size_i()

def inf_set_cc_size_i(_v: "uchar") -> "bool":
    r"""
    inf_set_cc_size_i(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_cc_size_i(_v)

def inf_get_cc_size_b() -> "uchar":
    r"""
    inf_get_cc_size_b() -> uchar
    """
    return _ida_ida.inf_get_cc_size_b()

def inf_set_cc_size_b(_v: "uchar") -> "bool":
    r"""
    inf_set_cc_size_b(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_cc_size_b(_v)

def inf_get_cc_size_e() -> "uchar":
    r"""
    inf_get_cc_size_e() -> uchar
    """
    return _ida_ida.inf_get_cc_size_e()

def inf_set_cc_size_e(_v: "uchar") -> "bool":
    r"""
    inf_set_cc_size_e(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_cc_size_e(_v)

def inf_get_cc_defalign() -> "uchar":
    r"""
    inf_get_cc_defalign() -> uchar
    """
    return _ida_ida.inf_get_cc_defalign()

def inf_set_cc_defalign(_v: "uchar") -> "bool":
    r"""
    inf_set_cc_defalign(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_cc_defalign(_v)

def inf_get_cc_size_s() -> "uchar":
    r"""
    inf_get_cc_size_s() -> uchar
    """
    return _ida_ida.inf_get_cc_size_s()

def inf_set_cc_size_s(_v: "uchar") -> "bool":
    r"""
    inf_set_cc_size_s(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_cc_size_s(_v)

def inf_get_cc_size_l() -> "uchar":
    r"""
    inf_get_cc_size_l() -> uchar
    """
    return _ida_ida.inf_get_cc_size_l()

def inf_set_cc_size_l(_v: "uchar") -> "bool":
    r"""
    inf_set_cc_size_l(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_cc_size_l(_v)

def inf_get_cc_size_ll() -> "uchar":
    r"""
    inf_get_cc_size_ll() -> uchar
    """
    return _ida_ida.inf_get_cc_size_ll()

def inf_set_cc_size_ll(_v: "uchar") -> "bool":
    r"""
    inf_set_cc_size_ll(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_cc_size_ll(_v)

def inf_get_cc_size_ldbl() -> "uchar":
    r"""
    inf_get_cc_size_ldbl() -> uchar
    """
    return _ida_ida.inf_get_cc_size_ldbl()

def inf_set_cc_size_ldbl(_v: "uchar") -> "bool":
    r"""
    inf_set_cc_size_ldbl(_v) -> bool

    @param _v: uchar
    """
    return _ida_ida.inf_set_cc_size_ldbl(_v)

def inf_get_procname() -> "size_t":
    r"""
    inf_get_procname() -> str
    """
    return _ida_ida.inf_get_procname()

def inf_set_procname(*args) -> "bool":
    r"""
    inf_set_procname(_v, len=size_t(-1)) -> bool

    @param _v: char const *
    @param len: size_t
    """
    return _ida_ida.inf_set_procname(*args)

def inf_get_strlit_pref() -> "size_t":
    r"""
    inf_get_strlit_pref() -> str
    """
    return _ida_ida.inf_get_strlit_pref()

def inf_set_strlit_pref(*args) -> "bool":
    r"""
    inf_set_strlit_pref(_v, len=size_t(-1)) -> bool

    @param _v: char const *
    @param len: size_t
    """
    return _ida_ida.inf_set_strlit_pref(*args)

def inf_get_cc(out: "compiler_info_t") -> "bool":
    r"""
    inf_get_cc(out) -> bool

    @param out: compiler_info_t *
    """
    return _ida_ida.inf_get_cc(out)

def inf_set_cc(_v: "compiler_info_t") -> "bool":
    r"""
    inf_set_cc(_v) -> bool

    @param _v: compiler_info_t const &
    """
    return _ida_ida.inf_set_cc(_v)

def inf_set_privrange(_v: "range_t") -> "bool":
    r"""
    inf_set_privrange(_v) -> bool

    @param _v: range_t const &
    """
    return _ida_ida.inf_set_privrange(_v)

def inf_get_privrange(*args) -> "range_t":
    r"""
    inf_get_privrange(out) -> bool

    @param out: range_t *

    inf_get_privrange() -> range_t
    """
    return _ida_ida.inf_get_privrange(*args)

def inf_get_af_low() -> "ushort":
    r"""
    inf_get_af_low() -> ushort
    Get/set low/high 16bit halves of inf.af.
    """
    return _ida_ida.inf_get_af_low()

def inf_set_af_low(saf: "ushort") -> "void":
    r"""
    inf_set_af_low(saf)

    @param saf: ushort
    """
    return _ida_ida.inf_set_af_low(saf)

def inf_get_af_high() -> "ushort":
    r"""
    inf_get_af_high() -> ushort
    """
    return _ida_ida.inf_get_af_high()

def inf_set_af_high(saf2: "ushort") -> "void":
    r"""
    inf_set_af_high(saf2)

    @param saf2: ushort
    """
    return _ida_ida.inf_set_af_high(saf2)

def inf_get_af2_low() -> "ushort":
    r"""
    inf_get_af2_low() -> ushort
    Get/set low 16bit half of inf.af2.
    """
    return _ida_ida.inf_get_af2_low()

def inf_set_af2_low(saf: "ushort") -> "void":
    r"""
    inf_set_af2_low(saf)

    @param saf: ushort
    """
    return _ida_ida.inf_set_af2_low(saf)

def inf_get_pack_mode() -> "int":
    r"""
    inf_get_pack_mode() -> int
    """
    return _ida_ida.inf_get_pack_mode()

def inf_set_pack_mode(pack_mode: "int") -> "int":
    r"""
    inf_set_pack_mode(pack_mode) -> int

    @param pack_mode: int
    """
    return _ida_ida.inf_set_pack_mode(pack_mode)

def inf_inc_database_change_count(cnt: "int"=1) -> "void":
    r"""
    inf_inc_database_change_count(cnt=1)

    @param cnt: int
    """
    return _ida_ida.inf_inc_database_change_count(cnt)

def inf_get_demname_form() -> "uchar":
    r"""
    inf_get_demname_form() -> uchar
    Get DEMNAM_MASK bits of #demnames.
    """
    return _ida_ida.inf_get_demname_form()

def inf_postinc_strlit_sernum(cnt: "uval_t"=1) -> "uval_t":
    r"""
    inf_postinc_strlit_sernum(cnt=1) -> uval_t

    @param cnt: uval_t
    """
    return _ida_ida.inf_postinc_strlit_sernum(cnt)

def inf_like_binary() -> "bool":
    r"""
    inf_like_binary() -> bool
    """
    return _ida_ida.inf_like_binary()
UA_MAXOP = _ida_ida.UA_MAXOP
r"""
max number of operands allowed for an instruction
"""


def calc_default_idaplace_flags() -> "int":
    r"""
    calc_default_idaplace_flags() -> int
    Get default disassembly line options.
    """
    return _ida_ida.calc_default_idaplace_flags()

def to_ea(reg_cs: "sel_t", reg_ip: "uval_t") -> "ea_t":
    r"""
    to_ea(reg_cs, reg_ip) -> ea_t
    Convert (sel,off) value to a linear address.

    @param reg_cs: (C++: sel_t)
    @param reg_ip: (C++: uval_t)
    """
    return _ida_ida.to_ea(reg_cs, reg_ip)
IDB_EXT32 = _ida_ida.IDB_EXT32

IDB_EXT64 = _ida_ida.IDB_EXT64

IDB_EXT = _ida_ida.IDB_EXT


def get_dbctx_id() -> "ssize_t":
    r"""
    get_dbctx_id() -> ssize_t
    Get the current database context ID

    @return: the database context ID, or -1 if no current database
    """
    return _ida_ida.get_dbctx_id()

def get_dbctx_qty() -> "size_t":
    r"""
    get_dbctx_qty() -> size_t
    Get number of database contexts

    @return: number of database contexts
    """
    return _ida_ida.get_dbctx_qty()

def switch_dbctx(idx: "size_t") -> "dbctx_t *":
    r"""
    switch_dbctx(idx) -> dbctx_t *
    Switch to the database with the provided context ID

    @param idx: (C++: size_t) the index of the database to switch to
    @return: the current dbctx_t instance or nullptr
    """
    return _ida_ida.switch_dbctx(idx)

def is_database_busy() -> "bool":
    r"""
    is_database_busy() -> bool
    Check if the database is busy (e.g. performing some critical operations and
    cannot be safely accessed)
    """
    return _ida_ida.is_database_busy()

def validate_idb(vld_flags: "uint32"=0) -> "size_t":
    r"""
    validate_idb(vld_flags=0) -> size_t
    Validate the database

    @param vld_flags: (C++: uint32) combination of VLD_.. constants
    @return: number of corrupted/fixed records
    """
    return _ida_ida.validate_idb(vld_flags)
VLD_AUTO_REPAIR = _ida_ida.VLD_AUTO_REPAIR
r"""
automatically repair the database
"""

VLD_DIALOG = _ida_ida.VLD_DIALOG
r"""
ask user to repair (this bit is mutually exclusive with VLD_AUTO_REPAIR)
"""

VLD_SILENT = _ida_ida.VLD_SILENT
r"""
no messages to the output window
"""


def move_privrange(new_privrange_start: "ea_t") -> "bool":
    r"""
    move_privrange(new_privrange_start) -> bool
    Move privrange to the specified address

    @param new_privrange_start: (C++: ea_t) new start address of the privrange
    @return: success
    """
    return _ida_ida.move_privrange(new_privrange_start)
class idbattr_valmap_t(object):
    r"""
    Proxy of C++ idbattr_valmap_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    value: "uint64" = property(_ida_ida.idbattr_valmap_t_value_get, _ida_ida.idbattr_valmap_t_value_set, doc=r"""value""")
    valname: "char const *" = property(_ida_ida.idbattr_valmap_t_valname_get, _ida_ida.idbattr_valmap_t_valname_set, doc=r"""valname""")

    def __init__(self):
        r"""
        __init__(self) -> idbattr_valmap_t
        """
        _ida_ida.idbattr_valmap_t_swiginit(self, _ida_ida.new_idbattr_valmap_t())
    __swig_destroy__ = _ida_ida.delete_idbattr_valmap_t

# Register idbattr_valmap_t in _ida_ida:
_ida_ida.idbattr_valmap_t_swigregister(idbattr_valmap_t)
class idbattr_info_t(object):
    r"""
    Proxy of C++ idbattr_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    name: "char const *" = property(_ida_ida.idbattr_info_t_name_get, _ida_ida.idbattr_info_t_name_set, doc=r"""name""")
    r"""
    human-readable name
    """
    offset: "uintptr_t" = property(_ida_ida.idbattr_info_t_offset_get, _ida_ida.idbattr_info_t_offset_set, doc=r"""offset""")
    r"""
    field position: offset within a structure (IDI_STRUCFLD) altval or supval index
    (IDI_NODEVAL) hashval name (IDI_ALTVAL/IDI_SUPVAL+IDI_HASH)
    """
    width: "size_t" = property(_ida_ida.idbattr_info_t_width_get, _ida_ida.idbattr_info_t_width_set, doc=r"""width""")
    r"""
    field width in bytes
    """
    bitmask: "uint64" = property(_ida_ida.idbattr_info_t_bitmask_get, _ida_ida.idbattr_info_t_bitmask_set, doc=r"""bitmask""")
    r"""
    mask for bitfields (0-not bitfield)
    """
    tag: "uchar" = property(_ida_ida.idbattr_info_t_tag_get, _ida_ida.idbattr_info_t_tag_set, doc=r"""tag""")
    r"""
    tag of node value (if IDI_NODEVAL is set)
    """
    vmap: "idbattr_valmap_t const *" = property(_ida_ida.idbattr_info_t_vmap_get, _ida_ida.idbattr_info_t_vmap_set, doc=r"""vmap""")
    r"""
    array value=>name (terminated by empty element)
    """
    individual_node: "char const *" = property(_ida_ida.idbattr_info_t_individual_node_get, _ida_ida.idbattr_info_t_individual_node_set, doc=r"""individual_node""")
    r"""
    individual node name (nullptr - use default)
    """
    idi_flags: "uint" = property(_ida_ida.idbattr_info_t_idi_flags_get, _ida_ida.idbattr_info_t_idi_flags_set, doc=r"""idi_flags""")
    maxsize: "uint32" = property(_ida_ida.idbattr_info_t_maxsize_get, _ida_ida.idbattr_info_t_maxsize_set, doc=r"""maxsize""")
    r"""
    max bytes reserved for storage in netnode
    """

    def is_node_altval(self) -> "bool":
        r"""
        is_node_altval(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_node_altval(self)

    def is_node_supval(self) -> "bool":
        r"""
        is_node_supval(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_node_supval(self)

    def is_node_valobj(self) -> "bool":
        r"""
        is_node_valobj(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_node_valobj(self)

    def is_node_blob(self) -> "bool":
        r"""
        is_node_blob(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_node_blob(self)

    def is_node_var(self) -> "bool":
        r"""
        is_node_var(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_node_var(self)

    def is_struc_field(self) -> "bool":
        r"""
        is_struc_field(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_struc_field(self)

    def is_cstr(self) -> "bool":
        r"""
        is_cstr(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_cstr(self)

    def is_qstring(self) -> "bool":
        r"""
        is_qstring(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_qstring(self)

    def is_bytearray(self) -> "bool":
        r"""
        is_bytearray(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_bytearray(self)

    def is_buf_var(self) -> "bool":
        r"""
        is_buf_var(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_buf_var(self)

    def is_decimal(self) -> "bool":
        r"""
        is_decimal(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_decimal(self)

    def is_hexadecimal(self) -> "bool":
        r"""
        is_hexadecimal(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_hexadecimal(self)

    def is_readonly_var(self) -> "bool":
        r"""
        is_readonly_var(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_readonly_var(self)

    def is_incremented(self) -> "bool":
        r"""
        is_incremented(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_incremented(self)

    def is_val_mapped(self) -> "bool":
        r"""
        is_val_mapped(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_val_mapped(self)

    def is_hash(self) -> "bool":
        r"""
        is_hash(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_hash(self)

    def use_hlpstruc(self) -> "bool":
        r"""
        use_hlpstruc(self) -> bool
        """
        return _ida_ida.idbattr_info_t_use_hlpstruc(self)

    def is_bitmap(self) -> "bool":
        r"""
        is_bitmap(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_bitmap(self)

    def is_onoff(self) -> "bool":
        r"""
        is_onoff(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_onoff(self)

    def is_scalar_var(self) -> "bool":
        r"""
        is_scalar_var(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_scalar_var(self)

    def is_bitfield(self) -> "bool":
        r"""
        is_bitfield(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_bitfield(self)

    def is_boolean(self) -> "bool":
        r"""
        is_boolean(self) -> bool
        """
        return _ida_ida.idbattr_info_t_is_boolean(self)

    def has_individual_node(self) -> "bool":
        r"""
        has_individual_node(self) -> bool
        """
        return _ida_ida.idbattr_info_t_has_individual_node(self)

    def str_true(self) -> "char const *":
        r"""
        str_true(self) -> char const *
        """
        return _ida_ida.idbattr_info_t_str_true(self)

    def str_false(self) -> "char const *":
        r"""
        str_false(self) -> char const *
        """
        return _ida_ida.idbattr_info_t_str_false(self)

    def ridx(self) -> "size_t":
        r"""
        ridx(self) -> size_t
        """
        return _ida_ida.idbattr_info_t_ridx(self)

    def hashname(self) -> "char const *":
        r"""
        hashname(self) -> char const *
        """
        return _ida_ida.idbattr_info_t_hashname(self)

    def __lt__(self, r: "idbattr_info_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: idbattr_info_t const &
        """
        return _ida_ida.idbattr_info_t___lt__(self, r)

    def __init__(self, name: "char const *", offset: "uintptr_t", width: "size_t", bitmask: "uint64"=0, tag: "uchar"=0, idi_flags: "uint"=0):
        r"""
        __init__(self, name, offset, width, bitmask=0, tag=0, idi_flags=0) -> idbattr_info_t

        @param name: char const *
        @param offset: uintptr_t
        @param width: size_t
        @param bitmask: uint64
        @param tag: uchar
        @param idi_flags: uint
        """
        _ida_ida.idbattr_info_t_swiginit(self, _ida_ida.new_idbattr_info_t(name, offset, width, bitmask, tag, idi_flags))
    __swig_destroy__ = _ida_ida.delete_idbattr_info_t

# Register idbattr_info_t in _ida_ida:
_ida_ida.idbattr_info_t_swigregister(idbattr_info_t)
IDI_STRUCFLD = _ida_ida.IDI_STRUCFLD
r"""
structure field (opposite to IDI_NODEVAL)
"""

IDI_ALTVAL = _ida_ida.IDI_ALTVAL
r"""
netnode: altval
"""

IDI_SUPVAL = _ida_ida.IDI_SUPVAL
r"""
netnode: supval
"""

IDI_VALOBJ = _ida_ida.IDI_VALOBJ
r"""
netnode: valobj
"""

IDI_BLOB = _ida_ida.IDI_BLOB
r"""
netnode: blob
"""

IDI_SCALAR = _ida_ida.IDI_SCALAR
r"""
scalar value (default)
"""

IDI_CSTR = _ida_ida.IDI_CSTR
r"""
string
"""

IDI_QSTRING = _ida_ida.IDI_QSTRING
r"""
qstring
"""

IDI_BYTEARRAY = _ida_ida.IDI_BYTEARRAY
r"""
byte array: binary representation
"""

IDI_EA_HEX = _ida_ida.IDI_EA_HEX
r"""
default representation: hex or "BADADDR"
"""

IDI_DEC = _ida_ida.IDI_DEC
r"""
show as decimal
"""

IDI_HEX = _ida_ida.IDI_HEX
r"""
show as hexadecimal
"""

IDI_INC = _ida_ida.IDI_INC
r"""
stored value is incremented (scalars only)
"""

IDI_MAP_VAL = _ida_ida.IDI_MAP_VAL
r"""
apply ea2node() to value
"""

IDI_HASH = _ida_ida.IDI_HASH
r"""
hashed node field, hash name in offset
"""

IDI_HLPSTRUC = _ida_ida.IDI_HLPSTRUC
r"""
call helper for pointer to structure
"""

IDI_READONLY = _ida_ida.IDI_READONLY
r"""
read-only field (cannot be modified)
"""

IDI_BITMAP = _ida_ida.IDI_BITMAP
r"""
bitmap field: interpret bitmask as bit number
"""

IDI_ONOFF = _ida_ida.IDI_ONOFF
r"""
show boolean as on/off (not true/false)
"""

IDI_NOMERGE = _ida_ida.IDI_NOMERGE
r"""
field should not be merged as part of INF
"""

IDI_NODEVAL = _ida_ida.IDI_NODEVAL

IDI_BUFVAR = _ida_ida.IDI_BUFVAR



#<pycode(py_ida)>
import sys

def __make_idainfo_bound(func, attr):
    def __func(self, *args):
        return func(*args)
    setattr(idainfo, attr, __func)

_NO_SETTER = "<nosetter>"
def __make_idainfo_accessors(
        attr,
        getter_name=None,
        setter_name=None):
    if getter_name is None:
        getter_name = attr
    getter = globals()["idainfo_%s" % getter_name]
    __make_idainfo_bound(getter, getter_name)
    if setter_name != _NO_SETTER:
        if setter_name is None:
            setter_name = "set_%s" % attr
        setter = globals()["idainfo_%s" % setter_name]
        __make_idainfo_bound(setter, setter_name)

def __make_idainfo_getter(name):
    return __make_idainfo_accessors(None, getter_name=name, setter_name=_NO_SETTER)


idainfo_big_arg_align = inf_big_arg_align
__make_idainfo_getter("big_arg_align")

idainfo_gen_null = inf_gen_null
idainfo_set_gen_null = inf_set_gen_null
__make_idainfo_accessors("gen_null")

idainfo_gen_lzero = inf_gen_lzero
idainfo_set_gen_lzero = inf_set_gen_lzero
__make_idainfo_accessors("gen_lzero")

idainfo_gen_tryblks = inf_gen_tryblks
idainfo_set_gen_tryblks = inf_set_gen_tryblks
__make_idainfo_accessors("gen_tryblks")

idainfo_get_demname_form = inf_get_demname_form
__make_idainfo_getter("get_demname_form")

idainfo_get_pack_mode = inf_get_pack_mode
idainfo_set_pack_mode = inf_set_pack_mode
__make_idainfo_accessors(None, "get_pack_mode", "set_pack_mode")

def idainfo_is_32bit(): return not inf_is_16bit() # in reality this means "is 32bit or higher"
__make_idainfo_getter("is_32bit")

idainfo_is_64bit = inf_is_64bit
idainfo_set_64bit = inf_set_64bit
__make_idainfo_accessors(None, "is_64bit", "set_64bit")

idainfo_is_auto_enabled = inf_is_auto_enabled
idainfo_set_auto_enabled = inf_set_auto_enabled
__make_idainfo_accessors(None, "is_auto_enabled", "set_auto_enabled")

idainfo_is_be = inf_is_be
idainfo_set_be = inf_set_be
__make_idainfo_accessors(None, "is_be", "set_be")

idainfo_is_dll = inf_is_dll
__make_idainfo_getter("is_dll")

idainfo_is_flat_off32 = inf_is_flat_off32
__make_idainfo_getter("is_flat_off32")

idainfo_is_graph_view = inf_is_graph_view
idainfo_set_graph_view = inf_set_graph_view
__make_idainfo_accessors(None, "is_graph_view", "set_graph_view")

idainfo_is_hard_float = inf_is_hard_float
__make_idainfo_getter("is_hard_float")

idainfo_is_kernel_mode = inf_is_kernel_mode
__make_idainfo_getter("is_kernel_mode")

idainfo_is_mem_aligned4 = inf_is_mem_aligned4
__make_idainfo_getter("is_mem_aligned4")

idainfo_is_snapshot = inf_is_snapshot
__make_idainfo_getter("is_snapshot")

idainfo_is_wide_high_byte_first = inf_is_wide_high_byte_first
idainfo_set_wide_high_byte_first = inf_set_wide_high_byte_first
__make_idainfo_accessors(None, "is_wide_high_byte_first", "set_wide_high_byte_first")

idainfo_like_binary = inf_like_binary
__make_idainfo_getter("like_binary")

idainfo_line_pref_with_seg = inf_line_pref_with_seg
idainfo_set_line_pref_with_seg = inf_set_line_pref_with_seg
__make_idainfo_accessors("line_pref_with_seg")

idainfo_show_auto = inf_show_auto
idainfo_set_show_auto = inf_set_show_auto
__make_idainfo_accessors("show_auto")

idainfo_show_line_pref = inf_show_line_pref
idainfo_set_show_line_pref = inf_set_show_line_pref
__make_idainfo_accessors("show_line_pref")

idainfo_show_void = inf_show_void
idainfo_set_show_void = inf_set_show_void
__make_idainfo_accessors("show_void")

idainfo_loading_idc = inf_loading_idc
__make_idainfo_getter("loading_idc")

idainfo_map_stkargs = inf_map_stkargs
__make_idainfo_getter("map_stkargs")

idainfo_pack_stkargs = inf_pack_stkargs
__make_idainfo_getter("pack_stkargs")

idainfo_readonly_idb = inf_readonly_idb
__make_idainfo_getter("readonly_idb")

idainfo_set_store_user_info = lambda *args: not inf_set_store_user_info()

idainfo_stack_ldbl = inf_stack_ldbl
__make_idainfo_getter("stack_ldbl")

idainfo_stack_varargs = inf_stack_varargs
__make_idainfo_getter("stack_varargs")

idainfo_use_allasm = inf_use_allasm
__make_idainfo_getter("use_allasm")

idainfo_use_gcc_layout = inf_use_gcc_layout
__make_idainfo_getter("use_gcc_layout")

macros_enabled = inf_macros_enabled
should_create_stkvars = inf_should_create_stkvars
should_trace_sp = inf_should_trace_sp
show_all_comments = inf_show_all_comments
show_comments = lambda *args: not inf_hide_comments()
show_repeatables = inf_show_repeatables

inf_get_comment = inf_get_cmt_indent
inf_set_comment = inf_set_cmt_indent
idainfo_comment_get = inf_get_cmt_indent
idainfo_comment_set = inf_set_cmt_indent

__make_idainfo_accessors(None, "is_graph_view", "set_graph_view")

def __wrap_hooks_callback(klass, new_name, old_name, do_call):
    bkp_name = "__real_%s" % new_name
    def __wrapper(self, *args):
        rc = getattr(self, bkp_name)(*args)
        cb = getattr(self, old_name, None)
        if cb:
            rc = do_call(cb, *args)
        return rc

    new_cb = getattr(klass, new_name)
    __wrapper.__doc__ = new_cb.__doc__
    setattr(klass, bkp_name, new_cb)
    setattr(__wrapper, "__trampoline", True)
    setattr(klass, new_name, __wrapper)
    return __wrapper


def __set_module_dynattrs(modname, pdict):
    import types
    class _module_wrapper_t(types.ModuleType):
        def __init__(self, orig):
            self.orig = orig
        def __getattribute__(self, name):
            if name in pdict:
                return pdict[name][0]()
            elif name == "orig":
                return types.ModuleType.__getattribute__(self, name)
            elif name == "__dict__":
                d = self.orig.__dict__
                d = d.copy()
                for name in pdict:
                    d[name] = pdict[name][0]()
                return d
            else:
                return getattr(self.orig, name)
        def __setattr__(self, name, value):
            if name == "orig":
                types.ModuleType.__setattr__(self, name, value)
            else:
                return setattr(self.orig, name, value)

    sys.modules[modname] = _module_wrapper_t(sys.modules[modname])

__set_module_dynattrs(
    __name__,
    {
        "MAXADDR" : (lambda: inf_get_privrange_start_ea(), None),
    })

#</pycode(py_ida)>



