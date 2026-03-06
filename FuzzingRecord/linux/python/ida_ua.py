r"""
Functions that deal with the disassembling of program instructions.

There are 2 kinds of functions:
* functions that are called from the kernel to disassemble an instruction. These
functions call IDP module for it.
* functions that are called from IDP module to disassemble an instruction. We
will call them 'helper functions'.

Disassembly of an instruction is made in three steps:
1. analysis: ana.cpp
2. emulation: emu.cpp
3. conversion to text: out.cpp

The kernel calls the IDP module to perform these steps. At first, the kernel
always calls the analysis. The analyzer must decode the instruction and fill the
insn_t instance that it receives through its callback. It must not change
anything in the database.

The second step, the emulation, is called for each instruction. This step must
make necessary changes to the database, plan analysis of subsequent
instructions, track register values, memory contents, etc. Please keep in mind
that the kernel may call the emulation step for any address in the program -
there is no ordering of addresses. Usually, the emulation is called for
consecutive addresses but this is not guaranteed.

The last step, conversion to text, is called each time an instruction is
displayed on the screen. The kernel will always call the analysis step before
calling the text conversion step. The emulation and the text conversion steps
should use the information stored in the insn_t instance they receive. They
should not access the bytes of the instruction and decode it again - this should
only be done in the analysis step."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_ua
else:
    import _ida_ua

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

SWIG_PYTHON_LEGACY_BOOL = _ida_ua.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

class operands_array(object):
    r"""
    Proxy of C++ wrapped_array_t< op_t,8 > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    data: "op_t (&)[8]" = property(_ida_ua.operands_array_data_get, doc=r"""data""")

    def __init__(self, data: "op_t (&)[8]"):
        r"""
        __init__(self, data) -> operands_array

        @param data: op_t (&)[8]
        """
        _ida_ua.operands_array_swiginit(self, _ida_ua.new_operands_array(data))

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_ua.operands_array___len__(self)

    def __getitem__(self, i: "size_t") -> "op_t const &":
        r"""
        __getitem__(self, i) -> op_t

        @param i: size_t
        """
        return _ida_ua.operands_array___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "op_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: op_t const &
        """
        return _ida_ua.operands_array___setitem__(self, i, v)

    def _get_bytes(self) -> "bytevec_t":
        r"""_get_bytes(self) -> bytevec_t"""
        return _ida_ua.operands_array__get_bytes(self)

    def _set_bytes(self, bts: "bytevec_t const &") -> "void":
        r"""
        _set_bytes(self, bts)

        Parameters
        ----------
        bts: bytevec_t const &

        """
        return _ida_ua.operands_array__set_bytes(self, bts)

    __iter__ = ida_idaapi._bounded_getitem_iterator
    bytes = property(_get_bytes, _set_bytes)

    __swig_destroy__ = _ida_ua.delete_operands_array

# Register operands_array in _ida_ua:
_ida_ua.operands_array_swigregister(operands_array)
class op_t(object):
    r"""
    Proxy of C++ op_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    n: "uchar" = property(_ida_ua.op_t_n_get, _ida_ua.op_t_n_set, doc=r"""n""")
    r"""
    Number of operand (0,1,2). Initialized once at the start of work. You have no
    right to change its value.
    """
    type: "optype_t" = property(_ida_ua.op_t_type_get, _ida_ua.op_t_type_set, doc=r"""type""")
    r"""
    Type of operand (see Operand types)
    """
    offb: "char" = property(_ida_ua.op_t_offb_get, _ida_ua.op_t_offb_set, doc=r"""offb""")
    r"""
    Offset of operand value from the instruction start (0 means unknown). Of course
    this field is meaningful only for certain types of operands. Leave it equal to
    zero if the operand has no offset. This offset should point to the 'interesting'
    part of operand. For example, it may point to the address of a function in
    call func  or it may point to bytes holding '5' in
    mov  ax, [bx+5]  Usually bytes pointed to this offset are relocated (have fixup
    information).
    """
    offo: "char" = property(_ida_ua.op_t_offo_get, _ida_ua.op_t_offo_set, doc=r"""offo""")
    r"""
    Same as offb (some operands have 2 numeric values used to form an operand). This
    field is used for the second part of operand if it exists. Currently this field
    is used only for outer offsets of Motorola processors. Leave it equal to zero if
    the operand has no offset.
    """
    flags: "uchar" = property(_ida_ua.op_t_flags_get, _ida_ua.op_t_flags_set, doc=r"""flags""")
    r"""
    Operand flags
    """

    def set_shown(self) -> "void":
        r"""
        set_shown(self)
        Set operand to be shown.
        """
        return _ida_ua.op_t_set_shown(self)

    def clr_shown(self) -> "void":
        r"""
        clr_shown(self)
        Set operand to hidden.
        """
        return _ida_ua.op_t_clr_shown(self)

    def shown(self) -> "bool":
        r"""
        shown(self) -> bool
        Is operand set to be shown?
        """
        return _ida_ua.op_t_shown(self)
    dtype: "op_dtype_t" = property(_ida_ua.op_t_dtype_get, _ida_ua.op_t_dtype_set, doc=r"""dtype""")
    r"""
    Type of operand value (see Operand value types). Usually first 9 types are used.
    This is the type of the operand itself, not the size of the addressing mode. for
    example, byte ptr [epb+32_bit_offset] will have dt_byte type.
    """
    reg: "uint16" = property(_ida_ua.op_t_reg_get, _ida_ua.op_t_reg_set, doc=r"""reg""")
    r"""
    number of register (o_reg)
    """
    phrase: "uint16" = property(_ida_ua.op_t_phrase_get, _ida_ua.op_t_phrase_set, doc=r"""phrase""")
    r"""
    number of register phrase (o_phrase,o_displ). you yourself define numbers of
    phrases as you like
    """

    def is_reg(self, r: "int") -> "bool":
        r"""
        is_reg(self, r) -> bool
        Is register operand?

        @param r: (C++: int)
        """
        return _ida_ua.op_t_is_reg(self, r)
    value: "uval_t" = property(_ida_ua.op_t_value_get, _ida_ua.op_t_value_set, doc=r"""value""")
    r"""
    operand value (o_imm) or outer displacement (o_displ+OF_OUTER_DISP). integer
    values should be in IDA's (little-endian) order. when using ieee_realcvt(),
    floating point values should be in the processor's native byte order. dt_double
    and dt_qword values take up 8 bytes (value and addr fields for 32-bit modules).
    NB: in case a dt_dword/dt_qword immediate is forced to float by user, the kernel
    converts it to processor's native order before calling FP conversion routines.
    """

    def is_imm(self, v: "uval_t") -> "bool":
        r"""
        is_imm(self, v) -> bool
        Is immediate operand?

        @param v: (C++: uval_t)
        """
        return _ida_ua.op_t_is_imm(self, v)
    addr: "ea_t" = property(_ida_ua.op_t_addr_get, _ida_ua.op_t_addr_set, doc=r"""addr""")
    r"""
    virtual address pointed or used by the operand. (o_mem,o_displ,o_far,o_near)
    """
    specval: "ea_t" = property(_ida_ua.op_t_specval_get, _ida_ua.op_t_specval_set, doc=r"""specval""")
    r"""
    This field may be used as you want.
    """
    specflag1: "char" = property(_ida_ua.op_t_specflag1_get, _ida_ua.op_t_specflag1_set, doc=r"""specflag1""")
    specflag2: "char" = property(_ida_ua.op_t_specflag2_get, _ida_ua.op_t_specflag2_set, doc=r"""specflag2""")
    specflag3: "char" = property(_ida_ua.op_t_specflag3_get, _ida_ua.op_t_specflag3_set, doc=r"""specflag3""")
    specflag4: "char" = property(_ida_ua.op_t_specflag4_get, _ida_ua.op_t_specflag4_set, doc=r"""specflag4""")

    def __init__(self):
        r"""
        __init__(self) -> op_t
        """
        _ida_ua.op_t_swiginit(self, _ida_ua.new_op_t())

    def __get_reg_phrase__(self) -> "uint16":
        r"""
        __get_reg_phrase__(self) -> uint16
        """
        return _ida_ua.op_t___get_reg_phrase__(self)

    def __set_reg_phrase__(self, r: "uint16") -> "void":
        r"""
        __set_reg_phrase__(self, r)

        @param r: uint16
        """
        return _ida_ua.op_t___set_reg_phrase__(self, r)

    def __get_value__(self) -> "ea_t":
        r"""
        __get_value__(self) -> ea_t
        """
        return _ida_ua.op_t___get_value__(self)

    def __set_value__(self, v: "ea_t") -> "void":
        r"""
        __set_value__(self, v)

        @param v: ea_t
        """
        return _ida_ua.op_t___set_value__(self, v)

    def __get_value64__(self) -> "uint64":
        r"""
        __get_value64__(self) -> uint64
        """
        return _ida_ua.op_t___get_value64__(self)

    def __set_value64__(self, v: "uint64") -> "void":
        r"""
        __set_value64__(self, v)

        @param v: uint64
        """
        return _ida_ua.op_t___set_value64__(self, v)

    def __get_addr__(self) -> "ea_t":
        r"""
        __get_addr__(self) -> ea_t
        """
        return _ida_ua.op_t___get_addr__(self)

    def __set_addr__(self, v: "ea_t") -> "void":
        r"""
        __set_addr__(self, v)

        @param v: ea_t
        """
        return _ida_ua.op_t___set_addr__(self, v)

    def __get_specval__(self) -> "ea_t":
        r"""
        __get_specval__(self) -> ea_t
        """
        return _ida_ua.op_t___get_specval__(self)

    def __set_specval__(self, v: "ea_t") -> "void":
        r"""
        __set_specval__(self, v)

        @param v: ea_t
        """
        return _ida_ua.op_t___set_specval__(self, v)

    def assign(self, other: "op_t") -> "void":
        r"""
        assign(self, other)

        @param other: op_t const &
        """
        return _ida_ua.op_t_assign(self, other)

    def has_reg(self, r):
        r"""
        Checks if the operand accesses the given processor register
        """
        return self.reg == r.reg

    reg = property(__get_reg_phrase__, __set_reg_phrase__)
    phrase = property(__get_reg_phrase__, __set_reg_phrase__)
    value = property(__get_value__, __set_value__)
    value64 = property(__get_value64__, __set_value64__)
    addr = property(__get_addr__, __set_addr__)
    specval = property(__get_specval__, __set_specval__)

    __swig_destroy__ = _ida_ua.delete_op_t

# Register op_t in _ida_ua:
_ida_ua.op_t_swigregister(op_t)
cvar = _ida_ua.cvar
o_void = cvar.o_void
r"""
No Operand.
"""
o_reg = cvar.o_reg
r"""
General Register (al,ax,es,ds...).

The register number should be stored in op_t::reg. All processor registers,
including special registers, can be represented by this operand type.
"""
o_mem = cvar.o_mem
r"""
Direct Memory Reference (DATA).

A direct memory data reference whose target address is known at compilation
time. The target virtual address is stored in op_t::addr and the full address is
calculated as to_ea(  insn_t::cs, op_t::addr ). For the processors with complex
memory organization the final address can be calculated using other segment
registers. For flat memories, op_t::addr is the final address and insn_t::cs is
usually equal to zero. In any case, the address within the segment should be
stored in op_t::addr.
"""
o_phrase = cvar.o_phrase
r"""
Memory Ref [Base Reg + Index Reg].

A memory reference using register contents. Indexed, register based, and other
addressing modes can be represented with the operand type. This addressing mode
cannot contain immediate values (use o_displ instead). The phrase number should
be stored in op_t::phrase. To denote the pre-increment and similar features
please use additional operand fields like op_t::specflag... Usually op_t::phrase
contains the register number and additional information is stored in
op_t::specflags... Please note that this operand type cannot contain immediate
values (except the scaling coefficients).
"""
o_displ = cvar.o_displ
r"""
Memory Ref [Base Reg + Index Reg + Displacement].

A memory reference using register contents with displacement. The displacement
should be stored in the op_t::addr field. The rest of information is stored the
same way as in o_phrase.
"""
o_imm = cvar.o_imm
r"""
Immediate Value.

Any operand consisting of only a number is represented by this operand type. The
value should be stored in op_t::value. You may sign extend short (1-2 byte)
values. In any case don't forget to specify op_t::dtype (should be set for all
operand types).
"""
o_far = cvar.o_far
r"""
Immediate Far Address (CODE).

If the current processor has a special addressing mode for inter-segment
references, then this operand type should be used instead of o_near. If you
want, you may use PR_CHK_XREF in processor_t::flag to disable inter-segment
calls if o_near operand type is used. Currently only IBM PC uses this flag.
"""
o_near = cvar.o_near
r"""
Immediate Near Address (CODE).

A direct memory code reference whose target address is known at the compilation
time. The target virtual address is stored in op_t::addr and the final address
is always to_ea( insn_t::cs, op_t::addr). Usually this operand type is used for
the branches and calls whose target address is known. If the current processor
has 2 different types of references for inter-segment and intra-segment
references, then this should be used only for intra-segment references.

If the above operand types do not cover all possible addressing modes, then use
o_idpspec... operand types.
"""
o_idpspec0 = cvar.o_idpspec0
r"""
processor specific type.
"""
o_idpspec1 = cvar.o_idpspec1
r"""
processor specific type.
"""
o_idpspec2 = cvar.o_idpspec2
r"""
processor specific type.
"""
o_idpspec3 = cvar.o_idpspec3
r"""
processor specific type.
"""
o_idpspec4 = cvar.o_idpspec4
r"""
processor specific type.
"""
o_idpspec5 = cvar.o_idpspec5
r"""
processor specific type. (there can be more processor specific types)
"""
OF_NO_BASE_DISP = _ida_ua.OF_NO_BASE_DISP
r"""
base displacement doesn't exist. meaningful only for o_displ type. if set, base
displacement (op_t::addr) doesn't exist.
"""

OF_OUTER_DISP = _ida_ua.OF_OUTER_DISP
r"""
outer displacement exists. meaningful only for o_displ type. if set, outer
displacement (op_t::value) exists.
"""

PACK_FORM_DEF = _ida_ua.PACK_FORM_DEF
r"""
packed factor defined. (!o_reg + dt_packreal)
"""

OF_NUMBER = _ida_ua.OF_NUMBER
r"""
the operand can be converted to a number only
"""

OF_SHOW = _ida_ua.OF_SHOW
r"""
should the operand be displayed?
"""

dt_byte = _ida_ua.dt_byte
r"""
8 bit integer
"""

dt_word = _ida_ua.dt_word
r"""
16 bit integer
"""

dt_dword = _ida_ua.dt_dword
r"""
32 bit integer
"""

dt_float = _ida_ua.dt_float
r"""
4 byte floating point
"""

dt_double = _ida_ua.dt_double
r"""
8 byte floating point
"""

dt_tbyte = _ida_ua.dt_tbyte
r"""
variable size ( processor_t::tbyte_size) floating point
"""

dt_packreal = _ida_ua.dt_packreal
r"""
packed real format for mc68040
"""

dt_qword = _ida_ua.dt_qword
r"""
64 bit integer
"""

dt_byte16 = _ida_ua.dt_byte16
r"""
128 bit integer
"""

dt_code = _ida_ua.dt_code
r"""
ptr to code (not used?)
"""

dt_void = _ida_ua.dt_void
r"""
none
"""

dt_fword = _ida_ua.dt_fword
r"""
48 bit
"""

dt_bitfild = _ida_ua.dt_bitfild
r"""
bit field (mc680x0)
"""

dt_string = _ida_ua.dt_string
r"""
pointer to asciiz string
"""

dt_unicode = _ida_ua.dt_unicode
r"""
pointer to unicode string
"""

dt_ldbl = _ida_ua.dt_ldbl
r"""
long double (which may be different from tbyte)
"""

dt_byte32 = _ida_ua.dt_byte32
r"""
256 bit integer
"""

dt_byte64 = _ida_ua.dt_byte64
r"""
512 bit integer
"""

dt_half = _ida_ua.dt_half
r"""
2-byte floating point
"""



def insn_add_cref(insn: "insn_t", to: "ea_t", opoff: "int", type: "cref_t") -> "void":
    r"""
    insn_add_cref(insn, to, opoff, type)

    @param insn: an ida_ua.insn_t, or an address (C++: const insn_t &)
    @param to: ea_t
    @param opoff: int
    @param type: enum cref_t
    """
    return _ida_ua.insn_add_cref(insn, to, opoff, type)

def insn_add_dref(insn: "insn_t", to: "ea_t", opoff: "int", type: "dref_t") -> "void":
    r"""
    insn_add_dref(insn, to, opoff, type)

    @param insn: an ida_ua.insn_t, or an address (C++: const insn_t &)
    @param to: ea_t
    @param opoff: int
    @param type: enum dref_t
    """
    return _ida_ua.insn_add_dref(insn, to, opoff, type)

def insn_add_off_drefs(insn: "insn_t", x: "op_t", type: "dref_t", outf: "int") -> "ea_t":
    r"""
    insn_add_off_drefs(insn, x, type, outf) -> ea_t

    @param insn: an ida_ua.insn_t, or an address (C++: const insn_t &)
    @param x: op_t const &
    @param type: enum dref_t
    @param outf: int
    """
    return _ida_ua.insn_add_off_drefs(insn, x, type, outf)

def insn_create_stkvar(insn: "insn_t", x: "op_t", v: "adiff_t", flags: "int") -> "bool":
    r"""
    insn_create_stkvar(insn, x, v, flags) -> bool

    @param insn: an ida_ua.insn_t, or an address (C++: const insn_t &)
    @param x: op_t const &
    @param v: adiff_t
    @param flags: int
    """
    return _ida_ua.insn_create_stkvar(insn, x, v, flags)
class insn_t(object):
    r"""
    Proxy of C++ insn_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self):
        r"""
        __init__(self) -> insn_t
        """
        _ida_ua.insn_t_swiginit(self, _ida_ua.new_insn_t())
    cs: "ea_t" = property(_ida_ua.insn_t_cs_get, _ida_ua.insn_t_cs_set, doc=r"""cs""")
    r"""
    Current segment base paragraph. Initialized by the kernel.
    """
    ip: "ea_t" = property(_ida_ua.insn_t_ip_get, _ida_ua.insn_t_ip_set, doc=r"""ip""")
    r"""
    Virtual address of the instruction (address within the segment). Initialized by
    the kernel.
    """
    ea: "ea_t" = property(_ida_ua.insn_t_ea_get, _ida_ua.insn_t_ea_set, doc=r"""ea""")
    r"""
    Linear address of the instruction. Initialized by the kernel.
    """
    itype: "uint16" = property(_ida_ua.insn_t_itype_get, _ida_ua.insn_t_itype_set, doc=r"""itype""")
    r"""
    Internal code of instruction (only for canonical insns - not user defined!). IDP
    should define its own instruction codes. These codes are usually defined in
    ins.hpp. The array of instruction names and features (ins.cpp) is accessed using
    this code.
    """
    size: "uint16" = property(_ida_ua.insn_t_size_get, _ida_ua.insn_t_size_set, doc=r"""size""")
    r"""
    Size of instruction in bytes. The analyzer should put here the actual size of
    the instruction.
    """
    auxpref: "uint32" = property(_ida_ua.insn_t_auxpref_get, _ida_ua.insn_t_auxpref_set, doc=r"""auxpref""")
    r"""
    processor dependent field
    """
    auxpref_u16: "uint16 [2]" = property(_ida_ua.insn_t_auxpref_u16_get, _ida_ua.insn_t_auxpref_u16_set, doc=r"""auxpref_u16""")
    auxpref_u8: "uint8 [4]" = property(_ida_ua.insn_t_auxpref_u8_get, _ida_ua.insn_t_auxpref_u8_set, doc=r"""auxpref_u8""")
    segpref: "char" = property(_ida_ua.insn_t_segpref_get, _ida_ua.insn_t_segpref_set, doc=r"""segpref""")
    r"""
    processor dependent field
    """
    insnpref: "char" = property(_ida_ua.insn_t_insnpref_get, _ida_ua.insn_t_insnpref_set, doc=r"""insnpref""")
    r"""
    processor dependent field
    """
    flags: "int16" = property(_ida_ua.insn_t_flags_get, _ida_ua.insn_t_flags_set, doc=r"""flags""")
    r"""
    Instruction flags
    """
    ops: "op_t [8]" = property(_ida_ua.insn_t_ops_get, _ida_ua.insn_t_ops_set, doc=r"""ops""")
    r"""
    array of operands
    """

    def is_macro(self) -> "bool":
        r"""
        is_macro(self) -> bool
        Is a macro instruction?
        """
        return _ida_ua.insn_t_is_macro(self)

    def is_64bit(self) -> "bool":
        r"""
        is_64bit(self) -> bool
        Belongs to a 64bit segment?
        """
        return _ida_ua.insn_t_is_64bit(self)

    def get_next_byte(self) -> "uint8":
        r"""
        get_next_byte(self) -> uint8
        """
        return _ida_ua.insn_t_get_next_byte(self)

    def get_next_word(self) -> "uint16":
        r"""
        get_next_word(self) -> uint16
        """
        return _ida_ua.insn_t_get_next_word(self)

    def get_next_dword(self) -> "uint32":
        r"""
        get_next_dword(self) -> uint32
        """
        return _ida_ua.insn_t_get_next_dword(self)

    def get_next_qword(self) -> "uint64":
        r"""
        get_next_qword(self) -> uint64
        """
        return _ida_ua.insn_t_get_next_qword(self)

    def create_op_data(self, *args) -> "bool":
        r"""
        create_op_data(self, ea_, opoff, dtype) -> bool
        Convenient alias.

        @param ea_: (C++: ea_t)
        @param opoff: int
        @param dtype: op_dtype_t

        create_op_data(self, ea_, op) -> bool

        @param ea_: ea_t
        @param op: op_t const &
        """
        return _ida_ua.insn_t_create_op_data(self, *args)

    def create_stkvar(self, x: "op_t", v: "adiff_t", flags_: "int") -> "bool":
        r"""
        create_stkvar(self, x, v, flags_) -> bool
        Create or modify a stack variable in the function frame. The emulator could use
        this function to create stack variables in the function frame before converting
        the operand to a stack variable. Please check with may_create_stkvars() before
        calling this function.

        @param x: (C++: const op_t &) operand (used to determine the addressing type)
        @param v: (C++: adiff_t) a displacement in the operand
        @param flags_: (C++: int) Stack variable flags
        @retval 1: ok, a stack variable exists now
        @retval 0: no, couldn't create stack variable
        """
        return _ida_ua.insn_t_create_stkvar(self, x, v, flags_)

    def add_cref(self, to: "ea_t", opoff: "int", type: "cref_t") -> "void":
        r"""
        add_cref(self, to, opoff, type)
        Add a code cross-reference from the instruction.

        @param to: (C++: ea_t) target linear address
        @param opoff: (C++: int) offset of the operand from the start of instruction. if the offset
                      is unknown, then 0.
        @param type: (C++: cref_t) type of xref
        """
        return _ida_ua.insn_t_add_cref(self, to, opoff, type)

    def add_dref(self, to: "ea_t", opoff: "int", type: "dref_t") -> "void":
        r"""
        add_dref(self, to, opoff, type)
        Add a data cross-reference from the instruction. See add_off_drefs() - usually
        it can be used in most cases.

        @param to: (C++: ea_t) target linear address
        @param opoff: (C++: int) offset of the operand from the start of instruction if the offset
                      is unknown, then 0
        @param type: (C++: dref_t) type of xref
        """
        return _ida_ua.insn_t_add_dref(self, to, opoff, type)

    def add_off_drefs(self, x: "op_t", type: "dref_t", outf: "int") -> "ea_t":
        r"""
        add_off_drefs(self, x, type, outf) -> ea_t
        Add xrefs for an operand of the instruction. This function creates all cross
        references for 'enum', 'offset' and 'structure offset' operands. Use
        add_off_drefs() in the presence of negative offsets.

        @param x: (C++: const op_t &) reference to operand
        @param type: (C++: dref_t) type of xref
        @param outf: (C++: int) out_value() flags. These flags should match the flags used to
                     output the operand
        @return: if is_off(): the reference target address (the same as
                 calc_reference_data). if is_stroff(): BADADDR because for stroffs the
                 target address is unknown else: BADADDR because enums do not represent
                 addresses
        """
        return _ida_ua.insn_t_add_off_drefs(self, x, type, outf)

    def __get_ops__(self) -> "wrapped_array_t< op_t,8 >":
        r"""
        __get_ops__(self) -> operands_array
        """
        return _ida_ua.insn_t___get_ops__(self)

    def __get_operand__(self, n: "int") -> "op_t *":
        r"""
        __get_operand__(self, n) -> op_t

        @param n: int
        """
        return _ida_ua.insn_t___get_operand__(self, n)

    def __get_auxpref__(self) -> "uint32":
        r"""
        __get_auxpref__(self) -> uint32
        """
        return _ida_ua.insn_t___get_auxpref__(self)

    def __set_auxpref__(self, v: "uint32") -> "void":
        r"""
        __set_auxpref__(self, v)

        @param v: uint32
        """
        return _ida_ua.insn_t___set_auxpref__(self, v)

    def assign(self, other: "insn_t") -> "void":
        r"""
        assign(self, other)

        @param other: an ida_ua.insn_t, or an address (C++: const insn_t &)
        """
        return _ida_ua.insn_t_assign(self, other)

    def is_canon_insn(self, *args) -> "bool":
        r"""
        is_canon_insn(self, ph) -> bool
        see processor_t::is_canon_insn()

        @param ph: (C++: const processor_t &) processor_t const &

        is_canon_insn(self) -> bool
        """
        return _ida_ua.insn_t_is_canon_insn(self, *args)

    def get_canon_feature(self, *args) -> "uint32":
        r"""
        get_canon_feature(self, ph) -> uint32
        see instruc_t::feature

        @param ph: (C++: const processor_t &) processor_t const &

        get_canon_feature(self) -> uint32
        """
        return _ida_ua.insn_t_get_canon_feature(self, *args)

    def get_canon_mnem(self, *args) -> "char const *":
        r"""
        get_canon_mnem(self, ph) -> char const
        see instruc_t::name

        @param ph: (C++: const processor_t &) processor_t const &

        get_canon_mnem(self) -> char const *
        """
        return _ida_ua.insn_t_get_canon_mnem(self, *args)

    ops = property(__get_ops__)
    Op1 = property(lambda self: self.__get_operand__(0))
    Op2 = property(lambda self: self.__get_operand__(1))
    Op3 = property(lambda self: self.__get_operand__(2))
    Op4 = property(lambda self: self.__get_operand__(3))
    Op5 = property(lambda self: self.__get_operand__(4))
    Op6 = property(lambda self: self.__get_operand__(5))
    Op7 = property(lambda self: self.__get_operand__(6))
    Op8 = property(lambda self: self.__get_operand__(7))

    auxpref = property(__get_auxpref__, __set_auxpref__)

    def __iter__(self):
        return (self.ops[idx] for idx in range(0, 8))

    def __getitem__(self, idx):
        r"""
        Operands can be accessed directly as indexes
        @return: op_t: Returns an operand of type op_t
        """
        if idx >= 8:
            raise KeyError
        else:
            return self.ops[idx]

    __swig_destroy__ = _ida_ua.delete_insn_t

# Register insn_t in _ida_ua:
_ida_ua.insn_t_swigregister(insn_t)
INSN_MACRO = _ida_ua.INSN_MACRO
r"""
macro instruction
"""

INSN_MODMAC = _ida_ua.INSN_MODMAC
r"""
may modify the database to make room for the macro insn
"""

INSN_64BIT = _ida_ua.INSN_64BIT
r"""
belongs to 64bit segment?
"""

STKVAR_VALID_SIZE = _ida_ua.STKVAR_VALID_SIZE
r"""
x.dtype contains correct variable type (for insns like 'lea' this bit must be
off). in general, dr_O references do not allow to determine the variable size
"""



def get_lookback() -> "int":
    r"""
    get_lookback() -> int
    Number of instructions to look back. This variable is not used by the kernel.
    Its value may be specified in ida.cfg: LOOKBACK = <number>. IDP may use it as
    you like it. (TMS module uses it)
    """
    return _ida_ua.get_lookback()

def calc_dataseg(insn: "insn_t", n: "int"=-1, rgnum: "int"=-1) -> "ea_t":
    r"""
    calc_dataseg(insn, n=-1, rgnum=-1) -> ea_t
    Get data segment for the instruction operand. 'opnum' and 'rgnum' are meaningful
    only if the processor has segment registers.

    @param insn: (C++: const insn_t &) an ida_ua.insn_t, or an address (C++: const insn_t &)
    @param n: (C++: int)
    @param rgnum: (C++: int)
    """
    return _ida_ua.calc_dataseg(insn, n, rgnum)

def map_data_ea(*args) -> "ea_t":
    r"""
    map_data_ea(insn, addr, opnum=-1) -> ea_t

    @param insn: an ida_ua.insn_t, or an address (C++: const insn_t &)
    @param addr: ea_t
    @param opnum: int

    map_data_ea(insn, op) -> ea_t

    @param insn: an ida_ua.insn_t, or an address (C++: const insn_t &)
    @param op: op_t const &
    """
    return _ida_ua.map_data_ea(*args)

def map_code_ea(*args) -> "ea_t":
    r"""
    map_code_ea(insn, addr, opnum) -> ea_t

    @param insn: an ida_ua.insn_t, or an address (C++: const insn_t &)
    @param addr: ea_t
    @param opnum: int

    map_code_ea(insn, op) -> ea_t

    @param insn: an ida_ua.insn_t, or an address (C++: const insn_t &)
    @param op: op_t const &
    """
    return _ida_ua.map_code_ea(*args)

def map_ea(*args) -> "ea_t":
    r"""
    map_ea(insn, op, iscode) -> ea_t

    @param insn: an ida_ua.insn_t, or an address (C++: const insn_t &)
    @param op: op_t const &
    @param iscode: bool

    map_ea(insn, addr, opnum, iscode) -> ea_t

    @param insn: an ida_ua.insn_t, or an address (C++: const insn_t &)
    @param addr: ea_t
    @param opnum: int
    @param iscode: bool
    """
    return _ida_ua.map_ea(*args)
class outctx_base_t(object):
    r"""
    Proxy of C++ outctx_base_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    insn_ea: "ea_t" = property(_ida_ua.outctx_base_t_insn_ea_get, _ida_ua.outctx_base_t_insn_ea_set, doc=r"""insn_ea""")
    outbuf: "qstring" = property(_ida_ua.outctx_base_t_outbuf_get, _ida_ua.outctx_base_t_outbuf_set, doc=r"""outbuf""")
    r"""
    buffer for the current output line once ready, it is moved to lnar
    """
    F32: "flags_t" = property(_ida_ua.outctx_base_t_F32_get, _ida_ua.outctx_base_t_F32_set, doc=r"""F32""")
    r"""
    please use outctx_t::F instead
    """
    default_lnnum: "int" = property(_ida_ua.outctx_base_t_default_lnnum_get, _ida_ua.outctx_base_t_default_lnnum_set, doc=r"""default_lnnum""")
    r"""
    index of the most important line in lnar
    """

    def only_main_line(self) -> "bool":
        r"""
        only_main_line(self) -> bool
        """
        return _ida_ua.outctx_base_t_only_main_line(self)

    def multiline(self) -> "bool":
        r"""
        multiline(self) -> bool
        """
        return _ida_ua.outctx_base_t_multiline(self)

    def force_code(self) -> "bool":
        r"""
        force_code(self) -> bool
        """
        return _ida_ua.outctx_base_t_force_code(self)

    def stack_view(self) -> "bool":
        r"""
        stack_view(self) -> bool
        """
        return _ida_ua.outctx_base_t_stack_view(self)

    def display_voids(self) -> "bool":
        r"""
        display_voids(self) -> bool
        """
        return _ida_ua.outctx_base_t_display_voids(self)

    def set_gen_xrefs(self, on: "bool"=True) -> "void":
        r"""
        set_gen_xrefs(self, on=True)

        @param on: bool
        """
        return _ida_ua.outctx_base_t_set_gen_xrefs(self, on)

    def set_gen_cmt(self, on: "bool"=True) -> "void":
        r"""
        set_gen_cmt(self, on=True)

        @param on: bool
        """
        return _ida_ua.outctx_base_t_set_gen_cmt(self, on)

    def clr_gen_label(self) -> "void":
        r"""
        clr_gen_label(self)
        """
        return _ida_ua.outctx_base_t_clr_gen_label(self)

    def set_gen_label(self) -> "void":
        r"""
        set_gen_label(self)
        """
        return _ida_ua.outctx_base_t_set_gen_label(self)

    def set_gen_demangled_label(self) -> "void":
        r"""
        set_gen_demangled_label(self)
        """
        return _ida_ua.outctx_base_t_set_gen_demangled_label(self)

    def set_comment_addr(self, ea: "ea_t") -> "void":
        r"""
        set_comment_addr(self, ea)

        @param ea: ea_t
        """
        return _ida_ua.outctx_base_t_set_comment_addr(self, ea)

    def set_dlbind_opnd(self) -> "void":
        r"""
        set_dlbind_opnd(self)
        """
        return _ida_ua.outctx_base_t_set_dlbind_opnd(self)

    def print_label_now(self) -> "bool":
        r"""
        print_label_now(self) -> bool
        """
        return _ida_ua.outctx_base_t_print_label_now(self)

    def forbid_annotations(self) -> "int":
        r"""
        forbid_annotations(self) -> int
        """
        return _ida_ua.outctx_base_t_forbid_annotations(self)

    def restore_ctxflags(self, saved_flags: "int") -> "void":
        r"""
        restore_ctxflags(self, saved_flags)

        @param saved_flags: int
        """
        return _ida_ua.outctx_base_t_restore_ctxflags(self, saved_flags)

    def out_printf(self, format: "char const *") -> "size_t":
        r"""
        out_printf(self, format) -> size_t
        Functions to append text to the current output buffer (outbuf) Append a
        formatted string to the output string.

        @param format: (C++: const char *) char const *
        @return: the number of characters appended
        """
        return _ida_ua.outctx_base_t_out_printf(self, format)

    def out_value(self, x: "op_t", outf: "int"=0) -> "flags64_t":
        r"""
        out_value(self, x, outf=0) -> flags64_t
        Output immediate value. Try to use this function to output all constants of
        instruction operands. This function outputs a number from x.addr or x.value in
        the form determined by F. It outputs colored text.

        @param x: (C++: const op_t &) value to output
        @param outf: (C++: int) Output value flags
        @return: flags of the output value, otherwise: -1 if printed a number with
                 COLOR_ERROR 0 if printed a nice number or character or segment or enum
        """
        return _ida_ua.outctx_base_t_out_value(self, x, outf)

    def out_symbol(self, c: "char") -> "void":
        r"""
        out_symbol(self, c)
        Output a character with COLOR_SYMBOL color.

        @param c: (C++: char)
        """
        return _ida_ua.outctx_base_t_out_symbol(self, c)

    def out_chars(self, c: "char", n: "int") -> "void":
        r"""
        out_chars(self, c, n)
        Append a character multiple times.

        @param c: (C++: char)
        @param n: (C++: int)
        """
        return _ida_ua.outctx_base_t_out_chars(self, c, n)

    def out_spaces(self, len: "ssize_t") -> "void":
        r"""
        out_spaces(self, len)
        Appends spaces to outbuf until its tag_strlen becomes 'len'.

        @param len: (C++: ssize_t)
        """
        return _ida_ua.outctx_base_t_out_spaces(self, len)

    def out_line(self, str: "char const *", color: "color_t"=0) -> "void":
        r"""
        out_line(self, str, color=0)
        Output a string with the specified color.

        @param str: (C++: const char *) char const *
        @param color: (C++: color_t)
        """
        return _ida_ua.outctx_base_t_out_line(self, str, color)

    def out_keyword(self, str: "char const *") -> "void":
        r"""
        out_keyword(self, str)
        Output a string with COLOR_KEYWORD color.

        @param str: (C++: const char *) char const *
        """
        return _ida_ua.outctx_base_t_out_keyword(self, str)

    def out_register(self, str: "char const *") -> "void":
        r"""
        out_register(self, str)
        Output a character with COLOR_REG color.

        @param str: (C++: const char *) char const *
        """
        return _ida_ua.outctx_base_t_out_register(self, str)

    def out_tagon(self, tag: "color_t") -> "void":
        r"""
        out_tagon(self, tag)
        Output "turn color on" escape sequence.

        @param tag: (C++: color_t)
        """
        return _ida_ua.outctx_base_t_out_tagon(self, tag)

    def out_tagoff(self, tag: "color_t") -> "void":
        r"""
        out_tagoff(self, tag)
        Output "turn color off" escape sequence.

        @param tag: (C++: color_t)
        """
        return _ida_ua.outctx_base_t_out_tagoff(self, tag)

    def out_addr_tag(self, ea: "ea_t") -> "void":
        r"""
        out_addr_tag(self, ea)
        Output "address" escape sequence.

        @param ea: (C++: ea_t)
        """
        return _ida_ua.outctx_base_t_out_addr_tag(self, ea)

    def out_colored_register_line(self, str: "char const *") -> "void":
        r"""
        out_colored_register_line(self, str)
        Output a colored line with register names in it. The register names will be
        substituted by user-defined names (regvar_t) Please note that out_tagoff tries
        to make substitutions too (when called with COLOR_REG)

        @param str: (C++: const char *) char const *
        """
        return _ida_ua.outctx_base_t_out_colored_register_line(self, str)

    def out_char(self, c: "char") -> "void":
        r"""
        out_char(self, c)
        Output one character. The character is output without color codes. see also
        out_symbol()

        @param c: (C++: char)
        """
        return _ida_ua.outctx_base_t_out_char(self, c)

    def out_btoa(self, Word: "uval_t", radix: "char"=0) -> "void":
        r"""
        out_btoa(self, Word, radix=0)
        Output a number with the specified base (binary, octal, decimal, hex) The number
        is output without color codes. see also out_long()

        @param Word: (C++: uval_t)
        @param radix: (C++: char)
        """
        return _ida_ua.outctx_base_t_out_btoa(self, Word, radix)

    def out_long(self, v: "sval_t", radix: "char") -> "void":
        r"""
        out_long(self, v, radix)
        Output a number with appropriate color. Low level function. Use out_value() if
        you can. if 'suspop' is set then this function uses COLOR_VOIDOP instead of
        COLOR_NUMBER. 'suspop' is initialized:
        * in out_one_operand()
        * in ..\ida\gl.cpp (before calling processor_t::d_out())

        @param v: (C++: sval_t) value to output
        @param radix: (C++: char) base (2,8,10,16)
        """
        return _ida_ua.outctx_base_t_out_long(self, v, radix)

    def out_name_expr(self, *args) -> "bool":
        r"""
        out_name_expr(self, x, ea, off=BADADDR) -> bool
        Output a name expression.

        @param x: (C++: const op_t &) instruction operand referencing the name expression
        @param ea: (C++: ea_t) address to convert to name expression
        @param off: (C++: adiff_t) the value of name expression. this parameter is used only to check
                    that the name expression will have the wanted value. You may pass
                    BADADDR for this parameter but I discourage it because it prohibits
                    checks.
        @return: true if the name expression has been produced
        """
        return _ida_ua.outctx_base_t_out_name_expr(self, *args)

    def close_comment(self) -> "void":
        r"""
        close_comment(self)
        """
        return _ida_ua.outctx_base_t_close_comment(self)

    def flush_outbuf(self, indent: "int"=-1) -> "bool":
        r"""
        flush_outbuf(self, indent=-1) -> bool
        Functions to populate the output line array (lnar) Move the contents of the
        output buffer to the line array (outbuf->lnar) The kernel augments the outbuf
        contents with additional text like the line prefix, user-defined comments,
        xrefs, etc at this call.

        @param indent: (C++: int)
        """
        return _ida_ua.outctx_base_t_flush_outbuf(self, indent)

    def flush_buf(self, buf: "char const *", indent: "int"=-1) -> "bool":
        r"""
        flush_buf(self, buf, indent=-1) -> bool
        Append contents of 'buf' to the line array. Behaves like flush_outbuf but
        accepts an arbitrary buffer

        @param buf: (C++: const char *) char const *
        @param indent: (C++: int)
        """
        return _ida_ua.outctx_base_t_flush_buf(self, buf, indent)

    def term_outctx(self, prefix: "char const *"=None) -> "int":
        r"""
        term_outctx(self, prefix=None) -> int
        Finalize the output context.

        @param prefix: (C++: const char *) char const *
        @return: the number of generated lines.
        """
        return _ida_ua.outctx_base_t_term_outctx(self, prefix)

    def gen_printf(self, indent: "int", format: "char const *") -> "bool":
        r"""
        gen_printf(self, indent, format) -> bool
        printf-like function to add lines to the line array.

        @param indent: (C++: int) indention of the line. if indent == -1, the kernel will indent
                       the line at idainfo::indent. if indent < 0, -indent will be used
                       for indention. The first line printed with indent < 0 is
                       considered as the most important line at the current address.
                       Usually it is the line with the instruction itself. This line
                       will be displayed in the cross-reference lists and other places.
                       If you need to output an additional line before the main line
                       then pass DEFAULT_INDENT instead of -1. The kernel will know that
                       your line is not the most important one.
        @param format: (C++: const char *) printf style colored line to generate
        @return: overflow, lnar_maxsize has been reached
        """
        return _ida_ua.outctx_base_t_gen_printf(self, indent, format)

    def gen_empty_line(self) -> "bool":
        r"""
        gen_empty_line(self) -> bool
        Generate empty line. This function does nothing if generation of empty lines is
        disabled.

        @return: overflow, lnar_maxsize has been reached
        """
        return _ida_ua.outctx_base_t_gen_empty_line(self)

    def gen_border_line(self, solid: "bool"=False) -> "bool":
        r"""
        gen_border_line(self, solid=False) -> bool
        Generate thin border line. This function does nothing if generation of border
        lines is disabled.

        @param solid: (C++: bool) generate solid border line (with =), otherwise with -
        @return: overflow, lnar_maxsize has been reached
        """
        return _ida_ua.outctx_base_t_gen_border_line(self, solid)

    def gen_cmt_line(self, format: "char const *") -> "bool":
        r"""
        gen_cmt_line(self, format) -> bool
        Generate one non-indented comment line, colored with COLOR_AUTOCMT.

        @param format: (C++: const char *) printf() style format line. The resulting comment line should not
                       include comment character (;)
        @return: overflow, lnar_maxsize has been reached
        """
        return _ida_ua.outctx_base_t_gen_cmt_line(self, format)

    def gen_collapsed_line(self, format: "char const *") -> "bool":
        r"""
        gen_collapsed_line(self, format) -> bool
        Generate one non-indented comment line, colored with COLOR_COLLAPSED.

        @param format: (C++: const char *) printf() style format line. The resulting comment line should not
                       include comment character (;)
        @return: overflow, lnar_maxsize has been reached
        """
        return _ida_ua.outctx_base_t_gen_collapsed_line(self, format)

    def gen_block_cmt(self, cmt: "char const *", color: "color_t") -> "bool":
        r"""
        gen_block_cmt(self, cmt, color) -> bool
        Generate big non-indented comment lines.

        @param cmt: (C++: const char *) comment text. may contain \n characters to denote new lines. should
                    not contain comment character (;)
        @param color: (C++: color_t) color of comment text (one of Color tags)
        @return: overflow, lnar_maxsize has been reached
        """
        return _ida_ua.outctx_base_t_gen_block_cmt(self, cmt, color)

    def setup_outctx(self, prefix: "char const *", makeline_flags: "int") -> "void":
        r"""
        setup_outctx(self, prefix, makeline_flags)
        Initialization; normally used only by the kernel.

        @param prefix: (C++: const char *) char const *
        @param makeline_flags: (C++: int)
        """
        return _ida_ua.outctx_base_t_setup_outctx(self, prefix, makeline_flags)

    def retrieve_cmt(self) -> "ssize_t":
        r"""
        retrieve_cmt(self) -> ssize_t
        """
        return _ida_ua.outctx_base_t_retrieve_cmt(self)

    def retrieve_name(self, arg2: "qstring *", arg3: "color_t *") -> "ssize_t":
        r"""
        retrieve_name(self, arg2, arg3) -> ssize_t

        @param arg2: qstring *
        @param arg3: color_t *
        """
        return _ida_ua.outctx_base_t_retrieve_name(self, arg2, arg3)

    def gen_xref_lines(self) -> "bool":
        r"""
        gen_xref_lines(self) -> bool
        """
        return _ida_ua.outctx_base_t_gen_xref_lines(self)

    def init_lines_array(self, answers: "qstrvec_t *", maxsize: "int") -> "void":
        r"""
        init_lines_array(self, answers, maxsize)

        @param answers: qstrvec_t *
        @param maxsize: int
        """
        return _ida_ua.outctx_base_t_init_lines_array(self, answers, maxsize)

    def get_stkvar(self, x: "op_t", v: "uval_t", vv: "sval_t *", is_sp_based: "int *", _frame: "tinfo_t") -> "ssize_t":
        r"""
        get_stkvar(self, x, v, vv, is_sp_based, _frame) -> ssize_t

        @param x: op_t const &
        @param v: uval_t
        @param vv: sval_t *
        @param is_sp_based: int *
        @param _frame: tinfo_t *
        """
        return _ida_ua.outctx_base_t_get_stkvar(self, x, v, vv, is_sp_based, _frame)

    def gen_empty_line_without_annotations(self) -> "void":
        r"""
        gen_empty_line_without_annotations(self)
        """
        return _ida_ua.outctx_base_t_gen_empty_line_without_annotations(self)

    def getF(self) -> "flags64_t":
        r"""
        getF(self) -> flags64_t
        """
        return _ida_ua.outctx_base_t_getF(self)

# Register outctx_base_t in _ida_ua:
_ida_ua.outctx_base_t_swigregister(outctx_base_t)
CTXF_MAIN = _ida_ua.CTXF_MAIN
r"""
produce only the essential line(s)
"""

CTXF_MULTI = _ida_ua.CTXF_MULTI
r"""
enable multi-line essential lines
"""

CTXF_CODE = _ida_ua.CTXF_CODE
r"""
display as code regardless of the database flags
"""

CTXF_STACK = _ida_ua.CTXF_STACK
r"""
stack view (display undefined items as 2/4/8 bytes)
"""

CTXF_GEN_XREFS = _ida_ua.CTXF_GEN_XREFS
r"""
generate the xrefs along with the next line
"""

CTXF_XREF_STATE = _ida_ua.CTXF_XREF_STATE
r"""
xref state:
"""

XREFSTATE_NONE = _ida_ua.XREFSTATE_NONE
r"""
not generated yet
"""

XREFSTATE_GO = _ida_ua.XREFSTATE_GO
r"""
being generated
"""

XREFSTATE_DONE = _ida_ua.XREFSTATE_DONE
r"""
have been generated
"""

CTXF_GEN_CMT = _ida_ua.CTXF_GEN_CMT
r"""
generate the comment along with the next line
"""

CTXF_CMT_STATE = _ida_ua.CTXF_CMT_STATE
r"""
comment state:
"""

COMMSTATE_NONE = _ida_ua.COMMSTATE_NONE
r"""
not generated yet
"""

COMMSTATE_GO = _ida_ua.COMMSTATE_GO
r"""
being generated
"""

COMMSTATE_DONE = _ida_ua.COMMSTATE_DONE
r"""
have been generated
"""

CTXF_VOIDS = _ida_ua.CTXF_VOIDS
r"""
display void marks
"""

CTXF_NORMAL_LABEL = _ida_ua.CTXF_NORMAL_LABEL
r"""
generate plain label (+demangled label as cmt)
"""

CTXF_DEMANGLED_LABEL = _ida_ua.CTXF_DEMANGLED_LABEL
r"""
generate only demangled label as comment
"""

CTXF_LABEL_OK = _ida_ua.CTXF_LABEL_OK
r"""
the label have been generated
"""

CTXF_DEMANGLED_OK = _ida_ua.CTXF_DEMANGLED_OK
r"""
the label has been demangled successfully
"""

CTXF_OVSTORE_PRNT = _ida_ua.CTXF_OVSTORE_PRNT
r"""
out_value should store modified values
"""

CTXF_OUTCTX_T = _ida_ua.CTXF_OUTCTX_T
r"""
instance is, in fact, a outctx_t
"""

CTXF_DBLIND_OPND = _ida_ua.CTXF_DBLIND_OPND
r"""
an operand was printed with double indirection (e.g. =var in arm)
"""

CTXF_BINOP_STATE = _ida_ua.CTXF_BINOP_STATE
r"""
opcode bytes state:
"""

BINOPSTATE_NONE = _ida_ua.BINOPSTATE_NONE
r"""
not generated yet
"""

BINOPSTATE_GO = _ida_ua.BINOPSTATE_GO
r"""
being generated
"""

BINOPSTATE_DONE = _ida_ua.BINOPSTATE_DONE
r"""
have been generated
"""

CTXF_HIDDEN_ADDR = _ida_ua.CTXF_HIDDEN_ADDR
r"""
To generate an hidden addr tag at the beginning of the line.
"""

CTXF_BIT_PREFIX = _ida_ua.CTXF_BIT_PREFIX
r"""
generate a line prefix with a bit offset, e.g.: 12345678.3
"""

OOF_SIGNMASK = _ida_ua.OOF_SIGNMASK
r"""
sign symbol (+/-) output
"""

OOFS_IFSIGN = _ida_ua.OOFS_IFSIGN
r"""
output sign if needed
"""

OOFS_NOSIGN = _ida_ua.OOFS_NOSIGN
r"""
don't output sign, forbid the user to change the sign
"""

OOFS_NEEDSIGN = _ida_ua.OOFS_NEEDSIGN
r"""
always out sign (+-)
"""

OOF_SIGNED = _ida_ua.OOF_SIGNED
r"""
output as signed if < 0
"""

OOF_NUMBER = _ida_ua.OOF_NUMBER
r"""
always as a number
"""

OOF_WIDTHMASK = _ida_ua.OOF_WIDTHMASK
r"""
width of value in bits
"""

OOFW_IMM = _ida_ua.OOFW_IMM
r"""
take from x.dtype
"""

OOFW_8 = _ida_ua.OOFW_8
r"""
8 bit width
"""

OOFW_16 = _ida_ua.OOFW_16
r"""
16 bit width
"""

OOFW_24 = _ida_ua.OOFW_24
r"""
24 bit width
"""

OOFW_32 = _ida_ua.OOFW_32
r"""
32 bit width
"""

OOFW_64 = _ida_ua.OOFW_64
r"""
64 bit width
"""

OOF_ADDR = _ida_ua.OOF_ADDR
r"""
output x.addr, otherwise x.value
"""

OOF_OUTER = _ida_ua.OOF_OUTER
r"""
output outer operand
"""

OOF_ZSTROFF = _ida_ua.OOF_ZSTROFF
r"""
meaningful only if is_stroff(F); append a struct field name if the field offset
is zero? if AFL_ZSTROFF is set, then this flag is ignored.
"""

OOF_NOBNOT = _ida_ua.OOF_NOBNOT
r"""
prohibit use of binary not
"""

OOF_SPACES = _ida_ua.OOF_SPACES
r"""
do not suppress leading spaces; currently works only for floating point numbers
"""

OOF_ANYSERIAL = _ida_ua.OOF_ANYSERIAL
r"""
if enum: select first available serial
"""

OOF_LZEROES = _ida_ua.OOF_LZEROES
r"""
print leading zeroes
"""

OOF_NO_LZEROES = _ida_ua.OOF_NO_LZEROES
r"""
do not print leading zeroes; if none of OOF_LZEROES and OOF_NO_LZEROES was
specified, is_lzero() is used
"""

DEFAULT_INDENT = _ida_ua.DEFAULT_INDENT

MAKELINE_NONE = _ida_ua.MAKELINE_NONE

MAKELINE_BINPREF = _ida_ua.MAKELINE_BINPREF
r"""
allow display of binary prefix
"""

MAKELINE_VOID = _ida_ua.MAKELINE_VOID
r"""
allow display of '<suspicious>' marks
"""

MAKELINE_STACK = _ida_ua.MAKELINE_STACK
r"""
allow display of sp trace prefix
"""


class outctx_t(outctx_base_t):
    r"""
    Proxy of C++ outctx_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    bin_ea: "ea_t" = property(_ida_ua.outctx_t_bin_ea_get, _ida_ua.outctx_t_bin_ea_set, doc=r"""bin_ea""")
    bin_state: "char" = property(_ida_ua.outctx_t_bin_state_get, _ida_ua.outctx_t_bin_state_set, doc=r"""bin_state""")
    gl_bpsize: "int" = property(_ida_ua.outctx_t_gl_bpsize_get, _ida_ua.outctx_t_gl_bpsize_set, doc=r"""gl_bpsize""")
    bin_width: "int" = property(_ida_ua.outctx_t_bin_width_get, _ida_ua.outctx_t_bin_width_set, doc=r"""bin_width""")
    insn: "insn_t" = property(_ida_ua.outctx_t_insn_get, _ida_ua.outctx_t_insn_set, doc=r"""insn""")
    curlabel: "qstring" = property(_ida_ua.outctx_t_curlabel_get, _ida_ua.outctx_t_curlabel_set, doc=r"""curlabel""")
    wif: "printop_t const *" = property(_ida_ua.outctx_t_wif_get, _ida_ua.outctx_t_wif_set, doc=r"""wif""")
    procmod: "procmod_t *" = property(_ida_ua.outctx_t_procmod_get, _ida_ua.outctx_t_procmod_set, doc=r"""procmod""")
    ph: "processor_t &" = property(_ida_ua.outctx_t_ph_get, _ida_ua.outctx_t_ph_set, doc=r"""ph""")
    ash: "asm_t &" = property(_ida_ua.outctx_t_ash_get, _ida_ua.outctx_t_ash_set, doc=r"""ash""")
    saved_immvals: "uval_t [8]" = property(_ida_ua.outctx_t_saved_immvals_get, _ida_ua.outctx_t_saved_immvals_set, doc=r"""saved_immvals""")
    prefix_ea: "ea_t" = property(_ida_ua.outctx_t_prefix_ea_get, _ida_ua.outctx_t_prefix_ea_set, doc=r"""prefix_ea""")
    next_line_ea: "ea_t" = property(_ida_ua.outctx_t_next_line_ea_get, _ida_ua.outctx_t_next_line_ea_set, doc=r"""next_line_ea""")

    def setup_outctx(self, prefix: "char const *", flags: "int") -> "void":
        r"""
        setup_outctx(self, prefix, flags)
        Initialization; normally used only by the kernel.

        @param prefix: (C++: const char *) char const *
        @param flags: int
        """
        return _ida_ua.outctx_t_setup_outctx(self, prefix, flags)

    def term_outctx(self, prefix: "char const *"=None) -> "int":
        r"""
        term_outctx(self, prefix=None) -> int
        Finalize the output context.

        @param prefix: (C++: const char *) char const *
        @return: the number of generated lines.
        """
        return _ida_ua.outctx_t_term_outctx(self, prefix)

    def retrieve_cmt(self) -> "ssize_t":
        r"""
        retrieve_cmt(self) -> ssize_t
        """
        return _ida_ua.outctx_t_retrieve_cmt(self)

    def retrieve_name(self, arg2: "qstring *", arg3: "color_t *") -> "ssize_t":
        r"""
        retrieve_name(self, arg2, arg3) -> ssize_t

        @param arg2: qstring *
        @param arg3: color_t *
        """
        return _ida_ua.outctx_t_retrieve_name(self, arg2, arg3)

    def gen_xref_lines(self) -> "bool":
        r"""
        gen_xref_lines(self) -> bool
        """
        return _ida_ua.outctx_t_gen_xref_lines(self)

    def out_btoa(self, Word: "uval_t", radix: "char"=0) -> "void":
        r"""
        out_btoa(self, Word, radix=0)
        Output a number with the specified base (binary, octal, decimal, hex) The number
        is output without color codes. see also out_long()

        @param Word: (C++: uval_t)
        @param radix: (C++: char)
        """
        return _ida_ua.outctx_t_out_btoa(self, Word, radix)

    def set_bin_state(self, value: "int") -> "void":
        r"""
        set_bin_state(self, value)

        @param value: int
        """
        return _ida_ua.outctx_t_set_bin_state(self, value)

    def out_mnem(self, width: "int"=8, postfix: "char const *"=None) -> "void":
        r"""
        out_mnem(self, width=8, postfix=None)
        Output instruction mnemonic for 'insn' using information in 'ph.instruc' array.
        This function outputs colored text. It should be called from
        processor_t::ev_out_insn() or processor_t::ev_out_mnem() handler. It will output
        at least one space after the instruction. mnemonic even if the specified 'width'
        is not enough.

        @param width: (C++: int) width of field with mnemonic. if < 0, then 'postfix' will be
                      output before the mnemonic, i.e. as a prefix
        @param postfix: (C++: const char *) optional postfix added to the instruction mnemonic
        """
        return _ida_ua.outctx_t_out_mnem(self, width, postfix)

    def out_custom_mnem(self, mnem: "char const *", width: "int"=8, postfix: "char const *"=None) -> "void":
        r"""
        out_custom_mnem(self, mnem, width=8, postfix=None)
        Output custom mnemonic for 'insn'. E.g. if it should differ from the one in
        'ph.instruc'. This function outputs colored text. See out_mnem

        @param mnem: (C++: const char *) custom mnemonic
        @param width: (C++: int) width of field with mnemonic. if < 0, then 'postfix' will be
                      output before the mnemonic, i.e. as a prefix
        @param postfix: (C++: const char *) optional postfix added to 'mnem'
        """
        return _ida_ua.outctx_t_out_custom_mnem(self, mnem, width, postfix)

    def out_mnemonic(self) -> "void":
        r"""
        out_mnemonic(self)
        Output instruction mnemonic using information in 'insn'. It should be called
        from processor_t::ev_out_insn() and it will call processor_t::ev_out_mnem() or
        out_mnem. This function outputs colored text.
        """
        return _ida_ua.outctx_t_out_mnemonic(self)

    def out_one_operand(self, n: "int") -> "bool":
        r"""
        out_one_operand(self, n) -> bool
        Use this function to output an operand of an instruction. This function checks
        for the existence of a manually defined operand and will output it if it exists.
        It should be called from processor_t::ev_out_insn() and it will call
        processor_t::ev_out_operand(). This function outputs colored text.

        @param n: (C++: int) 0..UA_MAXOP-1 operand number
        @retval 1: operand is displayed
        @retval 0: operand is hidden
        """
        return _ida_ua.outctx_t_out_one_operand(self, n)

    def out_immchar_cmts(self) -> "void":
        r"""
        out_immchar_cmts(self)
        Print all operand values as commented character constants. This function is used
        to comment void operands with their representation in the form of character
        constants. This function outputs colored text.
        """
        return _ida_ua.outctx_t_out_immchar_cmts(self)

    def gen_func_header(self, pfn: "func_t *") -> "void":
        r"""
        gen_func_header(self, pfn)

        @param pfn: func_t *
        """
        return _ida_ua.outctx_t_gen_func_header(self, pfn)

    def gen_func_footer(self, pfn: "func_t const *") -> "void":
        r"""
        gen_func_footer(self, pfn)

        @param pfn: func_t const *
        """
        return _ida_ua.outctx_t_gen_func_footer(self, pfn)

    def out_data(self, analyze_only: "bool") -> "void":
        r"""
        out_data(self, analyze_only)

        @param analyze_only: bool
        """
        return _ida_ua.outctx_t_out_data(self, analyze_only)

    def out_specea(self, segtype: "uchar") -> "bool":
        r"""
        out_specea(self, segtype) -> bool

        @param segtype: uchar
        """
        return _ida_ua.outctx_t_out_specea(self, segtype)

    def gen_header_extra(self) -> "void":
        r"""
        gen_header_extra(self)
        """
        return _ida_ua.outctx_t_gen_header_extra(self)

    def gen_header(self, *args) -> "void":
        r"""
        gen_header(self, flags=((1 << 0)|(1 << 1)), proc_name=None, proc_flavour=None)

        @param flags: int
        @param proc_name: char const *
        @param proc_flavour: char const *
        """
        return _ida_ua.outctx_t_gen_header(self, *args)

    def out_fcref_names(self) -> "void":
        r"""
        out_fcref_names(self)
        Print addresses referenced *from* the specified address as commented symbolic
        names. This function is used to show, for example, multiple callees of an
        indirect call. This function outputs colored text.
        """
        return _ida_ua.outctx_t_out_fcref_names(self)

# Register outctx_t in _ida_ua:
_ida_ua.outctx_t_swigregister(outctx_t)
GH_PRINT_PROC = _ida_ua.GH_PRINT_PROC
r"""
processor name
"""

GH_PRINT_ASM = _ida_ua.GH_PRINT_ASM
r"""
selected assembler
"""

GH_PRINT_BYTESEX = _ida_ua.GH_PRINT_BYTESEX
r"""
byte sex
"""

GH_PRINT_HEADER = _ida_ua.GH_PRINT_HEADER
r"""
lines from ash.header
"""

GH_BYTESEX_HAS_HIGHBYTE = _ida_ua.GH_BYTESEX_HAS_HIGHBYTE
r"""
describe inf.is_wide_high_byte_first()
"""

GH_PRINT_PROC_AND_ASM = _ida_ua.GH_PRINT_PROC_AND_ASM

GH_PRINT_PROC_ASM_AND_BYTESEX = _ida_ua.GH_PRINT_PROC_ASM_AND_BYTESEX

GH_PRINT_ALL = _ida_ua.GH_PRINT_ALL

GH_PRINT_ALL_BUT_BYTESEX = _ida_ua.GH_PRINT_ALL_BUT_BYTESEX



def create_outctx(ea: "ea_t", F: "flags64_t"=0, suspop: "int"=0) -> "outctx_base_t *":
    r"""
    create_outctx(ea, F=0, suspop=0) -> outctx_base_t
    Create a new output context. To delete it, just use "delete pctx"

    @param ea: (C++: ea_t)
    @param F: (C++: flags64_t)
    @param suspop: (C++: int)
    """
    return _ida_ua.create_outctx(ea, F, suspop)

def print_insn_mnem(ea: "ea_t") -> "qstring *":
    r"""
    print_insn_mnem(ea) -> str
    Print instruction mnemonics.

    @param ea: (C++: ea_t) linear address of the instruction
    @return: success
    """
    return _ida_ua.print_insn_mnem(ea)
FCBF_CONT = _ida_ua.FCBF_CONT
r"""
don't stop on decoding, or any other kind of error
"""

FCBF_ERR_REPL = _ida_ua.FCBF_ERR_REPL
r"""
in case of an error, use a CP_REPLCHAR instead of a hex representation of the
problematic byte
"""

FCBF_FF_LIT = _ida_ua.FCBF_FF_LIT
r"""
in case of codepoints == 0xFF, use it as-is (i.e., LATIN SMALL LETTER Y WITH
DIAERESIS). If both this, and FCBF_REPL are specified, this will take precedence
"""

FCBF_DELIM = _ida_ua.FCBF_DELIM
r"""
add the 'ash'-specified delimiters around the generated data. Note: if those are
not defined and the INFFL_ALLASM is not set, format_charlit() will return an
error
"""


def get_dtype_flag(dtype: "op_dtype_t") -> "flags64_t":
    r"""
    get_dtype_flag(dtype) -> flags64_t
    Get flags for op_t::dtype field.

    @param dtype: (C++: op_dtype_t)
    """
    return _ida_ua.get_dtype_flag(dtype)

def get_dtype_size(dtype: "op_dtype_t") -> "size_t":
    r"""
    get_dtype_size(dtype) -> size_t
    Get size of opt_::dtype field.

    @param dtype: (C++: op_dtype_t)
    """
    return _ida_ua.get_dtype_size(dtype)

def is_floating_dtype(dtype: "op_dtype_t") -> "bool":
    r"""
    is_floating_dtype(dtype) -> bool
    Is a floating type operand?

    @param dtype: (C++: op_dtype_t)
    """
    return _ida_ua.is_floating_dtype(dtype)

def create_insn(ea: "ea_t", out: "insn_t"=None) -> "int":
    r"""
    create_insn(ea, out=None) -> int
    Create an instruction at the specified address. This function checks if an
    instruction is present at the specified address and will try to create one if
    there is none. It will fail if there is a data item or other items hindering the
    creation of the new instruction. This function will also fill the 'out'
    structure.

    @param ea: (C++: ea_t) linear address
    @param out: (C++: insn_t *) the resulting instruction
    @return: the length of the instruction or 0
    """
    return _ida_ua.create_insn(ea, out)

def decode_insn(out: "insn_t", ea: "ea_t") -> "int":
    r"""
    decode_insn(out, ea) -> int
    Analyze the specified address and fill 'out'. This function does not modify the
    database. It just tries to interpret the specified address as an instruction and
    fills the 'out' structure.

    @param out: (C++: insn_t *) the resulting instruction
    @param ea: (C++: ea_t) linear address
    @return: the length of the (possible) instruction or 0
    """
    return _ida_ua.decode_insn(out, ea)

def can_decode(ea: "ea_t") -> "bool":
    r"""
    can_decode(ea) -> bool
    Can the bytes at address 'ea' be decoded as instruction?

    @param ea: (C++: ea_t) linear address
    @return: whether or not the contents at that address could be a valid
             instruction
    """
    return _ida_ua.can_decode(ea)

def print_operand(ea: "ea_t", n: "int", getn_flags: "int"=0, newtype: "printop_t"=None) -> "qstring *":
    r"""
    print_operand(ea, n, getn_flags=0, newtype=None) -> bool
    Generate text representation for operand #n. This function will generate the
    text representation of the specified operand (includes color codes.)

    @param ea: (C++: ea_t) the item address (instruction or data)
    @param n: (C++: int) 0..UA_MAXOP-1 operand number, meaningful only for instructions
    @param getn_flags: (C++: int) Name expression flags Currently only GETN_NODUMMY is
                       accepted.
    @param newtype: (C++: struct printop_t *) if specified, print the operand using the specified type
    @return: success
    """
    return _ida_ua.print_operand(ea, n, getn_flags, newtype)

def decode_prev_insn(out: "insn_t", ea: "ea_t") -> "ea_t":
    r"""
    decode_prev_insn(out, ea) -> ea_t
    Decode previous instruction if it exists, fill 'out'.

    @param out: (C++: insn_t *) the resulting instruction
    @param ea: (C++: ea_t) the address to decode the previous instruction from
    @return: the previous instruction address (BADADDR-no such insn)
    """
    return _ida_ua.decode_prev_insn(out, ea)
class macro_constructor_t(object):
    r"""
    Proxy of C++ macro_constructor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    reserved: "size_t" = property(_ida_ua.macro_constructor_t_reserved_get, _ida_ua.macro_constructor_t_reserved_set, doc=r"""reserved""")
    __swig_destroy__ = _ida_ua.delete_macro_constructor_t

    def construct_macro(self, insn: "insn_t", enable: "bool") -> "bool":
        r"""
        construct_macro(self, insn, enable) -> bool
        Construct a macro instruction. This function may be called from ana() to
        generate a macro instruction.

        The real work is done by the 'build_macro()' virtual function. It must be
        defined by the processor module.

        construct_macro() modifies the database using the info provided by
        build_macro(). It verifies if the instruction can really be created (for
        example, that other items do not hinder), may plan to reanalyze the macro, etc.
        If the macro instructions are disabled by the user, construct_macro() will
        destroy the macro instruction. Note: if INSN_MODMAC is not set in insn.flags,
        the database will not be modified.

        @param insn: (C++: insn_t *) the instruction to modify into a macro
        @param enable: (C++: bool) enable macro generation
        @retval true: the macro instruction is generated in 'insn'
        @retval false: did not create a macro
        """
        return _ida_ua.macro_constructor_t_construct_macro(self, insn, enable)

    def build_macro(self, insn: "insn_t", may_go_forward: "bool") -> "bool":
        r"""
        build_macro(self, insn, may_go_forward) -> bool
        Try to extend the instruction.

        @param insn: (C++: insn_t *) Instruction to modify, usually the first instruction of the macro
        @param may_go_forward: (C++: bool) Is it ok to consider the next instruction for the macro?
                               This argument may be false, for example, if there is a
                               cross reference to the end of INSN. In this case creating
                               a macro is not desired. However, it may still be useful
                               to perform minor tweaks to the instruction using the
                               information about the surrounding instructions.
        @return: true if created an macro instruction. This function may modify 'insn'
                 and return false; these changes will be accepted by the kernel but the
                 instruction will not be considered as a macro.
        """
        return _ida_ua.macro_constructor_t_build_macro(self, insn, may_go_forward)

    def __init__(self):
        r"""
        __init__(self) -> macro_constructor_t

        @param self: PyObject *
        """
        if self.__class__ == macro_constructor_t:
            _self = None
        else:
            _self = self
        _ida_ua.macro_constructor_t_swiginit(self, _ida_ua.new_macro_constructor_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_ua.disown_macro_constructor_t(self)
        return weakref.proxy(self)

# Register macro_constructor_t in _ida_ua:
_ida_ua.macro_constructor_t_swigregister(macro_constructor_t)

def decode_preceding_insn(out: "insn_t", ea: "ea_t") -> "PyObject *":
    r"""
    decode_preceding_insn(out, ea) -> (int, int)
    Decodes the preceding instruction. Please check ua.hpp / decode_preceding_insn()

    @param out: instruction storage
    @param ea: current ea
    @return: tuple(preceeding_ea or BADADDR, farref = Boolean)
    """
    return _ida_ua.decode_preceding_insn(out, ea)

def construct_macro(*args) -> "bool":
    r"""
    construct_macro(_this, insn, enable) -> bool
    See ua.hpp's construct_macro().

    @param _this: macro_constructor_t *
    @param insn: insn_t *
    @param enable: bool

    construct_macro(insn, enable, build_macro) -> bool

    @param insn: insn_t &
    @param enable: bool
    @param build_macro: PyObject *
    """
    return _ida_ua.construct_macro(*args)

def get_dtype_by_size(size: "asize_t") -> "int":
    r"""
    get_dtype_by_size(size) -> int
    Get op_t::dtype from size.

    @param size: (C++: asize_t)
    """
    return _ida_ua.get_dtype_by_size(size)

def get_immvals(ea: "ea_t", n: "int", F: "flags64_t"=0) -> "PyObject *":
    r"""
    get_immvals(ea, n, F=0) -> PyObject
    Get immediate values at the specified address. This function decodes instruction
    at the specified address or inspects the data item. It finds immediate values
    and copies them to 'out'. This function will store the original value of the
    operands in 'out', unless the last bits of 'F' are "...0 11111111", in which
    case the transformed values (as needed for printing) will be stored instead.

    @param ea: (C++: ea_t) address to analyze
    @param n: (C++: int) 0..UA_MAXOP-1 operand number, OPND_ALL all the operands
    @param F: (C++: flags64_t) flags for the specified address
    @return: number of immediate values (0..2*UA_MAXOP)
    """
    return _ida_ua.get_immvals(ea, n, F)

def get_printable_immvals(ea: "ea_t", n: "int", F: "flags64_t"=0) -> "PyObject *":
    r"""
    get_printable_immvals(ea, n, F=0) -> PyObject
    Get immediate ready-to-print values at the specified address

    @param ea: (C++: ea_t) address to analyze
    @param n: (C++: int) 0..UA_MAXOP-1 operand number, OPND_ALL all the operands
    @param F: (C++: flags64_t) flags for the specified address
    @return: number of immediate values (0..2*UA_MAXOP)
    """
    return _ida_ua.get_printable_immvals(ea, n, F)

def insn_t__from_ptrval__(ptrval: "size_t") -> "insn_t *":
    r"""
    insn_t__from_ptrval__(ptrval) -> insn_t

    @param ptrval: size_t
    """
    return _ida_ua.insn_t__from_ptrval__(ptrval)

def op_t__from_ptrval__(ptrval: "size_t") -> "op_t *":
    r"""
    op_t__from_ptrval__(ptrval) -> op_t

    @param ptrval: size_t
    """
    return _ida_ua.op_t__from_ptrval__(ptrval)

def outctx_base_t__from_ptrval__(ptrval: "size_t") -> "outctx_base_t *":
    r"""
    outctx_base_t__from_ptrval__(ptrval) -> outctx_base_t

    @param ptrval: size_t
    """
    return _ida_ua.outctx_base_t__from_ptrval__(ptrval)

def outctx_t__from_ptrval__(ptrval: "size_t") -> "outctx_t *":
    r"""
    outctx_t__from_ptrval__(ptrval) -> outctx_t

    @param ptrval: size_t
    """
    return _ida_ua.outctx_t__from_ptrval__(ptrval)

#<pycode(py_ua)>
ua_mnem = print_insn_mnem
#</pycode(py_ua)>



