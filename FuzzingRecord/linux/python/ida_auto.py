r"""
Functions that work with the autoanalyzer queue.

The autoanalyzer works when IDA is not busy processing the user keystrokes. It
has several queues, each queue having its own priority. The analyzer stops when
all queues are empty.

A queue contains addresses or address ranges. The addresses are kept sorted by
their values. The analyzer will process all addresses from the first queue, then
switch to the second queue and so on. There are no limitations on the size of
the queues.

This file also contains functions that deal with the IDA status indicator and
the autoanalysis indicator. You may use these functions to change the indicator
value."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_auto
else:
    import _ida_auto

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

SWIG_PYTHON_LEGACY_BOOL = _ida_auto.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi


def get_auto_state() -> "atype_t":
    r"""
    get_auto_state() -> atype_t
    Get current state of autoanalyzer. If auto_state == AU_NONE, IDA is currently
    not running the analysis (it could be temporarily interrupted to perform the
    user's requests, for example).
    """
    return _ida_auto.get_auto_state()

def set_auto_state(new_state: "atype_t") -> "atype_t":
    r"""
    set_auto_state(new_state) -> atype_t
    Set current state of autoanalyzer.

    @param new_state: (C++: atype_t) new state of autoanalyzer
    @return: previous state
    """
    return _ida_auto.set_auto_state(new_state)
class auto_display_t(object):
    r"""
    Proxy of C++ auto_display_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    type: "atype_t" = property(_ida_auto.auto_display_t_type_get, _ida_auto.auto_display_t_type_set, doc=r"""type""")
    ea: "ea_t" = property(_ida_auto.auto_display_t_ea_get, _ida_auto.auto_display_t_ea_set, doc=r"""ea""")
    state: "idastate_t" = property(_ida_auto.auto_display_t_state_get, _ida_auto.auto_display_t_state_set, doc=r"""state""")

    def __init__(self):
        r"""
        __init__(self) -> auto_display_t
        """
        _ida_auto.auto_display_t_swiginit(self, _ida_auto.new_auto_display_t())
    __swig_destroy__ = _ida_auto.delete_auto_display_t

# Register auto_display_t in _ida_auto:
_ida_auto.auto_display_t_swigregister(auto_display_t)
cvar = _ida_auto.cvar
AU_NONE = cvar.AU_NONE
r"""
placeholder, not used
"""
AU_UNK = cvar.AU_UNK
r"""
0: convert to unexplored
"""
AU_CODE = cvar.AU_CODE
r"""
1: convert to instruction
"""
AU_WEAK = cvar.AU_WEAK
r"""
2: convert to instruction (ida decision)
"""
AU_PROC = cvar.AU_PROC
r"""
3: convert to procedure start
"""
AU_TAIL = cvar.AU_TAIL
r"""
4: add a procedure tail
"""
AU_FCHUNK = cvar.AU_FCHUNK
r"""
5: find func chunks
"""
AU_USED = cvar.AU_USED
r"""
6: reanalyze
"""
AU_USD2 = cvar.AU_USD2
r"""
7: reanalyze, second pass
"""
AU_TYPE = cvar.AU_TYPE
r"""
8: apply type information
"""
AU_LIBF = cvar.AU_LIBF
r"""
9: apply signature to address
"""
AU_LBF2 = cvar.AU_LBF2
r"""
10: the same, second pass
"""
AU_LBF3 = cvar.AU_LBF3
r"""
11: the same, third pass
"""
AU_CHLB = cvar.AU_CHLB
r"""
12: load signature file (file name is kept separately)
"""
AU_FINAL = cvar.AU_FINAL
r"""
13: final pass
"""
st_Ready = cvar.st_Ready
r"""
READY: IDA is doing nothing.
"""
st_Think = cvar.st_Think
r"""
THINKING: Autoanalysis on, the user may press keys.
"""
st_Waiting = cvar.st_Waiting
r"""
WAITING: Waiting for the user input.
"""
st_Work = cvar.st_Work
r"""
BUSY: IDA is busy.
"""


def get_auto_display(auto_display: "auto_display_t") -> "bool":
    r"""
    get_auto_display(auto_display) -> bool
    Get structure which holds the autoanalysis indicator contents.

    @param auto_display: (C++: auto_display_t *)
    """
    return _ida_auto.get_auto_display(auto_display)

def show_auto(*args) -> "void":
    r"""
    show_auto(ea, type=AU_NONE)
    Change autoanalysis indicator value.

    @param ea: (C++: ea_t) linear address being analyzed
    @param type: (C++: atype_t) autoanalysis type (see Autoanalysis queues)
    """
    return _ida_auto.show_auto(*args)

def show_addr(ea: "ea_t") -> "void":
    r"""
    show_addr(ea)
    Show an address on the autoanalysis indicator. The address is displayed in the
    form " @:12345678".

    @param ea: (C++: ea_t) - linear address to display
    """
    return _ida_auto.show_addr(ea)

def set_ida_state(st: "idastate_t") -> "idastate_t":
    r"""
    set_ida_state(st) -> idastate_t
    Change IDA status indicator value

    @param st: (C++: idastate_t) - new indicator status
    @return: old indicator status
    """
    return _ida_auto.set_ida_state(st)

def may_create_stkvars() -> "bool":
    r"""
    may_create_stkvars() -> bool
    Is it allowed to create stack variables automatically?. This function should be
    used by IDP modules before creating stack vars.
    """
    return _ida_auto.may_create_stkvars()

def may_trace_sp() -> "bool":
    r"""
    may_trace_sp() -> bool
    Is it allowed to trace stack pointer automatically?. This function should be
    used by IDP modules before tracing sp.
    """
    return _ida_auto.may_trace_sp()

def auto_mark_range(start: "ea_t", end: "ea_t", type: "atype_t") -> "void":
    r"""
    auto_mark_range(start, end, type)
    Put range of addresses into a queue. 'start' may be higher than 'end', the
    kernel will swap them in this case. 'end' doesn't belong to the range.

    @param start: (C++: ea_t)
    @param end: (C++: ea_t)
    @param type: (C++: atype_t)
    """
    return _ida_auto.auto_mark_range(start, end, type)

def auto_mark(ea: "ea_t", type: "atype_t") -> "void":
    r"""
    auto_mark(ea, type)
    Put single address into a queue. Queues keep addresses sorted.

    @param ea: (C++: ea_t)
    @param type: (C++: atype_t)
    """
    return _ida_auto.auto_mark(ea, type)

def auto_unmark(start: "ea_t", end: "ea_t", type: "atype_t") -> "void":
    r"""
    auto_unmark(start, end, type)
    Remove range of addresses from a queue. 'start' may be higher than 'end', the
    kernel will swap them in this case. 'end' doesn't belong to the range.

    @param start: (C++: ea_t)
    @param end: (C++: ea_t)
    @param type: (C++: atype_t)
    """
    return _ida_auto.auto_unmark(start, end, type)

def plan_ea(ea: "ea_t") -> "void":
    r"""
    plan_ea(ea)
    Plan to perform reanalysis.

    @param ea: (C++: ea_t)
    """
    return _ida_auto.plan_ea(ea)

def plan_range(sEA: "ea_t", eEA: "ea_t") -> "void":
    r"""
    plan_range(sEA, eEA)
    Plan to perform reanalysis.

    @param sEA: (C++: ea_t)
    @param eEA: (C++: ea_t)
    """
    return _ida_auto.plan_range(sEA, eEA)

def auto_make_code(ea: "ea_t") -> "void":
    r"""
    auto_make_code(ea)
    Plan to make code.

    @param ea: (C++: ea_t)
    """
    return _ida_auto.auto_make_code(ea)

def auto_make_proc(ea: "ea_t") -> "void":
    r"""
    auto_make_proc(ea)
    Plan to make code&function.

    @param ea: (C++: ea_t)
    """
    return _ida_auto.auto_make_proc(ea)

def auto_postpone_analysis(ea: "ea_t") -> "bool":
    r"""
    auto_postpone_analysis(ea) -> bool
    Plan to reanalyze on the second pass The typical usage of this function in
    emu.cpp is: if ( !auto_postpone_analysis(ea) ) op_offset(ea, 0, ...); (we make
    an offset only on the second pass)

    @param ea: (C++: ea_t)
    """
    return _ida_auto.auto_postpone_analysis(ea)

def reanalyze_callers(ea: "ea_t", noret: "bool") -> "void":
    r"""
    reanalyze_callers(ea, noret)
    Plan to reanalyze callers of the specified address. This function will add to
    AU_USED queue all instructions that call (not jump to) the specified address.

    @param ea: (C++: ea_t) linear address of callee
    @param noret: (C++: bool) !=0: the callee doesn't return, mark to undefine subsequent
                  instructions in the caller. 0: do nothing.
    """
    return _ida_auto.reanalyze_callers(ea, noret)

def revert_ida_decisions(ea1: "ea_t", ea2: "ea_t") -> "void":
    r"""
    revert_ida_decisions(ea1, ea2)
    Delete all analysis info that IDA generated for for the given range.

    @param ea1: (C++: ea_t)
    @param ea2: (C++: ea_t)
    """
    return _ida_auto.revert_ida_decisions(ea1, ea2)

def auto_apply_type(caller: "ea_t", callee: "ea_t") -> "void":
    r"""
    auto_apply_type(caller, callee)
    Plan to apply the callee's type to the calling point.

    @param caller: (C++: ea_t)
    @param callee: (C++: ea_t)
    """
    return _ida_auto.auto_apply_type(caller, callee)

def auto_apply_tail(tail_ea: "ea_t", parent_ea: "ea_t") -> "void":
    r"""
    auto_apply_tail(tail_ea, parent_ea)
    Plan to apply the tail_ea chunk to the parent

    @param tail_ea: (C++: ea_t) linear address of start of tail
    @param parent_ea: (C++: ea_t) linear address within parent. If BADADDR, automatically try to
                      find parent via xrefs.
    """
    return _ida_auto.auto_apply_tail(tail_ea, parent_ea)

def plan_and_wait(ea1: "ea_t", ea2: "ea_t", final_pass: "bool"=True) -> "int":
    r"""
    plan_and_wait(ea1, ea2, final_pass=True) -> int
    Analyze the specified range. Try to create instructions where possible. Make the
    final pass over the specified range if specified. This function doesn't return
    until the range is analyzed.
    @retval 1: ok
    @retval 0: Ctrl-Break was pressed

    @param ea1: (C++: ea_t)
    @param ea2: (C++: ea_t)
    @param final_pass: (C++: bool)
    """
    return _ida_auto.plan_and_wait(ea1, ea2, final_pass)

def auto_wait() -> "bool":
    r"""
    auto_wait() -> bool
    Process everything in the queues and return true.

    @return: false if the user clicked cancel. (the wait box must be displayed by
             the caller if desired)
    """
    return _ida_auto.auto_wait()

def auto_wait_range(ea1: "ea_t", ea2: "ea_t") -> "ssize_t":
    r"""
    auto_wait_range(ea1, ea2) -> ssize_t
    Process everything in the specified range and return true.

    @param ea1: (C++: ea_t)
    @param ea2: (C++: ea_t)
    @return: number of autoanalysis steps made. -1 if the user clicked cancel. (the
             wait box must be displayed by the caller if desired)
    """
    return _ida_auto.auto_wait_range(ea1, ea2)

def auto_make_step(ea1: "ea_t", ea2: "ea_t") -> "bool":
    r"""
    auto_make_step(ea1, ea2) -> bool
    Analyze one address in the specified range and return true.

    @param ea1: (C++: ea_t)
    @param ea2: (C++: ea_t)
    @return: if processed anything. false means that there is nothing to process in
             the specified range.
    """
    return _ida_auto.auto_make_step(ea1, ea2)

def auto_cancel(ea1: "ea_t", ea2: "ea_t") -> "void":
    r"""
    auto_cancel(ea1, ea2)
    Remove an address range (ea1..ea2) from queues AU_CODE, AU_PROC, AU_USED. To
    remove an address range from other queues use auto_unmark() function. 'ea1' may
    be higher than 'ea2', the kernel will swap them in this case. 'ea2' doesn't
    belong to the range.

    @param ea1: (C++: ea_t)
    @param ea2: (C++: ea_t)
    """
    return _ida_auto.auto_cancel(ea1, ea2)

def auto_is_ok() -> "bool":
    r"""
    auto_is_ok() -> bool
    Are all queues empty? (i.e. has autoanalysis finished?).
    """
    return _ida_auto.auto_is_ok()

def peek_auto_queue(low_ea: "ea_t", type: "atype_t") -> "ea_t":
    r"""
    peek_auto_queue(low_ea, type) -> ea_t
    Peek into a queue 'type' for an address not lower than 'low_ea'. Do not remove
    address from the queue.

    @param low_ea: (C++: ea_t)
    @param type: (C++: atype_t)
    @return: the address or BADADDR
    """
    return _ida_auto.peek_auto_queue(low_ea, type)

def auto_get(type: "atype_t *", lowEA: "ea_t", highEA: "ea_t") -> "ea_t":
    r"""
    auto_get(type, lowEA, highEA) -> ea_t
    Retrieve an address from queues regarding their priority. Returns BADADDR if no
    addresses not lower than 'lowEA' and less than 'highEA' are found in the queues.
    Otherwise *type will have queue type.

    @param type: (C++: atype_t *)
    @param lowEA: (C++: ea_t)
    @param highEA: (C++: ea_t)
    """
    return _ida_auto.auto_get(type, lowEA, highEA)

def auto_recreate_insn(ea: "ea_t") -> "int":
    r"""
    auto_recreate_insn(ea) -> int
    Try to create instruction

    @param ea: (C++: ea_t) linear address of callee
    @return: the length of the instruction or 0
    """
    return _ida_auto.auto_recreate_insn(ea)

def is_auto_enabled() -> "bool":
    r"""
    is_auto_enabled() -> bool
    Get autoanalyzer state.
    """
    return _ida_auto.is_auto_enabled()

def enable_auto(enable: "bool") -> "bool":
    r"""
    enable_auto(enable) -> bool
    Temporarily enable/disable autoanalyzer. Not user-facing, but rather because IDA
    sometimes need to turn AA on/off regardless of inf.s_genflags:INFFL_AUTO

    @param enable: (C++: bool)
    @return: old state
    """
    return _ida_auto.enable_auto(enable)


