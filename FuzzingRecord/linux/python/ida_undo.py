r"""
"""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_undo
else:
    import _ida_undo

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

SWIG_PYTHON_LEGACY_BOOL = _ida_undo.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi


def create_undo_point(*args) -> "bool":
    r"""
    create_undo_point(input_bytes) -> bool
    Create a new restore point. The user can undo to this point in the future.

    @param bytes: (C++: const uchar *) body of the record for UNDO_ACTION_START
    @return: success; fails if undo is disabled
    create_undo_point(bytes, size) -> bool

    @param bytes: uchar const *
    """
    return _ida_undo.create_undo_point(*args)

def perform_undo() -> "bool":
    r"""
    perform_undo() -> bool
    Perform undo.

    @return: success
    """
    return _ida_undo.perform_undo()

def perform_redo() -> "bool":
    r"""
    perform_redo() -> bool
    Perform redo.

    @return: success
    """
    return _ida_undo.perform_redo()


