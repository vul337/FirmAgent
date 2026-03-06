r"""
Registry related functions.

IDA uses the registry to store global configuration options that must persist
after IDA has been closed.

On Windows, IDA uses the Windows registry directly. On Unix systems, the
registry is stored in a file (typically ~/.idapro/ida.reg).

The root key for accessing IDA settings in the registry is defined by
ROOT_KEY_NAME."""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_registry
else:
    import _ida_registry

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

SWIG_PYTHON_LEGACY_BOOL = _ida_registry.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi


def reg_read_string(name: "char const *", subkey: "char const *"=None, _def: "char const *"=None) -> "PyObject *":
    r"""
    reg_read_string(name, subkey=None, _def=None) -> PyObject
    Read a string from the registry.

    @param name: (C++: const char *) value name
    @param subkey: (C++: const char *) key name
    @param def: char const *
    @return: success
    """
    return _ida_registry.reg_read_string(name, subkey, _def)

def reg_data_type(name: "char const *", subkey: "char const *"=None) -> "regval_type_t":
    r"""
    reg_data_type(name, subkey=None) -> regval_type_t
    Get data type of a given value.

    @param name: (C++: const char *) value name
    @param subkey: (C++: const char *) key name
    @return: false if the [key+]value doesn't exist
    """
    return _ida_registry.reg_data_type(name, subkey)

def reg_read_binary(name: "char const *", subkey: "char const *"=None) -> "PyObject *":
    r"""
    reg_read_binary(name, subkey=None) -> PyObject
    Read binary data from the registry.

    @param name: (C++: const char *) value name
    @param subkey: (C++: const char *) key name
    @return: success
    """
    return _ida_registry.reg_read_binary(name, subkey)

def reg_write_binary(name: "char const *", py_bytes: "PyObject *", subkey: "char const *"=None) -> "PyObject *":
    r"""
    reg_write_binary(name, py_bytes, subkey=None) -> PyObject
    Write binary data to the registry.

    @param name: (C++: const char *) value name
    @param py_bytes: PyObject *
    @param subkey: (C++: const char *) key name
    """
    return _ida_registry.reg_write_binary(name, py_bytes, subkey)

def reg_subkey_subkeys(name: "char const *") -> "PyObject *":
    r"""
    reg_subkey_subkeys(name) -> [str, ...]
    Get all subkey names of given key.

    @param name: (C++: const char *) char const *
    """
    return _ida_registry.reg_subkey_subkeys(name)

def reg_subkey_values(name: "char const *") -> "PyObject *":
    r"""
    reg_subkey_values(name) -> [str, ...]
    Get all value names under given key.

    @param name: (C++: const char *) char const *
    """
    return _ida_registry.reg_subkey_values(name)
IDA_REGISTRY_NAME = _ida_registry.IDA_REGISTRY_NAME

HVUI_REGISTRY_NAME = _ida_registry.HVUI_REGISTRY_NAME

ROOT_KEY_NAME = _ida_registry.ROOT_KEY_NAME
r"""
Default key used to store IDA settings in registry (Windows version).
@note: this name is automatically prepended to all key names passed to functions
       in this file.
"""

reg_unknown = _ida_registry.reg_unknown
r"""
unknown
"""

reg_sz = _ida_registry.reg_sz
r"""
utf8 string
"""

reg_binary = _ida_registry.reg_binary
r"""
binary data
"""

reg_dword = _ida_registry.reg_dword
r"""
32-bit number
"""


def reg_delete_subkey(name: "char const *") -> "bool":
    r"""
    reg_delete_subkey(name) -> bool
    Delete a key from the registry.

    @param name: (C++: const char *) char const *
    """
    return _ida_registry.reg_delete_subkey(name)

def reg_delete_tree(name: "char const *") -> "bool":
    r"""
    reg_delete_tree(name) -> bool
    Delete a subtree from the registry.

    @param name: (C++: const char *) char const *
    """
    return _ida_registry.reg_delete_tree(name)

def reg_delete(name: "char const *", subkey: "char const *"=None) -> "bool":
    r"""
    reg_delete(name, subkey=None) -> bool
    Delete a value from the registry.

    @param name: (C++: const char *) value name
    @param subkey: (C++: const char *) parent key
    @return: success
    """
    return _ida_registry.reg_delete(name, subkey)

def reg_subkey_exists(name: "char const *") -> "bool":
    r"""
    reg_subkey_exists(name) -> bool
    Is there already a key with the given name?

    @param name: (C++: const char *) char const *
    """
    return _ida_registry.reg_subkey_exists(name)

def reg_exists(name: "char const *", subkey: "char const *"=None) -> "bool":
    r"""
    reg_exists(name, subkey=None) -> bool
    Is there already a value with the given name?

    @param name: (C++: const char *) value name
    @param subkey: (C++: const char *) parent key
    """
    return _ida_registry.reg_exists(name, subkey)

def reg_read_strlist(subkey: "char const *") -> "qstrvec_t *":
    r"""
    reg_read_strlist(subkey)
    Retrieve all string values associated with the given key. Also see
    reg_update_strlist(), reg_write_strlist()

    @param subkey: (C++: const char *) char const *
    """
    return _ida_registry.reg_read_strlist(subkey)

def reg_write_strlist(_in: "qstrvec_t const &", subkey: "char const *") -> "void":
    r"""
    reg_write_strlist(_in, subkey)
    Write string values associated with the given key. Also see reg_read_strlist(),
    reg_update_strlist()

    @param in: (C++: const qstrvec_t &) qstrvec_t const &
    @param subkey: (C++: const char *) char const *
    """
    return _ida_registry.reg_write_strlist(_in, subkey)

def reg_update_strlist(subkey: "char const *", add: "char const *", maxrecs: "size_t", rem: "char const *"=None, ignorecase: "bool"=False) -> "void":
    r"""
    reg_update_strlist(subkey, add, maxrecs, rem=None, ignorecase=False)
    Update list of strings associated with given key.

    @param subkey: (C++: const char *) key name
    @param add: (C++: const char *) string to be added to list, can be nullptr
    @param maxrecs: (C++: size_t) limit list to this size
    @param rem: (C++: const char *) string to be removed from list, can be nullptr
    @param ignorecase: (C++: bool) ignore case for 'add' and 'rem'
    """
    return _ida_registry.reg_update_strlist(subkey, add, maxrecs, rem, ignorecase)

def reg_write_string(name: "char const *", utf8: "char const *", subkey: "char const *"=None) -> "void":
    r"""
    reg_write_string(name, utf8, subkey=None)
    Write a string to the registry.

    @param name: (C++: const char *) value name
    @param utf8: (C++: const char *) utf8-encoded string
    @param subkey: (C++: const char *) key name
    """
    return _ida_registry.reg_write_string(name, utf8, subkey)

def reg_read_int(name: "char const *", defval: "int", subkey: "char const *"=None) -> "int":
    r"""
    reg_read_int(name, defval, subkey=None) -> int
    Read integer value from the registry.

    @param name: (C++: const char *) value name
    @param defval: (C++: int) default value
    @param subkey: (C++: const char *) key name
    @return: the value read from the registry, or 'defval' if the read failed
    """
    return _ida_registry.reg_read_int(name, defval, subkey)

def reg_write_int(name: "char const *", value: "int", subkey: "char const *"=None) -> "void":
    r"""
    reg_write_int(name, value, subkey=None)
    Write integer value to the registry.

    @param name: (C++: const char *) value name
    @param value: (C++: int) value to write
    @param subkey: (C++: const char *) key name
    """
    return _ida_registry.reg_write_int(name, value, subkey)

def reg_read_bool(name: "char const *", defval: "bool", subkey: "char const *"=None) -> "bool":
    r"""
    reg_read_bool(name, defval, subkey=None) -> bool
    Read boolean value from the registry.

    @param name: (C++: const char *) value name
    @param defval: (C++: bool) default value
    @param subkey: (C++: const char *) key name
    @return: boolean read from registry, or 'defval' if the read failed
    """
    return _ida_registry.reg_read_bool(name, defval, subkey)

def reg_write_bool(name: "char const *", value: "int", subkey: "char const *"=None) -> "void":
    r"""
    reg_write_bool(name, value, subkey=None)
    Write boolean value to the registry.

    @param name: (C++: const char *) value name
    @param value: (C++: int) boolean to write (nonzero = true)
    @param subkey: (C++: const char *) key name
    """
    return _ida_registry.reg_write_bool(name, value, subkey)

def reg_update_filestrlist(subkey: "char const *", add: "char const *", maxrecs: "size_t", rem: "char const *"=None) -> "void":
    r"""
    reg_update_filestrlist(subkey, add, maxrecs, rem=None)
    Update registry with a file list. Case sensitivity will vary depending on the
    target OS.
    @note: 'add' and 'rem' must be UTF-8, just like for regular string operations.

    @param subkey: (C++: const char *) char const *
    @param add: (C++: const char *) char const *
    @param maxrecs: (C++: size_t)
    @param rem: (C++: const char *) char const *
    """
    return _ida_registry.reg_update_filestrlist(subkey, add, maxrecs, rem)

def set_registry_name(name: "char const *") -> "bool":
    r"""
    set_registry_name(name) -> bool

    @param name: char const *
    """
    return _ida_registry.set_registry_name(name)


