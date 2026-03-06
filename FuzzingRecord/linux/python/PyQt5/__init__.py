# Copyright (c) 2021 Riverbank Computing Limited <info@riverbankcomputing.com>
# 
# This file is part of PyQt5.
# 
# This software is licensed for use under the terms of the Riverbank Commercial
# License.  See the file LICENSE for more details.  It is supplied WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.


# Support PyQt5 sub-packages that have been created by setuptools.
__path__ = __import__('pkgutil').extend_path(__path__, __name__)

# Hex-Rays addition: append version-specific subdir for sip
import os, sys
REQ = (3, 8)
v = sys.version_info[:2]
if v < REQ:
    raise ImportError("Unsupported Python version %d.%d (required >= %d.%d)" % (v, REQ) )
subdir = "python_%d.%d" % v
__path__.append(os.path.join(os.path.dirname(__file__), subdir))

