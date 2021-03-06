#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import contextlib
import ctypes
from ctypes import Structure, addressof, c_char_p, c_void_p
from ctypes.util import find_library

lib_name = find_library("rz_core")

if not lib_name:
    raise ImportError("No native rz_core library")

try:
    from ctypes import CDLL

    lib = CDLL(lib_name)
except ImportError:
    pass

try:
    from ctypes import WinDLL

    lib = WinDLL(lib_name)
except ImportError:
    pass


class AddressHolder(object):
    def __get__(self, obj, type_):
        if getattr(obj, "_address", None) is None:
            obj._address = addressof(obj)
        return obj._address

    def __set__(self, obj, value):
        obj._address = value


class WrappedRMethod(object):
    def __init__(self, cname, args, ret, lib=lib, ):
        self.cname = cname
        self.args = args
        self.ret = ret
        self.args_set = False
        self.method = getattr(lib, cname)

    def __call__(self, *args):
        if not self.args_set:
            if self.args:
                self.method.argtypes = [
                    getattr(ctypes, x.strip()) for x in self.args.split(",")
                ]
            self.method.restype = getattr(ctypes, self.ret) if self.ret else None
            self.args_set = True
        args = list(args)
        for i, arg_type in enumerate(self.method.argtypes):
            if arg_type is c_char_p:
                args[i] = args[i].encode()
        if self.method.restype is c_char_p:
            return self.method(*args).decode()
        return self.method(*args)


class WrappedApiMethod(object):
    def __init__(self, method, ret2, last):
        self.method = method
        self._o = None
        self.ret2 = ret2
        self.last = last

    def __call__(self, *a):
        result = self.method(self._o, *a)
        if self.ret2:
            if self.ret2 == "c_char_p":
                return result
            else:
                result = getattr(ctypes, self.ret2)(result)
        if self.last:
            return getattr(result, self.last)
        return result

    def __get__(self, obj, type_):
        if type_ is RzCore:
            self._o = obj._o
        return self


def register(cname, args, ret, lib=lib):
    ret2 = last = None
    if ret:
        if "A" <= ret[0] <= "Z":
            x = ret.find("<")
            if x != -1:
                ret = ret[0:x]
            last = "contents"
            ret = "POINTER(" + ret + ")"
        else:
            last = "value"
            ret2 = ret

    method = WrappedRMethod(cname, args, ret, lib=lib,)
    wrapped_method = WrappedApiMethod(method, ret2, last)
    return wrapped_method, method


class RzCore(Structure):  # 1
    def __init__(self, lib=lib):
        Structure.__init__(self)
        rz_core_new = lib.rz_core_new
        rz_core_new.restype = c_void_p
        self._o = rz_core_new()

    _o = AddressHolder()

    cmd_str, rz_core_cmd_str = register(
        "rz_core_cmd_str",
        "c_void_p, c_char_p",
        "c_char_p",
    )

    free, rz_core_free = register(
        "rz_core_free",
        "c_void_p",
        "c_void_p",
    )


@contextlib.contextmanager
def core():
    c = RzCore()
    yield c
    c.free()


__all__ = [
    core.__name__,
    register.__name__,
    RzCore.__name__,
    WrappedRMethod.__name__,
    WrappedApiMethod.__name__,
]
#  c = RzCore()
#  c.cmd_str("o /bin/ls")
#  print(c)
#  print(c.cmd_str("s entry0;pd 20"))
#  c.free();
