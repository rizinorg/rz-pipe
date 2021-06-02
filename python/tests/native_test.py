import importlib
import sys
from unittest import mock

import pytest


def delete_quietly(to_delete, key=None):
    if not to_delete:
        return
    try:
        if not key:
            del to_delete
            return
        del to_delete[key]
    except KeyError:
        pass


def mock_find_library(func=None):
    """
    Mock ctypes.util.find_library by default to return None to trigger path of native.py
    where ImportError is thrown.

    :param func:
    :return:
    """
    if not func:
        func = lambda *args: None

    import ctypes.util

    return mock.patch.object(ctypes.util, "find_library", func)


@pytest.fixture()
def native():
    """
    Fixture for the native module to test the import related side-effects.
    :return:
    """
    delete_quietly(sys.modules, key="rzpipe.native")
    mod = importlib.import_module("rzpipe.native")
    yield mod
    delete_quietly(sys.modules, key="rzpipe.native")


def test_rz_core_not_installed():
    """
    Test the case when rizin is not installed properly.
    :return:
    """
    with pytest.raises(ImportError):
        with mock_find_library():
            # Delete also before
            delete_quietly(sys.modules, key="rzpipe.native")
            importlib.import_module("rzpipe.native")
            delete_quietly(sys.modules, key="rzpipe.native")


def test_address_holder(native):
    """
    Test the AddressHolder class under the presumption that we run under non-Windows environment

    :param native:
    :return:
    """
    if sys.platform.startswith("win"):
        pytest.skip("skipping linux-only tests")
    from ctypes import CDLL, c_int

    libc = CDLL("libc.so.6")
    func = libc.printf
    func.restype = c_int

    class Temp:
        """
        This class sole purpose is to trigger __get__ and __set__ invocations of
        AddressHolder.
        """

        address_holder = native.AddressHolder()

    o = Temp()

    # __set__ was not called yet, so o._address is supposed to raise an AttributeError
    with pytest.raises(AttributeError):
        o._address

    o.address_holder = func
    assert o._address == func


def test_wrapped_rmethod(native):
    """

    :param native:
    :return:
    """
    if sys.platform.startswith("win"):
        pytest.skip("skipping linux-only tests")

    from ctypes import CDLL

    libc = CDLL("libc.so.6")

    # varargs arguments need to be known at declaration time, otherwise this happens:
    printf = native.WrappedRMethod("printf", "c_char_p, c_char_p", "c_int", lib=libc, )
    assert printf("%s", "hehe") == 4

    printf = native.WrappedRMethod("printf", "c_char_p", "c_int", lib=libc, )
    assert printf("%s", "hehe") == 1


def test_core_contextmanager(native):
    """
    Tests the convenience contextmanager that frees the native.RzCore object after creating it
    and also

    :param native:
    :return:
    """
    if sys.platform.startswith("win"):
        pytest.skip("skipping linux-only tests")

    with native.core() as c:
        c.cmd_str("o /bin/ls")
        print(c)
        print(c.cmd_str("s entry0; pd 20"))
