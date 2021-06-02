import contextlib
import os
import sys
from shutil import which

import pytest

from rzpipe import open_base


def kill(process_name):
    os.system(f"pkill {process_name}") == 0 or \
    os.system(f"killall {process_name}") == 0 or \
    os.system(f"taskkill /f /im  {process_name}") == 0 or \
    os.system(f"taskkill /f /im  {process_name}.exe") == 0


def setup(port: int = 9080):
    kill("rz-agent")
    os.system(f"rz-agent -p{port} -d")


def tear_down():
    kill("rz-agent")


@contextlib.contextmanager
def linux_test():
    setup()
    yield
    tear_down()


def test_constructor_win():
    if sys.platform.startswith("nt"):
        pytest.skip("skipping windows-only tests")
    # TODO: setup vagrant or similar to be able to add proper windows tests


def test_constructor_linux():
    """
    Tests the OpenBase constructor, the context manager and using
    OpenBase.cmd with the _cmd_native default.

    :return:
    """
    if sys.platform.startswith("win"):
        pytest.skip("skipping linux-only tests")
    with linux_test():
        with open_base.OpenBase("http://localhost:9080") as base:
            base.cmd(f"o {which('/bin/ls')}")
