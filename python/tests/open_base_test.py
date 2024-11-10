import sys
from shutil import which

import pytest

from rzpipe import open_base


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
    with open_base.OpenBase(which('ls')) as base:
        base.cmd("s entry0; pd 20")
