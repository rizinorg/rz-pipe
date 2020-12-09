#!/usr/bin/env python3
#
# Author: pancake@nopcode.org
#
# $ rizin -qc '#!pipe python ipython.py' /bin/ls
#

import os
import sys
import rzpipe
import IPython

rz = None
try:
    pipes = [int(os.environ["RZ_PIPE_IN"]), int(os.environ["RZ_PIPE_OUT"])]
    rz = rzpipe.open("#!pipe")
except:
    print("This script must be run from inside rizin:")
    print(" $ rizin -qi ipython.py /bin/ls")
    sys.exit(1)


class RizinBin:
    rz = None

    def __init__(self, rz):
        self.rz = rz
        self.baddr = 0
        self.filename = rz.cmd("i~file:0[1]").strip()

    def imports(self):
        if self.baddr != 0:
            return self.rz.syscmdj(
                "rz-bin -B %d -ij '%s'" % (self.baddr, self.filename)
            )["imports"]
        else:
            return self.rz.syscmdj("rz-bin -ij '%s'" % (self.filename))["imports"]

    def symbols(self):
        if self.baddr != 0:
            return self.rz.syscmdj(
                "rz-bin -B %d -sj '%s'" % (self.baddr, self.filename)
            )["symbols"]
        else:
            return self.rz.syscmdj("rz-bin -sj '%s'" % (self.filename))["symbols"]

    def entries(self):
        if self.baddr != 0:
            return self.rz.syscmdj(
                "rz-bin -B %d -ej '%s'" % (self.baddr, self.filename)
            )["entries"]
        else:
            return self.rz.syscmdj("rz-bin -ej '%s'" % (self.filename))["entries"]


class Rizin:
    rz = None
    Bin = None

    def __init__(self, rz):
        self.rz = rz
        self.Bin = RizinBin(rz)

    def seek(self, address):
        if type(address) == int:
            address = str(address)
        self.rz.cmd("s %s" % (address))
        return self

    def disasm(self, *arg):  # address, count):
        address = ""
        count = 16
        if len(arg) > 0:
            address = arg[0]
            if type(address) == int:
                address = str(address)
            if len(arg) > 1:
                count = arg[1]
        print(self.rz.cmd("e scr.color=true;pd %d @ %s" % (count, address)))
        return self

    def hexdump(self, address, count):
        if type(address) == int:
            address = str(address)
        print(self.rz.cmd("e scr.color=true;px %d @ %s" % (count, address)))
        return self


r = Rizin(rz)
r.disasm("entry0", 10)
r.hexdump("entry0", 10)

# Enter the shell
IPython.embed()
