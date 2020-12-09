#!/usr/bin/env python3

import rzpipe

rz = rzpipe.open("/bin/ls", ["-nd"])
for a in range(1, 10):
    regs = rz.cmdj("drj")
    print("0x%x  0x%x" % (regs["rip"], regs["rsp"]))
    rz.cmd("ds")
