#!/usr/bin/env python3

import rzpipe
import sys

r = rzpipe.open("/bin/ls")
try:
    print("rizin version: %s" % r.cmd("?V"))
    pid = int(r.cmd("?vi $p"))
    print("Killing rizin PID %d" % (pid))
    r.cmd('"!(sleep 1; kill -9 %d) &"' % pid)
    r.cmd("!sleep 3")
    print(r.cmd("x"))
    r.cmd("q")
    print("This was not expected!")
except:
    print("rizin was killed as expected")
    sys.exit(0)

sys.exit(1)
