#!/usr/bin/env python
import sys
import rzpipe

rzp = rzpipe.open()
num = int(sys.argv[1])
if num == 0x80:
    r = rzp.cmdj("arj")
    if r["eax"] == 1:
        print("[SYSCALL EXIT] {0:d}", r["ebx"])
    elif r["eax"] == 4:
        msg = rzp.cmd("psz %d@%d" % (r["edx"], r["ecx"]))
        print("[WRITE SYSCALL] ==> {0:s}", msg)
elif num == 3:
    print("[INT3]")
else:
    print("[unhandled SYSCALL {0:d}]", num)
