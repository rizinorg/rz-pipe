#!/usr/bin/env python3
import os
import sys
import rzpipe

curdir = os.path.dirname(os.path.realpath(__file__))

rz = rzpipe.open(curdir + "/ls", ["-2"])

# print(rzpipe.__file__)
# print(rzpipe.VERSION)

rz.cmd("aa")

sys.stdout.write("/bin/ls    ")

pi1 = rz.cmd("pi 1 @e:scr.color=0").strip()
if pi1 == "push rbp":
    print("OK")
else:
    print("FAIL")
# print(pi1)
# print(rz.cmd("pd 10"));
rz.quit()
