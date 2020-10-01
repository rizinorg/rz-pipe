import os
import sys
import rzpipe

curdir = os.path.dirname(os.path.realpath(__file__))

r2 = rzpipe.open(curdir + "/ls", ["-2"])

# print(rzpipe.__file__)
# print(rzpipe.VERSION)

r2.cmd("aa")

sys.stdout.write("/bin/ls    ")

pi1 = r2.cmd("pi 1 @e:scr.color=0").strip()
if pi1 == "push rbp":
    print("OK")
else:
    print("FAIL")
# print(pi1)
# print (r2.cmd("pd 10"));
r2.quit()
