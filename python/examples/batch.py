#!/usr/bin/env python3
import os
import rzpipe

rz = rzpipe.open("/bin/ls")
print(rz.cmd("?e one"))
print(rz.cmd("?e two"))
rz.quit()

rz = rzpipe.open("/bin/ls")
os.system("ps auxw| grep rizin")
print(rz.cmd("?e tri"))
rz.quit()

os.system("ps auxw| grep rizin")
