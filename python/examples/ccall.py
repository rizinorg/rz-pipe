#!/usr/bin/env python3
import rzpipe

rz = rzpipe.open("ccall:///bin/ls")
# rz = rzpipe.open("/bin/ls")
# rz.cmd("o /bin/ls")
print(rz.cmd("pd 10"))
rz.quit()
