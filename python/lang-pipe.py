#!/usr/bin/env python3
import rzpipe

r2 = rzpipe.open("#!pipe")

_dis = r2.cmd("pd 5")
print(_dis)
_hex = r2.cmd("px 64")
print(_hex)
