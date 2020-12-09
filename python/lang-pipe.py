#!/usr/bin/env python3
import rzpipe

rz = rzpipe.open("#!pipe")

_dis = rz.cmd("pd 5")
print(_dis)
_hex = rz.cmd("px 64")
print(_hex)
