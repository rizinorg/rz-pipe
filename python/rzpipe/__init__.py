#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""rzpipe

This module provides an API to interact with the rizin
commandline interface from Python using a pipe.

The pipe can be connected to the parent process to run
Python scripts from the rizin shell itself, or it can
spawn a new process, connect via HTTP to a remote r2 http
server, etc.

Some r2 commands display the information in JSON, that's
why rzpipe provides `-j` methods to directly parse it
and return a native Python object.

Example:
  $ python
  > import rzpipe
  > r = rzpipe.open("/bin/ls")
  > print(r.cmd("pd 10"))
  > print(r.cmdj("aoj")[0]['size'])
  > r.quit()
"""

import os
import sys
import time

try:
    import r2lang
except ImportError:
    r2lang = None

VERSION = "1.4.2"

from .open_sync import open


def version():
    """Return string with the version of the rzpipe library
        """
    return VERSION


"""open class is now in open_base.py"""

# Hello World
if __name__ == "__main__":

    print("[+] Spawning r2 tcp and http servers")
    os.system("pkill r2")
    os.system("rizin -qc.:9080 /bin/ls &")
    os.system("rizin -qc=h /bin/ls &")
    time.sleep(1)

    if sys.version_info <= (3, 0):
        # Test rzpipe with local process
        print("[+] Testing python rzpipe local")
        rlocal = open("/bin/ls")
        print(rlocal.cmd("pi 5"))
        # print rlocal.cmd("pn")
        info = rlocal.cmdj("ij")
        print("Architecture: " + info["bin"]["machine"])

        # Test rzpipe with remote tcp process (launch it with "rizin -qc.:9080 myfile")
        print("[+] Testing python rzpipe tcp://")
        rremote = open("tcp://127.0.0.1:9080")
        disas = rremote.cmd("pi 5")
        if not disas:
            print("Error with remote tcp conection")
        else:
            print(disas)

        # Test rzpipe with remote http process (launch it with "rizin -qc=H myfile")
        print("[+] Testing python rzpipe http://")
        rremote = open("http://127.0.0.1:9090")
        disas = rremote.cmd("pi 5")
        if not disas:
            print("Error with remote http conection")
        else:
            print(disas)
    else:
        # --------------------------------------------------------------------------
        # Python 3 examples, with non-blocking API and callbacks
        # --------------------------------------------------------------------------
        def callback(result):
            print(result)

        #
        # Test rzpipe with local process
        #
        #   Start 1 task
        print("[+] Testing python rzpipe local")
        rlocal = open("/bin/ls")
        t = rlocal.cmd("pi 5", callback=callback)
        rlocal.wait(t)  # Wait for task end
        info = rlocal.cmdj("ij")
        rlocal.wait(info)
        print("Architecture: " + info["bin"]["machine"])
        rlocal.close()
        #   Start 3 tasks with Context manager
        print("[+] Testing python rzpipe local with 3 queries")
        with open("/bin/ls") as rlocall:
            t1 = rlocall.cmd("pi 5", callback=callback)
            t2 = rlocall.cmd("pi 5", callback=callback)
            t3 = rlocall.cmd("pi 5", callback=callback)
            rlocall.wait([t1, t2, t3])

        #
        # Test rzpipe with remote tcp process (launch it with "rizin -qc.:9080 myfile")
        #
        #   Start 1 task
        print("[+] Testing python rzpipe tcp://")
        rremote = open("tcp://127.0.0.1:9080")
        t = rremote.cmd("pi 5", callback=callback)
        rremote.wait(t)
        rremote.close()

        #   Start 3 tasks with Context manager
        print("[+] Testing python rzpipe tcp:// with 3 queries")
        with open("tcp://127.0.0.1:9080") as rremote:
            t1 = rremote.cmd("pi 5", callback=callback)
            t2 = rremote.cmd("pi 5", callback=callback)
            t3 = rremote.cmd("pi 5", callback=callback)

            rremote.wait([t1, t2, t3])

        #
        # Test rzpipe with remote http process (launch it with "rizin -qc=H myfile")
        #
        print("[+] Testing python rzpipe http://")
        rremote = open("tcp://127.0.0.1:9080")
        t = rremote.cmd("pi 5", callback=callback)
        rremote.wait(t)
        rremote.close()

        #   Start 3 tasks with Context manager
        print("[+] Testing python rzpipe http:// with 3 queries")
        with open("http://127.0.0.1:9090") as rremote:
            t1 = rremote.cmd("pi 10", callback=callback)
            t2 = rremote.cmd("pi 5", callback=callback)
            t3 = rremote.cmd("pi 5", callback=callback)

            rremote.wait([t1, t2, t3])

    os.system("pkill -INT rizin")
