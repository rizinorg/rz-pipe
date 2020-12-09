# /usr/bin/env python

import rzpipe
from os import system
import time

if __name__ == "__main__":
    print("[+] Spawning rizin tcp and http servers")
    system("pkill rizin")
    system("rizin -qc.:9080 /bin/ls &")
    system("rizin -qc=h /bin/ls &")
    time.sleep(1)

    # Test rzpipe with local process
    print("[+] Testing python rzpipe local")
    rlocal = rzpipe.open("/bin/ls")
    print(rlocal.cmd("pi 5"))
    # print rlocal.cmd("pn")
    info = rlocal.cmdj("ij")
    print("Architecture: " + info["bin"]["machine"])

    # Test rzpipe with remote tcp process (launch it with "rizin -qc.:9080 myfile")
    print("[+] Testing python rzpipe tcp://")
    rremote = rzpipe.open("tcp://127.0.0.1:9080")
    disas = rremote.cmd("pi 5")
    if not disas:
        print("Error with remote tcp conection")
    else:
        print(disas)

    # Test rzpipe with remote http process (launch it with "rizin -qc=H myfile")
    print("[+] Testing python rzpipe http://")
    rremote = rzpipe.open("http://127.0.0.1:9090")
    disas = rremote.cmd("pi 5")
    if not disas:
        print("Error with remote http conection")
    else:
        print(disas)
    system("pkill -INT rizin")
