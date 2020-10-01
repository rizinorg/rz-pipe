import os
import rzpipe

r2 = rzpipe.open("http://cloud.radare.org")
print(r2.cmd("?e one"))
r2.quit()

r2 = rzpipe.open("/bin/ls")
print(r2.cmd("?e one"))
print(r2.cmd("?e two"))
r2.quit()

r2 = rzpipe.open("/bin/ls")
os.system("ps auxw| grep rizin")
print(r2.cmd("?e tri"))
r2.quit()

os.system("ps auxw| grep rizin")
