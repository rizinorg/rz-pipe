import rzpipe

r2 = rzpipe.open("ccall:///bin/ls")
# r2 = rzpipe.open("/bin/ls")
# r2.cmd("o /bin/ls")
print r2.cmd("pd 10")
r2.quit()
