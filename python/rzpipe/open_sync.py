#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""open_sync.py
This script use code from old __init__.py open object

"""

import re
import socket
import time
import os
from subprocess import Popen, PIPE
from urllib.request import urlopen
from urllib.error import URLError
from urllib.parse import quote
from .open_base import OpenBase


try:
    import fcntl
except ImportError:
    fcntl = None


class open(OpenBase):
    def __init__(self, filename="", flags=None, rizin_home=None, **kwargs):
        super(open, self).__init__(filename, flags, **kwargs)
        if flags is None:
            flags = []
        if filename.startswith("http://"):
            self._cmd = self._cmd_http
            self.uri = filename + "/cmd"
        elif filename.startswith("ccall://"):
            self._cmd = self._cmd_native
            self.uri = filename[7:]
        elif filename.startswith("tcp://"):
            r = re.match(r"tcp://(\d+\.\d+.\d+.\d+):(\d+)/?", filename)
            if not r:
                raise ValueError("You must provide the tcp address in this format:\n"
                                 "tcp://xxx.xxx.xxx.xxx:yyyy")
            self._cmd = self._cmd_tcp
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((r.group(1), int(r.group(2))))
        elif filename:
            self._cmd = self._cmd_process
            if rizin_home is not None:
                if not os.path.isdir(rizin_home):
                    raise Exception(
                        "`rizin_home` passed is invalid, leave it None or put a valid path to rizin folder"
                    )
                rze = os.path.join(rizin_home, "rizin")
            else:
                rze = "rizin"
            if os.name == "nt":
                # avoid errors on Windows when subprocess messes with name
                rze += ".exe"
            cmd = [rze, "-q0", filename]
            cmd = cmd[:1] + flags + cmd[1:]
            try:
                self.process = Popen(
                    cmd, shell=False, stdin=PIPE, stdout=PIPE, bufsize=0
                )
            except Exception:
                raise Exception("ERROR: Cannot find rizin in PATH")
            self.process.stdout.read(1)  # Reads initial \x00
            # make it non-blocking to speedup reading
            self.nonblocking = True
            fd = self.process.stdout.fileno()
            if not self.__make_non_blocking(fd):
                raise Exception("ERROR: Cannot make stdout pipe non-blocking")

    @staticmethod
    def __make_non_blocking(fd):
        if fcntl is not None:
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            return True

        if os.name != "nt":
            raise NotImplementedError()

        import msvcrt
        from ctypes import windll, byref
        from ctypes.wintypes import HANDLE, DWORD, BOOL

        try:
            from ctypes import POINTER
        except:
            from ctypes.wintypes import POINTER

        LPDWORD = POINTER(DWORD)
        SetNamedPipeHandleState = windll.kernel32.SetNamedPipeHandleState
        SetNamedPipeHandleState.argtypes = [HANDLE, LPDWORD, LPDWORD, LPDWORD]
        SetNamedPipeHandleState.restype = BOOL

        h = msvcrt.get_osfhandle(fd)

        PIPE_NOWAIT = DWORD(0x00000001)
        res = SetNamedPipeHandleState(h, byref(PIPE_NOWAIT), None, None)
        return res != 0

    def _cmd_process(self, cmd):
        cmd = cmd.strip().replace("\n", ";")
        self.process.stdin.write((cmd + "\n").encode("utf8"))
        r = self.process.stdout
        self.process.stdin.flush()
        out = b""
        while True:
            if self.nonblocking:
                try:
                    foo = r.read(4096)
                except Exception:
                    continue
            else:
                foo = r.read(1)
            if foo:
                if foo.endswith(b"\0"):
                    out += foo[:-1]
                    break

                out += foo
            else:
                # if there is no any output from pipe this loop will eat CPU, probably we have to do micro-sleep here
                if self.nonblocking:
                    time.sleep(0.001)

        return out.decode("utf-8", errors="ignore")

    def _cmd_http(self, cmd):
        try:
            quoted_cmd = quote(cmd)
            response = urlopen("{uri}/{cmd}".format(uri=self.uri, cmd=quoted_cmd))
            return response.read().decode("utf-8", errors="ignore")
        except URLError:
            pass
        return None

    def _cmd_tcp(self, cmd):
        res = b""
        self.conn.sendall(str.encode(cmd, "utf-8"))
        data = self.conn.recv(512)
        while data:
            res += data
            data = self.conn.recv(512)
        return res.decode("utf-8", errors="ignore")
