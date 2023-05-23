# -*- coding: utf-8 -*-
"""open_async.py
This script use code from rzpipe-async/open_p3.py script.

"""
import asyncio
import os
import re
import typing
from collections.abc import Iterable
from contextlib import ContextDecorator
from urllib.parse import quote, urlparse

from .open_base import OpenBase, get_rizin_path


class open(OpenBase, ContextDecorator):
    # --------------------------------------------------------------------------
    # Context manager functions
    # --------------------------------------------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self):
        if self._loop.is_running():
            self._loop.stop()
        if not self._loop.is_closed():
            self._loop.close()

    def __init__(self, filename="", flags=None, rz_home=None, **kwargs):
        super(open, self).__init__(filename, flags, **kwargs)

        if flags is None:
            flags = []

        self.rz_home = rz_home

        if os.name == "nt":
            self._loop = asyncio.ProactorEventLoop()
            asyncio.set_event_loop(self._loop)
        else:
            watcher = asyncio.get_child_watcher()
            self._loop = asyncio.new_event_loop()
            watcher.attach_loop(self._loop)

        self._async = True

        if filename.startswith("http://"):
            self._cmd_coro = self._cmd_http
            self.uri = "/cmd"

            _tmp = urlparse(filename)
            self._host = _tmp.hostname
            self._port = _tmp.port

        elif filename.startswith("ccall://"):
            self._cmd_coro = self._cmd_native
            self.uri = filename[7:]

        elif filename.startswith("tcp://"):

            r = re.match(r"tcp://(\d+\.\d+.\d+.\d+):(\d+)/?", filename)
            if not r:
                raise ValueError("You must provide the tcp address in this format:\n"
                                 "tcp://xxx.xxx.xxx.xxx:yyyy")

            self._cmd_coro = self._cmd_tcp
            self._host = r.group(1)
            self._port = r.group(2)
        elif filename.startswith("https://"):
            raise ValueError("https protocol is not supported yet")
        elif filename:

            self._cmd_coro = self._cmd_process

            cmd = ["-q0", filename]
            cmd = cmd[:1] + flags + cmd[1:]
            self._process_start_cmd = cmd

        else:
            self._async = False

    def _on_cmd_finished(self, future):
        """
        After a command is invoked this helper invokes the callback that is returned by the _cmd_*
        coroutine methods.

        :param future:
        :return:
        """
        result, callback = future.result()

        if callback:
            callback(result)

    def _cmd(self, cmd, **kwargs):
        # Get callback, if available
        callback = kwargs.get("callback")
        future = asyncio.Future(loop=self._loop)
        future.add_done_callback(self._on_cmd_finished)

        task = self._loop.create_task(self._cmd_coro(cmd, future, callback))

        # Create and start a new task (coroutine)
        self._loop.run_until_complete(task)
        return task.result() if task else None

    async def _cmd_process(self, cmd, future, callback):
        if not hasattr(self, "process"):
            rz_path = get_rizin_path()
            if self.rz_home is not None:
                if not os.path.isdir(self.rz_home):
                    raise Exception(
                        "`rizinhome` passed to `open` is invalid, leave it None or put a valid path to rizin folder"
                    )
                rz_path = os.path.join(self.rz_home, "rizin")
                if os.name == "nt":
                    rz_path += ".exe"


            # Init the process
            self.process = await asyncio.create_subprocess_exec(
                rz_path,
                *self._process_start_cmd,
                shell=False,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                loop=self._loop
            )

            await self.process.stdout.read(1)  # Reads initial \x00

        normalized_cmd = cmd.strip().replace("\n", ";")
        self.process.stdin.write(bytes(normalized_cmd + "\n", "utf-8"))

        buffer = []
        while True:
            # foo = self.process.stdout.read(1)
            char = await self.process.stdout.read(1)
            if char == b"\x00":
                break
            if len(char) < 1:
                return None
            buffer.append(char)

        decoded_buffer = b"".join(buffer).decode("utf-8")
        future.set_result((decoded_buffer, callback))
        return decoded_buffer

    async def _cmd_http(self, cmd, future, callback):
        try:
            quoted_cmd = quote(cmd)

            reader, writer = await asyncio.open_connection(
                self._host, self._port, loop=self._loop
            )

            message = "\n\r".join(
                [
                    "GET /cmd/%s HTTP/1.1" % quoted_cmd,
                    "Host: %s:%s" % (self._host, self._port),
                    "User-Agent: rzpipe/Python Client",
                    "Accept: */*",
                    "",
                    "",
                ]
            ).encode()

            writer.write(message)
            data = await reader.read(512)
            res = [data]
            while data:
                data = await reader.read(512)
                res.append(data)
            writer.close()

            res = b"".join(res)

            # Remove http headers
            start = 0
            for x in res.splitlines():
                if not x:
                    start += 1
                    break
                start += len(x) + 1  # +1 because we must be count '\n'
            res = res[start:].decode("utf-8", errors="ignore")
            future.set_result((res, callback))
            return res

        except Exception as e:
            future.set_result((str(e), callback))

    async def _cmd_tcp(self, cmd, future, callback):
        try:
            reader, writer = await asyncio.open_connection(
                self._host, self._port, loop=self._loop
            )

            writer.write(cmd.encode("utf-8"))
            data = await reader.read(512)

            res = [data]
            while data:
                res.append(data)
                data = await reader.read(512)
            res = b"".join(res).decode("utf-8", errors="ignore")
            future.set_result((res, callback))
            writer.close()
            return res

        except Exception as e:
            future.set_result((str(e), callback))

    def wait(self, task: typing.Union[asyncio.Task, asyncio.Future]):
        """
        Wait until the task or future is finished.

        :param task:
        :return:
        """
        tasks = task
        if not isinstance(task, Iterable):
            tasks = [task]

        if self._loop.is_running():
            asyncio.wait(tasks, loop=self._loop)
