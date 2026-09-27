from unittest.mock import MagicMock
import pytest
from rzpipe import open_sync


class MockPipe:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.read_count = 0

    def read(self, size=4096):
        if self.read_count < len(self.chunks):
            res = self.chunks[self.read_count]
            self.read_count += 1
            if isinstance(res, Exception):
                raise res
            return res
        return b""


def create_mock_open_instance():
    instance = open_sync.open.__new__(open_sync.open)
    instance.process = MagicMock()
    instance.process.stdin = MagicMock()
    return instance


def test_cmd_process_normal_output():
    instance = create_mock_open_instance()
    mock_stdout = MockPipe([b"hello world\n\x00"])
    mock_stderr = MockPipe([])

    instance.process.stdout = mock_stdout
    instance.process.stderr = mock_stderr

    result = instance._cmd_process("px 1")
    assert result == "hello world\n"


def test_cmd_process_printf_after_null():
    """
    Test case for Issue #60: Rizin prints debug messages via printf after command output \x00.
    The reader loop must not hang and should correctly extract command output up to \x00.
    """
    instance = create_mock_open_instance()
    mock_stdout = MockPipe([b"command output\x00extra printf debug message\n"])
    mock_stderr = MockPipe([])

    instance.process.stdout = mock_stdout
    instance.process.stderr = mock_stderr

    result = instance._cmd_process("px 1")
    assert result == "command output"


def test_cmd_process_multichunk_printf():
    """
    Test multichunk output where null byte and printf text are in the final chunk.
    """
    instance = create_mock_open_instance()
    mock_stdout = MockPipe([
        b"first line\n",
        b"second line\n\x00printf debug output\n"
    ])
    mock_stderr = MockPipe([])

    instance.process.stdout = mock_stdout
    instance.process.stderr = mock_stderr

    result = instance._cmd_process("px 1")
    assert result == "first line\nsecond line\n"


def test_cmd_process_blocking_io_error():
    """
    Ensure BlockingIOError during stdout reading is handled gracefully without unbound variable errors.
    """
    instance = create_mock_open_instance()
    mock_stdout = MockPipe([BlockingIOError(), b"result\x00"])
    mock_stderr = MockPipe([])

    instance.process.stdout = mock_stdout
    instance.process.stderr = mock_stderr

    result = instance._cmd_process("px 1")
    assert result == "result"
