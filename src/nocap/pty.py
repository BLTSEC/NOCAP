"""PTY-backed command execution and terminal I/O forwarding for NOCAP."""

from __future__ import annotations

import fcntl
import os
import select
import shlex
import shutil
import signal
import struct
import sys
import termios
import tty
from contextlib import contextmanager
from pathlib import Path

def _term_size() -> tuple[int, int]:
    try:
        ts = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, b"\x00" * 8)
        rows, cols = struct.unpack_from("HH", ts)
        if rows > 0 and cols > 0:
            return rows, cols
    except (OSError, AttributeError):
        pass
    return 24, 80


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    try:
        ws = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, ws)
    except OSError:
        pass


def _raw_terminal(fd: int):
    """Context manager: put *fd* in raw mode, restore on exit."""
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _parent_io_loop(
    master_fd: int,
    stdin_fd: int,
    is_tty: bool,
    logf,
) -> None:
    """Forward PTY output to stdout/logfile; forward stdin to the PTY."""
    watch_fds = [master_fd, stdin_fd] if is_tty else [master_fd]
    while True:
        try:
            r, _, _ = select.select(watch_fds, [], [], 0.05)
        except (ValueError, OSError):
            break

        if master_fd in r:
            try:
                data = os.read(master_fd, 4096)
            except OSError:
                break
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
            logf.write(data)
            logf.flush()

        if is_tty and stdin_fd in r:
            try:
                data = os.read(stdin_fd, 4096)
            except OSError:
                break
            if data:
                os.write(master_fd, data)


def _run_pty(cmd: list[str], outfile: Path) -> int:
    """Execute *cmd* under a PTY, appending all output to *outfile* while
    also echoing to stdout in real time.  Returns the child's exit code.

    Running under a PTY means tools that detect TTY (nmap, gobuster, etc.)
    emit colours and progress bars as expected.
    """
    import pty

    rows, cols = _term_size()
    master_fd, slave_fd = pty.openpty()
    _set_winsize(slave_fd, rows, cols)

    stdin_fd = sys.stdin.fileno()
    is_tty = sys.stdin.isatty()

    # If the command isn't a binary on PATH, wrap it in the user's shell
    # so that shell functions and aliases (e.g. from .zshrc) are available.
    if not shutil.which(cmd[0]):
        shell = os.environ.get("SHELL", "/bin/sh")
        cmd = [shell, "-ic", " ".join(shlex.quote(c) for c in cmd)]

    pid = os.fork()

    if pid == 0:
        # ── child ────────────────────────────────────────────────────────────
        try:
            os.close(master_fd)
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
            # Preserve redirected stdin (pipes/files) instead of replacing it
            # with the PTY slave.  A PTY cannot be half-closed, so replacing
            # fd 0 made commands such as `printf x | cap cat` wait forever for
            # an EOF that could never arrive.  Interactive stdin still uses
            # the PTY so prompts and terminal input behave normally.
            child_fds = (0, 1, 2) if is_tty else (1, 2)
            for fd in child_fds:
                os.dup2(slave_fd, fd)
            if slave_fd > 2:
                os.close(slave_fd)
            os.execvp(cmd[0], cmd)
        except FileNotFoundError:
            sys.stderr.write(f"nocap: command not found: {cmd[0]}\n")
        except OSError as exc:
            sys.stderr.write(f"nocap: failed to execute {cmd[0]}: {exc}\n")
        os._exit(127)

    # ── parent ───────────────────────────────────────────────────────────────
    os.close(slave_fd)

    # Propagate terminal resize events to the child
    def _sigwinch(sig: int, frame: object) -> None:  # noqa: ARG001
        r, c = _term_size()
        _set_winsize(master_fd, r, c)
        try:
            os.kill(pid, signal.SIGWINCH)
        except ProcessLookupError:
            pass

    old_sigwinch = signal.signal(signal.SIGWINCH, _sigwinch)

    exit_code = 127

    try:
        with outfile.open("ab") as logf:
            if is_tty:
                with _raw_terminal(stdin_fd):
                    _parent_io_loop(master_fd, stdin_fd, is_tty, logf)
            else:
                _parent_io_loop(master_fd, stdin_fd, is_tty, logf)
    finally:
        os.close(master_fd)
        signal.signal(signal.SIGWINCH, old_sigwinch)
        try:
            _, status = os.waitpid(pid, 0)
            exit_code = os.waitstatus_to_exitcode(status)
            if exit_code < 0:
                exit_code = 128 - exit_code
        except ChildProcessError:
            pass

    return exit_code
