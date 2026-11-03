#!/usr/bin/env python3
"""Exercise the real terminal event loop without touching the live Xray service."""
import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time

binary = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "target/debug/xray-tui")
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 42, 132, 0, 0))
original = termios.tcgetattr(slave)
process = subprocess.Popen([binary, "--demo"], stdin=slave, stdout=slave, stderr=slave,
                           env={**os.environ, "TERM": "xterm-256color"}, close_fds=True)
output = bytearray()


def pump(duration):
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.05)[0]:
            try:
                data = os.read(master, 65536)
                if not data:
                    break
                output.extend(data)
            except OSError:
                break


try:
    pump(0.5)
    os.write(master, b"2i")
    pump(0.2)
    os.write(master, b'\x1b[200~{"tag":"pty-test","protocol":"freedom"}\x1b[201~')
    pump(0.2)
    os.write(master, b"\x13")  # Ctrl-S: import preview
    pump(0.2)
    os.write(master, b"y")
    pump(0.2)
    os.write(master, b"ph")  # pause auto checks and open the health report (demo: no network)
    pump(0.2)
    os.write(master, b"\x1b[6~")  # PgDn report
    pump(0.2)
    os.write(master, b"\x1b")
    pump(0.3)
    os.write(master, b"q")  # dirty draft confirmation
    pump(0.2)
    os.write(master, b"y")
    pump(0.3)
    assert process.wait(timeout=5) == 0, output[-2000:].decode(errors="replace")
    assert b"pty-test" in output and b"Import preview" in output, "Import UI was not exercised"
    assert b"Unsaved draft" in output, "Exit did not protect the draft"
    assert b"Outbound health" in output, "Health report did not open"
    assert b"panicked" not in output
    restored = termios.tcgetattr(slave)
    mask = termios.ICANON | termios.ECHO
    assert restored[3] & mask == original[3] & mask, "Terminal flags not restored"
    print("PTY smoke passed: paste, import preview, health report, draft confirmation, clean exit, terminal restore")
finally:
    if process.poll() is None:
        process.kill()
        process.wait()
    os.close(master)
    os.close(slave)
