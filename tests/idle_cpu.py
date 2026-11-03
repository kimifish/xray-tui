#!/usr/bin/env python3
"""Linux idle CPU regression check with a PTY and isolated fake systemd/core."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import tempfile
import termios
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("client", nargs="?", default="target/release/xray-tui")
parser.add_argument("--config", type=Path, help="Use a private paused copy of this config")
parser.add_argument("--seconds", type=float, default=10)
parser.add_argument("--max-cpu", type=float, default=2)
parser.add_argument("--auto", action="store_true", help="Measure between automatic checks (fake core only)")
args = parser.parse_args()
client = str(Path(args.client).resolve())


def ticks(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[11]) + int(fields[12])


with tempfile.TemporaryDirectory(prefix="xray-tui-idle-") as tmp:
    root = Path(tmp)
    metadata = {}
    if args.config:
        lines = args.config.read_text().splitlines(keepends=True)
        for line in lines:
            if line.startswith("// @xray-tui:v1 "):
                metadata = json.loads(line[len("// @xray-tui:v1 "):])
        body = "".join(line for line in lines if not line.startswith("// @xray-tui:v1 "))
    else:
        body = json.dumps({
            "outbounds": [{"tag": f"node-{i}", "protocol": "freedom"} for i in range(12)],
            "inbounds": [], "routing": {"rules": []},
        })
    metadata.setdefault("health", {})["enabled"] = args.auto
    config = root / "config.jsonc"
    config.write_text("// @xray-tui:v1 " + json.dumps(metadata) + "\n" + body)
    config.chmod(0o600)

    controller = root / "systemctl"
    controller.write_text("""#!/bin/sh
case " $* " in
  *" show "*) printf 'LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=0\nMemoryCurrent=0\n';;
  *) exit 91;;
esac
""")
    core = root / "xray"
    core.write_text("#!/bin/sh\n[ \"$1\" = version ] || exit 92\nprintf 'Xray diagnostic core\\n'\n")
    controller.chmod(0o700)
    core.chmod(0o700)

    # Include stored history so Outbounds refreshes result ages once per second.
    state = root / "state" / "xray-tui"
    state.mkdir(parents=True, mode=0o700)
    identity = hashlib.sha256(f"{config}:xray.service:true".encode()).hexdigest()[:16]
    history = {"version": 1, "records": {"diagnostic": {
        "key": "diagnostic", "tag": "diagnostic", "samples": [{
            "at": int(time.time()), "origin": "Saved", "extended": False,
            "targets": [{"name": "diagnostic", "stage": "Ok", "elapsed_ms": 25,
                         "bytes": 0, "status": 204, "detail": "diagnostic"}],
        }],
    }}}
    (state / f"health-{identity}.json").write_text(json.dumps(history))
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 96, 131, 0, 0))
    env = {**os.environ, "TERM": "xterm-256color", "PATH": f"{root}:{os.environ['PATH']}",
           "XDG_STATE_HOME": str(root / "state")}
    process = subprocess.Popen([client, "--config", str(config), "--binary", str(core)],
                               stdin=slave, stdout=slave, stderr=slave, env=env)
    output = bytearray()

    def pump(seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if select.select([master], [], [], min(0.05, max(0, deadline - time.monotonic())))[0]:
                output.extend(os.read(master, 65536))
            assert process.poll() is None, "Client exited unexpectedly"

    try:
        pump(1)
        os.write(master, b"2")
        pump(1)
        expected = b"Auto ON" if args.auto else b"PAUSED"
        assert expected in output, "Outbounds view was not opened"
        start_time, start_ticks = time.monotonic(), ticks(process.pid)
        pump(args.seconds)
        cpu = (ticks(process.pid) - start_ticks) / os.sysconf("SC_CLK_TCK")
        percent = 100 * cpu / (time.monotonic() - start_time)
        mode = "Auto ON" if args.auto else "Auto paused"
        print(f"{mode}, Outbounds with history: {percent:.2f}% of one CPU ({cpu:.3f}s CPU)")
        assert percent < args.max_cpu, f"Idle CPU exceeds {args.max_cpu}%"
        # Input and resize must still redraw after the idle interval.
        output.clear()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 42, 132, 0, 0))
        os.write(master, b"?")
        pump(0.5)
        assert b"KEYBOARD" in output, "Help did not respond after idle"
        os.write(master, b"\x1b")
        pump(0.3)
        os.write(master, b"qy")
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        os.close(slave)
