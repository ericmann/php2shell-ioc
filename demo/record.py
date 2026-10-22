#!/usr/bin/env python3
"""Record the demo as an asciinema v2 cast (docs/demo.cast).

Runs the real demo (demo/run.sh) under a pseudo-terminal so the output and its
colours are genuine, then replays it line by line at a readable pace (the scan
itself finishes in about a second), preceded by a typed command line. Render it
with agg:

    python3 demo/record.py && agg --idle-time-limit 2 --fps-cap 8 docs/demo.cast docs/demo.gif

or simply `make cast`. Requires Docker (for the demo itself).
"""
import json
import os
import pty
import select
import sys
import time

WIDTH, HEIGHT = 112, 40
OUT = sys.argv[1] if len(sys.argv) > 1 else "docs/demo.cast"
PROMPT = "\x1b[1;32m$\x1b[0m "


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root)
    events = []
    t = 0.0

    def emit(data, delay=0.0):
        nonlocal t
        t += delay
        events.append([round(t, 4), "o", data])

    emit(PROMPT, 0.3)
    for ch in "make demo":
        emit(ch, 0.07)
    emit("\r\n", 0.4)

    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update({"COLUMNS": str(WIDTH), "LINES": str(HEIGHT), "TERM": "xterm-256color"})
        os.execvp("sh", ["sh", "demo/run.sh"])

    captured = b""
    while True:
        r, _, _ = select.select([fd], [], [], 0.1)
        if fd in r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            captured += chunk
    os.waitpid(pid, 0)

    # Replay: a beat per line, longer pauses where a reader wants to stop.
    for line in captured.decode("utf-8", "replace").splitlines(keepends=True):
        plain = line.replace("\x1b[1m", "").replace("\x1b[0m", "")
        if plain.startswith(">>>"):
            delay = 1.2
        elif plain.lstrip().startswith("== "):
            delay = 0.6
        elif "[FLAG]" in plain:
            delay = 0.35
        else:
            delay = 0.06
        emit(line, delay)
    emit(PROMPT, 0.5)
    emit("", 3.0)  # hold the final frame

    header = {"version": 2, "width": WIDTH, "height": HEIGHT, "timestamp": int(time.time()),
              "title": "php2shell-ioc demo", "env": {"SHELL": "/bin/sh", "TERM": "xterm-256color"}}
    with open(OUT, "w") as f:
        f.write(json.dumps(header) + "\n")
        for e in events:
            f.write(json.dumps(e) + "\n")
    print(f"wrote {OUT} ({len(events)} events, {t:.1f}s)")


if __name__ == "__main__":
    main()
