#!/usr/bin/env python3
"""Tiny socket helper for the sandbox probes.

Clients exit 0 when the operation succeeded and non-zero otherwise, printing one line that
names the outcome. Servers run outside the sandbox and answer every connection with "pong".
"""
import socket
import sys
import os

TIMEOUT = 2.0


def ok(msg):
    print(f"OK {msg}")
    sys.exit(0)


def fail(msg, exc):
    print(f"ERR {msg}: {type(exc).__name__}: {exc}")
    sys.exit(1)


def unix_addr(name, abstract):
    return ("\0" + name) if abstract else name


def connect_unix(name, abstract=False):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError as e:
        fail("socket(AF_UNIX)", e)
    s.settimeout(TIMEOUT)
    try:
        s.connect(unix_addr(name, abstract))
    except OSError as e:
        fail(f"connect {'@' if abstract else ''}{name}", e)
    try:
        s.settimeout(0.5)
        data = s.recv(16)
    except OSError:
        data = b""
    ok(f"connected to {'@' if abstract else ''}{name} recv={data!r}")


def connect_tcp(host, port):
    try:
        s = socket.create_connection((host, int(port)), timeout=TIMEOUT)
        s.close()
        ok(f"tcp connect {host}:{port}")
    except OSError as e:
        fail(f"tcp connect {host}:{port}", e)


def bind_tcp(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, int(port)))
        s.listen(1)
        ok(f"bound+listening {host}:{s.getsockname()[1]}")
    except OSError as e:
        fail(f"bind {host}:{port}", e)


def bind_unix(path):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(path)
        s.close()
        os.unlink(path)
        ok(f"bound unix {path}")
    except OSError as e:
        fail(f"bind unix {path}", e)


def serve(sock):
    sock.listen(16)
    while True:
        c, _ = sock.accept()
        try:
            c.sendall(b"pong")
        finally:
            c.close()


def serve_unix(name, abstract=False):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if not abstract and os.path.exists(name):
        os.unlink(name)
    s.bind(unix_addr(name, abstract))
    serve(s)


def serve_tcp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, int(port)))
    serve(s)


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    {
        "connect-unix": lambda: connect_unix(args[0]),
        "connect-abstract": lambda: connect_unix(args[0], abstract=True),
        "connect-tcp": lambda: connect_tcp(*args),
        "bind-tcp": lambda: bind_tcp(*args),
        "bind-unix": lambda: bind_unix(args[0]),
        "serve-unix": lambda: serve_unix(args[0]),
        "serve-abstract": lambda: serve_unix(args[0], abstract=True),
        "serve-tcp": lambda: serve_tcp(*args),
    }[cmd]()
