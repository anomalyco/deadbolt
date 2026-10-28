#!/usr/bin/env python3
"""A stand-in for `deadbolt browser-host` with made-up logins, for e2e runs.

The browser passes its environment through: DEADBOLT_FAKE_STATUS picks the
hello status, DEADBOLT_FAKE_LOG gets one JSON line per request, and
DEADBOLT_FAKE_RATE_LIMIT=fill answers every fill with rate_limited, and
DEADBOLT_FAKE_FILL_DELAY holds each fill reply for that many seconds. Saves
are checked against the spec's title and URL rules.
"""
import json, os, struct, sys, time

STATUS = os.environ.get("DEADBOLT_FAKE_STATUS", "ready")
LOG = os.environ.get("DEADBOLT_FAKE_LOG")
RATE_LIMIT = os.environ.get("DEADBOLT_FAKE_RATE_LIMIT", "")
FILL_DELAY = float(os.environ.get("DEADBOLT_FAKE_FILL_DELAY") or 0)
REF1 = "a" * 64 + ":" + "1" * 32
REF2 = "a" * 64 + ":" + "2" * 32
ACCOUNTS = [
    {"ref": REF1, "vault": "Personal", "title": "Acme", "username": "kit@acme.test", "hasPassword": True, "hasTotp": True, "urls": ["http://www.acme.test", "http://accounts.acme.test"]},
    {"ref": REF2, "vault": "Work", "title": "Acme admin", "username": "admin", "hasPassword": True, "hasTotp": False, "urls": []},
]
VALUES = {REF1: {"username": "kit@acme.test", "password": "correct horse", "totp": "492039"}, REF2: {"username": "admin", "password": "hunter2"}}


def read():
    head = sys.stdin.buffer.read(4)
    if len(head) < 4:
        sys.exit(0)
    (n,) = struct.unpack("<I", head)
    return json.loads(sys.stdin.buffer.read(n))


def write(msg):
    data = json.dumps(msg).encode()
    sys.stdout.buffer.write(struct.pack("<I", len(data)) + data)
    sys.stdout.buffer.flush()


def site(origin):
    host = origin.split("://", 1)[-1].split(":")[0]
    return host


def valid_entry(entry, origin):
    title, url = entry.get("title", ""), entry.get("url", "")
    if not (1 <= len(title) <= 128) or title != " ".join(title.split()):
        return False
    if url != url.strip() or " " in url or len(url.encode()) > 2048:
        return False
    return url.startswith(origin + "/") or url == origin


while True:
    req = read()
    if LOG:
        with open(LOG, "a") as f:
            f.write(json.dumps(req) + "\n")
    rid, kind = req.get("id"), req.get("type")
    if kind == "hello":
        write({"id": rid, "type": "hello", "protocol": 1, "version": "0.0.0-e2e", "status": STATUS, "capabilities": ["list", "fill", "check", "save"]})
    elif STATUS != "ready":
        write({"id": rid, "type": "error", "code": "locked", "message": "Deadbolt is locked."})
    elif kind == "list":
        write({"id": rid, "type": "list", "site": site(req["origin"]), "accounts": ACCOUNTS})
    elif kind in RATE_LIMIT.split(","):
        write({"id": rid, "type": "error", "code": "rate_limited", "message": "Too many requests."})
    elif kind == "fill":
        time.sleep(FILL_DELAY)
        values = {k: v for k, v in VALUES.get(req["ref"], {}).items() if k in req["want"]}
        write({"id": rid, "type": "fill", **values})
    elif kind == "check":
        known = [r for r, v in VALUES.items() if v["username"] == req["username"]]
        same = [r for r in known if VALUES[r]["password"] == req["password"]]
        status = "same" if same else "update" if known else "new"
        write({"id": rid, "type": "check", "status": status, "matches": same or known})
    elif kind == "save" and not valid_entry(req.get("entry") or {}, req["origin"]):
        write({"id": rid, "type": "error", "code": "bad_request", "message": "bad entry"})
    elif kind == "save":
        write({"id": rid, "type": "save", "ref": req.get("ref") or "b" * 64 + ":" + "3" * 32, "created": not req.get("ref")})
    else:
        write({"id": rid, "type": "error", "code": "bad_request", "message": "unknown"})
