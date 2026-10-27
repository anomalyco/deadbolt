#!/usr/bin/env python3
"""A stand-in for `deadbolt browser-host` with made-up logins, for e2e runs.

The browser passes its environment through: DEADBOLT_FAKE_STATUS picks the
hello status, DEADBOLT_FAKE_LOG gets one JSON line per request, and
DEADBOLT_FAKE_RATE_LIMIT=fill,generate-keep answers those with rate_limited, and
DEADBOLT_FAKE_FILL_DELAY holds each fill reply for that many seconds. Saves
are checked against the spec's title and URL rules. Generated passwords are
held per origin, as the agent holds them: candidates until generate-keep,
then pending, and check and save resolve only pending ones. Fields that allow
under 60 bits are weak, as the agent's floor.
"""
import json, math, os, secrets, string, struct, sys, time

STATUS = os.environ.get("DEADBOLT_FAKE_STATUS", "ready")
LOG = os.environ.get("DEADBOLT_FAKE_LOG")
RATE_LIMIT = os.environ.get("DEADBOLT_FAKE_RATE_LIMIT", "")
FILL_DELAY = float(os.environ.get("DEADBOLT_FAKE_FILL_DELAY") or 0)
REF1 = "a" * 64 + ":" + "1" * 32
REF2 = "a" * 64 + ":" + "2" * 32
ACCOUNTS = [
    {"ref": REF1, "vault": "Personal", "title": "Acme", "username": "kit@acme.test", "hasPassword": True, "hasTotp": True, "urls": []},
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


PENDING = {}
CANDIDATES = {}
DEFAULT_ALPHABET = string.ascii_letters + string.digits + "-_.!"


def refusal(req):
    """Why no password is made for the field: failed, weak, or None."""
    hi = min(req.get("maxLength") or 20, 20)
    lo = req.get("minLength") or 0
    if lo > hi:
        return "failed"
    alphabet = req.get("allowed") or DEFAULT_ALPHABET
    return "weak" if max(hi, lo) * math.log2(len(set(alphabet))) < 60 else None


def generate(req):
    if refusal(req):
        return refusal(req)
    hi = min(req.get("maxLength") or 20, 20)
    lo = req.get("minLength") or 0
    alphabet = req.get("allowed") or DEFAULT_ALPHABET
    rules = req.get("rules") or ""
    needs = [c for k, c in (("digit", string.digits), ("upper", string.ascii_uppercase), ("lower", string.ascii_lowercase)) if f"required: {k}" in rules]
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(max(hi, lo)))
        if all(any(ch in cls for ch in password) for cls in needs):
            break
    gid = secrets.token_hex(8)
    CANDIDATES[gid] = (req["origin"], password)
    return {"password": password, "generated": gid}


def secret(req, body):
    """The password a check or save names: typed, or generated for this origin."""
    if "generated" in body:
        origin, password = PENDING.get(body["generated"], (None, None))
        return password if origin == req["origin"] else None
    return body.get("password")


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
    if kind == "generate-check":
        # The agent answers it locked or not.
        why = refusal(req)
        write({"id": rid, "type": "error", "code": why, "message": "No strong password fits."} if why else {"id": rid, "type": "generate-check"})
    elif kind == "hello":
        write({"id": rid, "type": "hello", "protocol": 2, "version": "0.0.0-e2e", "status": STATUS, "capabilities": ["list", "fill", "check", "save", "generate"]})
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
    elif kind == "generate":
        made = generate(req)
        write({"id": rid, "type": "generate", **made} if isinstance(made, dict) else {"id": rid, "type": "error", "code": made, "message": "No password fits."})
    elif kind in ("generate-keep", "generate-drop"):
        held = CANDIDATES.get(req.get("generated"))
        if held and held[0] == req["origin"]:
            del CANDIDATES[req["generated"]]
            if kind == "generate-keep":
                PENDING[req["generated"]] = held
        if kind == "generate-keep" and not (held and held[0] == req["origin"]):
            write({"id": rid, "type": "error", "code": "not_found", "message": "No such candidate."})
        else:
            write({"id": rid, "type": kind})
    elif kind in ("check", "save") and secret(req, req if kind == "check" else req.get("entry") or {}) is None:
        write({"id": rid, "type": "error", "code": "not_found", "message": "No such generated password."})
    elif kind == "check" and "username" not in req:
        same = [r for r, v in VALUES.items() if v["password"] == secret(req, req)]
        write({"id": rid, "type": "check", "status": "same" if same else "new", "matches": same})
    elif kind == "check":
        known = [r for r, v in VALUES.items() if v["username"] == req["username"]]
        same = [r for r in known if VALUES[r]["password"] == secret(req, req)]
        status = "same" if same else "update" if known else "new"
        write({"id": rid, "type": "check", "status": status, "matches": same or known})
    elif kind == "save" and not valid_entry(req.get("entry") or {}, req["origin"]):
        write({"id": rid, "type": "error", "code": "bad_request", "message": "bad entry"})
    elif kind == "save":
        PENDING.pop(req["entry"].get("generated"), None)
        write({"id": rid, "type": "save", "ref": req.get("ref") or "b" * 64 + ":" + "3" * 32, "created": not req.get("ref")})
    else:
        write({"id": rid, "type": "error", "code": "bad_request", "message": "unknown"})
