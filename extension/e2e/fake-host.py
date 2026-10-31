#!/usr/bin/env python3
"""A stand-in for `deadbolt browser-host` with made-up logins, for e2e runs.

The browser passes its environment through: DEADBOLT_FAKE_STATUS picks the
hello status, DEADBOLT_FAKE_LOG gets one JSON line per request, and
DEADBOLT_FAKE_RATE_LIMIT=fill,generate-keep answers those with rate_limited,
DEADBOLT_FAKE_FILL_DELAY holds each fill reply for that many seconds
(DEADBOLT_FAKE_LIST_DELAY each list reply), and
DEADBOLT_FAKE_SIGNIN adds "Sign in with Google" logins, and
DEADBOLT_FAKE_GOOGLE lists three Google logins instead of its own, and
DEADBOLT_FAKE_KEYLOGIN adds a login with no username. Saves
are checked against the spec's title and URL rules. Generated passwords are held per
origin, as the agent holds them: candidates until generate-keep, then
pending, and check and save resolve only pending ones. Fields that allow
under 60 bits are weak, as the agent's floor.

`learn` answers `learned` (the log has each line), locked or not.

`forms` lists two identities and a card, and `fill-form` answers with only
the fields asked for. DEADBOLT_FAKE_TOUCHID=deny answers a fill-form that
asks for a card's number or code with `failed`, as the agent does when
Touch ID is turned down; DEADBOLT_FAKE_FILL_DELAY holds fill-form too.
"""
import json, math, os, secrets, string, struct, sys, time

STATUS = os.environ.get("DEADBOLT_FAKE_STATUS", "ready")
LOG = os.environ.get("DEADBOLT_FAKE_LOG")
RATE_LIMIT = os.environ.get("DEADBOLT_FAKE_RATE_LIMIT", "")
TOUCHID = os.environ.get("DEADBOLT_FAKE_TOUCHID", "")
FILL_DELAY = float(os.environ.get("DEADBOLT_FAKE_FILL_DELAY") or 0)
LIST_DELAY = float(os.environ.get("DEADBOLT_FAKE_LIST_DELAY") or 0)
REF1 = "a" * 64 + ":" + "1" * 32
REF2 = "a" * 64 + ":" + "2" * 32
ACCOUNTS = [
    {"ref": REF1, "vault": "Personal", "title": "Acme", "username": "kit@acme.test", "hasPassword": True, "hasTotp": True, "urls": ["http://www.acme.test", "http://accounts.acme.test"]},
    {"ref": REF2, "vault": "Work", "title": "Acme admin", "username": "admin", "hasPassword": True, "hasTotp": False, "urls": []},
]
HOME = "c" * 64 + ":" + "1" * 32
WORK = "c" * 64 + ":" + "2" * 32
VISA = "c" * 64 + ":" + "3" * 32
IDENTITIES = [
    {"ref": HOME, "title": "Home", "summary": "Kit Langton · 123 Main St, Brooklyn"},
    {"ref": WORK, "title": "Work", "summary": "Kit Langton · 1 Market St, San Francisco"},
]
CARDS = [{"ref": VISA, "title": "Personal Visa", "brand": "Visa", "last4": "4242", "expiry": "2028-08", "cardholder": "Kit Langton"}]
FORM_VALUES = {
    HOME: {"given-name": "Kit", "family-name": "Langton", "email": "kit@acme.test", "phone": "+14155550123", "organization": "Acme",
           "address-line1": "123 Main St", "address-line2": "Apt 4", "city": "Brooklyn", "region": "NY", "postal-code": "11201",
           "country": "US", "birthday": "1990-07-04"},
    WORK: {"given-name": "Kit", "family-name": "Langton", "address-line1": "1 Market St", "city": "San Francisco", "region": "CA",
           "postal-code": "94105", "country": "US"},
    VISA: {"number": "4242424242424242", "cvv": "123", "expiry": "2028-08", "cardholder": "Kit Langton", "brand": "Visa"},
}
VALUES = {REF1: {"username": "kit@acme.test", "password": "correct horse", "totp": "492039"}, REF2: {"username": "admin", "password": "hunter2"}}
# DEADBOLT_FAKE_USERNAME and DEADBOLT_FAKE_PASSWORD replace the first login's
# values (corpus/sweep.ts, on real sites).
if os.environ.get("DEADBOLT_FAKE_USERNAME"):
    ACCOUNTS[0]["username"] = VALUES[REF1]["username"] = os.environ["DEADBOLT_FAKE_USERNAME"]
if os.environ.get("DEADBOLT_FAKE_PASSWORD"):
    VALUES[REF1]["password"] = os.environ["DEADBOLT_FAKE_PASSWORD"]
# DEADBOLT_FAKE_KEYLOGIN=1 adds a login with no username, as an imported key
# or PIN often is.
if os.environ.get("DEADBOLT_FAKE_KEYLOGIN"):
    REF5 = "a" * 64 + ":" + "5" * 32
    ACCOUNTS.append({"ref": REF5, "vault": "Work", "title": "Acme API key", "hasPassword": True, "hasTotp": False, "urls": []})
    VALUES[REF5] = {"password": "acme api key"}
# Universal sign-in needs the fixture's exact origin, including its port.
if os.environ.get("DEADBOLT_FAKE_ORIGIN"):
    ACCOUNTS[0]["urls"] = [os.environ["DEADBOLT_FAKE_ORIGIN"]]
# DEADBOLT_FAKE_SIGNIN=1 adds a "Sign in with Google" login for the site, and
# the Google account's own login it signs in with.
if os.environ.get("DEADBOLT_FAKE_SIGNIN"):
    REF3 = "a" * 64 + ":" + "3" * 32
    REF4 = "a" * 64 + ":" + "4" * 32
    ACCOUNTS.append({"ref": REF3, "vault": "Personal", "title": "Acme", "hasPassword": False, "hasTotp": False, "urls": [], "signIn": {"provider": "google", "account": "kit@gmail.com"}})
    ACCOUNTS.append({"ref": REF4, "vault": "Personal", "title": "Google", "username": "kit@gmail.com", "hasPassword": True, "hasTotp": False, "urls": ["https://accounts.google.com"]})
    VALUES[REF3] = {}
    VALUES[REF4] = {"username": "kit@gmail.com", "password": "google password"}
# DEADBOLT_FAKE_GOOGLE=1: three google.com logins, for Google's password step.
if os.environ.get("DEADBOLT_FAKE_GOOGLE"):
    ACCOUNTS = [
        {"ref": "b" * 64 + ":" + str(i) * 32, "vault": "Personal", "title": "Google", "username": u, "hasPassword": True, "hasTotp": False, "urls": ["https://accounts.google.com"]}
        for i, u in enumerate(["ryan@gmail.com", "ryan@anoma.ly", "kit@gmail.com"], 1)
    ]


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


CLASSES = {"digit": string.digits, "upper": string.ascii_uppercase, "lower": string.ascii_lowercase, "special": "-~!@#$%^&*_+=`|(){}[:;\"'<>,.?]/"}


def required(rules):
    """The character sets passwordrules' `required:` entries ask one of each of: named classes and [custom] sets, as the agent reads them."""
    needs = []
    for part in rules.split(";"):
        name, _, value = part.partition(":")
        if name.strip() != "required":
            continue
        chars = ""
        for token in value.split(","):
            token = token.strip()
            chars += token[1:-1] if token.startswith("[") and token.endswith("]") else CLASSES.get(token, "")
        if chars:
            needs.append(chars)
    return needs


def generate(req):
    if refusal(req):
        return refusal(req)
    hi = min(req.get("maxLength") or 20, 20)
    lo = req.get("minLength") or 0
    rules = req.get("rules") or ""
    needs = required(rules)
    # With required classes and no `allowed:`, a password uses only those, as the agent's does.
    alphabet = req.get("allowed") or ("".join(needs) if needs and "allowed:" not in rules else DEFAULT_ALPHABET)
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
        write({"id": rid, "type": "hello", "protocol": 3, "version": "0.0.0-e2e", "status": STATUS, "capabilities": ["list", "fill", "check", "save", "generate", "forms", "learn"]})
    elif kind == "learn":
        # As the host: it works locked too, and keeps no values (the log has the line).
        write({"id": rid, "type": "learned"})
    elif STATUS != "ready":
        write({"id": rid, "type": "error", "code": "locked", "message": "Deadbolt is locked."})
    elif kind == "list":
        time.sleep(LIST_DELAY)
        write({"id": rid, "type": "list", "site": site(req["origin"]), "accounts": ACCOUNTS})
    elif kind in RATE_LIMIT.split(","):
        write({"id": rid, "type": "error", "code": "rate_limited", "message": "Too many requests."})
    elif kind == "fill":
        time.sleep(FILL_DELAY)
        values = {k: v for k, v in VALUES.get(req["ref"], {}).items() if k in req["want"]}
        write({"id": rid, "type": "fill", **values})
    elif kind == "forms":
        def listed(item):
            return {**item, "vault": "Personal", "fields": sorted(FORM_VALUES[item["ref"]])}
        write({"id": rid, "type": "forms", "canVerify": True, "identities": [listed(i) for i in IDENTITIES], "cards": [listed(c) for c in CARDS]})
    elif kind == "fill-form":
        time.sleep(FILL_DELAY)
        if TOUCHID == "deny" and set(req["fields"]) & {"number", "cvv"}:
            write({"id": rid, "type": "error", "code": "failed", "message": "Touch ID was cancelled."})
        else:
            values = {k: v for k, v in FORM_VALUES.get(req["ref"], {}).items() if k in req["fields"]}
            write({"id": rid, "type": "fill-form", "values": values, "verified": bool(set(values) & {"number", "cvv"})})
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
        same = [r for r, v in VALUES.items() if v.get("password") == secret(req, req)]
        write({"id": rid, "type": "check", "status": "same" if same else "new", "matches": same})
    elif kind == "check":
        known = [r for r, v in VALUES.items() if v.get("username") == req["username"]]
        same = [r for r in known if VALUES[r].get("password") == secret(req, req)]
        status = "same" if same else "update" if known else "new"
        write({"id": rid, "type": "check", "status": status, "matches": same or known})
    elif kind == "save" and not valid_entry(req.get("entry") or {}, req["origin"]):
        write({"id": rid, "type": "error", "code": "bad_request", "message": "bad entry"})
    elif kind == "save":
        PENDING.pop(req["entry"].get("generated"), None)
        write({"id": rid, "type": "save", "ref": req.get("ref") or "b" * 64 + ":" + "3" * 32, "created": not req.get("ref")})
    else:
        write({"id": rid, "type": "error", "code": "bad_request", "message": "unknown"})
