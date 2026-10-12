#!/usr/bin/env python3
"""Self-test for enroll-server.py. No root, no wireguard, no network beyond
loopback. Spins the real server with --insecure-no-tls (loopback only) and
ENROLL_STUB_APPLY=1, then exercises every status path.

Usage: test-enroll.py   (exit nonzero on any failure)
"""
import base64
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, "enroll-server.py")
PY = sys.executable

PASS = 0
FAIL = 0


def check(desc, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("ok: %s" % desc)
    else:
        FAIL += 1
        print("FAIL: %s" % desc)


def key_of(seed):
    # Two-byte seed prefix: all seeds < 65536 yield distinct keys, so peer
    # keys and request keys in these tests can never collide accidentally.
    body = bytes([seed & 0xFF, (seed >> 8) & 0xFF] +
                 [((seed * 37 + i * 11) & 0xFF) for i in range(29)])
    raw = body + bytes([(seed * 13) & 0xF0])  # low nibble 0 keeps b64 tail valid
    k = base64.b64encode(raw).decode()
    assert re.match(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$", k), k
    assert len(base64.b64decode(k)) == 32
    return k


SERVER_PUB = key_of(7)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def make_wgdir(octets=()):
    d = tempfile.mkdtemp(prefix="pw-enroll-test-")
    os.makedirs(os.path.join(d, "clients"))
    with open(os.path.join(d, "wg0.conf"), "w") as f:
        f.write("[Interface]\nPrivateKey = %s\nAddress = 10.66.66.1/24\n"
                "ListenPort = 51820\nSaveConfig = false\n" % key_of(99))
        for i, o in enumerate(octets):
            f.write("\n# client: c%d (10.66.66.%d)\n[Peer]\nPublicKey = %s\n"
                    "PresharedKey = %s\nAllowedIPs = 10.66.66.%d/32\n"
                    % (i, o, key_of(100 + o), key_of(200 + o), o))
    with open(os.path.join(d, "server_public.key"), "w") as f:
        f.write(SERVER_PUB + "\n")
    open(os.path.join(d, ".ip-alloc"), "w").close()
    return d


def arm(d, minutes=15):
    with open(os.path.join(d, ".enroll-window"), "w") as f:
        f.write("%d\n" % (int(time.time()) + minutes * 60))


class Srv:
    def __init__(self, d, budget=25, env_extra=None, open_registrar=False):
        self.port = free_port()
        env = dict(os.environ)
        env["ENROLL_STUB_APPLY"] = "1"
        if env_extra:
            env.update(env_extra)
        argv = [PY, SERVER, "--insecure-no-tls", "--bind", "127.0.0.1",
                "--port", str(self.port), "--wg-dir", d,
                "--window-file", os.path.join(d, ".enroll-window"),
                "--endpoint-host", "203.0.113.10", "--dns", "10.66.66.1",
                "--budget", str(budget)]
        if open_registrar:
            argv.append("--open-registrar")
        self.p = subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        # Wait for the listener (up to 5s).
        for _ in range(50):
            try:
                c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=1)
                c.request("GET", "/")
                c.getresponse().read()
                c.close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("server did not start")

    def post(self, path="/enroll", body=None, raw=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        data = raw if raw is not None else json.dumps(body).encode()
        c.request("POST", path, body=data,
                  headers={"Content-Type": "application/json"})
        r = c.getresponse()
        payload = r.read().decode()
        c.close()
        try:
            obj = json.loads(payload) if payload.strip() else None
        except ValueError:
            obj = None
        return r.status, obj, r.getheader("Retry-After")

    def get(self, path="/"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", path)
        r = c.getresponse()
        st, body = r.status, r.read().decode()
        c.close()
        return st, body

    def stop(self):
        self.p.terminate()
        try:
            self.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.p.kill()


def main():
    # --- 1. closed window refuses everything ---
    d = make_wgdir(octets=(2,))
    s = Srv(d)
    try:
        st, obj, _ = s.post(body={"name": "alice", "pubkey": key_of(1)})
        check("closed window -> 403 window_closed",
              st == 403 and obj.get("error") == "window_closed")
        st, _ = s.get("/")
        check("GET / -> 404", st == 404)
        st, obj, _ = s.post(path="/nope", body={"a": 1})
        check("POST /nope -> 404", st == 404 and obj.get("error") == "not_found")
    finally:
        s.stop()

    # --- 2. validation + happy path + idempotency + conflicts ---
    arm(d)
    s = Srv(d)
    try:
        st, obj, _ = s.post(raw=b"not json")
        check("bad json -> 400", st == 400 and obj.get("error") == "bad_json")
        st, obj, _ = s.post(body={"name": "alice", "pubkey": "junk"})
        check("bad pubkey -> 400", st == 400 and obj.get("error") == "bad_pubkey")
        st, obj, _ = s.post(body={"name": "../x", "pubkey": key_of(1)})
        check("bad name -> 400", st == 400 and obj.get("error") == "bad_name")
        st, obj, _ = s.post(raw=b"x" * 5000)
        check("oversize -> 400", st == 400)

        k1 = key_of(1)
        st, g1, _ = s.post(body={"name": "alice", "pubkey": k1})
        check("enroll -> 201", st == 201)
        check("lowest free skips .1/.2 -> .3", g1.get("address") == "10.66.66.3")
        check("grant echoes server key/endpoint/dns",
              g1.get("server_pubkey") == SERVER_PUB
              and g1.get("endpoint") == "203.0.113.10:51820"
              and g1.get("dns") == "10.66.66.1"
              and g1.get("allowed_ips") == "0.0.0.0/0")
        psk = g1.get("psk", "")
        check("grant carries fresh 32-byte psk",
              re.match(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$", psk or "")
              and len(base64.b64decode(psk)) == 32)

        conf = open(os.path.join(d, "wg0.conf")).read()
        check("peer block appended", "PublicKey = %s" % k1 in conf
              and "AllowedIPs = 10.66.66.3/32" in conf)
        check("alloc ledger updated", "alice 10.66.66.3/32" in
              open(os.path.join(d, ".ip-alloc")).read())
        check("record file written",
              os.path.exists(os.path.join(d, "clients", "alice.enrolled")))

        st, g2, _ = s.post(body={"name": "alice", "pubkey": k1})
        check("idempotent retry -> 200 same grant",
              st == 200 and g2.get("address") == "10.66.66.3"
              and g2.get("psk") == psk)
        check("retry burned no second ip",
              open(os.path.join(d, "wg0.conf")).read().count(k1) == 1)

        st, obj, _ = s.post(body={"name": "alice", "pubkey": key_of(2)})
        check("name taken -> 409", st == 409 and obj.get("error") == "name_taken")
        # Same key under a new name burns no new IP: the live grant comes
        # back with the ORIGINAL psk (recovered by pubkey), so it handshakes.
        st, gb, _ = s.post(body={"name": "bob", "pubkey": k1})
        check("same key new name -> 200 same ip+psk",
              st == 200 and gb.get("address") == "10.66.66.3"
              and gb.get("psk") == psk)

        st, g3, _ = s.post(body={"name": "bob", "pubkey": key_of(3)})
        check("gap fill: .2 taken, .3 taken -> .4",  # .2 pre-seeded above
              st == 201 and g3.get("address") == "10.66.66.4")
    finally:
        s.stop()

    # --- 3. gap reuse: .3/.5 taken -> .4 ---
    d2 = make_wgdir(octets=(2, 3, 5))
    arm(d2)
    s = Srv(d2)
    try:
        st, g, _ = s.post(body={"name": "gap", "pubkey": key_of(11)})
        check("gap reuse -> .4", st == 201 and g.get("address") == "10.66.66.4")
    finally:
        s.stop()

    # --- 4. per-window budget ---
    d3 = make_wgdir()
    arm(d3)
    s = Srv(d3, budget=1)
    try:
        st, _, _ = s.post(body={"name": "one", "pubkey": key_of(21)})
        check("budget: first enroll ok", st == 201)
        st, obj, _ = s.post(body={"name": "two", "pubkey": key_of(22)})
        check("budget: second -> 429 window_budget",
              st == 429 and obj.get("error") == "window_budget")
    finally:
        s.stop()

    # --- 5. per-IP rate cap ---
    d4 = make_wgdir()
    arm(d4)
    s = Srv(d4)
    try:
        codes = [s.post(body={"name": "x", "pubkey": "bad"})[0] for _ in range(25)]
        check("rate cap trips -> 429 rate_limited", 429 in codes)
    finally:
        s.stop()

    # --- 6. full subnet ---
    d5 = make_wgdir(octets=list(range(2, 255)))
    arm(d5)
    s = Srv(d5)
    try:
        st, obj, _ = s.post(body={"name": "full", "pubkey": key_of(31)})
        check("full subnet -> 503 subnet_full",
              st == 503 and obj.get("error") == "subnet_full")
    finally:
        s.stop()

    # --- 7. open-registrar mode: no window, no budget, legacy adoption ---
    d6 = make_wgdir(octets=(2,))  # .2 legacy peer, no record on file
    s = Srv(d6, budget=1, open_registrar=True)  # NOTE: not armed
    try:
        st, g, _ = s.post(body={"name": "fresh", "pubkey": key_of(41)})
        check("open mode: no window -> 201",
              st == 201 and g.get("address") == "10.66.66.3")
        st, _, _ = s.post(body={"name": "fresh2", "pubkey": key_of(42)})
        check("open mode: total budget lifted", st == 201)
        st, g, _ = s.post(body={"name": "legacyowner", "pubkey": key_of(102)})
        check("adoption keeps legacy ip with empty psk",
              st == 200 and g.get("address") == "10.66.66.2"
              and g.get("psk") == "")
        check("adoption touches no peer block",
              open(os.path.join(d6, "wg0.conf")).read().count(key_of(102)) == 1)
        st, g2, _ = s.post(body={"name": "legacyowner", "pubkey": key_of(102)})
        check("adoption idempotent",
              st == 200 and g2.get("address") == "10.66.66.2"
              and g2.get("psk") == "")
        st, obj, _ = s.post(body={"name": "fresh", "pubkey": key_of(102)})
        check("adoption name clash -> 409",
              st == 409 and obj.get("error") == "name_taken")
    finally:
        s.stop()

    # --- 8. insecure mode refuses non-loopback bind ---
    p = subprocess.run([PY, SERVER, "--insecure-no-tls", "--bind", "0.0.0.0",
                        "--port", str(free_port()), "--wg-dir", d5,
                        "--window-file", os.path.join(d5, ".enroll-window"),
                        "--endpoint-host", "203.0.113.10"],
                       capture_output=True, timeout=15)
    check("insecure-no-tls refuses 0.0.0.0", p.returncode != 0)

    print("--- pass=%d fail=%d ---" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
