#!/usr/bin/env python3
"""PrivateWire enrollment endpoint: register on-device WireGuard peers.

Owner-armed, time-boxed HTTPS API. The server NEVER sees a device private
key: the device generates its own keypair (official WireGuard library) and
POSTs only its public key. The server assigns the lowest free tunnel IP,
appends the peer to wg0.conf, live-applies, and returns the grant once.

Security properties (see docs/enrollment.md):
  - No open registrar: outside an owner-armed window every request gets 403
    (and the listener is normally not even running — see enroll-arm.sh).
  - Self-signed TLS cert, authenticated by the app via SPKI pin. There is no
    CA, no hostname trust: the pin IS the server identity.
  - Idempotent retry: the same public key always gets the same address/PSK
    back, so a client retry never burns a second IP.
  - Rate caps: per-source-IP sliding window + a per-window enrollment budget.
  - Logging policy: names, IPs and key PREFIXES only. PSKs are never logged.

Stdlib only. Bound to loopback without TLS ONLY via --insecure-no-tls
(which refuses any non-loopback bind) — used by the self-test.
"""
import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})$")
KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
PUB_RE = re.compile(r"PublicKey\s*=\s*(\S+)")
ALLOWED_RE = re.compile(r"AllowedIPs\s*=\s*(.+)")
ADDR_RE = re.compile(r"Address\s*=\s*([0-9.]+)/\d+")
COMMENT_RE = re.compile(r"^#\s*client:\s*(\S+)\s+\(([0-9.]+)\)")
MAX_BODY = 4096
RATE_PER_MIN = 20
RATE_WINDOW_S = 60


def b64_ok(s):
    if not isinstance(s, str) or not KEY_RE.match(s.strip()):
        return False
    try:
        return len(base64.b64decode(s.strip(), validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def die(msg):
    print("[privatewire][enroll][ERROR] %s" % msg, file=sys.stderr)
    sys.exit(1)


class EnrollState:
    """All mutable server state, guarded by one lock (enrollments serialize)."""

    def __init__(self, args):
        self.a = args
        self.lock = threading.Lock()
        self.hits = {}  # src ip -> deque[monotonic ts]
        self.successes = 0
        self.base = None
        self._load_network()

    def log(self, msg):
        print("[privatewire][enroll] %s" % msg, flush=True)

    def _load_network(self):
        addr = None
        try:
            with open(os.path.join(self.a.wg_dir, "wg0.conf")) as f:
                section = ""
                for line in f:
                    s = line.strip()
                    if s.startswith("[") and s.endswith("]"):
                        section = s
                        continue
                    if section == "[Interface]":
                        m = ADDR_RE.match(s)
                        if m:
                            addr = m.group(1)
                            break
        except OSError as e:
            die("cannot read wg0.conf: %s" % e)
        if addr is None:
            die("no Interface Address in wg0.conf")
        m = BASE_RE.match(addr)
        if not m:
            die("cannot parse server address %s" % addr)
        self.base = m.group(1)
        self.server_ip = addr

    # -- inventory -----------------------------------------------------
    def peers(self):
        """Return (pubkey->ip, name->(pubkey,ip)) scraped from wg0.conf."""
        by_pub, by_name = {}, {}
        cur_name, cur_ip, cur_pub = None, None, None
        try:
            with open(os.path.join(self.a.wg_dir, "wg0.conf")) as f:
                lines = f.readlines()
        except OSError:
            return by_pub, by_name
        body = "\n".join(lines)
        def flush():
            if cur_pub and cur_ip:
                by_pub[cur_pub] = cur_ip
                if cur_name:
                    by_name[cur_name] = (cur_pub, cur_ip)

        # Walk peer blocks: a "# client: NAME (IP)" comment starts each block.
        for line in lines:
            cm = COMMENT_RE.match(line.strip())
            if cm:
                flush()
                cur_name, cur_ip, cur_pub = cm.group(1), cm.group(2), None
                continue
            if line.strip() == "[Peer]":
                # A peer block without a preceding comment ends any tracked one.
                if cur_pub and cur_ip:
                    flush()
                    cur_name, cur_ip, cur_pub = None, None, None
                continue
            pm = PUB_RE.match(line.strip())
            if pm and cur_name is not None:
                cur_pub = pm.group(1)
                continue
            am = ALLOWED_RE.match(line.strip())
            if am and cur_name is not None and cur_ip is None:
                first = am.group(1).split(",")[0].strip()
                if first.endswith("/32"):
                    cur_ip = first[:-3]
        flush()
        # Peers without our comment (e.g. hand-added): still occupy IPs/pubkeys.
        for blk in body.split("[Peer]")[1:]:
            pm = PUB_RE.search(blk)
            am = ALLOWED_RE.search(blk)
            if pm and am:
                ip = am.group(1).split(",")[0].strip()
                if ip.endswith("/32"):
                    by_pub.setdefault(pm.group(1), ip[:-3])
        return by_pub, by_name

    def record_path(self, name):
        return os.path.join(self.a.wg_dir, "clients", "%s.enrolled" % name)

    def find_record_by_pub(self, pub):
        """Recover the stored record (and its PSK) for a known peer key."""
        try:
            files = os.listdir(os.path.join(self.a.wg_dir, "clients"))
        except OSError:
            return None
        for fn in sorted(files):
            if not fn.endswith(".enrolled"):
                continue
            rec = self.read_record(fn[:-len(".enrolled")])
            if rec and rec.get("PublicKey") == pub:
                return rec
        return None

    def read_record(self, name):
        rec = {}
        try:
            with open(self.record_path(name)) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    rec[k.strip()] = v.strip()
        except OSError:
            return None
        if not b64_ok(rec.get("PublicKey", "")) or not rec.get("Address"):
            return None
        return rec

    def write_record(self, name, pub, ip, psk):
        os.makedirs(os.path.join(self.a.wg_dir, "clients"), exist_ok=True)
        tmp = self.record_path(name) + ".tmp"
        with open(tmp, "w") as f:
            os.chmod(tmp, 0o600)
            f.write("# enrolled client %s — private key stays on the device\n"
                    % name)
            f.write("PublicKey = %s\nAddress = %s/32\n" % (pub, ip))
            f.write("PresharedKey = %s\nEnrolledAt = %d\n"
                    % (psk, int(time.time())))
        os.replace(tmp, self.record_path(name))

    def next_free_ip(self, by_pub):
        taken = {ip for ip in by_pub.values() if ip.startswith(self.base + ".")}
        taken.add(self.server_ip)
        taken.add("%s.2" % self.base)  # legacy official-app profile
        for o in range(3, 255):
            cand = "%s.%d" % (self.base, o)
            if cand not in taken:
                return cand
        return None

    def append_peer(self, name, pub, ip, psk):
        conf = os.path.join(self.a.wg_dir, "wg0.conf")
        with open(conf, "a") as f:
            f.write("\n# client: %s (%s)\n[Peer]\nPublicKey = %s\n"
                    % (name, ip, pub))
            f.write("PresharedKey = %s\nAllowedIPs = %s/32\n" % (psk, ip))
        os.chmod(conf, 0o600)
        alloc = os.path.join(self.a.wg_dir, ".ip-alloc")
        with open(alloc, "a") as f:
            f.write("%s %s/32\n" % (name, ip))
        try:
            os.chmod(alloc, 0o600)
        except OSError:
            pass

    def live_apply(self):
        if os.environ.get("ENROLL_STUB_APPLY") == "1":
            self.log("stub apply (ENROLL_STUB_APPLY=1)")
            return True
        try:
            strip = subprocess.run(
                ["wg-quick", "strip", os.path.join(self.a.wg_dir, "wg0.conf")],
                capture_output=True, timeout=15)
            if strip.returncode != 0:
                raise RuntimeError("wg-quick strip failed")
            tmp = os.path.join(self.a.wg_dir, ".wg-strip.tmp")
            with open(tmp, "wb") as f:
                f.write(strip.stdout)
            try:
                r = subprocess.run(["wg", "syncconf", "wg0", tmp],
                                   capture_output=True, timeout=15)
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            if r.returncode != 0:
                raise RuntimeError("wg syncconf failed")
            return True
        except Exception as e:  # noqa: BLE001 — fallback path below
            self.log("syncconf failed (%s), reloading service" % e)
        try:
            r = subprocess.run(["systemctl", "reload-or-restart", "wg-quick@wg0"],
                               capture_output=True, timeout=60)
            return r.returncode == 0
        except Exception as e:  # noqa: BLE001
            self.log("service reload failed: %s" % e)
            return False

    # -- policy --------------------------------------------------------
    def window_open(self):
        if self.a.open_registrar:
            return True
        try:
            with open(self.a.window_file) as f:
                return time.time() < int(f.read().strip())
        except (OSError, ValueError):
            return False

    def rate_ok(self, src):
        now = time.monotonic()
        q = self.hits.setdefault(src, deque())
        while q and now - q[0] > RATE_WINDOW_S:
            q.popleft()
        if len(q) >= RATE_PER_MIN:
            return False
        q.append(now)
        return True


def make_handler(state, cfg):
    class H(BaseHTTPRequestHandler):
        server_version = "PrivateWire"
        sys_version = ""

        def log_message(self, *a):  # route via our logger, no secret paths
            state.log("%s %s" % (self.command, self.path))

        def _json(self, code, obj, retry_after=None):
            body = (json.dumps(obj) + "\n").encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if retry_after is not None:
                self.send_header("Retry-After", str(retry_after))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802
            if self.path != "/enroll":
                return self._json(404, {"error": "not_found"})
            src = self.client_address[0]
            with state.lock:
                if not state.window_open():
                    return self._json(403, {"error": "window_closed"})
                # ^ In --open-registrar mode window_open() is always true:
                # anyone holding the APK may register (accepted tradeoff for
                # the friends build; rate caps still apply).
                if not state.rate_ok(src):
                    return self._json(429, {"error": "rate_limited"}, 60)
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    n = 0
                if n <= 0 or n > MAX_BODY:
                    return self._json(400, {"error": "bad_length"})
                try:
                    req = json.loads(self.rfile.read(n).decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    return self._json(400, {"error": "bad_json"})
                name = (req.get("name") or "").strip()
                pub = (req.get("pubkey") or "").strip()
                if not NAME_RE.match(name):
                    return self._json(400, {"error": "bad_name"})
                if not b64_ok(pub):
                    return self._json(400, {"error": "bad_pubkey"})
                by_pub, by_name = state.peers()
                # Same key back, same grant back — the pubkey is the
                # identity, names are just labels, and no new IP is ever
                # burned for a known key. Only a name owned by a DIFFERENT
                # key is refused. The live peer address is authoritative;
                # the stored PSK is recovered by pubkey so a retry under a
                # different name still handshakes. Record-less legacy peers
                # get a record minted (peer block untouched, empty psk).
                if pub in by_pub:
                    have = by_name.get(name)
                    if have is not None and have[0] != pub:
                        return self._json(409, {"error": "name_taken"})
                    rec = state.read_record(name)
                    if rec is None or rec.get("PublicKey") != pub:
                        rec = state.find_record_by_pub(pub)
                    ip = by_pub[pub]
                    if rec is None:
                        state.write_record(name, pub, ip, "")
                        state.log("adopted legacy %s (%s)" % (name, ip))
                        psk = ""
                    else:
                        psk = rec.get("PresharedKey", "")
                        state.log("reenroll %s (%s) idempotent" % (name, ip))
                    return self._json(200, grant(cfg, ip, psk))
                if name in by_name:
                    return self._json(409, {"error": "name_taken"})
                if not cfg["open"] and state.successes >= cfg["budget"]:
                    return self._json(429, {"error": "window_budget"})
                ip = state.next_free_ip(by_pub)
                if ip is None:
                    return self._json(503, {"error": "subnet_full"})
                psk = base64.b64encode(os.urandom(32)).decode()
                state.append_peer(name, pub, ip, psk)
                state.write_record(name, pub, ip, psk)
                if not state.live_apply():
                    return self._json(500, {"error": "apply_failed"})
                state.successes += 1
                state.log("enrolled %s (%s) key=%s.." % (name, ip, pub[:12]))
                return self._json(201, grant(cfg, ip, psk))

        def do_GET(self):  # noqa: N802
            self._json(404, {"error": "not_found"})

        def do_PUT(self):  # noqa: N802
            self._json(404, {"error": "not_found"})

        def do_DELETE(self):  # noqa: N802
            self._json(404, {"error": "not_found"})

    return H


def grant(cfg, ip, psk):
    return {"address": ip, "server_pubkey": cfg["server_pubkey"],
            "endpoint": cfg["endpoint"], "dns": cfg["dns"],
            "psk": psk, "allowed_ips": "0.0.0.0/0"}


def load_cfg(args):
    env = {}
    for cand in (args.env_file, "/etc/wireguard/privatewire.env"):
        try:
            with open(cand) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        env[k.strip()] = v.strip().strip("'\"")
            break
        except OSError:
            continue
    try:
        with open(os.path.join(args.wg_dir, "server_public.key")) as f:
            server_pub = f.read().strip()
    except OSError:
        die("missing server_public.key in %s" % args.wg_dir)
    if not b64_ok(server_pub):
        die("server_public.key is not a valid WireGuard key")
    host = args.endpoint_host or env.get("SERVER_PUBLIC_IP") or ""
    port = args.endpoint_port or int(env.get("WIREGUARD_PORT", "51820"))
    if not host:
        die("no endpoint host: pass --endpoint-host or set SERVER_PUBLIC_IP")
    dns = args.dns or env.get("DNS_SERVER")
    return {"server_pubkey": server_pub, "endpoint": "%s:%d" % (host, port),
            "dns": dns or "", "budget": args.budget,
            "open": args.open_registrar}


def main():
    p = argparse.ArgumentParser(description="PrivateWire enrollment endpoint")
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--wg-dir", default="/etc/wireguard")
    p.add_argument("--env-file", default="")
    p.add_argument("--window-file",
                   default="/etc/wireguard/.enroll-window")
    p.add_argument("--cert", default="/etc/wireguard/enroll-cert.pem")
    p.add_argument("--key", default="/etc/wireguard/enroll-key.pem")
    p.add_argument("--endpoint-host", default="")
    p.add_argument("--endpoint-port", type=int, default=0)
    p.add_argument("--dns", default="")
    p.add_argument("--budget", type=int, default=25)
    p.add_argument("--open-registrar", action="store_true",
                   help="ACCEPTED-RISK friends-build mode: no enrollment "
                        "window, anyone holding the APK may register a peer. "
                        "Per-IP rate caps still apply; the total budget is "
                        "lifted. Pair with a boot-enabled service.")
    p.add_argument("--insecure-no-tls", action="store_true",
                   help="loopback-only test mode; refuses non-loopback bind")
    args = p.parse_args()

    if args.insecure_no_tls and args.bind not in ("127.0.0.1", "::1"):
        die("--insecure-no-tls refuses non-loopback bind")
    if not args.insecure_no_tls:
        for f in (args.cert, args.key):
            if not os.path.exists(f):
                die("missing %s — run enroll-arm first" % f)

    state = EnrollState(args)
    if not state.base:
        die("network init failed")
    # DNS defaults to the VPN gateway (.1 of the tunnel subnet).
    cfg = load_cfg(args)
    if not cfg["dns"]:
        cfg["dns"] = "%s.1" % state.base

    httpd = ThreadingHTTPServer((args.bind, args.port),
                                make_handler(state, cfg))
    httpd.daemon_threads = True
    if not args.insecure_no_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(args.cert, args.key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    if args.open_registrar:
        state.log("OPEN REGISTRAR mode: anyone holding the APK may enroll "
                  "(accepted tradeoff); rate caps still apply, no total budget")
    state.log("listening on %s:%d base=%s.0/24 tls=%s" % (
        args.bind, args.port, state.base, not args.insecure_no_tls))

    # Self-terminate past the window so a forgotten arm cannot linger.
    # Disabled in open-registrar mode (there is no window to lapse).
    def reaper():
        while True:
            time.sleep(30)
            if not state.window_open():
                state.log("window lapsed, exiting")
                os._exit(0)  # noqa: PGH003 — listener-only process, no state to flush

    if not args.open_registrar:
        threading.Thread(target=reaper, daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
