### Summary

The service is a blind Schnorr signer over secp256k1 that answers one attacker-chosen challenge per session: `open` returns `R = r·G`, and `sign <id> <c>` returns `s = r + c·x`, where `X = x·G` is the per-connection public key. A triple `(R, s, m)` is valid iff `s·G = R + H(R,m)·X`, with `H(R,m) = SHA256(x || y || m) mod N`. Returning more valid signatures on distinct messages than challenges answered is a one-more forgery, and the ROS problem behind it is solvable in polynomial time once the number of concurrent sessions exceeds `log2(N)` (Benhamouda, Lepoint, Loss, Orru, Raykova, eprint 2020/945). The service allows 512 sessions, so 256 open sessions are enough to obtain 257 valid signatures from 256 answers, which makes the server print the flag.

### Steps

1. Read `files/server.py`. The protocol takes one command per message. On connect the server sends `X <hex64>`, the public key of this connection. `open` replies `id <k> R <hex64>`, and `sign <k> <c>` replies `s <int>` once per session. `submit` must be followed by one JSON line `[[msg_hex, Rx, Ry, s], ...]`. The server counts answered challenges in `answered` and `_judge` counts valid signatures on distinct messages in `good`. It prints `one more! <flag>` only when `good > answered`. The hash uses `ser(R) = x || y`, two 32-byte big-endian coordinates.

   ```
   X <hex64>            greeting: public key of this connection
   open                 -> id <k> R <hex64>
   sign <k> <c>         -> s <int>
   submit               -> then one JSON line [[msg_hex, Rx, Ry, s], ...]
   ```

2. Open `ℓ = 256` sessions and keep each commitment `R_i`. The attack needs `ℓ > log2(N)`, and since `N < 2^256`, 256 is enough. The service accepts up to 512. For each session choose two distinct messages `m_{i,0}` and `m_{i,1}` (the solver uses `one-more/<i>/0` and `one-more/<i>/1`) and precompute `e[i][b] = H(R_i, m_{i,b})`.

3. Compute `w_i = 2^i / (e[i][1] - e[i][0]) mod N` and `C = Σ w_i·e[i][0] mod N`. Choosing one bit per session selects `e[i][bits_i]`, and `Σ w_i·e[i][bits_i] = C + (bits read as a 256-bit integer)` for every bit vector. This interpolation is the core of the ROS attack: the challenges sent to the signer can be arranged to add up to any 256-bit target `h*`.

4. Build the forged commitment `R* = Σ w_i·R_i + C·X` and the target hash `h* = H(R*, m*)` for a fresh message `m* = one-more/forged`. Bit `i` of `h*` is `(h* >> i) & 1`, and it selects the challenge for session `i`.

5. For each session send `sign i c_i` with `c_i = e[i][bits_i]` and collect `s_i`. Let `s* = Σ w_i·s_i mod N`. Because `s_i = r_i + c_i·x`, we get `s*·G = Σ w_i·R_i + (C + h*)·X = (R* - C·X) + (C + h*)·X = R* + h*·X`. So `(R*, s*, m*)` is a valid signature that was never requested. The solver asserts this identity before submitting.

6. Submit the 256 honest signatures `(R_i, s_i, one-more/<i>/<bits_i>)` plus the forged `(R*, s*, one-more/forged)` as one JSON list. That is 257 valid signatures for 256 answers, so `good > answered` and the server replies with the flag.

   ```sh
   python3 work/scripts/solve.py wss://one-more.isfcr.xyz
   ```

   Output of the live run on 2026-10-10 (about 2:51, mostly WAN round trips):

   ```
   [+] server public key: X <hex64>
   [+] opened 256 sessions
   valid 257 answered 256
   one more! isfcr{REDACTED}
   ```

   The same script self-tests against `files/server.py` in-process with `python3 work/scripts/solve.py --local`. It prints `valid 257 answered 256` and the local test flag `TESTFLAG{local}`, which is not the real flag.

### Scripts

#### scripts/solve.py

Forges 257 signatures from 256 challenge answers over the live service (or the local copy of `server.py` with `--local`) and prints the server replies. Run it from the challenge directory with `python3 work/scripts/solve.py wss://one-more.isfcr.xyz`, after `pip install ecdsa websockets`.

```python
#!/usr/bin/env python3
"""
one-more solver: polynomial-time ROS forgery (Benhamouda et al., eprint 2020/945).

The service is a blind Schnorr signer over secp256k1. It answers one chosen challenge
per session: c -> s = r + c*x, with R = r*G and public key X = x*G. A submitted signature
(R, s, m) is valid iff s*G == R + H(R, m)*X.

We ask for `ell >= ceil(log2(N))` sessions with R_i. For each session we precompute two
candidate challenges e[i][0] = H(R_i, m_{i,0}) and e[i][1] = H(R_i, m_{i,1}). With
    w_i = 2^i / (e[i][1] - e[i][0]),   C = sum_i w_i * e[i][0],
the map (bits) -> sum_i w_i * e[i][bits_i] is the identity on ell-bit integers, so if we
choose the bits of a target h* we get sum_i w_i * e_i = C + h*. Then for any scalar offset
    R* = sum_i w_i * R_i + C * X,    s* = sum_i w_i * s_i,
we have s* * G = R* + h* * X. Setting h* = H(R*, m_*) turns (R*, s*, m_*) into a valid
signature we never asked for: ell answers, ell+1 signatures.

Usage:
    python3 solve.py                     # live: wss://one-more.isfcr.xyz
    python3 solve.py wss://HOST          # live: explicit endpoint
    python3 solve.py --local             # drive files/server.py in-process (self-test)
"""
import argparse
import hashlib
import importlib.util
import json
import os
import sys

from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point

G = SECP256k1.generator
N = int(SECP256k1.order)
ELL = 256  # > log2(N); the service allows up to 512


def ser(P):
    return int(P.x()).to_bytes(32, "big") + int(P.y()).to_bytes(32, "big")


def H(R, m):
    return int.from_bytes(hashlib.sha256(ser(R) + m).digest(), "big") % N


def parse_point(hex64):
    b = bytes.fromhex(hex64)
    return Point(SECP256k1.curve, int.from_bytes(b[:32], "big"), int.from_bytes(b[32:], "big"))


def message(i, bit):
    return f"one-more/{i}/{bit}".encode()


FORGED_MSG = b"one-more/forged"


def build_forgery(X, R, msg=FORGED_MSG):
    """Given public key X and commitments R (points), return (R*, h*, [c_i])."""
    e = [[H(R[i], message(i, b)) for b in (0, 1)] for i in range(len(R))]
    w = []
    for i in range(len(R)):
        d = (e[i][1] - e[i][0]) % N
        w.append((pow(2, i, N) * pow(d, -1, N)) % N)
    C = 0
    for i in range(len(R)):
        C = (C + w[i] * e[i][0]) % N
    Rstar = C * X
    for i in range(len(R)):
        Rstar = Rstar + w[i] * R[i]
    hstar = H(Rstar, msg)
    bits = [(hstar >> i) & 1 for i in range(len(R))]
    challenges = [e[i][bits[i]] for i in range(len(R))]
    return Rstar, hstar, challenges, w, bits


def assemble(R, s, w, Rstar, hstar, bits):
    sigs = []
    for i in range(len(R)):
        sigs.append([message(i, bits[i]).hex(),
                     int(R[i].x()), int(R[i].y()), int(s[i]) % N])
    sstar = 0
    for i in range(len(R)):
        sstar = (sstar + w[i] * s[i]) % N
    sigs.append([FORGED_MSG.hex(), int(Rstar.x()), int(Rstar.y()), sstar])
    return sigs


# live client

def solve_live(url):
    import asyncio
    from websockets.asyncio.client import connect

    async def run():
        async with connect(url, max_size=None, ping_interval=20) as ws:
            greeting = await ws.recv()
            assert greeting.startswith("X "), greeting
            X = parse_point(greeting.split()[1])
            print(f"[+] server public key: {greeting}", file=sys.stderr)

            R = []
            for i in range(ELL):
                await ws.send("open")
                reply = await ws.recv()
                R.append(parse_point(reply.split()[-1]))
            print(f"[+] opened {ELL} sessions", file=sys.stderr)

            Rstar, hstar, challenges, w, bits = build_forgery(X, R)

            s = []
            for i in range(ELL):
                await ws.send(f"sign {i} {challenges[i]}")
                reply = await ws.recv()
                s.append(int(reply.split()[1]) % N)

            sstar = 0
            for i in range(ELL):
                sstar = (sstar + w[i] * s[i]) % N
            assert G * sstar == Rstar + hstar * X, "forgery identity failed"

            sigs = assemble(R, s, w, Rstar, hstar, bits)
            await ws.send("submit")
            await ws.send(json.dumps(sigs))
            replies = []
            while len(replies) < 2:
                try:
                    replies.append(await ws.recv())
                except Exception:
                    break
            return replies

    return asyncio.run(run())


# local client

def load_server():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "files", "server.py")
    spec = importlib.util.spec_from_file_location("omsrv", os.path.abspath(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def solve_local():
    mod = load_server()
    sess = mod.Session("TESTFLAG{local}")
    X = parse_point(sess.greeting().split()[1])
    R = []
    for _ in range(ELL):
        R.append(parse_point(sess.feed("open")[0].split()[-1]))
    Rstar, hstar, challenges, w, bits = build_forgery(X, R)
    s = []
    for i in range(ELL):
        s.append(int(sess.feed(f"sign {i} {challenges[i]}")[0].split()[1]) % N)
    sstar = 0
    for i in range(ELL):
        sstar = (sstar + w[i] * s[i]) % N
    assert G * sstar == Rstar + hstar * X, "forgery identity failed"
    sigs = assemble(R, s, w, Rstar, hstar, bits)
    sess.feed("submit")
    out = sess.feed(json.dumps(sigs))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", default="wss://one-more.isfcr.xyz")
    ap.add_argument("--local", action="store_true")
    args = ap.parse_args()
    if args.local:
        for line in solve_local():
            print(line)
    else:
        for line in solve_live(args.url):
            print(line)


if __name__ == "__main__":
    main()
```

### Notes

- The server's `sign` uses the plus convention `s = r + c·x`. The classic Sage PoC uses the minus convention, so the challenges and the `C·X` offset carry a plus sign in this solver.
- The forged triple needs its own `s*` as the fourth element. Without it `_judge` skips the entry and `good` stays capped at `answered`.
- `ℓ = 256 = ⌈log2 N⌉` is enough because `h* < N < 2^256`. The server would allow up to 512 sessions.
- Each connection gets a fresh key `X` and fresh sessions, so the whole attack must run on one connection. The `X` printed by one run cannot be reused.
- Server limits per connection: 1800 s, and at most 600 signatures in one `submit`. The solve sends 257.
- `--local` needs `files/server.py` next to the challenge directory, and it runs the in-process server with a test flag, not the real one.
