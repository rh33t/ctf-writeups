### Summary

The seal is the 32-byte payload inside `isfcr{...}`, read as eight little-endian 32-bit registers. The binary runs these registers through a 160-step bytecode VM whose instruction decode and seed chain both depend on the register values, so forward guessing does not work. Every VM operation is invertible, and an end-of-loop check pins the final seed, so the VM can be run backwards from the required final register state to recover the initial state and the payload.

### Steps

1. Confirm the input and the catalogue. The `?` command lists three job cards. JOB 00 and JOB 02 are decoys (the strings say "SELFTEST ONLY" and "SUPERSEDED"). JOB 04 is the live job.
   ```sh
   printf '?\n' | ./palimpsest
   ```
2. Locate the VM data in `.rodata`. The header at vaddr `0x1000390` holds the magic `PPRSP03`, the initial seed `0x6d2b79f5` and the initial register pointer `3`. The 160 eight-byte instructions start at vaddr `0x10003d0`, and the required final registers are at `0x1000120` (R[4..7]) and `0x1000130` (R[0..3]). The file offset is the vaddr minus `0x1000000`.
   ```sh
   objdump -s -j .rodata files/palimpsest
   ```
3. Model one step. For instruction `i` (`edx = 8*i`, bytes `b0..b7`), the running seed `S` is expanded into a hash chain `h[k] = rol32(h[k-1] + b[k] + edx + 0x9e3779b9 + k, 5) ^ 0xa5a5f00d` with `h[0] = S`. The fields are:
   - `opcode = (S >> 24) ^ b0`
   - `ra = (((h1 >> 24) ^ b1) + r15) & 7`, `rb = (((h2 >> 24) ^ b2) + r15) & 7`
   - rotate amount `cl = (h3 >> 24) ^ b3`
   - a 4-byte immediate from `h4..h7`

   The opcodes are `0x13` (`^=imm`), `0x27` (`+=imm`), `0x39` (rotate left by `cl`), `0x4d` (`*=imm`, imm odd), `0x62` (`+= rol(R[rb], cl)`), `0x78` (`^= rol(R[rb], cl)`), `0x8b` (swap), and `0xa6` (`r15 = (r15 + b) & 7`). The next seed mixes two registers, `R[(r15+i)&7]` and `R[(r15+i+3)&7]`:
   `S' = i + rol(rol(edx + h7 + b7 + 0x9e3779c0, 5) ^ R[a] ^ rol(R[a3], 0xb) ^ 0xa5a5f00d, 7) + 0x7f4a7c15`.

   Cross-check the model against the binary in gdb. Step 0 runs as opcode `0x4d` with `t0 = 7`, `t1 = 3`, `t2 = 30`, and leaves seed `0x34ce5ef1` for a payload of `A`s.
   ```sh
   python3 -c "print('isfcr{'+'A'*32+'}')" > in.txt
   gdb -q -batch -ex 'set debuginfod enabled off' -ex 'break *0x1001b5d' \
       -ex 'run < in.txt' -ex 'printf "%#x %#x %#x\n",$ebx,$r14d,$ecx' files/palimpsest
   ```
4. Invert. Every opcode is invertible (`^=`, `+=`, rotate, multiply by an odd constant, `+= rol`, `^= rol`, swap). The end-of-loop check `inner + 160 == 0xf7f77ddb` pins the final seed to `159 + 0xf7f77d3b + 0x7f4a7c15`. Start from the required final registers (R[0..3] from `0x1000130`, R[4..7] from `0x1000120`, final `r15 = 1`) and undo the 160 steps from last to first. The recovered initial seed `0x6d2b79f5` and pointer `3` match the header, which confirms the inversion. The script prints the seal.
   ```sh
   python3 scripts/solve.py
   # isfcr{REDACTED}
   ```
5. Verify against the live binary. It prints `Seal accepted. Job 04 restored.`
   ```sh
   printf 'isfcr{REDACTED}\n' | ./palimpsest
   # Seal accepted. Job 04 restored.
   ```

### Scripts

#### scripts/solve.py

Inverts the VM from the final register state and prints the seal. The script reads the 160 instructions and the target registers directly from the binary file at file offsets `0x3d0`, `0x130` and `0x120`. It uses only the Python 3 standard library. Run it as `python3 scripts/solve.py [path/to/palimpsest]`, the default being `../../files/palimpsest` relative to the script.

```python
#!/usr/bin/env python3
"""Solve Palimpsest (id 47) by inverting the restoration-press VM.

The challenge binary (files/palimpsest) treats the 32 bytes inside isfcr{...}
as eight 32-bit registers and runs a 160-step bytecode VM over them. Both the
program decode and the seed chain depend on register values, so forward
execution from a random guess is impossible. The VM is a bijection though:
starting from the required final register state and the final seed (pinned by
the 0xf7f77ddb consistency check), each instruction can be decoded and undone
backwards until the initial seed 0x6d2b79f5 and pointer 3 are recovered.

Run:  python3 solve.py [path/to/palimpsest]
Prints the seal on stdout.
"""
import struct, sys, os

SEED0 = 0x6d2b79f5
R15_0 = 3
M = 0xa5a5f00d
C = [0x9e3779b9, 0x9e3779ba, 0x9e3779bb, 0x9e3779bc,
     0x9e3779bd, 0x9e3779be, 0x9e3779bf]
NSTEPS = 160


def rol(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def ror(x, n):
    n &= 31
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def inv_mod32(odd):
    x = 1
    for _ in range(6):
        x = (x * (2 - odd * x)) & 0xffffffff
    return x


def inv_hashchain(h7, b, edx):
    """Undo h_k = rol(h_{k-1} + b_k + edx + C_k, 5) ^ M, returning h1..h6 and S."""
    h = [0] * 7
    h[6] = h7
    for k in range(6, 0, -1):
        h[k - 1] = (ror(h[k] ^ M, 5) - b[k] - edx - C[k]) & 0xffffffff
    S = (ror(h[0] ^ M, 5) - b[0] - edx - C[0]) & 0xffffffff
    return h, S


def inv_step(seed_after, r15_post, R_after, code, i):
    edx = 8 * i
    b = code[edx:edx + 8]
    R = list(R_after)
    a = (r15_post + i) & 7
    a3 = (r15_post + i + 3) & 7
    X = R[a] ^ rol(R[a3], 0xb) ^ M
    V = (seed_after - i - 0x7f4a7c15) & 0xffffffff
    K = ror(V, 7) ^ X
    h7 = (ror(K, 5) - edx - 0x9e3779c0 - b[7]) & 0xffffffff
    h, S = inv_hashchain(h7, b, edx)
    b0, b1, b2, b3, b4, b5, b6, b7 = b
    op = ((S >> 24) ^ b0) & 0xff
    t0 = ((h[0] >> 24) ^ b1) & 0xff
    t1 = ((h[1] >> 24) ^ b2) & 0xff
    t2 = ((h[2] >> 24) ^ b3) & 0xff
    r11d = ((h[3] >> 24) ^ b4) & 0xff
    imm = (((h[6] >> 24) ^ b7) << 24) | (((h[5] >> 24) ^ b6) << 16) \
        | (((h[4] >> 24) ^ b5) << 8) | r11d
    r15_pre = ((r15_post - r11d) & 7) if op == 0xa6 else r15_post
    ra = (t0 + r15_pre) & 7
    rb = (t1 + r15_pre) & 7
    if op == 0x13:
        R[ra] ^= imm
    elif op == 0x27:
        R[ra] = (R[ra] - imm) & 0xffffffff
    elif op == 0x39:
        R[ra] = ror(R[ra], t2)
    elif op == 0x4d:
        assert imm & 1
        R[ra] = (R[ra] * inv_mod32(imm)) & 0xffffffff
    elif op == 0x62:
        R[ra] = (R[ra] - rol(R[rb], t2)) & 0xffffffff
    elif op == 0x78:
        R[ra] = (R[ra] ^ rol(R[rb], t2)) & 0xffffffff
    elif op == 0x8b:
        R[ra], R[rb] = R[rb], R[ra]
    elif op == 0xa6:
        pass
    else:
        raise ValueError("unexpected opcode %#x at step %d" % (op, i))
    return S, r15_pre, R


def solve(path):
    blob = open(path, 'rb').read()
    code = blob[0x3d0:0x8d0]          # 160 x 8-byte instructions
    target0 = list(struct.unpack('<4I', blob[0x130:0x140]))  # regs 0..3
    target4 = list(struct.unpack('<4I', blob[0x120:0x130]))  # regs 4..7
    R = target0 + target4
    # final seed is pinned by: V + 160 == 0xf7f77ddb, seed = 159 + V + 0x7f4a7c15
    seed_after = (159 + 0xf7f77d3b + 0x7f4a7c15) & 0xffffffff
    r15 = 1
    for i in range(NSTEPS - 1, -1, -1):
        seed_after, r15, R = inv_step(seed_after, r15, R, code, i)
    assert r15 == R15_0, r15
    assert seed_after == SEED0, hex(seed_after)
    return struct.pack('<8I', *R)


if __name__ == '__main__':
    here = os.path.dirname(os.path.abspath(__file__))
    default = os.path.join(here, '..', '..', 'files', 'palimpsest')
    path = sys.argv[1] if len(sys.argv) > 1 else default
    payload = solve(path)
    print('isfcr{%s}' % payload.decode('latin1'))
```

### Notes

- The two catalogue strings `isfcr{th3_pr3ss_p4ss3d_1ts_s3lf_t3st_0}` (JOB 00) and `isfcr{0ld_1nk_n3v3r_t3lls_n3w_t4l3s_v2}` (JOB 02) are decoys. Only the JOB 04 seal produces `Seal accepted. Job 04 restored.`
- The VM is a bijection. A forward run of a random payload is rejected at step 1 because a decoded field is out of range, which confirms that the decode depends on the registers. Do not attempt a forward search.
- For opcode `0xa6` the script undoes the `r15` update first, using the byte it decodes as `r11d`, and only then computes the operand registers.
- The vault copy of `files/palimpsest` has no exec bit. Run `chmod +x` on a copy before the commands in steps 1, 3 and 5.
- The binary is statically linked and stripped, 4200 bytes. The end-of-loop check `0xf7f77ddb` is what fixes the final seed, so an incorrect final state fails the assertions in `solve()`.
- The gdb breakpoint address `0x1001b5d` and the register values in step 3 come from the vault write-up and were recorded against this binary. Check them with your own copy before relying on them.
