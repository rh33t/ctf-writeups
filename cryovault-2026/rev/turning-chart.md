### Summary

The binary checks a 39-byte input of the form `isfcr{` + 32 characters from `[a-z0-9_]` + `}`. The 32 payload bytes go through a fixed-key byte-permutation cipher of 320 rounds, where each round applies one of nine invertible byte operations picked from keystream data. All keys (keystream, dial and S-box) derive from a constant string, so the operation sequence is the same for every input. Tracing the per-round registers with gdb, replaying the operations forward to validate them, and then running them backward against the target recovers the payload.

### Steps

Commands run from the challenge directory. The binary in `files/` is not executable, so the commands that run it use a copy.

1. Identify the artifact and the messages it prints.

   ```sh
   file files/turning_chart
   strings -a files/turning_chart
   ```

   It is a static, stripped x86-64 ELF (sha256 `32744353e3ccedb39ee0a395dae8a0b305cc7a285734d92a65d0c8c64439be55`). The strings include `Course: `, `Course refused.`, `Museum dial (retired): 4 1 7 0 9 2 5 3 8 6`, `Chart opened. Course restored.` and the constant `a chart is a record of motion, not of place`.

2. Read the front-end checks from the disassembly.

   ```sh
   mkdir -p work/artifacts
   objdump -d -M intel files/turning_chart > work/artifacts/disasm.txt
   objdump -s -j .rodata files/turning_chart > work/artifacts/rodata.txt
   ```

   The code at `0x4010d8`-`0x401145` requires exactly 39 bytes, the prefix `isfcr{`, a suffix `}`, and 32 payload characters in `[a-z0-9_]`. The payload is copied to a 32-byte working buffer at `[rsp-0x48]`.

3. Understand the transform. The constant string is hashed with FNV-1a (the result is xored with `0xe21f48c7`) to seed two things: a permutation of `0..9`, called the dial, and a 256-byte S-box. The main loop runs 320 rounds. In each round it:

   - generates 5 keystream bytes from an LCG and table mix,
   - finds the dial index of `keystream[0]`, which selects one of nine byte operations (swap, add, xor with rotate, S-box lookup, and 8-byte group rotate or reverse),
   - applies that operation to the buffer.

   All indices and parameters come from keystream and register state, never from the buffer. The operation sequence is therefore fixed. Reading the register shuffling across the nine operations by hand is error-prone, so the sequence is captured from the running binary instead.

4. Capture the exact per-round register state with gdb. The dispatch decision point is `0x401321`, which is hit once per round, and the end of the transform is `0x40148c`. The trace script logs the registers at the first address and the final buffer and S-box at the second. The trace does not depend on the input, so any input that passes the length and charset checks works. The script runs the binary with the input from `work/scratch/in.txt`.

   ```sh
   mkdir -p work/scratch work/artifacts
   printf 'isfcr{%s}\n' "$(printf 'a%.0s' {1..32})" > work/scratch/in.txt
   gdb -q -batch -x work/scripts/trace.gdb files/turning_chart > work/artifacts/trace.txt
   ```

   The trace has 320 `OP` lines (one per round, with the 15 registers as decimal values), one `EDIFINAL` line, and two hexdumps: the 32-byte buffer and the 256-byte S-box. The program's own output (`Course refused.`) also appears in the file.

5. Replay and invert in Python. The script parses the trace and replays the 320 operations forward on `'a' * 32`. It checks the result against the buffer dump the binary wrote at the end. Then it computes the effective target from the binary's comparison constant, applies the inverse operations in reverse order, and prints the payload.

   ```sh
   python3 work/scripts/solve.py
   ```

   ```
   forward matches binary dump: True
   payload ascii: <32-character flag payload>
   FLAG: isfcr{REDACTED}
   ```

   The `payload ascii` line is the 32-character payload without the `isfcr{` and `}` wrapper, which the last line adds back.

6. Confirm against the binary.

   ```sh
   cp files/turning_chart scratch/tc && chmod +x scratch/tc
   printf '%s\n' 'isfcr{REDACTED}' | ./scratch/tc
   ```

   ```
   Course: Chart opened. Course restored.
   ```

   A wrong input prints `Course: Course refused.`

### Scripts

#### scripts/trace.gdb

A gdb batch script. It logs the 15 registers at the dispatch point `0x401321` for every round, then the final `edi`, the 32-byte buffer and the 256-byte S-box at `0x40148c`. Run it from the challenge directory with `gdb -q -batch -x work/scripts/trace.gdb files/turning_chart > work/artifacts/trace.txt` after creating `work/scratch/in.txt` as in step 4.

```gdb
set pagination off
set confirm off
set debuginfod enabled off
break *0x401321
commands
 silent
 printf "OP %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n", ($r10 & 0xff), ($rax & 0xffffffff), ($rbx & 0xffffffff), ($rcx & 0xffffffff), ($rdx & 0xffffffff), ($rsi & 0xffffffff), ($rdi & 0xffffffff), ($r8 & 0xffffffff), ($r9 & 0xffffffff), ($r10 & 0xffffffff), ($r11 & 0xffffffff), ($r12 & 0xffffffff), ($r13 & 0xffffffff), ($r14 & 0xffffffff), ($r15 & 0xffffffff)
 continue
end
break *0x40148c
commands
 silent
 printf "EDIFINAL %d\n", ($edi & 0xffffffff)
 x/32xb $rsp - 0x48
 x/256xb $rsp + 0x18
 continue
end
run < work/scratch/in.txt
quit
```

#### scripts/solve.py

Parses the gdb trace, validates the forward replay of the 320 operations, inverts them against the target, and prints the payload and the flag. It reads `work/artifacts/trace.txt` by default, or the path given as the first argument. Run it from the challenge directory with `python3 work/scripts/solve.py`.

```python
#!/usr/bin/env python3
"""Invert the Turning chart byte-permutation cipher.

The op sequence is recovered from a gdb trace (trace.txt).  Every op is a
fixed, input-independent transformation of a 32-byte buffer, so the sequence
can be replayed forward (to validate) and backward (to recover the input).
"""
import re, sys

TRACE = sys.argv[1] if len(sys.argv) > 1 else 'work/artifacts/trace.txt'
TARGET = bytes([
    0x23,0x20,0x7c,0x57,0xaa,0x47,0xa6,0xe8,0xe1,0x71,0xe3,0xfd,0x01,0xe3,0xd8,0x5c,
    0x34,0xc6,0x8c,0x18,0xb5,0x6b,0x70,0x78,0x17,0xc3,0xa5,0x6e,0xf8,0x58,0xe4,0xe5,
])

def m32(x):
    return x & 0xffffffff

def xorshift(x):
    x = m32(x)
    x ^= m32(x << 13)
    x ^= x >> 17
    x ^= m32(x << 5)
    return m32(x)

def rol8(x, c):
    c &= 7
    return ((x << c) | (x >> (8 - c))) & 0xff if c else x

# parse trace
ops = []
buf_dump = None
sbox_dump = None
edi_final = None
with open(TRACE) as fh:
    lines = fh.readlines()

xblocks = []
for ln in lines:
    ln = ln.strip()
    mo = re.search(r'OP (\d+)((?: -?\d+){14})', ln)
    if mo:
        vals = list(map(int, mo.group(2).split()))
        ops.append([int(mo.group(1))] + vals)
        continue
    me = re.search(r'EDIFINAL (-?\d+)', ln)
    if me:
        edi_final = m32(int(me.group(1)))
        continue
    mx = re.match(r'0x[0-9a-f]+:\s*((?:0x[0-9a-f]{1,2}\s*)+)', ln)
    if mx:
        xblocks.append(bytes(int(b, 16) for b in mx.group(1).split()))

assert len(ops) == 320, f'got {len(ops)} ops'
assert edi_final is not None
xdata = b''.join(xblocks)
assert len(xdata) == 32 + 256, len(xdata)
buf_dump = xdata[:32]
S = xdata[32:32 + 256]
print('ops', len(ops), 'buf_dump', buf_dump.hex(), 'edi_final', hex(edi_final))

# Register layout captured at 0x401321: r10, rax, rbx, rcx, rdx, rsi, rdi,
# r8, r9, r10, r11, r12, r13, r14, r15 (all 32-bit).
def op_forward(o, r, buf):
    rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15 = r
    if o == 2:
        A, B = rax & 0x1f, rbx & 0x1f
        buf[A], buf[B] = buf[B], buf[A]
    elif o == 3:
        A, B = rax & 0x1f, rbx & 0x1f
        cl = (rcx & 0xff) + buf[A]
        buf[B] = (buf[B] + cl) & 0xff
    elif o == 4:
        A, B = rax & 0x1f, rbx & 0x1f
        buf[B] = buf[B] ^ rol8(buf[A], rcx & 0xff)
    elif o == 5:
        B = rbx & 0x1f
        buf[B] = S[(buf[B] ^ (rcx & 0xff)) & 0xff]
    elif o == 6:
        A, B = rax & 0x1f, rbx & 0x1f
        a, b = buf[A], buf[B]
        buf[B] = a
        idx = (rcx + a) & 0xff
        buf[A] = b ^ S[idx]
    elif o == 0:
        base = (r14 & 3) * 8
        R = (rcx & 0xff) % 7
        temp = [0] * 8
        for i in range(1, 9):
            temp[(R + i) & 7] = buf[base + i - 1]
        buf[base:base+8] = temp
    elif o == 1:
        eax = rcx & 0xff
        rem = eax % 3
        be = (rsi + rdx) & 7
        temp = [0] * 4
        for j in range(4):
            temp[(rem + 1 + j) & 3] = buf[be + 8 * j]
        for j in range(4):
            buf[be + 8 * j] = temp[j]
    elif o == 7:
        base = (r14 & 3) * 8
        buf[base:base+8] = buf[base:base+8][::-1]
    elif o in (8, 9):
        pass
    else:
        raise ValueError(o)

def forward(init):
    buf = bytearray(init)
    for rec in ops:
        op_forward(rec[0], rec[1:], buf)
    return bytes(buf)

# validate forward replay against the binary's dump for the 'a' test input
init = b'a' * 32
fw = forward(init)
print('forward matches binary dump:', fw == buf_dump)
if fw != buf_dump:
    for i in range(32):
        if fw[i] != buf_dump[i]:
            print('  first diff at', i, hex(fw[i]), hex(buf_dump[i]))
            break

# invert
def op_inverse(o, r, buf):
    rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15 = r
    if o == 2:
        A, B = rax & 0x1f, rbx & 0x1f
        buf[A], buf[B] = buf[B], buf[A]
    elif o == 3:
        A, B = rax & 0x1f, rbx & 0x1f
        cl = (rcx & 0xff) + buf[A]
        buf[B] = (buf[B] - cl) & 0xff
    elif o == 4:
        A, B = rax & 0x1f, rbx & 0x1f
        buf[B] = buf[B] ^ rol8(buf[A], rcx & 0xff)
    elif o == 5:
        B = rbx & 0x1f
        inv = [0] * 256
        for i in range(256):
            inv[S[i]] = i
        buf[B] = inv[buf[B]] ^ (rcx & 0xff)
    elif o == 6:
        A, B = rax & 0x1f, rbx & 0x1f
        a = buf[B]              # forward stored old a here
        idx = (rcx + a) & 0xff
        b = buf[A] ^ S[idx]
        buf[A] = a
        buf[B] = b
    elif o == 0:
        base = (r14 & 3) * 8
        R = (rcx & 0xff) % 7
        old = [0] * 8
        for i in range(1, 9):
            old[i - 1] = buf[base + ((R + i) & 7)]
        buf[base:base+8] = old
    elif o == 1:
        eax = rcx & 0xff
        rem = eax % 3
        be = (rsi + rdx) & 7
        old = [0] * 4
        for j in range(4):
            old[j] = buf[be + 8 * ((rem + 1 + j) & 3)]
        for j in range(4):
            buf[be + 8 * j] = old[j]
    elif o == 7:
        base = (r14 & 3) * 8
        buf[base:base+8] = buf[base:base+8][::-1]
    elif o in (8, 9):
        pass
    else:
        raise ValueError(o)

# effective target for the in-loop buffer
edi = m32(edi_final ^ 0xd06f27b5)
eff = bytearray(32)
for i in range(32):
    edi = xorshift(edi)
    eff[i] = TARGET[i] ^ ((edi >> 24) & 0xff)
print('effective target:', eff.hex())

buf = bytearray(eff)
for rec in reversed(ops):
    op_inverse(rec[0], rec[1:], buf)
payload = bytes(buf)
print('payload:', payload)
print('payload ascii:', payload.decode('latin1'))

flag = b'isfcr{' + payload + b'}'
print('FLAG:', flag.decode())
```

### Notes

- The "museum dial" `4 1 7 0 9 2 5 3 8 6` is a decoy. The binary prints it on refusal, and it is not the dial used for dispatch.
- The trace is input-independent, so the `a` test input only needs to reach the transform. The solve script checks its forward replay against the buffer the binary dumps at `0x40148c`, which is how the trace is validated before inversion.
- `TARGET` in `solve.py` is the 32-byte value the binary compares the transformed buffer against. The effective target is derived from it by xoring each byte with a xorshift32 stream seeded from the final `edi` value.
- The first `OP` line in the trace shares a line with the program's `Course: ` output, so a grep for `^OP` finds 319 lines. The parser matches `OP` anywhere in the line and finds all 320.
- The trace file in the challenge (`work/artifacts/trace.txt`) is the capture for the `a` input. Re-run gdb only if the binary changes.
- Running the transform with the wrong input prints `Course refused.`, not the flag, so the output of a wrong guess is not a hint.
