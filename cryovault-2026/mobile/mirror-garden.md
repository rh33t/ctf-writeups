### Summary

The APK contains 1024 classes `one.sr.garden.leaf.L0000` to `L1023`, each with a `verify(byte[])` method. The native `bloom` routine computes a 48-byte constant and a leaf index (357 here), then calls `verify` on the matching leaf. That `verify` checks 8 arithmetic relations over a 16-byte input; symbolic execution with Z3 gives the unique 16-byte "whisper", and `verify` returns `payload XOR whisper`. Feeding that result back into the emulated native `bloom` makes the native code build the flag, so the whole chain runs offline by emulation.

### Steps

1. Find the leaf index by emulating the internal native routine at `0x2374` with Unicorn. It writes a 48-byte constant and an index. The script maps the ELF segments, sets up the stack and output buffer, and runs until the routine returns:
   ```
   const48 = 657db61a964a04d3a54b416f0243ab7baaf6b1146475155b2b6faa6e3f56b86d1784d10160343a78ca7a31c665f12b33
   index   = 357        -> class one/sr/garden/leaf/L0357
   ```
   The leaf class name follows the format `one/sr/garden/leaf/L%04d`, so index 357 gives `L0357`.

2. Disassemble `L0357.verify` and solve the "whisper". `dexdump -d` prints the bytecode of `verify`. The network is 64-bit arithmetic (multiplications by constants, additions, XOR, shifts and masks with `0xffffffff`). The script executes it symbolically over 16 input bytes and collects the 8 final equality constraints, then Z3 solves them. An extra exclusion constraint on the solution is unsatisfiable, so the whisper is unique:
   ```
   whisper = 4c2e5d5e6f6f71284c6c555e28615d23   # "L.]^ooq(LlU^(a]#"
   ```

3. Read the payload of `verify`. It is a `fill-array-data` payload of 48 bytes, located from the `fill-array-data` operand (dexdump code offsets are in 16-bit units). The 48-byte payload is:
   ```
   c9fd8c81c3b9da820eff4ac45347ea1525f0921ec88b554f85fabc6f92cd33ae20cbb21d9d44baf903c3ea9d1e6a05b8
   ```
   `verify` returns `payload[i] XOR input[i % 16]`, so the value the native code receives is `payload XOR whisper` with the whisper cycled modulo 16.

4. Emulate `bloom` end to end with Unicorn. The native code calls JNI functions (FindClass, GetStaticMethodID, CallStaticObjectMethod, GetArrayLength, GetByteArrayElements, NewByteArray, DeleteLocalRef, NewStringUTF) and the PLT functions `snprintf` and `memcpy`. The script stubs the JNI calls, makes the `verify` call return the value from step 3, and captures the strings passed to `NewStringUTF`. The captured string starting with `isfcr{` is the flag. The run takes about one second.
   ```sh
   python3 work/scripts/solve.py files/mirror-garden.apk
   # isfcr{REDACTED}
   ```

### Scripts

#### scripts/solve.py

Emulates `0x2374` to get the 48-byte constant and leaf index, disassembles the matching `L####.verify` with `dexdump`, solves the 8 equality checks for the whisper with Z3, and emulates `bloom` with Unicorn, feeding it the `verify` output, to print the flag. Requires `dexdump` (Android SDK build-tools), `z3-solver` and `unicorn`. Run `python3 work/scripts/solve.py files/mirror-garden.apk` from the challenge directory.

```python
#!/usr/bin/env python3
"""Mirror Garden: recover the flag from the APK.

Pipeline:
  1. emulate native 0x2374 to get the 48-byte constant and the leaf index;
  2. disassemble the matching one.sr.garden.leaf.L####.verify with dexdump and
     solve its 8 equality checks for the 16-byte "whisper" (Z3);
  3. emulate the native bloom() end to end with JNI stubs, feeding it the
     verify() output (payload XOR whisper) to read the string it builds.

Usage: python3 scripts/solve.py files/mirror-garden.apk
Requires: dexdump (Android SDK build-tools), z3-solver, unicorn.
"""
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

import z3
from unicorn import *
from unicorn.arm64_const import *


def find_dexdump():
    for c in ("dexdump", os.path.expanduser("~/sdks/Android/Sdk/build-tools/37.0.0/dexdump")):
        if shutil.which(c) or os.path.exists(c):
            return c
    raise SystemExit("dexdump not found (set PATH or install Android build-tools)")


def load_elf(uc, data):
    # map PT_LOAD segments at their virtual addresses (base 0)
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    uc.mem_map(0, 0x10000, UC_PROT_ALL)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type != 1:
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, off + 8)
        p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
        uc.mem_write(p_vaddr, data[p_offset:p_offset + p_filesz])


def emulate_2374(so):
    """Return (const48, index) computed by the native function at 0x2374."""
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    load_elf(uc, so)
    uc.mem_map(0x20000000, 0x20000, UC_PROT_ALL)
    uc.reg_write(UC_ARM64_REG_SP, 0x2001F000)
    uc.mem_map(0x30000000, 0x1000, UC_PROT_ALL)
    out = 0x30000000
    uc.mem_write(out, b"\x00" * 0x80)
    ret = 0x40000000
    uc.mem_map(ret, 0x1000, UC_PROT_ALL)
    uc.reg_write(UC_ARM64_REG_X0, out)
    uc.reg_write(UC_ARM64_REG_LR, ret)
    uc.hook_add(UC_HOOK_CODE, lambda u, a, s, d: u.emu_stop() if a == ret else None)
    uc.emu_start(0x2374, ret, count=2_000_000)
    buf = bytes(uc.mem_read(out, 0x40))
    return buf[:48], struct.unpack_from("<I", buf, 0)[0] & 0x3FF


def parse_leaf(apk_dex_path, index):
    """Return (instruction list, payload bytes) for leaf L####.verify."""
    text = subprocess.run([find_dexdump(), "-d", apk_dex_path], capture_output=True).stdout.decode("latin1")
    cls = "one.sr.garden.leaf.L%04d.verify" % index
    lines = text.splitlines()
    start = next(i for i, l in enumerate(lines) if cls in l)
    first_ins = next(l for l in lines[start + 1:] if "|" in l)
    code_base = int(re.match(r"\s*([0-9a-f]+):", first_ins).group(1), 16)
    insns = []
    for l in lines[start + 1:]:
        if l.strip().startswith("Class #") or "Class descriptor" in l:
            break
        if "|" not in l:
            continue
        right = l.split("|", 1)[1]
        mm = re.match(r"\s*([0-9a-f]+):\s*(\S+)\s*(.*)$", right)
        if mm:
            insns.append((int(mm.group(1), 16), mm.group(2), mm.group(3).strip()))
    # payload offset from the fill-array-data operand (code units, so *2)
    fa = next(a for o, mn, a in insns if mn == "fill-array-data")
    pay_off = code_base + 2 * int(re.findall(r"\b([0-9a-f]{1,8})\b", fa.split("//")[0])[-1], 16)
    dex = open(apk_dex_path, "rb").read()
    size = struct.unpack_from("<I", dex, pay_off + 4)[0]
    return insns, dex[pay_off + 8:pay_off + 8 + size]


def solve_whisper(insns):
    """Symbolically execute verify() and solve the 8 equality checks."""
    off_to_idx = {o: i for i, (o, mn, a) in enumerate(insns)}
    inb = [z3.BitVec("in%d" % i, 8) for i in range(16)]
    V, cons = {}, []

    def tgt(s):
        return off_to_idx[int(re.findall(r"\b([0-9a-f]{2,4})\b", s.split("//")[0])[-1], 16)]

    def const(s):
        m = re.search(r"//\s*#([0-9a-fA-F]+)\s*$", s)
        if m:
            return int(m.group(1), 16)
        return int(re.search(r"#int\s+(-?\d+)", s).group(1)) & ((1 << 64) - 1)

    pc = 0
    while 0 <= pc < len(insns) and len(cons) < 8:
        off, mn, args = insns[pc]
        R = re.findall(r"v\d+", args)
        nxt = pc + 1
        if mn == "move-object/from16" or (mn == "move-wide/from16"):
            V[R[0]] = ("arr",) if mn == "move-object/from16" else V[R[1]]
        elif mn == "array-length":
            V[R[0]] = 16
        elif mn in ("const/16", "const/4", "const-wide/16", "const-wide/32", "const-wide"):
            V[R[0]] = const(args)
        elif mn == "aget-byte":
            V[R[0]] = z3.ZeroExt(56, inb[int(V[R[2]])])
        elif mn == "int-to-long":
            V[R[0]] = V[R[1]]
        elif mn in ("mul-long", "and-long", "or-long", "sub-long", "xor-long",
                    "add-long", "shl-long", "ushr-long") or mn.endswith("/2addr"):
            if mn.endswith("/2addr"):
                a, b, base = V[R[0]], V[R[1]], mn.split("/")[0]
            else:
                a, b, base = V[R[1]], V[R[2]], mn
            if base == "shl-long":
                r = a << (b & 63)
            elif base == "ushr-long":
                r = (a >> (b & 63)) if isinstance(a, int) else z3.LShR(a, b & 63)
            elif isinstance(a, int) and isinstance(b, int):
                r = {"mul-long": a * b, "and-long": a & b, "or-long": a | b, "sub-long": a - b,
                     "xor-long": a ^ b, "add-long": a + b}[base] & ((1 << 64) - 1)
            else:
                r = {"mul-long": a * b, "and-long": a & b, "or-long": a | b, "sub-long": a - b,
                     "xor-long": a ^ b, "add-long": a + b}[base]
            if mn.endswith("/2addr"):
                V[R[0]] = r
            else:
                V[R[0]] = r
        elif mn == "cmp-long":
            V[R[0]] = ("cmp", V[R[1]], V[R[2]])
        elif mn in ("if-nez", "if-eqz"):
            v = V[R[0]]
            if isinstance(v, tuple) and v[0] == "cmp":
                cons.append(v[1] == v[2])
                if mn == "if-eqz":
                    nxt = tgt(args)
            elif isinstance(v, int) and ((mn == "if-eqz" and v == 0) or (mn == "if-nez" and v != 0)):
                nxt = tgt(args)
        elif mn == "if-eq":
            if isinstance(V[R[0]], int) and V[R[0]] == V[R[1]]:
                nxt = tgt(args)
        elif mn == "if-ge":
            if isinstance(V[R[0]], int) and isinstance(V[R[1]], int) and V[R[0]] >= V[R[1]]:
                nxt = tgt(args)
        elif mn in ("goto", "goto/16"):
            nxt = tgt(args)
        elif mn == "return-object":
            break
        pc = nxt
    s = z3.Solver()
    s.add(cons)
    assert s.check() == z3.sat
    m = s.model()
    return bytes(m.eval(b, model_completion=True).as_long() & 0xFF for b in inb)


def emulate_bloom(so, result48):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    load_elf(uc, so)
    uc.mem_map(0x20000000, 0x40000, UC_PROT_ALL)
    uc.reg_write(UC_ARM64_REG_SP, 0x20030000)
    E, T, SB, NIDX = 0x30000000, 0x30001000, 0x30002000, 260
    uc.mem_map(0x30000000, 0x40000, UC_PROT_ALL)
    uc.mem_write(E, struct.pack("<Q", T))
    for i in range(NIDX):
        uc.mem_write(T + i * 8, struct.pack("<Q", SB + i * 4))
    resbuf = 0x30020000
    uc.mem_write(resbuf, result48)
    H = {k: 0x30030000 + i * 0x10 for i, k in enumerate("cmrin")}
    handles, captured = {}, []
    heap = [0x30040000]
    ret = 0x40000000
    uc.mem_map(ret, 0x1000, UC_PROT_ALL)

    def cstr(a):
        out = bytearray()
        while True:
            b = uc.mem_read(a, 1)[0]
            if b == 0:
                return bytes(out)
            out.append(b)
            a += 1

    def snprintf():
        dst, fmt = uc.reg_read(UC_ARM64_REG_X0), cstr(uc.reg_read(UC_ARM64_REG_X2)).decode("latin1")
        arg = uc.reg_read(UC_ARM64_REG_X3)
        for spec in ("%04d", "%03d", "%02d", "%d"):
            if spec in fmt:
                fmt = fmt.replace(spec, ("%%0%dd" % (len(spec) - 2)) % arg, 1)
                break
        uc.mem_write(dst, fmt.encode("latin1") + b"\x00")
        uc.reg_write(UC_ARM64_REG_X0, len(fmt))

    def memcpy():
        uc.mem_write(uc.reg_read(UC_ARM64_REG_X0),
                     bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_X1), uc.reg_read(UC_ARM64_REG_X2))))

    def jni(idx):
        if idx == 6:
            uc.reg_write(UC_ARM64_REG_X0, H["c"])
        elif idx == 113:
            uc.reg_write(UC_ARM64_REG_X0, H["m"])
        elif idx == 114:
            uc.reg_write(UC_ARM64_REG_X0, H["r"])
        elif idx == 171:
            a = uc.reg_read(UC_ARM64_REG_X1)
            uc.reg_write(UC_ARM64_REG_X0, 48 if a == H["r"] else handles.get(a, (0, 0))[1])
        elif idx == 184:
            a = uc.reg_read(UC_ARM64_REG_X1)
            uc.reg_write(UC_ARM64_REG_X0, resbuf if a == H["r"] else handles.get(a, (heap[0], 0))[0])
        elif idx == 176:
            n = uc.reg_read(UC_ARM64_REG_X1)
            addr = heap[0]; heap[0] += (n + 0x40) & ~0xf
            handles[addr] = (addr, n); uc.mem_write(addr, b"\x00" * n)
            uc.reg_write(UC_ARM64_REG_X0, addr)
        elif idx == 167:
            captured.append(cstr(uc.reg_read(UC_ARM64_REG_X1)))
            uc.reg_write(UC_ARM64_REG_X0, H["n"])
        else:
            uc.reg_write(UC_ARM64_REG_X0, 0)

    def hook(u, addr, size, ud):
        if addr == ret:
            u.emu_stop(); return
        if SB <= addr < SB + NIDX * 4:
            jni((addr - SB) // 4)
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR)); return
        if addr == 0x2dd0:
            snprintf(); u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR)); return
        if addr == 0x2de0:
            memcpy(); u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR)); return

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.reg_write(UC_ARM64_REG_X0, E)
    uc.reg_write(UC_ARM64_REG_X1, H["i"])
    uc.reg_write(UC_ARM64_REG_X2, H["i"])
    uc.reg_write(UC_ARM64_REG_LR, ret)
    uc.emu_start(0x1b28, ret, count=20_000_000)
    return [s.decode("latin1") for s in captured]


def main(apk):
    tmp = tempfile.mkdtemp()
    with zipfile.ZipFile(apk) as z:
        dex = os.path.join(tmp, "classes.dex")
        open(dex, "wb").write(z.read("classes.dex"))
        so = z.read("lib/arm64-v8a/libgarden.so")
    const48, index = emulate_2374(so)
    insns, payload = parse_leaf(dex, index)
    whisper = solve_whisper(insns)
    result48 = bytes(payload[i] ^ whisper[i % 16] for i in range(48))
    outs = emulate_bloom(so, result48)
    for s in outs:
        if s.startswith("isfcr{"):
            print(s)
            return
    raise SystemExit("flag not found; outputs=%r" % outs)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "files/mirror-garden.apk")
```

### Notes

- `verify` returns `payload[i] ^ input[i % 16]`. The payload alone does not give the flag; the value must go through the native `bloom` pipeline.
- Code offsets in `dexdump` output are in 16-bit units, so the payload is at `code_base + 2*offset`. An earlier pass read the rodata word as big-endian and mis-parsed the payload offset; both were fixed.
- The native failure paths build messages such as "the mirror cracks." and "the leaf refuses." These are not the flag.
- The script looks for `dexdump` on PATH and falls back to `~/sdks/Android/Sdk/build-tools/37.0.0/dexdump`. The analysis used SDK build-tools 37.0.0.
- The APK ships only `lib/arm64-v8a/libgarden.so`, and the package is `one.sr.garden` v1.0.
- The solver is fully offline and needs no device.
