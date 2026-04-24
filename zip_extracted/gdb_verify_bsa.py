import gdb
gdb.execute('set pagination off')
gdb.execute('b *0x8049376')
gdb.execute('run /root/bsa/dummy.in')
print('=== GADGET MEMORY DUMP ===')
for base_candidate in [0x070493e0, 0x070493e8]:
    try:
        v = int(gdb.parse_and_eval('*((unsigned int*)%d)' % base_candidate))
        b = v.to_bytes(4, 'little')
        print('0x%08x: %s' % (base_candidate, ' '.join('%02x' % x for x in b)))
    except Exception as e:
        print('0x%08x: ERROR %s' % (base_candidate, e))
# Dump 40 bytes starting at whichever base looks right
for i in range(0, 40, 4):
    addr = 0x070493e0 + i
    try:
        v = int(gdb.parse_and_eval('*((unsigned int*)%d)' % addr))
        b = v.to_bytes(4, 'little')
        print('0x%08x: %s' % (addr, ' '.join('%02x' % x for x in b)))
    except Exception as e:
        print('0x%08x: ERROR' % addr)
gdb.execute('quit')
