#!/bin/bash
set -e
BSA=~/bsa

# Create dummy input
python3 -c "print('60 ' + 'A'*60)" > "$BSA/dummy.in"

echo "=== GDB Memory dump at 0x070493e0 ==="
env -i TEMP=1000 HOME=~ PATH=/usr/bin:/bin setarch i686 -R --3gb \
  gdb -batch \
  -ex "source $BSA/gdb_verify_bsa.py" \
  "$BSA/bin.1" 2>&1 | grep -E "GADGET|0x07049"
