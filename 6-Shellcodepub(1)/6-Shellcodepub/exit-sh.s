.section .data
.section .text
.globl _start
 
_start:
    xor  %eax, %eax
    inc  %eax
    mov  %eax, %ebx
    int  $0x80
