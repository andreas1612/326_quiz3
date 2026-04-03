section .data
.section .text
.globl _start
 
_start:
    xor %eax,%eax
    push %eax
    push $0x6e69622f 
    mov  $0xc, %al
    int  $0x80
