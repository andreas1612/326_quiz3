.section .data
.section .text
.globl _start

// s 		n 		i 		o 		c 		t 		i 		b
// 0x73		0x6e	0x69	0x6f	0x63	0x74	0x69	0x62
 
_start:
    xor 	%eax,%eax
    push 	%eax
	push	$0x736e696f
    push 	$0x63746962 	
	mov 	%esp,%ebx
    mov 	$0xb,%al
	dec		%al
    int  	$0x80
	
	xor		%eax,%eax
    inc		%eax
	mov 	%eax,%ebx
	int 	$0x80	
