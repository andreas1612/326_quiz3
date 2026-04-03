/*
 * Testing a shellcode
 * (c) Elias Athanasopoulos,  athanasopoulos.elias@ucy.ac.cy
 *
 * Compile the attached C program.
 * $ gcc -Wall -m32 -z execstack run-shellcode.c -o run-shellcode
 * 
 * Run the program, normally.
*/

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {

	char buff[128];
	const char *shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
			  "\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80";

	strcpy(buff, shellcode);

	int (*fptr)() = (int (*)()) buff;
	
	fptr();

	return 1;
}
