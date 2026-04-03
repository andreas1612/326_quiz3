
#include <stdio.h>

int main(int argc, char *argv[]) {
	char *shellcode ="\x31\xc0\x40\x89\xc3\xcd\x80";

	int (*fptr)() = (int (*)()) shellcode;

	fptr();

	fprintf(stderr, "Should not be printed\n");

	return 1;
}

