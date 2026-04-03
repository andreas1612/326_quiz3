#include <stdio.h>

void display(void) {
	unsigned int a = 0xdeadbeef;

	printf("Hello World: 0x%x\n", a);	
}

int main(int argc, char *argv[]) {
	
	display();

	return 1;
}
