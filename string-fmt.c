/*
 * String-formatting bug.
 * (c) Elias Athanasopoulos,  eliasathan@cs.ucy.ac.cy
 *
 * Compile (in 32-bit) and run the program using the appropriate input:
 * $ ./string-fmt --0x%x--0x%x--0x%x--
 * 0xff9f16bc 0xff9f16b8
 * --0xff9f16bc--0xff9f16b8--0xf76dbe28--$ 
 *
 */

#include <stdio.h>
#include <stdlib.h>

void foo(char *s) {
        int marker0 = 0xdead0000;
        int marker1 = 0xbeef0000;

        printf("%p %p\n", &marker0, &marker1);

        printf(s);
}

int main(int argc, char *argv[]) {

        if (argc == 1) 
                exit(1);

        foo(argv[1]);

        return 1;
}
