#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>

void foo(void) {
    uid_t (*f)(void);

    f = getuid;

    fprintf(stderr, "%d\n", f());
}

int main(int argc, char *argv[]) {
    foo();

    return 1;
}
