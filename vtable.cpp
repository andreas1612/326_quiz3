/*
 * Vtable dispatching mechanics.
 * (c) Elias Athanasopoulos, athanasopoulos.elias@ucy.ac.cy
 *
 * Compile the attached C++ program.
 * $ g++ -Wall -no-pie -fno-pic -g3 -m32 vtable.cpp -o vtable
 *
 * 
 * (gdb) b *0x0804919f
 * Breakpoint 1 at 0x804919f: file vtable.cpp, line 29.
 * (gdb) r
 * Starting program: /home/elathan/src/epl326-src/heap/vtable
 * [Thread debugging using libthread_db enabled]
 * Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
 * 
 * Breakpoint 1, 0x0804919f in main (argc=1, argv=0xbffffe04) at vtable.cpp:29
 * 29          b->m1();
 * (gdb) info vtbl b
 * vtable for 'Base' @ 0x804a034 (subobject @ 0x8051bb0):
 * [0]: 0x80491e8 <Base::m1()>
 * [1]: 0x8049202 <Base::m2()>
 * [2]: 0x804921c <Base::m3()>
 * (gdb) x $eax
 * 0x8051bb0:      0x0804a034   # Object pointer '0x8051bb0' (allocated in the heap) hosting vtable pointer (0x804a034) allocate in read-only pages
 * (gdb) x *$eax
 * 0x804a034 <_ZTV4Base+8>:        0x080491e8
 * (gdb) x *$eax+0x4
 * 0x804a038 <_ZTV4Base+12>:       0x08049202
 * (gdb) x *$eax+0x8
 * 0x804a03c <_ZTV4Base+16>:       0x0804921c
 * (gdb)
 */

 #include <stdio.h>

 class Base {
 public:    
    virtual void m1() {
        printf("Base::m1()\n");
    }
    virtual void m2() {
        printf("Base::m2()\n");
    }
    virtual void m3() {
        printf("Base::m3()\n");
    }

 };     

 int main(int argc, char* argv[]) {
    Base *b = new Base();

    b->m1();
    b->m2();
    b->m3();

    return 0;
 }