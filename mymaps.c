/*
 * Testing ASLR and PIEs.
 * (c) Elias Athanasopoulos,  eliasathan@cs.ucy.ac.cy
 *
 * Compile the program as PIE and not PIE:
 *
 * $ gcc -Wall -m32 mymaps.c -pie -o mymaps_pie
 * $ gcc -Wall -m32 -fno-pic -no-pie mymamps.c -o mymaps
 *
 *
 * Run both programs when ASLR is on/off (/proc/sys/kernel/randomize_va_space)
 *
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[]) {

	pid_t mypid = getpid();
	char map_path[128];

	fprintf(stderr, "My pid: %d\n", mypid);
	sprintf(map_path, "/proc/%d/maps", mypid);

	FILE *file;
	size_t nread;
	char part[1024];

	file = fopen(map_path, "r");
	if (file) {
		while ((nread = fread(part, 1, sizeof part, file)) > 0)
			fwrite(part, 1, nread, stdout);
	        if (ferror(file)) {
			/* deal with error */
		}
		fclose(file);
	}

	return 1;
}