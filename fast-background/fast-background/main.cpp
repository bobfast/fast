#include "hook.h"

void terminating(unsigned int t_pid) {

	//printf("fast-background starts unhooking dlls.\n");
	//mon(1, t_pid);
	printf("Terminating fast-background...\n");
	exiting(t_pid);
}


int CDECL main(int argc, char** argv)
{

	printf("Initializing fast-background...\n");
	init();



	if (argc > 1 && 0 == strcmp(argv[1], "-f")) {
		terminating(atoi(argv[1]));
		return 0;
	}

	//atexit(terminating);

	//printf("fast-background starts global hooking.\n");
	//mon(0,  atoi(argv[1]));
	

	printf("fast-background is monitoring...\n");
	while (1) {
		Sleep(0);
	}

	return 0;
}