#include "hook.h"

void terminating() {

	printf("fast-background starts unhooking dlls.\n");
	mon(1);
	printf("Terminating fast-background...\n");
	exiting();
}


int CDECL main(int argc, char** argv)
{

	printf("Initializing fast-background...\n");
	init();

	atexit(terminating);

	printf("fast-background starts global hooking.\n");
	mon(0);

	printf("fast-background is monitoring...\n");
	while (1) {
		Sleep(0);
	}

	return 0;
}