#include <stdio.h>
#include <stdlib.h>

extern char** environ;

int main()
{
	printf("Running my code\n");
	system("/bin/zsh");
	return 0;
}
