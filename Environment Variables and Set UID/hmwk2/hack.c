#include <stdio.h>
#include <stdlib.h>


int main()
{
	printf("my malicious code is being called \n");
	system("/bin/dash");
	return 0;
}
