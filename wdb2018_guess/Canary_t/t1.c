#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char const *argv[])
{
	char buffer[0x100] = {0};
	read(0, buffer, 0x200);

	return 0;
}