#include<stdio.h>
#include<stdlib.h>

int main(int argc, char const *argv[])
{
	void *ptrlist[8];
	for (int i = 0; i < 8; ++i)
	{
		/* code */
		ptrlist[i] = malloc(0x70);
	}
	for (int i = 0; i < 8; ++i)
	{
		/* code */
		free(ptrlist[i]);
	}
	void *ptr = calloc(1,0x70);
	printf("%p\n", ptr);
	return 0;
}