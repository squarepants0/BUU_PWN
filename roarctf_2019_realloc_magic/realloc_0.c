#include<stdio.h>
#include<stdlib.h>

int main(){
	char *ptr = (char *)malloc(0x20);
	realloc(ptr,0x20);

	return 0;
}
