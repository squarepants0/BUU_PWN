#include<stdio.h>
#include<stdlib.h>

int main(int argc, char const *argv[])
{
	FILE *fp = fopen("./flag","r");
	char s[100];
	fgets(s,100,fp);
	return 0;
}