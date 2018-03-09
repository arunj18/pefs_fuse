#include<stdio.h>
#include "node.h"
#include<sys/stat.h>
#include<unistd.h>

int main(void){
	struct stat buf;
	printf("%lu\n",sizeof(buf.st_ino));
}
