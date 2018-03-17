
#include <sys/stat.h>

#ifndef _NODE_H
#define _NODE_H

struct node {
  struct stat   vstat;

 //copy paste all stat attributes - not sure

  int data;	//block no. of direntry table or data block
  unsigned int  fd_count; 
  int           delete_on_close;
};

int getNodeRel(const char *path, struct node *root, struct node *node);

#endif

