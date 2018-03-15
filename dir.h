
#include <linux/limits.h>
#include "node.h"

#ifndef _DIR_H
#define _DIR_H

#define DIRENT_SIZE sizeof(struct direntry)
#define MAX_DIRENTRY 14

struct direntry {
  char  name[256]; //assume PATH_MAX is 256
  ino_t   node_num;
  int 	next;	//stores 0 or 1 indicating if there is a file or directory in the same level
};																																																																		

int dir_add(struct node *dir, struct direntry *entry, int replace, int *added);

int dir_add_alloc(struct node *dir, const char *name, struct node *node, int replace);

int dir_remove(struct node *dir, const char *name);

int dir_find(struct node *dir, const char *name, int namelen, struct direntry *entry,int *blk_no,int *entry_no);

#endif


