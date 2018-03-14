
#include <errno.h>

#include "node.h"
#include "dir.h"

//node should be allocated memory by calling function
int getNodeRel(const char *path, struct node *root, struct node *node){
	printf("Get Node Rel:%s\n",path);
	if(!S_ISDIR(root->vstat.st_mode)){	
		errno = ENOTDIR;
		return 0;
	}
	if(path[0] != '/') {
		errno = EINVAL;
		return 0;
	}

  // Root directory
  // This also handles paths with trailing slashes (as long as it is a
  // directory) due to recursion.
	if(path[1] == '\0'){
		*node = *root;
		return 1;
	}

  // Extract name from path
	const char *name = path + 1;
	int namelen = 0;
	const char *name_end = name;
	while(*name_end != '\0' && *name_end != '/'){
		name_end++;
		namelen++;
	}

  // Search directory
	struct direntry dirent;
	int blk_no;
	int entry_no;

	//dir_find will return the direntry structure	
	if(!dir_find(root, name, namelen, &dirent,&blk_no,&entry_no)){
		//printf("DIR find problem\n");
		errno = ENOENT;
		return 0;
	}

	struct node temp;
	if(*name_end == '\0'){
    // Last node in path
		getinode(dirent.node_num,&temp);
		*node = temp;
		return 1;
	}
	else{
    // Not the last node in path (or a trailing slash)
		//getInode of dirent.node_num
		struct node pnode;
		if(getinode(dirent.node_num,&pnode)<0)
		{
			//set errno for inode not found maybe I/O ERROR
			return 0;
		} 
		return getNodeRel(name_end,&pnode, node);
	}
}


