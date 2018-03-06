#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dir.h"

int dir_add(struct node *dirnode, struct direntry *entry, int replace, int *added) {
  	int bnum = dirnode->data;
	int prev;
  	struct direntry existing_entry;

  	if(dir_find(dirnode, entry->name, strlen(entry->name), &existing_entry)) {
    //fix this
		if(replace) {
      			*added = 0;
      			existing_entry->node = entry->node;
      			return 1;
    		} else {
      			errno = EEXIST;
      			return 0;
    		}
  	}

	//new entry - Increase the link count
  	st_ino inode = entry->node_num;
	
	struct node cur_node;
	if(get_inode(inode,&cur_node)<0)
	{
		errno = ; //set errno num
		return 0;
	}
	
	cur_node->vstat.st_nlink++; //write this back to disk when new entry is written
	
	if(S_ISDIR(cur_node->vstat.st_mode)) 
	{
		dirnode->vstat.st_nlink++;
		//write this back to disk when new entry is written	
	}

				
	//find an empty location and place 
	//read the bitmap array
	int offset=MAX_DIRENTRY*DIRENT_SIZE;
	char bitmap[MAX_DIRENTRY/8]; // MAX_DIRENTRY/8 no. of bytes to be read

	while(1)	//Traverse for all blocks of the directory.
	{
		if(readblock(bnum,offset,MAX_DIRENTRY/8,bitmap)!=MAX_DIRENTRY/8)
		{	//set errno for I/O ERROR
			return 0;
		}
		ent_num = 0;
		for(index=0;index<MAX_DIRENTRY/8;index++)
		{	bit_no=128;
			for(int bit=0;bit<8;bit++)
			{	++ent_num;
				if(!(bit_no & bitmap[index]))
				{	//is this cast required??
					if(writeblock(bnum,(char *)entry,DIRENT_SIZE*(ent_num-1),DIRENT_SIZE)!=DIRENT_SIZE)
					{	errno = ; //I/O error;
						return 0;
					}
					//write its Inode
		//make sure all these functions work otherwise revert all changes back - how ??			
					if(write_inode(inode,cur_node)<0) //check with parameters
					{
						errno = ;
						return 0;
					}
					bitmap[index] |= bit_no; 
					if(writeblock(bnum,bitmap,MAX_DIRENTRY*DIRENT_SIZE,MAX_DIRENTRY/8)!=MAX_DIRENTRY/8)
					{	errno = ; //I/O error;
						return 0;
					}
					//write parent Inode 
					if(write_inode(dirnode->vstat.st_ino,dirnode)<0) //check with parameters
					{
						errno = ;
						return 0;
					}
					*added = 1;
					return 1;
				}
				bit_no = bit_no >>  1;
			}
		}
		prev=bnum;
		bnum=get_next_block(bnum,1);
		if(bnum==-1)	//There are no more blocks allocated for this directory.
			break;
	}
	//request for new block 
	if((bnum=reqblock(prev))<0)
	{	errno = ; //set errno  to out of memory
		return 0;
	}
		//write direntry and bitmap
	for(index=0;index<MAX_DIRENTRY/8;index++)
		bitmap[index]=0;
	bitmap[0] |= 128;
	if(writeblock(bnum,(char *)entry,0,DIRENT_SIZE)!=DIRENT_SIZE)
	{	errno = ; //I/O error;
		return 0;
	}
	//write its Inode
				
	if(write_inode(inode,cur_node)<0) //check with parameters
	{
		errno = ;
		return 0;
	}
					
	if(writeblock(bnum,bitmap,MAX_DIRENTRY*DIRENT_SIZE,MAX_DIRENTRY/8)!=MAX_DIRENTRY/8)
	{	errno = ; //I/O error;
		return 0;
	}
	//write parent Inode 
	if(write_inode(dirnode->vstat.st_ino,dirnode)<0) //check with parameters
	{
		errno = ;
		return 0;
	}
	*added = 1;
	return 1;
	
}	

int dir_add_alloc(struct node *dirnode, const char *name, struct node *node, int replace) {
  struct direntry *entry = malloc(sizeof(struct direntry));
  int added;

  if(!entry) {
    errno = ENOMEM;
    return 0;
  }

  strcpy(entry->name, name);
  entry->node_num = node->vstat.st_ino; //node should be allocated

  if(!dir_add(dirnode, entry, replace, &added)) {
    free(entry);
    return 0;
  }

  if(!added) free(entry);

  return 1;
}

int dir_remove(struct node *dirnode, const char *name) {
	
  //bnum will store block no. of directory entry table
	int bnum = dirnode->data;
	int ent_num=0; //cast each element of bitmap to int and then & with ent_num- one more loop!!
	int index;
	int bit_no;

	//read the bitmap array
	int offset=MAX_DIRENTRY*DIRENT_SIZE;
	char bitmap[MAX_DIRENTRY/8]; // MAX_DIRENTRY/8 no. of bytes to be read

	int namelen=strlen(name);
	//int zero_places[8]={254,253,251,247,239,223,191,127};

	struct direntry *ent;
	ent=(struct direntry *)malloc(sizeof(struct direntry)*MAX_DIRENTRY);

	while(1)	//Traverse for all blocks of the directory.
	{
		if(readblock(bnum,bitmap,offset,MAX_DIRENTRY/8)!=MAX_DIRENTRY/8)
		{	//set errno for I/O ERROR
			return 0;
		}

		offset=0;
		if(readblock(bnum,ent,offset,DIRENT_SIZE*MAX_DIRENTRY)!=DIRENT_SIZE*MAX_DIRENTRY)
		{	
			//set errno for I/O ERROR
			free(ent);
			return 0;
		}
	
		ent_num = 0;

		for(index=0;index<MAX_DIRENTRY/8;index++)
		{	bit_no=128;
			for(int bit=0;bit<8;bit++)
			{	++ent_num;
				if(bit_no & bitmap[index])
				{	if(strlen(ent->name) == namelen) 
					{	if(strncmp(ent->name, name, namelen) == 0) 
						{
							bitmap[index] = bitmap[index] & !bit_no;
							//write the bitmap back to disk
							writeblock(bnum,bitmap,MAX_DIRENTRY*DIRENT_SIZE,MAX_DIRENTRY/8);
							st_ino inode = ent[ent_num-1].node_num;
							struct node cur_node;
							get_inode(inode,&cur_node);
							if(S_ISDIR(cur_node.vstat.st_mode))
							{	dirnode->vstat.st_nlink--;
								write_inode(dirnode->vstat.st_ino,dirnode);
							}
							free(ent); 
							return 1;
						}
					}
				}
				bit_no = bit_no >>  1;
			}
		}
		bnum=get_next_block(bnum,1);
		if(bnum==-1)	//There are no more blocks allocated for this directory.
			break;
	}
	free(ent);
  	errno = ENOENT;
	return 0;
}

//the memory for dirnode should be allocated.  //manage locks 
int dir_find(struct node *dirnode, const char *name, int namelen, struct direntry *entry) {
  
  //bnum will store block no. of directory entry table
	int bnum = dirnode->data;
	int ent_num=0; //cast each element of bitmap to int and then & with ent_num- one more loop!!
	int index;
	int bit_no;

	//read the bitmap array
	int offset=MAX_DIRENTRY*DIRENT_SIZE;
	char bitmap[MAX_DIRENTRY/8]; // MAX_DIRENTRY/8 no. of bytes to be read

	struct direntry *ent;
	ent=(struct direntry *)malloc(sizeof(struct direntry)*MAX_DIRENTRY);

	while(1)	//Traverse for all blocks of the directory.
	{
		if(readblock(bnum,bitmap,offset,MAX_DIRENTRY/8)!=MAX_DIRENTRY/8)
		{	//set errno for I/O ERROR
			return 0;
		}

		offset=0;
		if(readblock(bnum,ent,offset,DIRENT_SIZE*MAX_DIRENTRY)!=DIRENT_SIZE*MAX_DIRENTRY)
		{	
			//set errno for I/O ERROR
			free(ent);
			return 0;
		}
	
		ent_num=0;
		for(index=0;index<MAX_DIRENTRY/8;index++)
		{	bit_no=128;
			for(int bit=0;bit<8;bit++)
			{	ent_num++;
				if(bit_no & bitmap[index])
				{	if(strlen(ent->name) == namelen) 
					{	if(strncmp(ent->name, name, namelen) == 0) 
						{
							if(entry != NULL) *entry = ent[ent_num-1]; //entry should be allocated memory before
							//check if *entry = ent copies everything
							free(ent);
							return 1;
						}
					}
				}
				bit_no = bit_no >> 1;
			}
		}
		bnum=get_next_block(bnum,1);
		if(bnum==-1)	//There are no more blocks allocated for this directory.
			break;
	}
	free(ent);
  	errno = ENOENT;
	return 0;
}

