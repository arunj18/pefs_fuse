#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "dir.h"

int dir_add(struct node *dirnode, struct direntry *entry, int replace, int *added)
{
  	int bnum = dirnode->data;
	int prev;

	//printf("parent:%d\tchild:%d\n",dirnode->vstat.st_ino,entry->node_num);
	if(bnum == -1)
	{
		
		bnum = reqblock(-1,'f');
		int off = MAX_DIRENTRY*DIRENT_SIZE;
		char bmap[2]={'\0'};
		if(writeblock(bnum,bmap,off,2)<0)
			printf("Write Block error\n");
		dirnode->data = bnum;
		writeinode(dirnode->vstat.st_ino,dirnode);
		printf("first block: %d\n",bnum);
	}

  	struct direntry existing_entry;

  	int existing_blk;
	int entry_no;
  	if(dir_find(dirnode, entry->name, strlen(entry->name), &existing_entry,&existing_blk,&entry_no)) {
		if(replace) {
      			*added = 0;
      			existing_entry.node_num = entry->node_num;
			writeblock(existing_blk,(char *)&existing_entry,DIRENT_SIZE*(entry_no-1),DIRENT_SIZE);
      			return 1;
    		} else {
      			errno = EEXIST;
      			return 0;
    		}
  	}

	//new entry - Increase the link count
  	ino_t inode = entry->node_num; //inode is allocated
	
	
	struct node cur_node;
	if(getinode(inode,&cur_node)<0)
	{
		printf("Inode not found\n");
		errno =  EIO; //set errno num
		return 0;
	}
	
	cur_node.vstat.st_nlink++; //write this back to disk when new entry is written
	
	if(S_ISDIR(cur_node.vstat.st_mode)) 
	{
		dirnode->vstat.st_nlink++;
		//write this back to disk when new entry is written	
	}

				
	//find an empty location and place 
	//read the bitmap array
	int offset=MAX_DIRENTRY*DIRENT_SIZE;
	char bitmap[(int)ceil(MAX_DIRENTRY/(float)8)]; // (int)ceil(MAX_DIRENTRY/(float)8) no. of bytes to be read
	//bnum for new directory
	while(bnum!=-1)	//Traverse for all blocks of the directory.
	{
		//printf("Block num:%d\n",bnum);
		if(readblock(bnum,bitmap,offset,(int)ceil(MAX_DIRENTRY/(float)8))!=(int)ceil(MAX_DIRENTRY/(float)8))
		{	//set errno for I/O ERROR
			printf("Coudn't find bitmap\n");
			errno =  EIO;
			return 0;
		}
		int ent_num = 0;
		//printf("%d\n",(int)ceil(MAX_DIRENTRY/(float)8));
		for(int index=0;index<(int)ceil(MAX_DIRENTRY/(float)8);index++)
		{	unsigned char bit_no=128;
			for(int bit=0;bit<8;bit++)
			{	++ent_num;
				//printf("bitmap[%d]:%d\n",index,(int)bitmap[index]);
				if(!(bit_no & bitmap[index]))
				{	//is this cast required??
					if(writeblock(bnum,(char *)entry,DIRENT_SIZE*(ent_num-1),DIRENT_SIZE)!=DIRENT_SIZE)
					{	printf("Coudn't write directory entry to %d block\n",bnum);
						errno =  EIO; //I/O error;
						return 0;
					}
					//printf("Directory entry added\n");
					//write its Inode
		//make sure all these functions work otherwise revert all changes back - how ??			
					if(writeinode(inode,&cur_node)<0) //check with parameters
					{	printf("Coudn't write inode %d\n",inode);
						errno =  EIO;
						return 0;
					}
					bitmap[index] |= bit_no; 
					if(writeblock(bnum,bitmap,MAX_DIRENTRY*DIRENT_SIZE,(int)ceil(MAX_DIRENTRY/(float)8))!=(int)ceil(MAX_DIRENTRY/(float)8))
					{	printf("Coudn't write bitmap to %d block\n",bnum);
						errno =  EIO; //I/O error;
						return 0;
					}
					//write parent Inode - if it is a directory
					if(S_ISDIR(cur_node.vstat.st_mode)) 
					{	printf("root->data:%d\n",dirnode->data);
						if(writeinode(dirnode->vstat.st_ino,dirnode)<0) //check with parameters
						{
							printf("Coudn't write parent inode %d \n",dirnode->vstat.st_ino);
							errno = EIO;
							return 0;
						}
					}
					*added = 1;
					struct node root;
					getinode(0,&root);
					printf("%d\n",root.data);
					//printf("Added direntry\n");
					return 1;
				}
				bit_no = bit_no >>  1;
				if(index==1 && bit==5)
					break;
			}
		}
		prev=bnum;
		bnum=get_next_block(bnum,1);
		/*
		if(bnum==-1)	//There are no more blocks allocated for this directory.
			break; */
	}
	//request for new block 
	if((bnum=reqblock(prev,'f'))<0)
	{	errno =  ENOMEM; //set errno  to out of memory
		return 0;
	}
		//write direntry and bitmap
	for(int index=0;index<(int)ceil(MAX_DIRENTRY/(float)8);index++)
		bitmap[index]=0;
	bitmap[0] |= 128;
	if(writeblock(bnum,(char *)entry,0,DIRENT_SIZE)!=DIRENT_SIZE)
	{	printf("Coudn't write directory entry to %d block\n",bnum);
		errno =  EIO; //I/O error;
		return 0;
	}
	//write its Inode
				
	if(writeinode(inode,cur_node)<0) //check with parameters
	{	printf("Coudn't write inode %d \n",inode);
		errno =  EIO;
		return 0;
	}
					
	if(writeblock(bnum,bitmap,MAX_DIRENTRY*DIRENT_SIZE,(int)ceil(MAX_DIRENTRY/(float)8))!=(int)ceil(MAX_DIRENTRY/(float)8))
	{	printf("Coudn't write bitmap to %d block\n",bnum);
		errno =  EIO; //I/O error;
		return 0;
	}
	//write parent Inode 
	if(S_ISDIR(cur_node.vstat.st_mode)) 
	{	
		//printf("%lu\n",dirnode->vstat.st_ino);
		if(writeinode(dirnode->vstat.st_ino,dirnode)<0) //check with parameters
		{	printf("Coudn't write parent inode %d \n",dirnode->vstat.st_ino);
			errno = EIO;
			return 0;
		}
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
	unsigned char bit_no;

	//read the bitmap array
	int offset=MAX_DIRENTRY*DIRENT_SIZE;
	char bitmap[(int)ceil(MAX_DIRENTRY/(float)8)]; // (int)ceil(MAX_DIRENTRY/(float)8) no. of bytes to be read

	int namelen=strlen(name);
	//int zero_places[8]={254,253,251,247,239,223,191,127};

	struct direntry *ent;
	ent=(struct direntry *)malloc(sizeof(struct direntry)*MAX_DIRENTRY);

	while(1)	//Traverse for all blocks of the directory.
	{
		if(readblock(bnum,bitmap,offset,(int)ceil(MAX_DIRENTRY/(float)8))!=(int)ceil(MAX_DIRENTRY/(float)8))
		{	//set errno for I/O ERROR
			errno =  EIO;
			free(ent);
			return 0;
		}

		offset=0;
		if(readblock(bnum,ent,offset,DIRENT_SIZE*MAX_DIRENTRY)!=DIRENT_SIZE*MAX_DIRENTRY)
		{	
			//set errno for I/O ERROR
			errno =  EIO;
			free(ent);
			return 0;
		}
	
		ent_num = 0;

		for(index=0;index<(int)ceil(MAX_DIRENTRY/(float)8);index++)
		{	bit_no=128;
			for(int bit=0;bit<8;bit++)
			{	++ent_num;
				if(bit_no & bitmap[index])
				{	if(strlen(ent[ent_num-1].name) == namelen) 
					{	if(strncmp(ent[ent_num-1].name, name, namelen) == 0) 
						{
							bitmap[index] = bitmap[index] & ~bit_no;
							//write the bitmap back to disk
							writeblock(bnum,bitmap,MAX_DIRENTRY*DIRENT_SIZE,(int)ceil(MAX_DIRENTRY/(float)8));
							ino_t inode = ent[ent_num-1].node_num;
							struct node cur_node;
							getinode(inode,&cur_node);
							if(S_ISDIR(cur_node.vstat.st_mode))
							{	dirnode->vstat.st_nlink--;
								writeinode(dirnode->vstat.st_ino,dirnode);
							}
							cur_node.vstat.st_nlink--;
							int temp=cur_node.vstat.st_ino;
							//if(cur_node.vstat.st_nlink==0 && cur_node.fd_count==0)
							//	relinode(temp);
							//else
							writeinode(inode,&cur_node);
							free(ent); 
							return 1;
						}
					}
				}
				bit_no = bit_no >>  1;
				if(index==1 && bit==5)
					break;
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
int dir_find(struct node *dirnode, const char *name, int namelen, struct direntry *entry,int *blk_no,int *entry_no) {
  
	printf("dir find : %s\n",name);
  //bnum will store block no. of directory entry table
	//printf("parent inode :%d\n",dirnode->vstat.st_ino);
	int bnum = dirnode->data;
	//printf("Block no: %d\n",bnum);
	int ent_num=0; //cast each element of bitmap to int and then & with ent_num- one more loop!!
	int index;
	unsigned char bit_no;

	//read the bitmap array
	int offset=MAX_DIRENTRY*DIRENT_SIZE;
	char bitmap[(int)ceil(MAX_DIRENTRY/(float)8)]; // (int)ceil(MAX_DIRENTRY/(float)8) no. of bytes to be read

	struct direntry *ent;
	ent=(struct direntry *)malloc(sizeof(struct direntry)*MAX_DIRENTRY);

	while(bnum!=-1)	//Traverse for all blocks of the directory.
	{	//printf("Block no: %d\n",bnum);
		if(readblock(bnum,bitmap,offset,(int)ceil(MAX_DIRENTRY/(float)8))!=(int)ceil(MAX_DIRENTRY/(float)8))
		{	//set errno for I/O ERROR
			errno =  EIO;
			free(ent);
			return 0;
		}

		offset=0;
		if(readblock(bnum,ent,offset,DIRENT_SIZE*MAX_DIRENTRY)!=DIRENT_SIZE*MAX_DIRENTRY)
		{	
			//set errno for I/O ERROR
			errno =  EIO;
			free(ent);
			return 0;
		}
	
		ent_num=0;
		for(index=0;index<(int)ceil(MAX_DIRENTRY/(float)8);index++)
		{	bit_no=128;
			for(int bit=0;bit<8;bit++)
			{	ent_num++;
				if(bit_no & bitmap[index])
				{	if(strlen(ent[ent_num-1].name) == namelen) 
					{	if(strncmp(ent[ent_num-1].name, name, namelen) == 0) 
						{
							if(entry != NULL) *entry = ent[ent_num-1]; //entry should be allocated memory before
							//check if *entry = ent copies everything
							*entry_no = ent_num;
							*blk_no = bnum;
							free(ent);
							return 1;
						}
					}
				}
				bit_no = bit_no >> 1;
				if(index==1 && bit==5)
					break;
			}
		}
		bnum=get_next_block(bnum,1);
	}
	free(ent);
  	errno = ENOENT;
	return 0;
}

