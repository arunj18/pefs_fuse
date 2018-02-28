#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dir.h"

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
	int zero_places[8]={254,253,251,247,239,223,191,127};

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
	
		

		for(index=0;index<MAX_DIRENTRY/8;index++)
		{	bit_no=128;
			for(int bit=0;bit<8;bit++)
			{	++ent_num;
				while(bit_no & bitmap[index])
				{	if(strlen(ent->name) == namelen) 
					{	if(strncmp(ent->name, name, namelen) == 0) 
						{
							bitmap[index] = bitmap[index] & zero_places[bit];
							//write the bitmap back to disk
							writeblock(bnum,bitmap,MAX_DIRENTRY*DIRENT_SIZE,MAX_DIRENTRY/8);
							free(ent); 
							return 1;
						}
					}
					bit_no = bit_no >>  1;
				}
			}
		}
		bnum=getNextBlock(bnum);
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
	
		for(index=0;index<MAX_DIRENTRY/8;index++)
		{	bit_no=1;
			for(int bit=0;bit<8;bit++)
			{	ent_num++;
				while(bit_no & bitmap[index])
				{	if(strlen(ent->name) == namelen) 
					{	if(strncmp(ent->name, name, namelen) == 0) 
						{
							if(entry != NULL) *entry = ent[ent_num]; //entry should be allocated memory before
							//check if *entry = ent copies everything
							free(ent);
							return 1;
						}
					}
					bit_no = bit_no <<  1;
				}
			}
		}
		bnum=getNextBlock(bnum);
		if(bnum==-1)	//There are no more blocks allocated for this directory.
			break;
	}
	free(ent);
  	errno = ENOENT;
	return 0;
}

