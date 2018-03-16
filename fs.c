
#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/time.h>
#include <libgen.h>
#include <pthread.h>
#include <math.h>

#include "node.h"
#include "dir.h"

pthread_mutex_t lock;

#define BLOCKSIZE 4096

#define O_WRITE(flags) ((flags) & (O_RDWR | O_WRONLY))
#define O_READ(flags)  (((flags) & (O_RDWR | O_RDONLY)) | !O_WRITE(flags))

#define U_ATIME (1 << 0)
#define U_CTIME (1 << 1)
#define U_MTIME (1 << 2)

static int fd;

struct filesystem{
	struct node *root;
};

struct filehandle{
	struct node *node;
	int o_flags;
};

struct filesystem our_fs;


//
// Utility functions
//

struct disk_block{
	char type;
	int prev_block;
	int next_block;
}__attribute__((packed));
static int opendisk(void){
	//static int fd;
	fd=open("/home/ajvm/Desktop/fuse_ork/eval/the_fs",O_RDWR|O_CREAT|O_EXCL,0777);
	if(fd<0){
		fd=open("/home/ajvm/Desktop/fuse_ork/eval/the_fs",O_RDWR,0644);
		if(fd<0)
			exit(4);
		char id_buf1[9],id_buf2[9];
		char bitmap_free1[2055],bitmap_free2[2055];
		lseek(fd,0,SEEK_SET);
		read(fd,(char *)&id_buf1,8);
		read(fd,(char *)&bitmap_free1,2054);
		lseek(fd,-BLOCKSIZE,SEEK_END);
		read(fd,(char *)&id_buf2,8);
		read(fd,(char *)&bitmap_free2,2054);
		bitmap_free1[2054]='\0';
		bitmap_free2[2054]='\0';
		id_buf1[8]='\0';
		id_buf2[8]='\0';
	
		if(strcmp(id_buf1,"AJARAKFS")!=0){
			exit(4);
		}
		if(strcmp(id_buf1,"AJARAKFS")!=0)
		{
			exit(4);
		}
		if(strcmp(bitmap_free1,bitmap_free2)!=0)
			exit(4);
		//char bitmap_free1[2055],bitmap_free2[2055];
		else{
			return 1;		
		}
	}
	else{
		for(int i=0;i<8388608;i++){ //maybe change this to file size?
			write(fd,"0",1);	
		}
		lseek(fd,0,SEEK_SET);
		write(fd,"AJARAKFS",8);
		//lseek(fd,8,SEEK_SET);
		for(int i=0;i<2046;i++){ //set next 1022 bytes to zero
			write(fd,"0",1);
		}
		int free_blocks=2046;
		int total_blocks=2046;
		write(fd,(char *)&free_blocks,sizeof(free_blocks));
		write(fd,(char *)&total_blocks,sizeof(total_blocks));
		lseek(fd,-BLOCKSIZE,SEEK_END);
		write(fd,"AJARAKFS",8);
		for(int i=0;i<2046;i++){ //set next 1022 bytes to zero
			write(fd,"0",1);
		}
		write(fd,(char *)&total_blocks,sizeof(total_blocks));
		write(fd,(char *)&free_blocks,sizeof(free_blocks));	
		// 2 super blocks written,one at end,one at beginning	
		lseek(fd,0,SEEK_SET);
		//lseek(fd,8,SEEK_SET);
		return 0;
	}
}
int superblockread(){
	int n_free_blocks;
	pthread_mutex_lock(&lock); //get a lock on the read and write from file
	fd=open("/home/ajvm/Desktop/fuse_ork/eval/the_fs",O_RDWR);
	if(fd<0)
		perror("open");	
	lseek(fd,8+2046,SEEK_SET); //move to where the block info is stored
	read(fd,(char *)n_free_blocks,sizeof(int));	//read from that location
	close(fd);	
	pthread_mutex_unlock(&lock); //give up the lock on the file read/write
	return n_free_blocks;
}
char getblocktype(int block_no){ //function to know what kind of block it is, i.e. Inode,directory,data
	struct disk_block temp; //temporary storage
	pthread_mutex_lock(&lock); //get a lock on the read and write from file
	fd=open("/home/ajvm/Desktop/fuse_ork/eval/the_fs",O_RDWR);
	if(fd<0)
		perror("open");	
	lseek(fd,BLOCKSIZE*(block_no+2)-sizeof(struct disk_block),SEEK_SET); //move to where the block info is stored
	read(fd,(char *)&temp,sizeof(struct disk_block));	//read from that location
	close(fd);	
	pthread_mutex_unlock(&lock); //give up the lock on the file read/write
	return temp.type; //return the type of the block
}
int readblock(int block_no,char *data,int offset,size_t bytes){ //function that reads from a block. Not much error handling done
	int read_done;	//how many bytes read done
	pthread_mutex_lock(&lock); //get a lock on file read/write
	fd=open("/home/ajvm/Desktop/fuse_ork/eval/the_fs",O_RDWR);
	if(fd<0)
		perror("open");	
	lseek(fd,(BLOCKSIZE*(block_no+1))+offset,SEEK_SET);	//move to beginning of block
	if(offset+bytes > BLOCKSIZE-sizeof(struct disk_block)) //check if size of what is given to this function should not exceed block
		read_done=read(fd,data,(BLOCKSIZE-sizeof(struct disk_block)-offset));
	else
		read_done=read(fd,data,bytes);
	close(fd);	
	pthread_mutex_unlock(&lock); //give up the lock on file read/write
	if(read_done<0)
		perror("read");
	return read_done; //return how many bytes have been read
}
int writeblock(int block_no,char *data,int offset,size_t bytes){ //function that writes to a block, Not much error handling done
	int write_done;	//how many bytes write done
	if(offset>BLOCKSIZE-sizeof(struct disk_block))
		return -1;
	pthread_mutex_lock(&lock);	//get a lock on file read/write
	fd=open("/home/ajvm/Desktop/fuse_ork/eval/the_fs",O_RDWR);
	if(fd<0)
		perror("open");
	lseek(fd,(BLOCKSIZE*(block_no+1))+offset,SEEK_SET);	//move to beginning of the block
	if(offset+bytes > BLOCKSIZE-sizeof(struct disk_block)) //check if size of what is given to this function should not exceed block
		write_done=write(fd,data,(BLOCKSIZE-sizeof(struct disk_block)-offset));
	else
		write_done=write(fd,data,bytes);
	//int test =BLOCKSIZE-sizeof(struct disk_block);
	close(fd);	
	pthread_mutex_unlock(&lock); //give up lock on file read/write
	if(write_done<0)
		perror("read");
	return write_done; //return how many bytes have been written
}
int get_next_block(int block_no,int nxorpr){ //function to get next and prev block numbers
	struct disk_block temp; //block info buffer
	pthread_mutex_lock(&lock); //get a lock on file read/write
	fd=open("/home/ajvm/Desktop/fuse_ork/eval/the_fs",O_RDWR);
	if(fd<0)
		perror("open");
	lseek(fd,BLOCKSIZE*(block_no+2)-sizeof(struct disk_block),SEEK_SET); //move to block info
	read(fd,(char *)&temp,sizeof(struct disk_block)); //read the block info
	close(fd);
	pthread_mutex_unlock(&lock); //give up lock on file read/write
	if(nxorpr==0)	//if 0,prev; if 1,next : Replace with #define or enum?
		return temp.prev_block; 
	else if(nxorpr==1)
		return temp.next_block;
}
int reqblock(int block_no,char type){ //function to request a block 
	char buf;
	int i;
	int free_b;
	int prev=-1;
	int next=-1;
	pthread_mutex_lock(&lock); //get a lock on file read/write
	fd=open("/home/ajvm/Desktop/fuse_ork/eval/the_fs",O_RDWR);
	if(fd<0)
		perror("open");
	lseek(fd,8+2046,SEEK_SET); //go to super block and get the number of free blocks
	read(fd,(char *)&free_b,sizeof(int));
	if(free_b==0){
		pthread_mutex_unlock(&lock);
		close(fd);
		return -1;	//if no free blocks,return an error?
	}	
	lseek(fd,8,SEEK_SET); //go to bitmap
	for(i=0;i<2046;i++){ //go through bitmap one by one and check which block is free
		read(fd,(char *)&buf,1);
		if(buf=='0'){ //if free
			lseek(fd,-1,SEEK_CUR); //move behind
			write(fd,"1",1); //set it as not free
			lseek(fd,-BLOCKSIZE+8+i,SEEK_END); //do the same for the super block at the end
			write(fd,"1",1); 
			free_b--; //reduce number of free blocks
			break;
		}
	}
	if(i==2046){
		pthread_mutex_unlock(&lock); //should never come here
		close(fd);		
		return -1; //why? because if this happens free_b should be zero,but it's not. Crash the filesystem here. Superblock is corrupt.
	}
	lseek(fd,8+2046,SEEK_SET); //update the number of free blocks
	write(fd,(char *)&free_b,sizeof(free_b));
	lseek(fd,-BLOCKSIZE+8+2046,SEEK_END); //for superblock at end
	write(fd,(char *)&free_b,sizeof(free_b)); 
	struct disk_block temp; //block info buffer
	if(block_no >= 0){ //to do previous block linking
		lseek(fd,BLOCKSIZE*(block_no+2)-sizeof(struct disk_block),SEEK_SET); //go to previous block's block info
		read(fd,(char *)&temp,sizeof(struct disk_block)); //read block info
		buf=temp.type; //get type from prev block
		temp.next_block=i; //make prev block point to new block
		lseek(fd,-1*(sizeof(struct disk_block)),SEEK_CUR); //move to block info
		write(fd,(char *)&temp,sizeof(struct disk_block)); //write the block info back 
	}
	lseek(fd,BLOCKSIZE*(i+2)-sizeof(struct disk_block),SEEK_SET); //go to new block's block info 
	temp.type=type; //get the type of block from parameter
	if(block_no>=0) 
		temp.type=buf; //if it is to continue a linked list of blocks
	temp.prev_block=block_no; //set previous block number
	temp.next_block=-1; //no next block
	write(fd,(char *)&temp,sizeof(struct disk_block)); //write changes to block info
	close(fd);	
	pthread_mutex_unlock(&lock); //give up lock on file read/write
	return i; //return block number allocated
}
int relblock(int block_no){ //function to release a block assigned to you
	char buf;
	int i;
	int free_b;
	struct disk_block temp,temp1;
	if(block_no<0 && block_no >2046) //can't release a block that doesn't exist
		return -1;
	pthread_mutex_lock(&lock); //get a lock on file read/write
	fd=open("/home/ajvm/Desktop/fuse_ork/eval/the_fs",O_RDWR);
	if(fd<0)
		perror("open");
	lseek(fd,8+block_no,SEEK_SET); //move to superblock's bitmap
	write(fd,"0",1); //write 0 to indicate block is free
	lseek(fd,8+2046,SEEK_SET); //move to superblock number of free blocks part
	read(fd,(char *)&free_b,sizeof(int));  //read how many blocks are free
	lseek(fd,-sizeof(int),SEEK_CUR); //move back
	free_b++; //increase the number of free blocks
	write(fd,(char *)&free_b,sizeof(int)); //write the number of free blocks
	lseek(fd,BLOCKSIZE*(block_no+2)-sizeof(struct disk_block),SEEK_SET); //move to the block to be freed
	read(fd,(char* )&temp,sizeof(struct disk_block)); //read block info
	if(temp.prev_block!=-1){ //if there is a block pointing to it,the link should be cut
		lseek(fd,BLOCKSIZE*(temp.prev_block+2)-sizeof(struct disk_block),SEEK_SET); //move to that block
		read(fd,(char *)&temp1,sizeof(struct disk_block)); //read block info
		temp1.next_block=temp.next_block; //this should be -1! Except when we use it for inode blocks
		lseek(fd,-sizeof(struct disk_block),SEEK_CUR); //move to block info
		write(fd,(char *)&temp1,sizeof(struct disk_block)); //write back changes to block info
	}
	if(temp.next_block!=-1 && temp.type=='i'){ //difference for inode blocks
		lseek(fd,BLOCKSIZE*(temp.next_block+2)-sizeof(struct disk_block),SEEK_SET); //move to next block
		read(fd,(char *)&temp1,sizeof(struct disk_block)); //get block info
		temp1.prev_block=temp.prev_block; //make next block point to the one before one being released
		lseek(fd,-sizeof(struct disk_block),SEEK_CUR); //move back
		write(fd,(char *)&temp1,sizeof(struct disk_block)); //write changess
	}
	lseek(fd,-BLOCKSIZE+8+block_no,SEEK_END); //move to superblock at end
	write(fd,"0",1); //write the changes to bitmap
	lseek(fd,-BLOCKSIZE+8+2046,SEEK_END); //move to free block number
	write(fd,(char *)&free_b,sizeof(int)); //write changes
	close(fd);	
	pthread_mutex_unlock(&lock); //give up lock on file read/write
	return 0; //successful release of block
}
struct inode_block{ //inode block structure
	struct node inodes[25]; //inodes
	char bitmap[25]; //bitmap
	int free_inode_no; //number of inodes that can be added
}__attribute__((packed));
int writeinode(ino_t inode_no,struct node *inode){ //function to write an inode to file
	int block_no=inode_no%10000; //which block is the inode present in?
	if(getblocktype(block_no)!='i') //make sure  the block is a inode block
		return -1;
	inode_no=inode_no/10000; //shift to get the node_in_block
	int node_in_block=inode_no%100; //get the node_in_block
	if(node_in_block > 24) //if the node_in_block doesn't exist, return error
		return -2;
	struct inode_block inode_table; //complete inode block
	readblock(block_no,(char *)&inode_table,0,sizeof(struct inode_block)); //read the whole block at once
	//inode=(struct node *)(malloc(sizeof(struct node))); //make some memory on to point the result to
	inode_table.inodes[node_in_block]=*inode; //change inode in the inode table
	writeblock(block_no,(char *)&inode_table,0,sizeof(struct inode_block)); //write the changed inode table back
	return 0;
}
int relinode(ino_t inode_no){ //function to release an inode
	int block_no=inode_no%10000; //which block is the inode present in?
	if(getblocktype(block_no)!='i') //check if inode block
		return -1;
	inode_no=inode_no/10000; //shift to get node_in_block
	int node_in_block=inode_no%100; //get the node_in_block
	if(node_in_block > 24) //if node_in_block doesn't exist,return an error
		return -1;
	struct inode_block inode_table; //inode table
	readblock(block_no,(char *)&inode_table,0,sizeof(struct inode_block)); //get inode table from memory
	//inode=(struct node *)(malloc(sizeof(struct node))); //make some memory on to point the result to
	//*inode=inode_table.inodes[node_in_block]; //need not do this?
	inode_table.bitmap[node_in_block]='0'; //mark that inode as free to use
	inode_table.free_inode_no++; //increase the number of free inodes
	if(inode_table.free_inode_no==25 && block_no!=0) //if block is empty and it is not the root inode block,we should free it
		relblock(block_no); //release that block
	else 
		writeblock(block_no,(char *)&inode_table,0,sizeof(struct inode_block)); //if not,write the changed inode block back
	return 0; //return success
}
ino_t reqinode(void){ //change here,no parameters. Use write inode itself to update it. This function will only give you an inode number
	int block_no=0; //which block is the inode present in?
	ino_t inode_no=0; //start from root inode block
	int node_in_block=0;
	struct inode_block inode_table;
	//readblock(block_no,&inode_table,0,sizeof(struct inode_block));
	//inode=(struct node *)(malloc(sizeof(struct node))); //make some memory on to point the result to
	while(1){ //keep doing till an inode is assigned
		readblock(block_no,(char *)&inode_table,0,sizeof(struct inode_block)); //read the inode block
		if(inode_table.free_inode_no !=0){ //if there's a free inode in that block
			for(int k=0;k<25;k++){ //find from bitmap which one is free
				if(inode_table.bitmap[k]=='0'){ //found a free block!
					node_in_block=k; //this will be our node in block
					break; //break from this loop
				}
			}
			break; //break from outer loop,we found an inode to use
		}
		else{
			if(get_next_block(block_no,1)==-1){ //no free inodes in this inode block, we don't have another block either
				int temp=reqblock(block_no,'i'); //request for a new block. 
				if(temp==-1) //no free blocks either,return error
					return -1;
				else
					block_no=temp; //we got a free block
				for(int k=0;k<25;k++) //set the bitmap for the new inode table
					inode_table.bitmap[k]='0';
				inode_table.free_inode_no=25; //all inodes are free to use
			}
			else
				block_no=get_next_block(block_no,1); //move to the next block to check for empty entries we can use
		}
	}	
	//inode_table.inodes[node_in_block]=*inode; //don't need to do this because you have requested for a inode number 
	inode_table.bitmap[node_in_block]='1'; //bitmap will show this inode is taken
	inode_table.free_inode_no--; //reduce the number of free inodes
	writeblock(block_no,(char *)&inode_table,0,sizeof(struct inode_block)); //write the changed inode table back
	return node_in_block*10000+block_no; //return inode number
}
int getinode(ino_t inode_no,struct node * inode){ //get the inode
	int block_no=inode_no%10000; //which block is the inode present in?
	if(getblocktype(block_no)!='i') //make sure it is an inode block
		return -1;
	inode_no=inode_no/10000; //shift to get the node_in_block
	int node_in_block=inode_no%100; 
	if(node_in_block > 24) //node_in_block should exist otherwise return error
		return -1;
	struct inode_block inode_table; 
	readblock(block_no,(char *)&inode_table,0,sizeof(struct inode_block)); //get the inode table
	//inode=(struct node *)(malloc(sizeof(struct node))); //make some memory on to point the result to
	*inode=inode_table.inodes[node_in_block]; //get the inode from the inode table and copy values
	return 0; //successful return
}

int inodesused(){
	int inodes_used=0;
	int block_no=0;
	struct inode_block inode_table;
	readblock(block_no,(char *)&inode_table,0,sizeof(struct inode_block)); //get the inode table
	//inode=(struct node *)(malloc(sizeof(struct node))); //make some memory on to point the result to
	inodes_used+=25-inode_table.free_inode_no; //get the inode from the inode table and copy values
	block_no=get_next_block(block_no,1);	
	while(block_no!=-1){
		readblock(block_no,(char *)&inode_table,0,sizeof(struct inode_block)); //get the inode table
		//inode=(struct node *)(malloc(sizeof(struct node))); //make some memory on to point the result to
		inodes_used+=25-inode_table.free_inode_no; //get the inode from the inode table and copy values
		block_no=get_next_block(block_no,1);	
	}
	return inodes_used; //successful return
}
char * makeDirnameSafe(const char *message){
	char *buffer =strdup(message);
	char *directory =dirname(buffer);
	char *result =strdup(directory);
	free(buffer);
	return result;
}


char * makeBasenameSafe(const char *message){
  	char *buffer =strdup(message);
	char *name =basename(buffer);
	char *result =strdup(name);
	free(buffer);
  	return result;
}

//* node must be allocated memory
int getNodeByPath(const char *path,struct filesystem *fs,struct node *node){
	return getNodeRel(path,fs->root,node);
}

//whenever called node must be written back
static void updateTime(struct node *node,int which){
time_t current = time(0);
	if(which & U_ATIME) 
		node->vstat.st_atime =current;
	if(which & U_CTIME)
		node->vstat.st_ctime =current;
	if(which & U_MTIME)
		node->vstat.st_mtime =current;
}

static int initstat(struct node *node,mode_t mode){
	struct stat *stbuffer = &node->vstat;
	memset(stbuffer, 0, sizeof(struct stat));
	stbuffer->st_mode  =mode;
	stbuffer->st_nlink = 0;
	updateTime(node, U_ATIME | U_MTIME | U_CTIME);
	return 1;
}

//our_fs must have root node read into memory
static int createEntry(const char *path, mode_t mode,struct node **node){

	printf("createEntry :%s\n",path);
	char *directorypath =makeDirnameSafe(path);

  // Find parent node
	struct node directory;
	int ret =getNodeByPath(directorypath,&our_fs,&directory);
	free(directorypath);
	if(!ret){
	    	return -errno;
	}
 // Create new node
	*node = malloc(sizeof(struct node));
	//printf("New Inode no:%d\n",(*node)->vstat.st_ino);
	if(!*node){
		return -ENOMEM;
	}

	
  // Initialize stats
	if(!initstat(*node, mode)){
		free(*node);
		return -errno;
	}

	(*node)->vstat.st_ino = reqinode();

	(*node)->fd_count =0;
	(*node)->delete_on_close =0;

	(*node)->data=-1;

	struct fuse_context *context =fuse_get_context();
	(*node)->vstat.st_uid =context->uid;
  	(*node)->vstat.st_gid =context->gid;

	writeinode((*node)->vstat.st_ino,*node);

  // Add to parent directory
	if(directory.vstat.st_ino==0)
	{	if(!dir_add_alloc(our_fs.root, makeBasenameSafe(path), *node, 0)){
			free(*node);
			return -errno;
		}
	}
	else{
		if(!dir_add_alloc(&directory, makeBasenameSafe(path), *node, 0)){
			free(*node);
			return -errno;
		}
	}
	return 0;
}


//
// Filesystem entry points
//

static int ourfs_getattr(const char *path,struct stat *stbuffer){
	
	struct node node;
	if(!getNodeByPath(path,&our_fs,&node)){
		return -errno;
	}
	stbuffer->st_mode   =node.vstat.st_mode;
	stbuffer->st_nlink  =node.vstat.st_nlink;
	stbuffer->st_size   =node.vstat.st_size;
	stbuffer->st_blocks =node.vstat.st_blocks;
	stbuffer->st_uid    =node.vstat.st_uid;
	stbuffer->st_gid    =node.vstat.st_gid;
	stbuffer->st_mtime  =node.vstat.st_mtime;
	stbuffer->st_atime  =node.vstat.st_atime;
	stbuffer->st_ctime  =node.vstat.st_ctime;

  // Directories contain the implicit hardlink '.'
	if(S_ISDIR(node.vstat.st_mode)){
		stbuffer->st_nlink++;
	}

	return 0;
}

static int ourfs_readlink(const char *path,char *buf,size_t size){

	struct node node;
	if(!getNodeByPath(path, &our_fs, &node)){
		return -errno;
	}
	if(!S_ISLNK(node.vstat.st_mode)){
		return -ENOLINK;
	}

  // Fuse breaks compatibility with other readlink() implementations as we cannot use the return
  // value to indicate how many bytes were written. Instead, we need to null-terminate the string,
  // unless the buffer is not large enough to hold the path. In that case, fuse will null-terminate
  // the string before passing it on.

	char *buffer;
	buffer=(char *) malloc(node.vstat.st_size);
	readblock(node.data,buffer,0,node.vstat.st_size);

	if(node.vstat.st_size > size) {

		memcpy(buf,buffer, size);
	}
	else{
    		strcpy(buf, buffer);
	}
	free(buffer);
	return 0;
}

static int ourfs_readdir(const char *path,void *buf,fuse_fill_dir_t filler,off_t offset,struct fuse_file_info *fi){
	
	printf("readdir :%s\n",path);
	struct node directory;
	if(!getNodeByPath(path,&our_fs,&directory)){
		return -errno;
	}
	if(!S_ISDIR(directory.vstat.st_mode)){
		return -ENOTDIR;
	}
	filler(buf, ".",  &directory.vstat, 0,0);
	if(directory.vstat.st_ino == our_fs.root->vstat.st_ino){
		filler(buf, "..", NULL, 0,0);
	}
	else{
		char *parent_path = makeDirnameSafe(path);
		struct node parent;
		getNodeByPath(parent_path,&our_fs,&parent);
		free(parent_path);
		filler(buf, "..", &parent.vstat, 0,0);
	}
	//problem adding . and .. to direntry table?

	int dtab_bnum = directory.data;
	//printf("%d\n",dtab_bnum);
	int off = MAX_DIRENTRY*DIRENT_SIZE;
	char bitmap[2];
	int ent_num;

	struct direntry *ent;
	ent=(struct direntry *)malloc(sizeof(struct direntry)*MAX_DIRENTRY);

	struct node inode;

	while(dtab_bnum!=-1){
	
		if(readblock(dtab_bnum,bitmap,off,(int)ceil(MAX_DIRENTRY/(float)8))!=(int)ceil(MAX_DIRENTRY/(float)8))
		{	//set errno for I/O ERROR
			errno =  EIO;
			free(ent);
			return 0;
		}
		off=0;
		if(readblock(dtab_bnum,ent,off,DIRENT_SIZE*MAX_DIRENTRY)!=DIRENT_SIZE*MAX_DIRENTRY)
		{	
			//set errno for I/O ERROR
			errno =  EIO;
			free(ent);
			return 0;
		}
		unsigned char bit_no;
		ent_num = 0;
		int index;
		for(index=0;index<2;index++)
		{	bit_no=128;
			for(int bit=0;bit<8;bit++)
			{	++ent_num;
				if(bit_no & bitmap[index])
				{	
					int temp=ent[ent_num-1].node_num;
					getinode(temp,&inode);	//assuming works without error
					if(filler(buf, ent[ent_num-1].name, &inode.vstat, 0,0))
					{	free(ent);
						return 0;	//break;
					}
				}
				bit_no = bit_no >> 1;
				if(index==1 && bit==5)
					break;
			}
		}
		dtab_bnum=get_next_block(dtab_bnum,1);
	}
	return 0;
}

static int ourfs_mknod(const char *path, mode_t mode, dev_t rdev){
	struct node *node;
	int res = createEntry(path, mode, &node);
	if(res)
		return res;
	//if its a regualr file , instead of setting the data to NULL, in our implementation we set the block no to -1
	if(S_ISREG(mode)){
		node->data = -1;
		node->vstat.st_blocks = 0;
		node->vstat.st_nlink=1;
		node->delete_on_close=0;
		//writeinode because inode attributes are changed
		if(writeinode(node->vstat.st_ino,node) != 0)
			return -errno;
  	}
	else{
	    	return -ENOSYS;
  	}
	return 0;
}

//what should we do to set the directory entries to 0
static int ourfs_mkdir(const char *path,mode_t mode){
	printf("mkdir :%s\n",path);
	struct node *node;
	int res =createEntry(path, S_IFDIR | mode, &node);
	if(res)
		return res;

  	//read the bitmap and set all the entries in the bitmap to 0 indicating 0 entries in the directory block
	node->data = reqblock(-1,'f');	//find??
	int offset = MAX_DIRENTRY*DIRENT_SIZE;
	char bitmap[2]={'\0'};
	writeblock(node->data,bitmap,offset,2);
	writeinode(node->vstat.st_ino,node);
	printf("mkdir done\n");
	struct node root;
	getinode(0,&root);
	printf("%d\n",root.data);
	printf("%d\n",our_fs.root->data);
	return 0;
}


static int ourfs_unlink(const char *path){
	char *dirpath, *name;
	char *data;
  	struct node directory, node;
	int a[50];
  // Find inode
	if(!getNodeByPath(path, &our_fs, &node)){
		return -errno;
	}
	if(S_ISDIR(node.vstat.st_mode)){
		return -EISDIR;
	}
	dirpath =makeDirnameSafe(path);

  // Find parent inode
	if(!getNodeByPath(dirpath, &our_fs, &directory)){
		free(dirpath);
		return -errno;
	}

	free(dirpath);
	name =makeBasenameSafe(path);

  // Find directory entry in parent
	if(!dir_remove(&directory, name)){
		free(name);
		return -errno;
	}
	free(name);
	getinode(node.vstat.st_ino,&node);
  // If the link count is zero, delete the associated data
	if(node.vstat.st_nlink ==0){
		if(node.fd_count == 0){

			ino_t inode_num = node.vstat.st_ino;
	      		// No open file descriptors, we can safely delete the node
		        int bnum = node.data;
			int x = bnum;
			a[0] = bnum;
			int i= 1;
			//store all the block nos to be deleted in an array "a"	
			if(node.data != -1) 
			{	
				while((x = get_next_block(x,1)) != -1 && i<50)
				{	a[i] = x;
					i++;
				
				}
			}

			for(int j=0;j<i;j++)
			{	if(relblock(a[j]) != 0)
					return -errno;
			}

		    if(relinode(inode_num) != 0)
			return -errno;
    		}
		else{
      // There are open file descriptors, schedule deletion
			node.delete_on_close = 1;
			int temp=node.vstat.st_ino;
			if(writeinode(temp,&node) != 0)
				return -errno;
		}
	}
	return 0;
}

static int ourfs_rmdir(const char *path){
	char *dirpath, *name;
	struct node dir, node;

	char bitmap[2];
	int empty_flag = 1;
	int index;
  // Find inode
	if(!getNodeByPath(path, &our_fs, &node)){
		return -errno;
	}
	if(!S_ISDIR(node.vstat.st_mode)){
		return -ENOTDIR;
	}

  // Check if directory is empty
  // read the bitmap of that block and check if all the entries are 0 
	if(node.data==-1)
	{	if(relinode(node.vstat.st_ino) != 0)
			return -errno;	
		return 0;
	}

	int bnum = node.data;

	int flag =0;
	while(bnum !=-1){
		if(readblock(bnum, bitmap, MAX_DIRENTRY*DIRENT_SIZE,(int)ceil(MAX_DIRENTRY/(float)8))!= (int)ceil(MAX_DIRENTRY/(float)8))
		{	
				return -errno;
		}
		for(index=0;index < 2;index++)
		{	if(bitmap[index]!=0)
			{	empty_flag = 0;
				return -ENOTEMPTY; 
			}	
		}
		bnum=get_next_block(bnum,1);
		if(empty_flag)
			relblock(bnum);
		
	}
	
	dirpath = makeDirnameSafe(path);

  // Find parent inode
	if(!getNodeByPath(dirpath, &our_fs, &dir)){
		free(dirpath);
		return -errno;	
	}

	free(dirpath);
	
	name = makeBasenameSafe(path);

  // Find directory entry in parent
	if(!dir_remove(&dir, name)){
		free(name);
		return -errno;
	}

	free(name);

	if(relinode(node.vstat.st_ino) != 0)
		return -errno;
	return 0;
}


static int ourfs_symlink(const char *from, const char *to){
	struct node *node;
	int res = createEntry(to, S_IFLNK | 0766, &node);
	if(res)
		return res;
	//write "from" to that particular block assuming that while creating the node, we are chaning the values in the super block
	int bnum = node->data;
	int len = strlen(from);
	if(writeblock(bnum,from,0,len) != len)
			{	
				return -errno;
			}
	node->vstat.st_size = strlen(from);
	if(writeinode(node->vstat.st_ino,node) != 0)
		return -errno;
	return 0;
}


static int ourfs_rename(const char *from, const char *to){
	char *fromdir, *fromnam, *todir, *tonam;
	struct node node, fromdirnode, todirnode;
	if(!getNodeByPath(from, &our_fs, &node)){
		return -errno;
	}
	fromdir = makeDirnameSafe(from);

	if(!getNodeByPath(fromdir, &our_fs, &fromdirnode)){
		free(fromdir);
		return -errno;
	}
	free(fromdir);

	todir = makeDirnameSafe(to);

	if(!getNodeByPath(todir, &our_fs, &todirnode)){
		free(todir);
		return -errno;
	}
	free(todir);
	tonam = makeBasenameSafe(to);

	if(!dir_add_alloc(&todirnode, tonam, &node, 1)){
		free(tonam);
		return -errno;
	}
	free(tonam);
	fromnam = makeBasenameSafe(from);

	if(!dir_remove(&fromdirnode, fromnam)){
		free(fromnam);
		return -errno;
	}
	free(fromnam);
	return 0;
}

static int ourfs_link(const char *from, const char *to){
	char *todir, *tonam;
	struct node node, todirnode;
	if(!getNodeByPath(from, &our_fs, &node)){
		return -errno;
	}
	todir = makeDirnameSafe(to);

	if(!getNodeByPath(todir, &our_fs, &todirnode)){
		free(todir);
		return -errno;
	}

	free(todir);
	tonam = makeBasenameSafe(to);

	if(!dir_add_alloc(&todirnode, tonam, &node, 0)){
		free(tonam);
		return -errno;
	}

	free(tonam);

	return 0;
}

static int ourfs_chmod(const char *path, mode_t mode){
	struct node node;
	if(!getNodeByPath(path, &our_fs, &node)){
		return -errno;
	}

	mode_t mask = S_ISUID | S_ISGID | S_ISVTX |
	                S_IRUSR | S_IWUSR | S_IXUSR |
	                S_IRGRP | S_IWGRP | S_IXGRP |
	                S_IROTH | S_IWOTH | S_IXOTH;

	node.vstat.st_mode = (node.vstat.st_mode & ~mask) | (mode & mask);
	updateTime(&node, U_CTIME);
	int temp=node.vstat.st_ino;
	if(writeinode(temp,&node) != 0)
		return -errno;
	return 0;
}

static int ourfs_chown(const char *path, uid_t uid, gid_t gid){
	struct node node;
	if(!getNodeByPath(path, &our_fs, &node)){
		return -errno;
	}

	node.vstat.st_uid = uid;
	node.vstat.st_gid = gid;
	updateTime(&node, U_CTIME);
	int temp=node.vstat.st_ino;
	if(writeinode(temp,&node) != 0)
		return -errno;
	return 0;
}

static int ourfs_utimens(const char *path, const struct timespec ts[2]){
	struct node node;
	if(!getNodeByPath(path, &our_fs, &node)){
	return -errno;
	}
	node.vstat.st_atime = ts[0].tv_sec;
	node.vstat.st_mtime = ts[1].tv_sec;
	int temp=node.vstat.st_ino;	
	if(writeinode(node.vstat.st_ino,&node) != 0)
		return -errno;
	return 0;
}

// Assumption that size_t data structure can take off_t data structure also
static int ourfs_truncate(const char *path, off_t size){
	struct node node;
	if(!getNodeByPath(path, &our_fs, &node)){
		return -errno;
	}

  // Calculate new block count
	blkcnt_t newblkcnt = (size + (BLOCKSIZE-sizeof(struct disk_block)) - 1) / (BLOCKSIZE - sizeof(struct disk_block));
	blkcnt_t oldblkcnt = node.vstat.st_blocks;

	if(oldblkcnt < newblkcnt){
    // Allocate additional memory
		char *newdata = malloc(newblkcnt * (BLOCKSIZE-sizeof(struct disk_block)) );
		if(!newdata){
			return -ENOMEM;
		}
		//get that block , and perfrom a writeblock copying the truncated data back into that block
		if(readblock(node.data,newdata,0,node.vstat.st_size)!= node.vstat.st_size)
			{	//set errno for I/O ERROR
				return -errno;
			}
		if(writeblock(node.data,newdata,0,size)!= size)
			{	//set errno for I/O ERROR
				return -errno;
			}
				}

  // Update file size
	node.vstat.st_size = size;
	node.vstat.st_blocks = newblkcnt;
	int temp=node.vstat.st_ino;
	if(writeinode(temp,&node) != 0)
		return -errno;
	return 0;
}

static int ourfs_open(const char *path, struct fuse_file_info *fi){	
	struct node *node_new=malloc(sizeof(struct node));
	if(!getNodeByPath(path, &our_fs, node_new)){
		return -errno;
	}
	if(!S_ISREG(node_new->vstat.st_mode)){
		if(S_ISDIR(node_new->vstat.st_mode)){
			return -EISDIR;	
		}
	}

  // Update file timestamps
	updateTime(node_new, U_ATIME);
	if(writeinode(node_new->vstat.st_ino,node_new) != 0)
		return -errno;

  // The "file handle" is a pointer to a struct we use to keep track of the inode and the
  // flags passed to open().
	struct filehandle *fh = malloc(sizeof(struct filehandle));
	fh->node    = node_new;
	fh->o_flags = fi->flags;
	fi->fh = (uint64_t) fh;

	node_new->fd_count++;
	if(writeinode(node_new->vstat.st_ino,node_new) != 0)
		return -errno;
	return 0;
}

static int ourfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
	struct filehandle *fh = (struct filehandle *) fi->fh;

  // Check whether the file was opened for reading
	if(!O_READ(fh->o_flags)) {	
		return -EACCES;
	}

	struct node *node = fh->node;

	off_t filesize = node->vstat.st_size;

  // Check whether offset is at or beyond the end of file
	if(offset >= filesize){
		return 0;
	}

  // Calculate number of bytes to copy
	size_t avail = filesize - offset;
	size_t n = (size < avail) ? size : avail; //n bytes to read? but they might be in different blocks
	int block_no= offset/(BLOCKSIZE+1-(sizeof(struct disk_block)));//which block to move to?
	int read_block=node->data;	
	while(block_no!=0){
		read_block=get_next_block(read_block,1);
		block_no--;
	}
	int in_block=offset%(BLOCKSIZE-sizeof(struct disk_block));//where in the block
	size_t left_to_do=n,done=0;	
// Copy file contents
	//readblock and copy the contents to a buffer
	size_t bytesdoing=BLOCKSIZE-sizeof(struct disk_block)-in_block<left_to_do?BLOCKSIZE-sizeof(struct disk_block)-in_block:left_to_do;
	if(readblock(read_block,buf+done,in_block,bytesdoing)!= bytesdoing)
			{	//set errno for I/O ERROR
				return 0;
			}
	done+=bytesdoing;
	left_to_do-=bytesdoing;
	while(left_to_do){
		read_block=get_next_block(read_block,1);
		bytesdoing=BLOCKSIZE-sizeof(struct disk_block)<left_to_do?BLOCKSIZE-sizeof(struct disk_block):left_to_do;
		int val=readblock(read_block,buf+done,0,bytesdoing);
		if(val!= bytesdoing)
			{	//set errno for I/O ERROR
				return done+val;
			}
		done+=bytesdoing;
		left_to_do-=bytesdoing;
	}
	
	updateTime(node, U_ATIME);
	if(writeinode(node->vstat.st_ino,node) != 0)
		return -errno;
	return done;
}


static int ourfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	struct filehandle *fh = (struct filehandle *) fi->fh;

  // Check whether the file was opened for writing
	if(!O_WRITE(fh->o_flags)){
		return -EACCES;
  	}

	struct node *node = fh->node;
	char *newdata;
  // Calculate number of required blocks
	blkcnt_t req_blocks = (offset + size + (BLOCKSIZE-sizeof(struct disk_block))- 1) / (BLOCKSIZE-sizeof(struct disk_block));
	//req_blocks+=1;
	printf("blocks:%d\n",req_blocks);

	int max_data = (BLOCKSIZE-sizeof(struct disk_block));
	int count = (int)ceil(node->vstat.st_size/(float)max_data);

	int bnum = node->data;

	if(node->vstat.st_blocks < req_blocks){
    // Allocate more memory, get the next block
		if(node->vstat.st_blocks==0){	
    // Update allocation information
			
			node->data = reqblock(-1,'d');
			count = req_blocks - 1;
			printf("allocating :%d blocks\n",count);
			bnum = node->data;
			while(count!=0)
			{	bnum=reqblock(bnum,'d');
				count--;
			}
			printf("last allocated block :%d block\n",bnum);
		}
		else{
			count = node->vstat.st_blocks;
			bnum = node->data;
			while(count !=1)
			{	bnum = get_next_block(bnum,1);
				count--;
			}
			printf("last bnum:%d\n",bnum);
			count = req_blocks - node->vstat.st_blocks;
			printf("extra:%d blocks\n",count);
			while(count!=0)
			{
				bnum=reqblock(bnum,'d');
				count--;
			}
		}		
		node->vstat.st_blocks = req_blocks;
	}

  // Write new contents from buf to newdata
	//memcpy(newdata + offset, buf, size);

	count = (int)ceil(offset/(float)max_data);
	printf("count:%d\n",count);
	bnum = node->data;
	while(count > 1)
	{	bnum = get_next_block(bnum,1);
		count--;
	}

	count = (int)ceil(offset/(float)max_data);

	int new_offset=offset;
	if(count>0)
		new_offset = offset - ((count-1)*max_data);
	int size_left=size;
	int i=0;
	int written;
	while(size_left!=0)
	{	printf("size_left:%d\n",size_left);
		written = writeblock(bnum,buf+i,new_offset,size_left);
		printf("written %d bytes to %d block\n",written,bnum);
		size_left-= written;
		if(size_left!=0)
		{	bnum = get_next_block(bnum,1);
			new_offset=0;
			i += written;
		}
	}

	printf("written\n");
  // Update file size if necessary
	off_t minsize = offset + size;
	if(minsize > node->vstat.st_size){
		node->vstat.st_size = minsize;
	}

	updateTime(node, U_CTIME | U_MTIME);
	//if
	if(writeinode(node->vstat.st_ino , node) != 0)
		return -errno;
	return size;
}

static int ourfs_release(const char *path, struct fuse_file_info *fi){
	struct filehandle *fh = (struct filehandle *) fi->fh;
	int a[50],i,x,j;
	//i contains the no of elements in the array
  // If the file was deleted but we could not free it due to open file descriptors,
  // free the node and its data after all file descriptors have been closed.
	--fh->node->fd_count;
	if(fh->node->fd_count == 0){
		if(fh->node->delete_on_close){
	//free that block ,if that file occupies more than one block then keep calling getnextblock until -1 is returned
			int bnum = fh->node->data;
			x = bnum;
			a[0] = bnum;
			//store all the block nos to be deleted in an array "a"	
			if(fh->node->data != -1) 
			{	i= 1;
				while((x = get_next_block(x,1)) != -1)
				{	a[i] = x;
					i++;
				
				}
			}

			for(j=0;j<i;j++)
			{	if(relblock(a[j]) != 0)
					return -errno;
			}
			
			if(relinode(fh->node->vstat.st_ino) != 0)
				return -errno;
				
				free(fh->node);
		}
		else{
			writeinode(fh->node->vstat.st_ino,(fh->node));		
		}
	}
	else{
		writeinode(fh->node->vstat.st_ino,(fh->node));
	}
  // Free "file handle"
	free(fh);
	return 0;
}
/*
static int ourfs_flush(const char *path, struct fuse_file_info *fi){	
	struct node *node_new=malloc(sizeof(struct node));
	if(!getNodeByPath(path, &our_fs, node_new)){
		return -errno;
	}
	if(!S_ISREG(node_new->vstat.st_mode)){
		if(S_ISDIR(node_new->vstat.st_mode)){
			return -EISDIR;	
		}
	}

  // Update file timestamps
	updateTime(node_new, U_ATIME);
	if(writeinode(node_new->vstat.st_ino,node_new) != 0)
		return -errno;

  // The "file handle" is a pointer to a struct we use to keep track of the inode and the
  // flags passed to open().
	struct filehandle *fh = malloc(sizeof(struct filehandle));
	fh->node    = node_new;
	fh->o_flags = fi->flags;
	fi->fh = (uint64_t) fh;

	node_new->fd_count++;
	if(writeinode(node_new->vstat.st_ino,node) != 0)
		return -errno;
	return 0;
}*/
int ourfs_statfs(const char *anyfile, struct statvfs *storage){
	storage->f_bsize=BLOCKSIZE;
	storage->f_blocks=2048;
	storage->f_namemax=256;
	storage->f_bfree=superblockread();
	storage->f_bavail=storage->f_bfree;
	storage->f_files=inodesused();
	return 0;
}
static struct fuse_operations ourfs_oper ={
	.getattr      = ourfs_getattr,
	.readlink     = ourfs_readlink,
	.readdir      = ourfs_readdir,
	.mknod        = ourfs_mknod,
	.mkdir        = ourfs_mkdir,
	.symlink      = ourfs_symlink,
	.unlink       = ourfs_unlink,
	.rmdir        = ourfs_rmdir,
	.rename       = ourfs_rename,
	.link         = ourfs_link,
	.chmod        = ourfs_chmod,
	.chown        = ourfs_chown,
	.truncate     = ourfs_truncate,
	.utimens      = ourfs_utimens,
	.open         = ourfs_open,
	.read         = ourfs_read,
	.write        = ourfs_write,
	.release      = ourfs_release,
	.statfs	      = ourfs_statfs,
	//.flush	      = ourfs_flush
	//.close	      = ourfs_close
};
//
// Application entry point
//

int main(int argc, char *argv[]){
  // Initialize root directory
	struct node *root = malloc(sizeof(struct node));
	memset(root, 0, sizeof(struct node));
	//initstat(root, S_IFDIR | 0755);
	//root->vstat.st_uid = getuid();
	//root->vstat.st_gid = getgid();
	int status=opendisk();
	if(status){
		printf("There was a root\n");
		getinode(0,root);
	}
	else{
		struct inode_block inode_table;
		initstat(root, S_IFDIR | 0755);
		root->vstat.st_uid = getuid();
		root->vstat.st_gid = getgid();
		root->data = -1;
		reqblock(-1,'i');
		readblock(0,(char *)&inode_table,0,sizeof(struct inode_block));
		inode_table.free_inode_no=25;
		writeblock(0,(char *)&inode_table,0,sizeof(struct inode_block));
		root->vstat.st_ino=reqinode();
		writeinode(root->vstat.st_ino,root);
	}
  // No entries
  // Set root directory of filesystem
	//char temp[4400];
	//writeblock(0,&temp,0,4400);
	printf("root->data:%d\n",root->data);
	our_fs.root = root;
	umask(0);
	close(fd);
	printf("Done\n");
	return fuse_main(argc, argv, &ourfs_oper, NULL);
}
