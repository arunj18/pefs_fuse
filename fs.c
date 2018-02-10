
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



int getNodeByPath(const char *path,struct filesystem *fs,struct node **node){
	return getNodeRel(path,fs->root,node);
}

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

static int createEntry(const char *path, mode_t mode,struct node **node){
	char *directorypath =makeDirnameSafe(path);

  // Find parent node
	struct node *directory;
	int ret =getNodeByPath(directorypath,&our_fs,&directory);
	free(directorypath);
	if(!ret){
	    	return -errno;
	}
 // Create new node
	*node = malloc(sizeof(struct node));
	if(!*node){
		return -ENOMEM;
	}

	(*node)->fd_count =0;
	(*node)->delete_on_close =0;

  // Initialize stats
	if(!initstat(*node, mode)){
		free(*node);
		return -errno;
	}
	struct fuse_context *context =fuse_get_context();
	(*node)->vstat.st_uid =context->uid;
  	(*node)->vstat.st_gid =context->gid;

  // Add to parent directory
	if(!dir_add_alloc(directory, makeBasenameSafe(path), *node, 0)){
		free(*node);
		return -errno;
	}
	return 0;
}


//
// Filesystem entry points
//

static int ourfs_getattr(const char *path,struct stat *stbuffer){
	struct node *node;
	if(!getNodeByPath(path,&our_fs,&node)){
		return -errno;
	}
	stbuffer->st_mode   =node->vstat.st_mode;
	stbuffer->st_nlink  =node->vstat.st_nlink;
	stbuffer->st_size   =node->vstat.st_size;
	stbuffer->st_blocks =node->vstat.st_blocks;
	stbuffer->st_uid    =node->vstat.st_uid;
	stbuffer->st_gid    =node->vstat.st_gid;
	stbuffer->st_mtime  =node->vstat.st_mtime;
	stbuffer->st_atime  =node->vstat.st_atime;
	stbuffer->st_ctime  =node->vstat.st_ctime;

  // Directories contain the implicit hardlink '.'
	if(S_ISDIR(node->vstat.st_mode)){
		stbuffer->st_nlink++;
	}

	return 0;
}

static int ourfs_readlink(const char *path,char *buf,size_t size){
	struct node *node;
	if(!getNodeByPath(path, &our_fs, &node)){
		return -errno;
	}
	if(!S_ISLNK(node->vstat.st_mode)){
		return -ENOLINK;
	}

  // Fuse breaks compatibility with other readlink() implementations as we cannot use the return
  // value to indicate how many bytes were written. Instead, we need to null-terminate the string,
  // unless the buffer is not large enough to hold the path. In that case, fuse will null-terminate
  // the string before passing it on.

	if(node->vstat.st_size > size) {
		memcpy(buf, node->data, size);
	}
	else{
    		strcpy(buf, node->data);
	}
	return 0;
}

static int ourfs_readdir(const char *path,void *buf,fuse_fill_dir_t filler,off_t offset,struct fuse_file_info *fi){
	struct node *directory;
	if(!getNodeByPath(path,&our_fs,&directory)){
		return -errno;
	}
	if(!S_ISDIR(directory->vstat.st_mode)){
		return -ENOTDIR;
	}
	filler(buf, ".",  &directory->vstat, 0,0);
	if(directory == our_fs.root){
		filler(buf, "..", NULL, 0,0);
	}
	else{
		char *parent_path = makeDirnameSafe(path);
		struct node *parent;
		getNodeByPath(parent_path,&our_fs,&parent);
		free(parent_path);
		filler(buf, "..", &parent->vstat, 0,0);
	}

	struct direntry *entry = directory->data;
	while(entry != NULL){
		if(filler(buf, entry->name, &entry->node->vstat, 0,0))
			break;
		entry = entry->next;
	}
	return 0;
}

static int ourfs_mknod(const char *path, mode_t mode, dev_t rdev){
	struct node *node;
	int res = createEntry(path, mode, &node);
	if(res)
		return res;

	if(S_ISREG(mode)){
		node->data = NULL;
		node->vstat.st_blocks = 0;
  	}
	else{
	    	return -ENOSYS;
  	}
	return 0;
}

static int ourfs_mkdir(const char *path,mode_t mode){
	struct node *node;
	int res =createEntry(path, S_IFDIR | mode, &node);
	if(res)
		return res;

  // No entries
	node->data = NULL;
	return 0;
}

static int ourfs_unlink(const char *path){
	char *dirpath, *name;
  	struct node *directory, *node;

  // Find inode
	if(!getNodeByPath(path, &our_fs, &node)){
		return -errno;
	}
	if(S_ISDIR(node->vstat.st_mode)){
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
	if(!dir_remove(directory, name)){
		free(name);
		return -errno;
	}
	free(name);

  // If the link count is zero, delete the associated data
	if(node->vstat.st_nlink ==0){
		if(node->fd_count == 0){
      // No open file descriptors, we can safely delete the node
		if(node->data)
			free(node->data);
		free(node);
    		}
		else{
      // There are open file descriptors, schedule deletion
			node->delete_on_close = 1;
		}
	}
	return 0;
}

static int ourfs_rmdir(const char *path){
	char *dirpath, *name;
	struct node *dir, *node;

  // Find inode
	if(!getNodeByPath(path, &our_fs, &node)){
		return -errno;
	}
	if(!S_ISDIR(node->vstat.st_mode)){
		return -ENOTDIR;
	}

  // Check if directory is empty
	if(node->data != NULL) {
		return -ENOTEMPTY;
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
	if(!dir_remove(dir, name)){
		free(name);
		return -errno;
	}

	free(name);
	free(node);
	return 0;
}

static int ourfs_symlink(const char *from, const char *to){
	struct node *node;
	int res = createEntry(to, S_IFLNK | 0766, &node);
	if(res)
		return res;
	node->data = strdup(from);
	node->vstat.st_size = strlen(from);
	return 0;
}


static int ourfs_rename(const char *from, const char *to){
	char *fromdir, *fromnam, *todir, *tonam;
	struct node *node, *fromdirnode, *todirnode;
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

	if(!dir_add_alloc(todirnode, tonam, node, 1)){
		free(tonam);
		return -errno;
	}
	free(tonam);
	fromnam = makeBasenameSafe(from);

	if(!dir_remove(fromdirnode, fromnam)){
		free(fromnam);
		return -errno;
	}
	free(fromnam);
	return 0;
}

static int ourfs_link(const char *from, const char *to){
	char *todir, *tonam;
	struct node *node, *todirnode;
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

	if(!dir_add_alloc(todirnode, tonam, node, 0)){
		free(tonam);
		return -errno;
	}

	free(tonam);

	return 0;
}

static int ourfs_chmod(const char *path, mode_t mode){
	struct node *node;
	if(!getNodeByPath(path, &our_fs, &node)){
		return -errno;
	}

	mode_t mask = S_ISUID | S_ISGID | S_ISVTX |
	                S_IRUSR | S_IWUSR | S_IXUSR |
	                S_IRGRP | S_IWGRP | S_IXGRP |
	                S_IROTH | S_IWOTH | S_IXOTH;

	node->vstat.st_mode = (node->vstat.st_mode & ~mask) | (mode & mask);
	updateTime(node, U_CTIME);
	return 0;
}

static int ourfs_chown(const char *path, uid_t uid, gid_t gid){
	struct node *node;
	if(!getNodeByPath(path, &our_fs, &node)){
		return -errno;
	}

	node->vstat.st_uid = uid;
	node->vstat.st_gid = gid;

	updateTime(node, U_CTIME);

	return 0;
}

static int ourfs_utimens(const char *path, const struct timespec ts[2]){
	struct node *node;
	if(!getNodeByPath(path, &our_fs, &node)){
	return -errno;
	}
	node->vstat.st_atime = ts[0].tv_sec;
	node->vstat.st_mtime = ts[1].tv_sec;
	return 0;
}

static int ourfs_truncate(const char *path, off_t size){
	struct node *node;
	if(!getNodeByPath(path, &our_fs, &node)){
		return -errno;
	}

  // Calculate new block count
	blkcnt_t newblkcnt = (size + BLOCKSIZE - 1) / BLOCKSIZE;
	blkcnt_t oldblkcnt = node->vstat.st_blocks;

	if(oldblkcnt < newblkcnt){
    // Allocate additional memory
		void *newdata = malloc(newblkcnt * BLOCKSIZE);
		if(!newdata){
			return -ENOMEM;
		}
		memcpy(newdata, node->data, node->vstat.st_size);
		free(node->data);
		node->data = newdata;
	}
	else if(oldblkcnt > newblkcnt){
	
    // Allocate new memory so we can free the unnecessarily large memory
		void *newdata = malloc(newblkcnt * BLOCKSIZE);
		if(!newdata){
			return -ENOMEM;
		}

		memcpy(newdata, node->data, size);
		free(node->data);
		node->data = newdata;
 	}

  // Fill additional memory with zeroes
	if(node->vstat.st_size < size) {
	 	memset(node->data + node->vstat.st_size, 0, node->vstat.st_size - size);
	}

  // Update file size
	node->vstat.st_size = size;
	node->vstat.st_blocks = newblkcnt;
	return 0;
}

static int ourfs_open(const char *path, struct fuse_file_info *fi){	
	struct node *node;
	if(!getNodeByPath(path, &our_fs, &node)){
		return -errno;
	}
	if(!S_ISREG(node->vstat.st_mode)){
		if(S_ISDIR(node->vstat.st_mode)){
			return -EISDIR;	
		}
	}

  // Update file timestamps
	updateTime(node, U_ATIME);

  // The "file handle" is a pointer to a struct we use to keep track of the inode and the
  // flags passed to open().
	struct filehandle *fh = malloc(sizeof(struct filehandle));
	fh->node    = node;
	fh->o_flags = fi->flags;
	fi->fh = (uint64_t) fh;

	node->fd_count++;
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
	size_t n = (size < avail) ? size : avail;

  // Copy file contents
	memcpy(buf, node->data + offset, n);

	updateTime(node, U_ATIME);
	return n;
}

static int ourfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	struct filehandle *fh = (struct filehandle *) fi->fh;

  // Check whether the file was opened for writing
	if(!O_WRITE(fh->o_flags)){
		return -EACCES;
  	}

	struct node *node = fh->node;

  // Calculate number of required blocks
	blkcnt_t req_blocks = (offset + size + BLOCKSIZE - 1) / BLOCKSIZE;

	if(node->vstat.st_blocks < req_blocks){
    // Allocate more memory
		void *newdata = malloc(req_blocks * BLOCKSIZE);
		if(!newdata){
			return -ENOMEM;
		}

    // Copy old contents
		if(node->data != NULL){
			memcpy(newdata, node->data, node->vstat.st_size);
			free(node->data);
		}

    // Update allocation information
		node->data = newdata;
		node->vstat.st_blocks = req_blocks;
	}

  // Write to file buffer
	memcpy(((char *) node->data) + offset, buf, size);

  // Update file size if necessary
	off_t minsize = offset + size;
	if(minsize > node->vstat.st_size){
		node->vstat.st_size = minsize;
	}
	updateTime(node, U_CTIME | U_MTIME);
	return size;
}

static int ourfs_release(const char *path, struct fuse_file_info *fi){
	struct filehandle *fh = (struct filehandle *) fi->fh;

  // If the file was deleted but we could not free it due to open file descriptors,
  // free the node and its data after all file descriptors have been closed.	
	if(--fh->node->fd_count == 0){
		if(fh->node->delete_on_close){
			if(fh->node->data) free(fh->node->data);
      				free(fh->node);
		}
	}

  // Free "file handle"
	free(fh);
	return 0;
}
struct disk_block{
	char type;
	int prev_block;
	int next_block;
};
static int opendisk(void){
	int fd=open("the_fs",O_RDWR|O_CREAT|O_EXCL);
	if(fd<0){
		fd=open("the_fs",O_RDWR);
		if(fd<0)
			exit(4);
		char buf[9];
		read(fd,&buf,8);
		buf[8]='\0';
		if(strcmp(buf,"AJARAKFS")!=0){
			exit(4);
		}
		else{
			return fd;		
		}
	}
	else{
		for(int i=0;i<8388608;i++){ //maybe change this to file size?
			write(fd,"0",1);	
		}
		write(fd,"AJARAKFS",8);
		lseek(fd,8,SEEK_SET);
		for(int i=0;i<2046;i++){ //set next 1022 bytes to zero
			write(fd,"0",1);
		}
		int free_blocks=2046;
		int total_blocks=2046;
		write(fd,total_blocks,sizeof(total_blocks));
		write(fd,free_blocks,sizeof(free_blocks));
		lseek(fd,-4096,SEEK_END);
		write(fd,"AJARAKFS",8);
		for(int i=0;i<2046;i++){ //set next 1022 bytes to zero
			write(fd,"0",1);
		}
		write(fd,total_blocks,sizeof(total_blocks));
		write(fd,free_blocks,sizeof(free_blocks));	
		// 2 super blocks written,one at end,one at beginning	
		lseek(fd,0,SEEK_SET);
		//lseek(fd,8,SEEK_SET);
		return fd;
	}
}
static int readblock(unsigned int block_no,char *data,int offset,size_t bytes){
	pthread_mutex_lock(&lock);
	lseek(fd,(BLOCKSIZE*block_no)+offset,SEEK_SET);
	static int read_done;	
	if(offset+bytes > BLOCKSIZE-sizeof(struct disk_block)) //1 for char at end
		read_done=read(fd,data,(bytes-(BLOCKSIZE-(offset+bytes))));
	else
		read_done=read(fd,data,bytes);
	pthread_mutex_unlock(&lock);
	return read_done;
}
static int writeblock(unsigned int block_no,char *data,int offset,size_t bytes){
	pthread_mutex_lock(&lock);	
	lseek(fd,(BLOCKSIZE*block_no)+offset,SEEK_SET);
	static int write_done;	
	if(offset+bytes > BLOCKSIZE-sizeof(struct disk_block)) //1 for char at end
		write_done=write(fd,data,(bytes-(BLOCKSIZE-(offset+bytes))));
	else
		write_done=write(fd,data,bytes);
	pthread_mutex_unlock(&lock);	
	return write_done;
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
	.release      = ourfs_release
};

//
// Application entry point
//

int main(int argc, char *argv[]){
  // Initialize root directory
	struct node *root = malloc(sizeof(struct node));

	memset(root, 0, sizeof(struct node));
	initstat(root, S_IFDIR | 0755);
	root->vstat.st_uid = getuid();
	root->vstat.st_gid = getgid();
	int fd=opendisk();
  // No entries
	root->data = NULL;

  // Set root directory of filesystem
	our_fs.root = root;
	umask(0);
	return fuse_main(argc, argv, &ourfs_oper, NULL);
}

