fs: fs.c node.c dir.h dir.c node.h
	gcc -g -w fs.c node.c dir.c `pkg-config fuse3 --cflags --libs` -lm -o fs
	./fs test #pass some commandline arguments
	cd test
clean: fs the_fs
	rm fs the_fs
	fusermount -u test
