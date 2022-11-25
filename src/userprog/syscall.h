#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "filesys/inode.h"

void syscall_init (void);
void force_exit(void);
int fibonacci (int n);
int max_of_four_int (int a, int b, int c, int d);

struct file_lock {
	block_sector_t sector;
	struct lock lock;
};

struct file_lock filesys_lock[200];

#endif /* userprog/syscall.h */
