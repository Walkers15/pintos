#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */


/* Block device that contains the file system. */
extern struct block *fs_device;

struct path {
  char file_name[15];
  struct dir* dir;
};

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
struct file *filesys_open (const char *name);
bool filesys_remove (const char *name);
bool filesys_create_dir(char* name);

void make_path(char* path_name, struct path* result);

#endif /* filesys/filesys.h */
