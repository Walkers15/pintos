#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");
  buffer_cache_init();
  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();
// printf("call free map open\n");
  free_map_open ();
  thread_current()->current_dir = dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  buffer_cache_terminate();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  // printf("filesys create name %s size %d\n", name, initial_size);

  block_sector_t inode_sector = 0;
  // struct dir *dir = dir_open_root ();
  char* copy_name = (char*)malloc(strlen(name) + 1);
  strlcpy(copy_name, name, strlen(name) + 1);

  struct path path;
  path.dir = NULL;
  // printf("make path!!\n");
  make_path(copy_name, &path);

  if (path.dir == NULL || strlen(path.file_name) > NAME_MAX) {
    return false;
  }

  struct dir* dir = path.dir;
  // printf("path file name %s %d\n", path.file_name, strlen(path.file_name));
  // printf("file name len %d\n", strlen(path.file_name));

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, false)
                  && dir_add (dir, path.file_name, inode_sector));
  // printf("FILESYS_CREATE %d\n", success);
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

void make_path(char* path_name, struct path* result) {
  /**
   * 절대 경로 /cse20181641/pintos/text/abc
   * 상대 경로 ../../pintos/text/abc
  */
  struct dir* dir;
  strlcpy(result->file_name, "\0", 2);
  
  if (path_name[0] == '/') {
    dir = dir_open_root();
  } else {
    // printf("dir reopen! %d\n", inode_get_inumber(dir_get_inode(thread_current()->current_dir)));
    dir = dir_reopen(thread_current()->current_dir);
  }
  // dir = dir_reopen(thread_current()->current_dir);

  ASSERT(dir != NULL);
  ASSERT(inode_is_dir(dir_get_inode(dir)));

  char* token1;
  char* token2;
  char* temp;

  // dir_token = strtok_r(path_name, "/", &next);
  token1 = strtok_r(path_name, "/", &temp);
  token2 = strtok_r(NULL, "/", &temp);
  // printf("token1 %s, token2 %s\n", token1, token2);
  while(token2 != NULL && token1 != NULL) {
    // path의 끝에 닿을 때 까지 계속 이동
  // printf("token1 %s token2 %s\n", token1, token2);
    struct inode* inode = NULL;

    if (strlen(token1) > NAME_MAX || dir_lookup(dir, token1, &inode) == false || inode_is_dir(inode) == false) {
      // path가 ../file/file 인 경우 Error
  // printf("path find ERROR!!!!!\n");
      dir_close(dir);
      return;
    }

    dir_close(dir);
    
    dir = dir_open(inode);
  // printf("path dir_open %s %p\n", token1, dir);

    token1 = token2;
    token2 = strtok_r(NULL, "/", &temp);
  }

  if (token1 == NULL) {
    // 마지막 끝이 디렉터리인 경우
    strlcpy(result->file_name, ".", 2);
  } else if (strlen(token1) <= NAME_MAX) {
    // printf("asdasdqaaa %d", strlen(token1));
    strlcpy(result->file_name, token1, strlen(token1) + 1);
  }

  result->dir = dir;

  return;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  // printf("filesys open name %s\n", name);

  if (strlen(name) == 0) {
    return false;
  }

  char* copy_name = (char*)malloc(strlen(name) + 1);
  strlcpy(copy_name, name, strlen(name) + 1);

  struct path path;
  make_path(copy_name, &path);

  if (path.dir == NULL || strlen(path.file_name) > NAME_MAX) {
    return false;
  }

  struct dir* dir = path.dir;
  struct inode *inode = NULL;

  // printf("path file name %s dir %p\n", path.file_name, path.dir);

  if (dir != NULL)
    dir_lookup (dir, path.file_name, &inode);
  dir_close (dir);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  // printf("filesys remove name %s\n", name);

  if (strlen(name) == 0) {
    return false;
  }

  char* copy_name = (char*)malloc(strlen(name) + 1);
  strlcpy(copy_name, name, strlen(name) + 1);

  struct path path;
  make_path(copy_name, &path);

  if (path.dir == NULL || strlen(path.file_name) > NAME_MAX) {
    return false;
  }

  struct dir *dir = dir_open_root ();
  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir); 
  return success;
}

bool filesys_create_dir(char* name) {
  // printf("filesys_create_dir %s\n", name);

  if (strlen(name) == 0) {
    return false;
  }

  char* copy_name = (char*)malloc(strlen(name) + 1);
  strlcpy(copy_name, name, strlen(name) + 1);

  struct path path;
  make_path(copy_name, &path);

  if (path.dir == NULL || strlen(path.file_name) > NAME_MAX) {
    return false;
  }

  // printf("path file name %s %d\n", path.file_name, strlen(path.file_name));
  // printf("file name len %d\n", strlen(path.file_name));

  struct dir *dir = path.dir;

  block_sector_t inode_sector;

  bool success = (dir != NULL
                 && free_map_allocate (1, &inode_sector)
                 && dir_create(inode_sector, 25)
                 && dir_add (dir, path.file_name, inode_sector));
  // printf("FILESYS_CREATE %d\n", success);
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  else {
    struct dir* current_dir = dir_open(inode_open(inode_sector));
    dir_add(current_dir, ".", inode_sector);
    dir_add(current_dir, "..", inode_get_inumber(dir_get_inode(dir)));
    dir_close(current_dir);
  }
  dir_close (dir);

  return success;
}


/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting   file system...");
  free_map_create ();
//   printf("\n\nfree_map_create 끝! dir_create 시작\n\n");
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");

  struct dir* root = dir_open_root();
  dir_add(root, ".", ROOT_DIR_SECTOR);
  dir_add(root, "..", ROOT_DIR_SECTOR);
  free_map_close ();
  printf ("done.\n");
}
