#include "filesys/inode.h"
#include <debug.h>
#include <round.h>
#include <string.h>
#include "stdio.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

#include "threads/thread.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_BLOCK_COUNT 123
#define INDIRECT_BLOCK_COUNT (BLOCK_SECTOR_SIZE / 4)

enum inode_type {
  DIRECT,
  INDIRECT,
  DOUBLE
};

struct sector_type {
  enum inode_type inode_type;
  int direct_index;
  int indirect_index;
  int double_indirect_index;
};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    // block_sector_t start;               /* First data sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    // uint32_t unused[125];               /* Not used. */
    bool is_dir;
    block_sector_t indirect_block_sector_idx;
    block_sector_t double_indirect_block_sector_idx;
    block_sector_t direct_blocks[DIRECT_BLOCK_COUNT];
  };



struct index_block {
  block_sector_t blocks[INDIRECT_BLOCK_COUNT];
};

bool allocate_new_block (struct inode_disk* disk_inode, off_t current_length);
void free_all_block(struct inode* inode);

static void calculate_sector_type(off_t pos, struct sector_type *sector_type) {
  off_t block_index = pos / BLOCK_SECTOR_SIZE;
  if (block_index < DIRECT_BLOCK_COUNT) {
    sector_type->inode_type = DIRECT;
    sector_type->direct_index = block_index;

  } else if (block_index < (DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT)) {
    block_index -= DIRECT_BLOCK_COUNT;
    sector_type->inode_type = INDIRECT;
    sector_type->indirect_index = block_index;

  } else if (block_index < (DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT * (INDIRECT_BLOCK_COUNT + 1))) {
    block_index -= (DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT);
    sector_type->inode_type = DOUBLE;
    sector_type->double_indirect_index = block_index / INDIRECT_BLOCK_COUNT;
    sector_type->indirect_index = block_index % INDIRECT_BLOCK_COUNT;
    
  }
  // printf("calculate_sector_type pos %d block index is %d\n", pos, block_index);
}

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}


/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);

  struct inode_disk* disk_inode = malloc(BLOCK_SECTOR_SIZE);
  buffer_cache_read(inode->sector, disk_inode, 0, BLOCK_SECTOR_SIZE, 0);

  block_sector_t target = -1;
  if (disk_inode->length < pos) {
    return target;
  }

  struct sector_type current_sector_type;
  calculate_sector_type(pos, &current_sector_type);
// printf("pos %d sector type %d direct index %d\n", pos, current_sector_type.inode_type, current_sector_type.direct_index);
  switch (current_sector_type.inode_type) {
    case DIRECT: {
      
      target = disk_inode->direct_blocks[current_sector_type.direct_index];
      break;
    }
    case INDIRECT: {
      struct index_block* indirect_block = malloc(BLOCK_SECTOR_SIZE);
      buffer_cache_read(disk_inode->indirect_block_sector_idx, indirect_block, 0, BLOCK_SECTOR_SIZE, 0);
      target = indirect_block->blocks[current_sector_type.indirect_index];
      free(indirect_block);
      break;
    }
    case DOUBLE: {
      struct index_block* double_indirect_block = malloc(BLOCK_SECTOR_SIZE);
      struct index_block* indirect_block = malloc(BLOCK_SECTOR_SIZE);

      buffer_cache_read(disk_inode->double_indirect_block_sector_idx, double_indirect_block, 0, BLOCK_SECTOR_SIZE, 0);
      buffer_cache_read(double_indirect_block->blocks[current_sector_type.double_indirect_index], indirect_block, 0, BLOCK_SECTOR_SIZE, 0);
      
      target = indirect_block->blocks[current_sector_type.indirect_index];
      free(double_indirect_block);
      free(indirect_block);
      break;
    }
  }
// printf("byte to sector target index %d %d\n", current_sector_type.direct_index, target);
  free(disk_inode);
  return target;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  // printf("##INODE CREATE %s %d %d\n", thread_current()->name, sector, length);
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  // inode_disk 생성
  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
  // printf("SECTOR %d LENGTH %d\n", sectors, length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->double_indirect_block_sector_idx = 0;
      disk_inode->indirect_block_sector_idx = 0;
      disk_inode->is_dir = is_dir;
      buffer_cache_write (sector, disk_inode);
      // contiguous하지 않아도 되므로 한 block씩 할당하면서 전부 찰때까지 반복
	  off_t current_length = 0;
      for (size_t i = 0; i < sectors; i++) {
  // printf("CREATE: TRY ALLOCATE NEW BLOCK... i is %d\n", i);
        if (!allocate_new_block(disk_inode, current_length)) {
  // printf("CREATE: ALLOCATED NEW BLOCK 실패!\n");
          goto done;
        }
  // printf("성공! \n");
        current_length += BLOCK_SECTOR_SIZE;
      }
  // printf("전체 성공! %d \n", disk_inode->direct_blocks[0]);
      // 업데이트한 정보 inode_disk로 기록
      buffer_cache_write (sector, disk_inode);
      success = true; 
      free (disk_inode);
    }

  done:
  // printf("INODE CREATE RETURN SUCCESS..... %d\n", success);
  return success;
}

bool allocate_new_block (struct inode_disk* disk_inode, off_t current_length) {
  static char zeros[BLOCK_SECTOR_SIZE];
  bool success = false;
// printf("allocate new block %p %d\n", disk_inode, current_length);
  block_sector_t new_sector_idx;
  if(!free_map_allocate(1, &new_sector_idx)) {
  // printf("INODE CREATasdE: FREE MAP ALLOCATE ERROR!! %p %d\n", disk_inode, current_length);
    goto done;
  }

  // printf("allocate new block 1\n");
  buffer_cache_write(new_sector_idx, zeros);
  struct sector_type current_sector_type;
  calculate_sector_type(current_length, &current_sector_type);
  current_length += BLOCK_SECTOR_SIZE;
// printf("allocate new block 2 %d %d\n", current_sector_type.inode_type, current_sector_type.direct_index);
  switch(current_sector_type.inode_type) {
    case DIRECT: {
      // direct_blocks 배열에 바로 할당 (0 ~ 122)
// printf("\nDIRECT INDEXING.. %d %d 는 %d\n\n", current_sector_type.direct_index, disk_inode->direct_blocks[current_sector_type.direct_index] , new_sector_idx);
      disk_inode->direct_blocks[current_sector_type.direct_index] = new_sector_idx;
      break;
    }
    
    case INDIRECT: {
      // INDIRECT 인 경우 INDEX BLOCK 읽어오기 (없으면 할당)
  // printf("INDIRECT BLOCk 할당 1 %d\n", disk_inode->indirect_block_sector_idx);
      if (disk_inode->indirect_block_sector_idx == 0) {
        block_sector_t index_sector;
        if (!free_map_allocate(1, &index_sector)) { 
  // printf("INODE CREATE: FREE MAP ALLOCATE ERROR!!\n");
          goto done;
        }
  // printf("INDEX SECTOR %d\n", index_sector);
        disk_inode->indirect_block_sector_idx = index_sector;
        buffer_cache_write(index_sector, zeros);
      }
  // printf("INDIRECT BLOCk 할당 2\n");
      struct index_block* indirect_block = malloc(BLOCK_SECTOR_SIZE);
      buffer_cache_read(disk_inode->indirect_block_sector_idx, indirect_block, 0, BLOCK_SECTOR_SIZE, 0);


      // 해당 INDEX 블록에 새로 할당한 sector indexing
  // printf("INDIRECT BLOCk 할당3 \n");
      indirect_block->blocks[current_sector_type.indirect_index] = new_sector_idx;
      buffer_cache_write(disk_inode->indirect_block_sector_idx, indirect_block);
      break;
    }

    case DOUBLE: {
      // DOUBLE INDEX BLOCK 읽어오기 (없으면 할당)
      if (disk_inode->double_indirect_block_sector_idx == 0) {
        block_sector_t index_sector = 0;
        if (!free_map_allocate(1, &index_sector)) { 
  // printf("INODE CREATE: FREE MAP ALLOCATE ERROR!!\n");
          goto done;
        }

        disk_inode->double_indirect_block_sector_idx = index_sector;
        buffer_cache_write(&index_sector, zeros);
      }
      struct index_block* double_indirect_block = malloc(BLOCK_SECTOR_SIZE);
      buffer_cache_read(disk_inode->double_indirect_block_sector_idx, double_indirect_block, 0, BLOCK_SECTOR_SIZE, 0);

      // DOBULE INDEX BLOCK에서 current sector의 indirect block 읽어오기 (없으면 할당)
      if (double_indirect_block->blocks[current_sector_type.double_indirect_index] == 0) {
        block_sector_t index_sector = 0;
        if (!free_map_allocate(1, &index_sector)) { 
  // printf("INODE CREATE: FREE MAP ALLOCATE ERROR!!\n");
          goto done;
        }

        double_indirect_block->blocks[current_sector_type.double_indirect_index] = index_sector;
        buffer_cache_write(&index_sector, zeros);
      }
      struct index_block* indirect_block = malloc(BLOCK_SECTOR_SIZE);
      buffer_cache_read(double_indirect_block->blocks[current_sector_type.double_indirect_index], indirect_block, 0, BLOCK_SECTOR_SIZE, 0);
      
      // current sector의 indirect block에 index에 새로 할당한 블록 적어두기
      indirect_block->blocks[current_sector_type.indirect_index] = new_sector_idx;
      buffer_cache_write(double_indirect_block->blocks[current_sector_type.double_indirect_index], indirect_block);
      break;
    }
  }
  success = true;

  done:
// printf("allocate new block 3 결과는? %d\n", success);
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  // printf("INODE OPEN %d\n", sector);
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&(inode->inode_lock));
  // block_read (fs_device, inode->sector, &inode->data);
  // printf("open inode %d  file size %d done\n", sector, inode_length(inode));
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_all_block(inode);
          free_map_release (inode->sector, 1);
        }
      free (inode); 
    }
}

void free_all_block(struct inode* inode) {
  struct inode_disk* disk_inode = malloc(BLOCK_SECTOR_SIZE);
  buffer_cache_read(inode->sector, disk_inode, 0, BLOCK_SECTOR_SIZE, 0);

  struct sector_type inode_sector_type;
  calculate_sector_type(disk_inode->length, &inode_sector_type);


  switch (inode_sector_type.inode_type) {
    case DOUBLE: {
      struct index_block* double_indirect = malloc(BLOCK_SECTOR_SIZE);
      buffer_cache_read(disk_inode->double_indirect_block_sector_idx, double_indirect, 0, BLOCK_SECTOR_SIZE, 0);
      for (int i = 0; i < INDIRECT_BLOCK_COUNT; i++) {
        if (double_indirect->blocks[i] == 0) {
          continue;
        }
        struct index_block* indirect = malloc(BLOCK_SECTOR_SIZE);
        buffer_cache_read(double_indirect->blocks[i], indirect, 0, BLOCK_SECTOR_SIZE, 0);
        for (int j = 0; j < INDIRECT_BLOCK_COUNT; j++) {
          if(indirect->blocks[j] == 0) {
            continue;
          }
          free_map_release(indirect->blocks[j], 1);
        }
        free_map_release(double_indirect->blocks[i], 1);
        free(indirect);
      }
      free_map_release(disk_inode->double_indirect_block_sector_idx, 1);
      free(double_indirect);
    }
    case INDIRECT: {
      struct index_block* indirect = malloc(BLOCK_SECTOR_SIZE);
      buffer_cache_read(disk_inode->indirect_block_sector_idx, indirect, 0, BLOCK_SECTOR_SIZE, 0);
      for (int i = 0; i < INDIRECT_BLOCK_COUNT; i++) {
        if (indirect->blocks[i] == 0) {
          continue;
        }
        free_map_release(indirect->blocks[i], 1);
      }
      free_map_release(disk_inode->indirect_block_sector_idx, 1);
      free(indirect);
    }
    case DIRECT: {
      for (int i = 0; i < DIRECT_BLOCK_COUNT; i++) {
        if (disk_inode->direct_blocks[i] == 0) {
          continue;
        }
        free_map_release(disk_inode->direct_blocks[i], 1);
      }
    }
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  // lock_acquire(&inode->inode_lock);
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  // printf("inode read at %p %d %d %d\n", inode, inode->sector, size, offset);
  while (size > 0) 
    {
  // printf("current size is %d\n", size);
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      // printf("get inode length..\n");
      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;
      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
  // printf("size %d min_left %d sector_left %d inode_left %d\n", size, min_left, inode_left, sector_left);
      // printf("chunk size is %d\n");
      if (chunk_size <= 0)
        break;
  // printf("inode read real sector idx %d\n", sector_idx);
      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          // block_read (fs_device, sector_idx, buffer + bytes_read);
          buffer_cache_read(sector_idx, buffer, bytes_read, chunk_size, sector_ofs);
        }
      else 
        {
          buffer_cache_read(sector_idx, buffer, bytes_read, chunk_size, sector_ofs);
        }
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  // free (bounce);
//   if (inode->sector == 4) {
// 	struct inode_disk* disk_inode = malloc(BLOCK_SECTOR_SIZE);
// 	buffer_cache_read(4, disk_inode, 0, BLOCK_SECTOR_SIZE, 0);
// 	for (int i = 0; i < DIRECT_BLOCK_COUNT; i++) {	
// 		if(disk_inode->direct_blocks[i] == 0) break;
// 	}
//   }
// if (inode->sector == 1 && offset > BLOCK_SECTOR_SIZE) {
//     char hex_buffer[512];
//     buffer_cache_read(3, hex_buffer, 0, 512, 0);
//     hex_dump(0, hex_buffer, 512, true);
//     buffer_cache_read(345, hex_buffer, 0, 512, 0);
//     hex_dump(0, hex_buffer, 512, true);
//   }
  // lock_release(&inode->inode_lock);
  // printf("inode read 결과 %d\n\n", bytes_read);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;
// printf("CALL INODE WRITE AT %p %d %p %d %d\n", inode, inode->sector, buffer, size, offset);
  // hex_dump(0, buffer, 100, true);
  struct inode_disk* disk_inode = malloc(BLOCK_SECTOR_SIZE);
  buffer_cache_read(inode->sector, disk_inode, 0, BLOCK_SECTOR_SIZE, 0);

  // printf("@@write 시작 전 inode disk length %d\n", disk_inode->length);

  off_t total_length = offset + size;
// printf("둘이 달라요?? %d %d %d\n", inode->sector, total_length, disk_inode->length);
  if (total_length > disk_inode->length) {
    off_t current_length = disk_inode->length;
    if (disk_inode->length == 0 || disk_inode->length / BLOCK_SECTOR_SIZE != total_length / BLOCK_SECTOR_SIZE) {
      lock_acquire(&inode->inode_lock);
// printf("LOCK ACQUIRED AT %s\n", thread_current()->name);
      while (current_length <= total_length) {
// printf("EXTENDS BLOCK %d %d\n", current_length, total_length);
        allocate_new_block(disk_inode, current_length + BLOCK_SECTOR_SIZE -1);
        current_length += BLOCK_SECTOR_SIZE;
      }
// printf("lock release %s\n", thread_current()->name);
      lock_release(&inode->inode_lock);
    }
// printf("total len update %d\n", total_length);
    disk_inode->length = total_length;
  }
  buffer_cache_write(inode->sector, disk_inode);
  free(disk_inode);

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
// printf("write 시 도 %d %d %d\n", sector_idx, chunk_size, sector_ofs);
      ASSERT(sector_idx != 0);
      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          // block_write (fs_device, sector_idx, buffer + bytes_written);
          buffer_cache_write (sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            // block_read (fs_device, sector_idx, bounce);
            buffer_cache_read(sector_idx, bounce, 0, BLOCK_SECTOR_SIZE, 0);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          // block_write (fs_device, sector_idx, bounce);
          buffer_cache_write(sector_idx, bounce);
        }

      /* Advance. */
      // printf("Inode Write 한 사이클 끝남! chunk size %d\n", chunk_size);
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  // printf("INODE WRITE AT 결과... %p %d\n", inode, bytes_written);
  // printf("INODE WRITE 후 inode length %d\n", inode_length(inode));
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  char buffer[BLOCK_SECTOR_SIZE];
  // printf("get inode length of sector %d\n", inode->sector);
  struct inode_disk disk_inode; // = malloc(BLOCK_SECTOR_SIZE);
  // printf("length 0\n");
  buffer_cache_read(inode->sector, buffer, 0, BLOCK_SECTOR_SIZE, 0);
  // printf("length 1\n");
  off_t length = ((struct inode_disk*)(buffer))->length;
  // printf("length 2\n");
  // free(disk_inode);
  // printf("INODE LENGTH return value %p %d\n", inode, length);
  return length;
}

bool inode_is_dir(const struct inode* inode) {
  char buffer[BLOCK_SECTOR_SIZE];
  struct inode_disk disk_inode;
  buffer_cache_read(inode->sector, buffer, 0, BLOCK_SECTOR_SIZE, 0);
  bool is_dir = ((struct inode_disk*)(buffer))->is_dir;
  return is_dir;
}