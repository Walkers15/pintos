#include "filesys/filesys.h"
#include "devices/block.h"
#include "debug.h"
#include "threads/synch.h"

struct buffer_cache_entry {
    bool valid_bit;
    bool reference_bit;
    bool dirty_bit;
    block_sector_t disk_sector;
    uint8_t buffer[BLOCK_SECTOR_SIZE];
};

#define NUM_CACHE 64

void buffer_cache_init(void);
void buffer_cache_terminate(void);

struct buffer_cache_entry *buffer_cache_lookup(block_sector_t);
struct buffer_cache_entry *buffer_cache_select_victim(void);

void buffer_cache_read(block_sector_t sector_idx, void* buffer, off_t bytes_read, int chunk_size, int sector_ofs);
void buffer_cache_write(block_sector_t sector_idx, void* buffer);

void buffer_cache_flush_etnry(struct buffer_cache_entry*);
void buffer_cache_flush_all(void);