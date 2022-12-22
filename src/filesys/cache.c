#include "filesys/cache.h"
#include "filesys/filesys.h"
#include <string.h>
#include <stdio.h>

static struct buffer_cache_entry cache[NUM_CACHE];
static struct lock buffer_cache_lock;

static int second_chance_index;

void buffer_cache_init(void) {
    lock_init(&buffer_cache_lock);
    second_chance_index = 0;
}

void buffer_cache_terminate(void) {
    buffer_cache_flush_all();
}
void buffer_cache_read(block_sector_t sector_idx, void* buffer, off_t bytes_read, int chunk_size, int sector_ofs) {
    lock_acquire(&buffer_cache_lock);
    // printf("CACHE READ\n");
    struct buffer_cache_entry* buffer_cache = buffer_cache_lookup(sector_idx);
    // printf("1\n");
    memcpy (buffer + bytes_read, buffer_cache->buffer + sector_ofs, chunk_size);
    // printf("2\n");
    buffer_cache->reference_bit = 1;
    lock_release(&buffer_cache_lock);   
    // printf("DONE\n"); 
};

void buffer_cache_write(block_sector_t sector_idx, void* buffer) {
    lock_acquire(&buffer_cache_lock);
    // printf("CACHE WRITE\n");
    struct buffer_cache_entry* buffer_cache = buffer_cache_lookup(sector_idx);
    memcpy (buffer_cache->buffer, buffer, BLOCK_SECTOR_SIZE);
    buffer_cache->reference_bit = 1;
    buffer_cache->dirty_bit = 1;
    lock_release(&buffer_cache_lock);    
};

struct buffer_cache_entry *buffer_cache_lookup(block_sector_t sector_idx) {
    for (int i = 0; i < NUM_CACHE; i++) {
        if (cache[i].valid_bit == 1 && cache[i].disk_sector == sector_idx) {
            return &cache[i];
        }
    }
    // 캐시를 순회해도 못찾은 경우 swap out 필요
    struct buffer_cache_entry* new_cache = buffer_cache_select_victim();

    // swap in
    new_cache->disk_sector = sector_idx;
    block_read (fs_device, sector_idx, new_cache->buffer);
    new_cache->valid_bit = 1;
    return new_cache;
}

struct buffer_cache_entry *buffer_cache_select_victim(void) {
    while(true) {
        // printf("SELECT VICTIM %d %d\n", second_chance_index, cache[second_chance_index].reference_bit);
        if (cache[second_chance_index].reference_bit == 0) {
            if (cache[second_chance_index].dirty_bit == 1) {
                buffer_cache_flush_etnry(&cache[second_chance_index]);
            }
            // printf("RETURN!!\n");
            return &cache[second_chance_index];
        }
        cache[second_chance_index].reference_bit = 0;
        second_chance_index = (second_chance_index + 1) % NUM_CACHE;
    }
}

void buffer_cache_flush_etnry(struct buffer_cache_entry* victim) {
    block_write (fs_device, victim->disk_sector, victim->buffer);
    victim->dirty_bit = 0;
    victim->valid_bit = 0;
    return;
}

void buffer_cache_flush_all(void) {
    lock_acquire(&buffer_cache_lock);
    for (int i = 0; i < NUM_CACHE; i++) {
        if(cache[i].valid_bit == 1) {
            buffer_cache_flush_etnry(&cache[i]);
        }
    }
    lock_release(&buffer_cache_lock);
}