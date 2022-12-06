#include "vm/swap.h"
#include <bitmap.h>
#include <debug.h>
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

static struct block *swap_device;

static struct bitmap *swap_bitmap;

static struct lock swap_lock;

#define PAGE_SECTORS (PGSIZE / BLOCK_SECTOR_SIZE)

void swap_init() {
	// printf("swap init!!\n");
	swap_device = block_get_role(BLOCK_SWAP);
	swap_bitmap = bitmap_create(block_size(swap_device) / PAGE_SECTORS);
	// printf("swap init!!2\n");
	lock_init(&swap_lock);
	page_list_init();
}

void swap_in(size_t slot_index, uint8_t* kaddr) {
	// printf("Swap in\n");
	if(bitmap_test(swap_bitmap, slot_index) == true) {
		for (int i = 0; i < PAGE_SECTORS; i++) {
			block_read(swap_device, PAGE_SECTORS * slot_index + i, kaddr + i * BLOCK_SECTOR_SIZE);
		}
	}
	bitmap_reset(swap_bitmap, slot_index);
	// printf("Swap in done!\n");
}

size_t swap_out(uint8_t* kaddr) {
	lock_acquire(&swap_lock);
	// printf("bitmap scan %u\n", bitmap_scan(swap_bitmap, 0, 1, false));
	size_t slot_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
	for (int i = 0; i < PAGE_SECTORS; i++) {
		block_write(swap_device, PAGE_SECTORS * (slot_index + i), kaddr + i * BLOCK_SECTOR_SIZE);
	}
	free_page(kaddr);
	lock_release(&swap_lock);
	// printf("swap out done! %d\n", slot_index);
	return slot_index;
}