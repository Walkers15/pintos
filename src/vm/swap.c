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
	swap_device = block_get_role (BLOCK_SWAP);
	if (swap_device == NULL) {
			swap_bitmap = bitmap_create (0);
	} else {
		swap_bitmap = bitmap_create (block_size (swap_device) / PAGE_SECTORS);
	}
	if (swap_bitmap == NULL) {
		PANIC ("couldn't create swap bitmap");
	}
	// printf("swap init!!2\n");
	lock_init (&swap_lock);
	page_list_init();
}

void swap_in(size_t slot_index, uint8_t* kaddr) {
	if(bitmap_test(swap_bitmap, slot_index) == true) {
		for (int i = 0; i < PAGE_SECTORS; i++) {
			block_read (swap_device, PAGE_SECTORS * slot_index + i, kaddr + i * BLOCK_SECTOR_SIZE);
		}
	}
	bitmap_reset (swap_bitmap, slot_index);
}

size_t swap_out(uint8_t* kaddr) {
	lock_acquire (&swap_lock);
	size_t slot_index = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
	lock_release (&swap_lock);
	for (int i = 0; i < PAGE_SECTORS; i++) {
		block_write (swap_device, PAGE_SECTORS * slot_index + i, kaddr + i * BLOCK_SECTOR_SIZE);
	}
	free_page(kaddr);
	return slot_index;
}