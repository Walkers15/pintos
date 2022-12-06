#ifndef PAGE_H

#define PAGE_H
#include <stdio.h>
#include <stdint.h>
#include <hash.h>
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/inode.h"

typedef enum _page_type {
    FILE,
    SWAP
} page_type;

struct page_header {
    page_type type;
    bool loaded;
    bool writeable;

    void* address;

    off_t offset;
    uint32_t read_bytes;
    uint32_t zero_bytes;

    size_t swap;

    struct file* fp;

    struct hash_elem elem;
};

struct page {
    uint8_t* kaddr;
    struct page_header* header;
    struct thread* thread;
    struct list_elem elem;
    bool is_stack;
};

void init_page_headers(struct thread* t);

bool insert_header(struct thread* t, struct page_header* ph);
bool delete_header(struct thread* t, struct page_header* ph);
struct page_header* find_header(const void* address);
void destory_page_header(struct thread *t);

unsigned page_header_hash (const struct hash_elem* e, void* aux UNUSED);
bool page_header_less (const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED);

#endif