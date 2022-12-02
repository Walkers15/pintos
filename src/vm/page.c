#include "page.h"
#include <string.h>
#include "threads/palloc.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "vm/frame.h"

unsigned page_header_hash (const struct hash_elem* e, void* aux UNUSED) {
    // printf("PAGE HEADER HASH\n");
    struct page_header* header = hash_entry(e, struct page_header, elem);
    // printf("PAGE HEADER HASH DONE %p %d\n", header->address, hash_bytes(header->address, sizeof(header->address)));
    // return hash_bytes(header->address, sizeof(header->address));
    return hash_int((int)header->address);
}

bool page_header_less (const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED) {
    // printf("PAGE HEADER LESS\n");
    struct page_header* header_a = hash_entry(a, struct page_header, elem);
    struct page_header* header_b = hash_entry(b, struct page_header, elem);
    return header_b->address > header_a->address;
}

void init_page_headers(struct thread* t) {
    // printf("쓰레드 이름 %s\n", t->name);
    hash_init(&t->page_headers, page_header_hash, page_header_less, NULL);
    // printf("INIT HEADER!456!\n");
}

bool insert_header(struct thread* t, struct page_header* ph) {
    // printf("INSERT HEADER %p\n", ph->address);
    hash_insert(&t->page_headers, &ph->elem);
    // printf("INSERT HEADER 123 \n");
    return hash_find(&t->page_headers, &ph->elem) != NULL;
}

bool delete_header(struct thread* t, struct page_header* ph) {
    hash_delete(&t->page_headers, &ph->elem);
    return hash_find(&t->page_headers, &ph->elem) == NULL;
}

struct page_header* find_header(const void* address) {
    struct page_header p;
    
    p.address = pg_round_down(address);
    // printf("FIND HEADER %p\n", p.address);
    struct hash_elem* e = hash_find(&(thread_current()->page_headers), &p.elem);
    if (e == NULL) {
        // printf("NULL FIND\n");
        return NULL;
    }

    return hash_entry(e, struct page_header, elem);
}

void destory_page_header(struct thread *t) {
    hash_destroy(&t->page_headers, NULL);
}

bool load_file(struct page_header* header, uint8_t *kpage) {
    // file_seek(header->fp, header->offset);

    // printf("로드 파일 누구세요? %s %s\n", thread_current()->name, header->file_name);
    /* Load this page. */
    // struct file* file = filesys_open(header->file_name);
    // printf("FILE READ %p %d\n", file, header->offset);
    // int read_byte = file_read (header->fp, kpage, header->read_bytes);
    // header->fp->inode = header->inode;
    int read_byte = file_read_at (header->fp, kpage, header->read_bytes, header->offset);
    if (read_byte != (int) header->read_bytes) {
        // printf("file read 실패 ㅠㅠ %d %d\n", read_byte, header->read_bytes);
        free_page (kpage);
        return false; 
    }
    memset (kpage + header->read_bytes, 0, header->zero_bytes);

    // /* Add the page to the process's address space. */
    // if (!install_page (header->address, kpage, header->writeable)) {
    //     palloc_free_page (kpage);
    //     return false; 
    // }
    return true;
}