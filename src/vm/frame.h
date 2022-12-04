#include "vm/page.h"
#include "threads/palloc.h"

void page_list_init(void);
struct page* alloc_page(enum palloc_flags flags, struct page_header* header, bool is_stack);
void free_page(uint8_t* kaddr);

// struct list_elem* get_next_page(void);

void page_replacement(void); 