#include "vm/page.h"
#include "threads/palloc.h"

void page_list_init(void);
struct page* alloc_page(enum palloc_flags flags, struct page_header* header);
void free_page(void* kaddr);

struct list_elem* get_next_page(void);