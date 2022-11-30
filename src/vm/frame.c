#include "list.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"

struct list page_list;
struct semaphore page_list_sema;
struct list_elem* page_ptr;

void page_list_init(void) {
	list_init(&page_list);
	page_ptr = NULL;
}

struct page* alloc_page(enum palloc_flags flags, struct page_header* header) {
	/* Get a page of memory. */
	uint8_t *kpage = palloc_get_page (flags);
	if (kpage == NULL) {
		printf("NO LEFT PAGE:: DO EVICT\n");
		page_replacement(flags);
		kpage = palloc_get_page (flags);
		return false;
	}

	struct page* page = (struct page*) malloc(sizeof(struct page));
	page->kaddr = kpage;
	page->header = header;
	page->thread = thread_current();

	list_insert(&page_list, &page->elem);
	return page;
}

void free_page(uint8_t* kaddr) {
	struct list_elem* page_ptr = list_begin(&page_list);
	struct page* page = NULL;
	for (; page != list_end(&page_list); page_ptr = list_next(page_ptr)) {
		page = list_entry(page_ptr, struct page, elem);
		if (page->kaddr == kaddr) {
			list_remove(&page->elem);
			palloc_free_page(page->kaddr);
			free(page);
			break;
		}
	}
}

static struct list_elem* get_next_page(void) {
	if (page_ptr == NULL || page_ptr == list_end(&page_list)) {
		page_ptr = list_begin(&page_list);
	} else {
		page_ptr = list_next(page_ptr);
	}
	return page_ptr;
}

void page_replacement(enum palloc_flags flags) {
	while(true) {
		printf("PAGE REPLACEMENT PROCESS...\n");
		struct list_elem* page_ptr = get_next_page();
		struct page* page = list_entry(page_ptr, struct page, elem);

	}
}