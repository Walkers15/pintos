#include "list.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "vm/frame.h"

struct list page_list;
struct semaphore page_list_sema;
struct list_elem* page_ptr;

void page_list_init(void) {
	// printf("page list init!\n");
	list_init(&page_list);
	page_ptr = NULL;
	sema_init(&page_list_sema, 1);
}

struct page* alloc_page(enum palloc_flags flags, struct page_header* header, bool is_stack) {
	// printf("GET SEMA\n");
	/* Get a page of memory. */
	sema_down(&page_list_sema);
	// printf("GET SEMA\n");
	uint8_t *kpage = palloc_get_page (flags);
	if (kpage == NULL) {
		// printf("NO LEFT PAGE:: DO EVICT\n");
		page_replacement();
		kpage = palloc_get_page (flags);
	}

	struct page* page = (struct page*) malloc(sizeof(struct page));
	// printf("palloc get page %p\n", kpage);
	page->kaddr = kpage;
	page->header = header;
	page->thread = thread_current();
	page->is_stack = is_stack;


	list_push_front(&page_list, &page->elem);
	sema_up(&page_list_sema);
	return page;
}

void free_page(uint8_t* kaddr) {
	// sema_down(&page_list_sema);
	struct list_elem* page_ptr = list_begin(&page_list);
	struct page* page = NULL;
	for (; page_ptr != list_end(&page_list); page_ptr = list_next(page_ptr)) {
		page = list_entry(page_ptr, struct page, elem);
		if (page->kaddr == kaddr) {

			list_remove(&page->elem);
			// printf("free page\n");
			palloc_free_page(page->kaddr);
			free(page);
			break;
		}
	}
	// sema_up(&page_list_sema);
}

static struct list_elem* get_next_page(void) {
	if (page_ptr == NULL || list_next(page_ptr) == list_end(&page_list)) {
		page_ptr = list_begin(&page_list);
	} else {
		page_ptr = list_next(page_ptr);
	}
	return page_ptr;
}

void page_replacement(void) {
	while(true) {
		struct list_elem* page_ptr = get_next_page();
		struct page* page = list_entry(page_ptr, struct page, elem);
		// printf("page replacement %p %s %d\n", page->header->address, thread_current()->name, page->thread->status);
		if (thread_current() != page->thread) { continue; }
		if (page->is_stack) { continue; }
		bool accessed = pagedir_is_accessed(page->thread->pagedir, page->header->address);
		if (accessed) {
			pagedir_set_accessed(page->thread->pagedir, page->header->address, false);
			continue;
		} else {
			// printf("Victim Selected... %p\n", page->header->address);
			if (pagedir_is_dirty(page->thread->pagedir, page->header->address) && page->header->fp != NULL) {
				printf("page is dirty\n");
				file_write_at(page->header->fp, page->kaddr, page->header->read_bytes, page->header->offset);
			}
			page->header->type = SWAP;
			// printf("SWAP OUT\n");
			page->header->swap = swap_out(page->kaddr);
			// printf("DONE\n");
			break;
		}
	}
}