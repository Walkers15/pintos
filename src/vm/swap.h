#include <stddef.h>

void swap_init(void);
void swap_in(size_t slot_index, void* kaddr);
size_t swap_out(void* kaddr);