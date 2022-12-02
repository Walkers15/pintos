#include <stddef.h>
#include <stdio.h>

void swap_init(void);
void swap_in(size_t slot_index, uint8_t* kaddr);
size_t swap_out(uint8_t* kaddr);