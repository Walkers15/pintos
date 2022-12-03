#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "syscall.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "vm/frame.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
void make_stack (void** esp, char* file_name);
struct thread* find_child_thread(tid_t tid);
/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
	// printf("execute!!! %s\n", file_name);
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
	char* args = NULL;
	char* origin_file_name = (char*) malloc(sizeof(char) * strlen(file_name) + 1);
	// 그냥 file_name을 Parse 했더니, exec에서 child가 명령어를 parse할 때 page falut 에러가 발생함
	// 이를 피하기 위해 새로 이름을 복사하여 사용함
	strlcpy(origin_file_name, file_name, strlen(file_name) + 1);
	char* instruction_name = strtok_r((char*)origin_file_name, " ", &args); // Thread 이름은 명령어만 들어가야 함 (exit 출력시 사용)

	// printf("file open start!!! %s\n", instruction_name);
  /* Open executable file. */
  // struct file *file = filesys_open (instruction_name);
  // if (file == NULL) {
		// printf("file open null!!! %s\n", instruction_name);
		// return -1;
	// }
	// printf("file open done!!! %s\n", instruction_name);
  tid = thread_create (instruction_name, PRI_DEFAULT, start_process, fn_copy);
	free(origin_file_name);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
	else {
		struct thread* child_thread = find_child_thread(tid);
		struct semaphore* load = &child_thread->load;
		// printf("load sema down!!! %d %s\n", child_thread->tid, instruction_name);
		sema_down(load);
		// printf("load success!!!!!\n");
		if (child_thread->load_status == -1) {
			// printf("Child가 Start Process에 실패하여 제거합니다\n");
			return process_wait(child_thread->tid);
		}
	}

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
	thread_current()->load_status = 1;
	// printf("%d %s load done!!!\n",thread_current()->tid, file_name);
  /* If load failed, quit. */
  palloc_free_page (file_name);
	// printf("load sema up@ %d\n", thread_current()->tid);
  if (!success){
		// printf("%s: exit(%d)\n", thread_current()->name, -1);
		// thread_current()->exit_status = -1;
		thread_current()->load_status = -1;
		sema_up(&(thread_current()->load));
		// thread_exit();
    // printf("SASDASD\n");
		force_exit();
	} else {
		sema_up(&(thread_current()->load));
	}
  // printf("START USER PROGORAM!\n");
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

struct thread* find_child_thread(tid_t tid) {
	struct list_elem* child_ptr = list_begin(&(thread_current())->child_list);
	struct thread* child = NULL;
	for (; child_ptr != list_end(&(thread_current())->child_list); child_ptr = list_next(child_ptr)) {
		child = list_entry(child_ptr, struct thread, child_elem);
		if (child->tid == tid) {
			break;
		}
	}
	return child;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
	int exit_status = -1;
	struct thread* child = find_child_thread(child_tid);
	if (child == NULL) {
		return -1;
	}
	sema_down(&child->wait);
	exit_status = child->exit_status;
	list_remove(&(child->child_elem));
	sema_up(&child->post_process);

	return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  destory_page_header(cur);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      // pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

	char* origin_file_name = (char*)malloc(sizeof(char) * strlen(file_name) + 1);
	strlcpy(origin_file_name, file_name, strlen(file_name) + 1);
	char* args = NULL;
	char* instruction_name = strtok_r((char*)file_name, " ", &args);
	// printf("%s 랑%s\n", instruction_name, args);
  /* Open executable file. */
  file = filesys_open (instruction_name);

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
			free(origin_file_name);
      goto done; 
    }
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
			free(origin_file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file)){
				free(origin_file_name);
        goto done;
			}
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr){
				free(origin_file_name);
        goto done;
			}
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  // printf("SETUP STACK\n");
  /* Set up stack. */
  if (!setup_stack (esp)){
		free(origin_file_name);
    goto done;
	}
  // printf("SETUP STACK DONE\n");
  // 여기서 stack을 만든다!
  make_stack(esp, origin_file_name);
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
	free(origin_file_name);
  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  // file_close (file);

  // printf("LOAD SUCCESS? %d\n", success);
  return success;
}

/* load() helpers. */

void make_stack(void** esp, char* args) {
	// argc, argv 계산

	// argc 계산을 위해 tokenize 하는 동안 원본 문자열이 없어지면 안되니까 복사해서 세기
	char copy_args[strlen(args + 1)];
	// printf("매개변수 복사하기 %s %d\n", args, strlen(args));
	strlcpy(copy_args, args, strlen(args) + 1);
	// printf("메이크 스택!! 복사한 매개변수 %s\n", copy_args);

	// argc 계산
	// argv를 한번에 만들지 않는 이유는 argc를 알기 전까지는 argv를 몇짜리로 malloc해야 하는지 모르기 때문에!
	char* remain_args = NULL;
	char* arg_ptr = strtok_r(copy_args, " ", &remain_args);
	int argc = 0;
	while (arg_ptr != NULL) {
		argc++; // While 문 전에 strtok를 이미 한번 실행했으므로 argc를 바로 증가시켜줌
		arg_ptr = strtok_r(remain_args, " ", &remain_args);
		// printf("이번에 잘라온 놈 %s\n", arg_ptr);
	}

	// printf("argc는 %d\n", argc);

	// argv 만들기
	char** argv = NULL;
	int arg_len = argc; // 이따가 word align 하려고 미리 전체 길이 알아두기
	strlcpy(copy_args, args, strlen(args) + 1);
	argv = (char**) malloc(sizeof(char*) * argc);
	arg_ptr = strtok_r(copy_args, " ", &remain_args);
	for(int i = 0; i < argc; i++) {
		argv[i] = (char*) malloc((sizeof(char) * strlen(arg_ptr)) + 1);
		strlcpy(argv[i], arg_ptr, strlen(arg_ptr) + 1);
		arg_len += strlen(argv[i]);
		arg_ptr = strtok_r(remain_args, " ", &remain_args);
	}
	// for (int i = 0; i < argc; i++) {
	// 	printf("%d번째 매개변수는 %s 입니다\n", i, argv[i]);
	// }
	// printf("NULL을 고려한 매개변수의 총 길이는 %d 입니다\n", arg_len);

	// 만든 argc와 argv로 stack 만들기
	for (int i = argc - 1; i >= 0; i--) {
		*esp -= strlen(argv[i]) + 1;
		strlcpy(*esp, argv[i], strlen(argv[i]) + 1);
		argv[i] = *esp; // 이미 문자열은 옮겨놨으므로 괜찮음, stack에 각 argv에 주소값이 필요하므로 저장
	}

	// Word Alignment 맞추기
	if (arg_len % 4 != 0) {
		*esp -= 4 - (arg_len % 4);
	}

	// NULL Pointer sentinel 넣기
	*esp -= 4;
	**(char***)esp = 0; // void pointer이므로 Casting 필요

	// argv의 주소 넣기
	for (int i = argc - 1; i >= 0; i--) {
		*esp -= 4;
		**(char***) esp = argv[i];
	}

	// argv 주소 넣기
	*esp -= 4;
	**(char****) esp = *esp + 4;

	// argc 넣기
	*esp -= 4;
	**(int**) esp = argc;

	// return address 넣기
	*esp -= 4;
	**(uintptr_t **) esp = 0;

	// hex_dump((uintptr_t) esp, *esp, 100, 1);
}


static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);

  struct thread *t = thread_current();
    // printf("LOAD SEGMENT\n"); 
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      // /* Get a page of memory. */
      // uint8_t *kpage = palloc_get_page (PAL_USER);
      // if (kpage == NULL)
      //   return false;

      // /* Load this page. */
      // int read = file_read (file, kpage, page_read_bytes);
      // printf("LOAD SEGMENT FILE READ %p %p %d %d\n", file, kpage, page_read_bytes, read);
      // if (read != (int) page_read_bytes)
      //   {
      //     palloc_free_page (kpage);
      //     return false; 
      //   }
      // memset (kpage + page_read_bytes, 0, page_zero_bytes);

      // /* Add the page to the process's address space. */
      // if (!install_page (upage, kpage, writable)) 
      //   {
      //     palloc_free_page (kpage);
      //     return false; 
      //   }

      struct page_header* new = (struct page_header*) malloc(sizeof(struct page_header));
      new->type = FILE;
      new->loaded = false;
      new->writeable = writable;
      
      new->address = upage;

      // printf("LOAD SEGMENT FILE %p %p\n", file, file->inode);
      new->fp = file;
      // new->inode = file->inode;

      new->read_bytes = page_read_bytes;
      new->zero_bytes = page_zero_bytes;
      new->offset = ofs;

      // new->file_name = (char*)malloc(sizeof(char) * strlen(file_name) + 1);
      // strlcpy(new->file_name, file_name, strlen(file_name) + 1);

      // printf("인서트 해더 파일 누구세요? %s %s\n", t->name, new->file_name);
      insert_header(t, new);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  // printf("LOAD SEGMENT DONE\n"); 
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  bool success = false;

  struct page_header *new = (struct page_header*) malloc(sizeof(struct page_header));
  struct page* page = alloc_page(PAL_USER | PAL_ZERO, new);

  if (page->kaddr != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, page->kaddr, true);
      if (success)
        *esp = PHYS_BASE;
      else
        free_page(page->kaddr);
    }
  if (success) {
    new->type = SWAP;
    new->loaded = true;
    new->writeable = true;

    new->address = page->kaddr;

    // 이미 install 된 stack page이므로 아래 값들은 필요 없음
    new->offset = 0;
    new->read_bytes = 0;
    new->zero_bytes = 0;
    // printf("insert stack header %p\n", new->address);
    insert_header(thread_current(), new);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

bool handle_mm_fault(struct page_header* header) {
    /* Get a page of memory. */
    struct page* page = alloc_page(PAL_USER, header);
    // uint8_t *kpage = palloc_get_page (PAL_USER);
    if (page->kaddr == NULL)
      return false;

   if (header->type == FILE) {
      if(!load_file(header, page->kaddr)) {
        return false;
      }
      // printf("LOAD SUCCESS\n");
      if (!install_page(header->address, page->kaddr, header->writeable)) {
        free_page(page->kaddr);
        return false;
      }
      // printf("INSTALL SUCCESS\n");
      return true;
   } else if (header->type == SWAP) {
      swap_in(header->swap, page->kaddr);
      install_page(header->address, page->kaddr, header->writeable);
      return true;
   }
   return true;
}

bool grow_stack(void* addr) {
  bool success = false;

  struct page_header *new = malloc(sizeof(struct page_header));
	struct page *page = alloc_page(PAL_USER | PAL_ZERO, new);
  
  if (page->kaddr != NULL) {
    success = install_page (pg_round_down(addr), page->kaddr, true);
  }

  if (success) {
    // 이미 install 된 stack page이므로 아래 값들은 필요 없음
    new->type = SWAP;
    new->loaded = true;
    new->writeable = true;

    new->address = pg_round_down(addr);

    new->offset = 0;
    new->read_bytes = 0;
    new->zero_bytes = 0;
    // printf("insert stack header %p\n", new->address);
    insert_header(thread_current(), new);
  } else {
    free_page(page->kaddr);
		free(new);
  }
  return success;
}