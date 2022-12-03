#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <debug.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include <string.h>
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);

void check_valid_pointer(const void* ptr);
void check_valid_buffer(void* buffer, unsigned size);

struct file* get_fp_from_fd(int fd);
struct lock* get_lock(struct file* fp);

int current_max_lock = 0;

	void
syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

	static void
syscall_handler (struct intr_frame *f) 
{
	// printf ("system call! %d\n", *(int*)f->esp);
	// printf("esp %d\n",  *(int *)f->esp);

	int syscall_number = *(int *)f->esp; // syscallN 에서 esp에 System call number를 넣어준다

	switch (syscall_number) {
		case SYS_HALT: {
			shutdown_power_off();
			break;
		}
		case SYS_EXIT: {
			// exit (int status)
			check_valid_pointer(f->esp + 4);

			int status = *(int*) (f->esp + 4);

			// 열려있는 file pointer close
			struct file** ofile = thread_current()->ofile;
			printf("%s: exit(%d)\n", thread_current()->name, status); 
			for (int fd = 2; fd < 200; fd ++) {
				if (ofile[fd] != NULL) {
					file_close(ofile[fd]);
					ofile[fd] = NULL;
				}
			}
			free(ofile);
			thread_current()->exit_status = status;
			printf("SYS EXIT DONE\n");
			thread_exit();
			break;
		}
		case SYS_EXEC: {
			// pit_t exec (const char* file)

			check_valid_pointer(f->esp + 4);

			const char* instruction = *(const char**) (f->esp + 4);
			check_valid_pointer(instruction);
			// printf("EXEC!!! %s\n", instruction);
			f->eax = process_execute(instruction); // Return Value 전달
			break;
		}
		case SYS_WAIT: {
			// int wait(pid_t pid)
			check_valid_pointer(f-> esp + 4);

			tid_t pid = *(tid_t*) (f->esp + 4);
			int status_code = process_wait(pid);
			// printf("Wait DONE! status code: %d\n", status_code);
			f->eax = status_code;
			break;
		}
		case SYS_CREATE: {
				// bool create (const char *file, unsigned initial_size)
				check_valid_pointer(f->esp + 4);
				check_valid_pointer(f->esp + 8);
				const char* file = *(char**)(f->esp + 4);
				check_valid_pointer(file);
				unsigned initial_size = *(unsigned*)(f->esp + 8);
				if (file == NULL) {
					printf("asdf\n");
					force_exit();
				}
				// printf("%s %d\n", file, initial_size);
				f->eax = filesys_create(file, initial_size);
				break;
			}
		case SYS_REMOVE: {
				// bool remove (const char* file)
				// printf("Remove!!\n");
				check_valid_pointer(f->esp + 4);
				const char* file = *(char**)(f->esp + 4);
				if (file == NULL) {
					printf("asd\n");
					force_exit();
				}
				check_valid_pointer(file);
				int result = filesys_remove(file);
				// f->eax = filesys_remove(f->esp + 4);
				f->eax = result;
				// printf("Remove Done!! %s %d\n", file, result);
				break;
			}
		case SYS_OPEN: {
			// int open (const char* file)
			check_valid_pointer(f->esp + 4);
			const char* file = *(char**)(f->esp + 4);
			if (file == NULL) {
				f->eax = -1;
				break;
			}
			check_valid_pointer(file);
			struct file* fp = filesys_open(*(char**)(f->esp + 4));
			if (fp == NULL) {
				f->eax = -1;
				break;
			}

			struct file** ofile = thread_current()->ofile;
			int fd_index = 2;
			int fd = -1;

			while (fd == -1) {
				if (ofile[fd_index] == NULL) {
					fd = fd_index;
				}
				fd_index++;
			}

			if (fd == -1) {
				f->eax = fd;
				break;
			}

			ofile[fd] = fp;

			// Open한 File이 현재 실행중인 process file이라면 deny
			if(strcmp(thread_current()->name, file) == 0) {
				file_deny_write(fp);
			}
			f->eax = fd;
			break;
		}
		case SYS_FILESIZE: {
					// int filesize(int fd)
					check_valid_pointer(f-> esp + 4);
					int fd = *(int*) (f->esp + 4);
					struct file* fp = get_fp_from_fd(fd);
					f->eax = file_length(fp);
					break;
				}
		case SYS_READ: {
			// read(int fd, void * buffer, unsigned size)
			// hex_dump((uintptr_t) f->esp, f->esp, 100, 1);
			check_valid_pointer(f-> esp + 4);
			check_valid_pointer(f-> esp + 8);
			check_valid_pointer(f-> esp + 12);
			printf("READ!!\n");
			int fd = *(int*) (f-> esp + 4);
			if (fd == 0) {
				input_getc();
			} else if (fd > 1) {
				struct file* fp = get_fp_from_fd(fd);
				void* buffer = (void*) *(uintptr_t*)(f->esp + 8);
				check_valid_pointer(buffer);
				unsigned size = *(unsigned*)(f->esp + 12);
				// check_valid_buffer(buffer, size);
				struct lock* current_lock = get_lock(fp);
				lock_acquire(current_lock);
				// printf("READ FILE %d\n", size);
				f->eax = file_read(fp, buffer, size);
				lock_release(current_lock);
				// printf("read done!\n");
			}
			break;
		}
		case SYS_WRITE: {
			// write (int fd, const void *buffer, unsigned size)
			// syscall3(SYS_WRITE, fd, buffer, size)
			check_valid_pointer(f->esp + 4);
			check_valid_pointer(f->esp + 8);
			check_valid_pointer(f->esp + 12);

			int fd = *(int*) (f->esp + 4);
			// printf("fd is %d\n", fd);
			void* buffer = (void*) *(uintptr_t*)(f->esp + 8);
			unsigned size = *(unsigned *)(f->esp + 12);
			if (fd == 1) {
				putbuf(buffer, size);
			} else if (fd > 1) {
				struct file* fp = get_fp_from_fd(fd);
				struct lock* current_lock = get_lock(fp);

				if(fp->deny_write == true) {
					file_deny_write(fp);
					lock_acquire(current_lock);

					f->eax = file_write(fp, buffer, size);

					lock_release(current_lock);
					break;
				}

				lock_acquire(current_lock);
				f->eax = file_write(fp, buffer, size);
				lock_release(current_lock);
			}
			break;
		}
		case SYS_SEEK: {
			check_valid_pointer(f->esp + 4);
			check_valid_pointer(f->esp + 8);
			int fd = *(int*) (f->esp + 4);
			unsigned position = *(unsigned *)(f->esp + 8);

			struct file* fp = get_fp_from_fd(fd);

			file_seek(fp, position);
			break;
		}
		case SYS_TELL: {
			check_valid_pointer(f->esp + 4);
			int fd = *(int*) (f->esp + 4);
			struct file* fp = get_fp_from_fd(fd);
			f->eax = file_tell(fp);
			break;
		}
		case SYS_CLOSE: {
			check_valid_pointer(f->esp + 4);
			int fd = *(int*) (f->esp + 4);
			struct file* fp = get_fp_from_fd(fd);

			file_close(fp);

			thread_current()->ofile[fd] = NULL;
			break;
										}
		case SYS_FIBO: {
			// printf("FIBO CALL\n");
			check_valid_pointer(f->esp + 4);
			int n = *(int*) (f->esp + 4);
			f->eax = fibonacci(n);
			// printf("%d %d\n", n, fibonacci(n));
			break;
		}
		case SYS_MAX_OF_FOUR_INT: {
			// printf("MAX OF FOUR INT CALL이다!\n");
			check_valid_pointer(f->esp + 4);
			check_valid_pointer(f->esp + 8);
			check_valid_pointer(f->esp + 12);
			check_valid_pointer(f->esp + 16);
			int a = *(int*) (f->esp + 4);
			int b = *(int*) (f->esp + 8);
			int c = *(int*) (f->esp + 12);
			int d = *(int*) (f->esp + 16);
			f->eax = max_of_four_int(a, b, c, d);
			// printf("MAX OF FOUR INT CALL %d\n", f->eax);
			break;
		}
	}
	// printf("EXIT!!!\n");
	// thread_exit ();
}

void check_valid_pointer(const void* ptr) {
	if(is_user_vaddr(ptr) == false) {
		printf("asd\n");
		force_exit();
	}
}

void check_valid_buffer (void* buffer, unsigned size) {
	printf("check_valid_buffer %p\n", buffer);
	while (size > 0) {
		check_valid_pointer(buffer);
		// struct page_header* header = find_header(buffer);
		// if(header->writeable == false) {
		// 	force_exit();
		// }
		size -= PGSIZE;
		buffer += PGSIZE;
	}
}

void force_exit() {
	printf("Force Exit!\n");
	// System Call Handler 를 강제로 종료시킨다.
	// abnormal way로 종료되었으므로 exit code는 -1이다.
	printf("%s: exit(%d)\n", thread_current()->name, -1);
	// 열려있는 file pointer close
	struct file** ofile = thread_current()->ofile;
	for (int fd = 2; fd < 200; fd ++) {
		if (ofile[fd] != NULL) {
			file_close(ofile[fd]);
			ofile[fd] = NULL;
		}
	}
	free(ofile);
	thread_current()->exit_status = -1;
	thread_exit();
}

struct file* get_fp_from_fd(int fd) {
	struct file** ofile = thread_current()->ofile;
	// printf("get fp from fd %d %d\n", fd, sizeof(ofile));
	struct file* f = ofile[fd];
	if (f == NULL) {
		printf("f null\n");
		force_exit();
	}
	return f;
}

struct lock* get_lock(struct file* fp) {
	// printf("get lock %p\n",fp);

	for (int i = 0; i < current_max_lock; i++) {

		if (inode_get_inumber(fp->inode) == filesys_lock[i].sector) {
			// 이미 해당 file name의 lock이 있으면 해당 lock을 가져옴
			// printf("find lock!\n");
			return &filesys_lock[i].lock;
		}
	}
	//printf("create new lock!\n");
	// 현재 사용중인 모든 lock에 file_name에 대한 lock이 없다면 새로운 lock을 할당
	int new_lock_index = current_max_lock;
	current_max_lock++;
	// strlcpy(filesys_lock[new_lock_index].file_name, file_name, sizeof(file_name) + 1);
	filesys_lock[new_lock_index].sector = inode_get_inumber(fp->inode);
	lock_init(&filesys_lock[new_lock_index].lock);

	return &filesys_lock[new_lock_index].lock;
}

int fibonacci(int n) {
	int num1 = 0;
	int num2 = 1;
	int result = 1;
	for (int i = 2; i < n; i++) {
		num1 = num2;
		num2 = result;
		result = num1 + num2;
	}
	return result;
}

int max_of_four_int(int a, int b, int c, int d) {
	int max_num = a;

	if (max_num < b) {
		max_num = b;
	}

	if (max_num < c) {
		max_num = c;
	}

	if (max_num < d) {
		max_num = d;
	}

	return max_num;
}
