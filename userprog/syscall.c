#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/palloc.h"


void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file_name);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
int fork(const char *thread_name, struct intr_frame *f);
int exec(const char *cmd_line);
int wait(int pid);


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {	
	int syscall_number = f->R.rax;

	switch (syscall_number) {
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
			break;
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:						
			exit(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;		
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;		
	}

}

void check_address(void* addr) {
	if (addr == NULL) {
		exit(-1);
	}

	if (!is_user_vaddr(addr)) {
		exit(-1);
	}

	if (pml4_get_page(thread_current()->pml4, addr) == NULL) {
		exit(-1);
	}

}

void halt(void) {
	power_off();
}

void exit(int status) {	
	struct thread* cur = thread_current();
	cur->exit_status = status;	
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}


bool create(const char *file , unsigned initial_size) {
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file) {
	check_address(file);
	return filesys_remove(file);
}

int open (const char *file_name) {
	check_address(file_name);	
	struct file *file_opened = filesys_open(file_name);

	if (file_opened == NULL) {
		return -1;
	}

	int fd = process_add_file(file_opened);
	if (fd == -1) {
		file_close(file_opened);
	}

	return fd;	
}

// int exec (const char *cmd_line) {
// 	check_address(cmd_line);
// 	return process_exec(cmd_line);
// }

int exec(const char *cmd_line)
{
	check_address(cmd_line);

	char *cmd_line_copy;
	cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL)
		exit(-1);							  // 메모리 할당 실패 시 status -1로 종료한다.
	strlcpy(cmd_line_copy, cmd_line, PGSIZE); // cmd_line을 복사한다.

	// 스레드의 이름을 변경하지 않고 바로 실행한다.
	if (process_exec(cmd_line_copy) == -1)
		exit(-1); // 실패 시 status -1로 종료한다.
}

int fork (const char *thread_name, struct intr_frame *f) {
	return process_fork(thread_name, f);	
}

int wait(int pid) {
	return process_wait(pid);
}

int filesize (int fd) {
	struct file *file_found = process_get_file(fd);	
	if (file_found == NULL) {
		return -1;
	}
	return file_length(file_found);
}

int read (int fd, void *buffer, unsigned length) {	
	check_address(buffer);

	if (fd == 0) {
		return input_getc();
	}

	if (fd == 1) {
		return -1;
	}

	struct file *file_found = process_get_file(fd);	
	if (file_found == NULL) {
		return -1;
	}

	lock_acquire(&filesys_lock);
	int bytes = file_read(file_found, buffer, length);
	lock_release(&filesys_lock);

	return bytes;
}

int write (int fd, const void *buffer, unsigned length) {
	if (fd == 0) {
		return -1;
	}

	if (fd == 1) {
		putbuf(buffer, length);		
		return length;
	}

	struct file *file_found = process_get_file(fd);	
	if (file_found == NULL) {
		return -1;
	}

	lock_acquire(&filesys_lock);
	int bytes = file_write(file_found, buffer, length);
	lock_release(&filesys_lock);
	
	return bytes;
}

void seek (int fd, unsigned position) {
	if (fd < 2 || fd >= 128) {
		return;
	}

	struct file *file_found = process_get_file(fd);	
	if (file_found == NULL) {
		return;
	}
	file_seek(file_found, position);
}

unsigned tell (int fd) {
	if (fd < 2 || fd >= 128) {
		return;
	}

	struct file *file_found = process_get_file(fd);	
	if (file_found == NULL) {
		return;
	}

	return file_tell(file_found);
}

void close (int fd) {
	if (fd < 2 || fd >= 128) {
		return;
	}
	struct file *file = process_get_file(fd);
	if (file == NULL) {
		return;
	}
	
	file_close(file);
	process_close_file(fd);	
}