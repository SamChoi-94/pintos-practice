#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "lib/user/syscall.h"
#include "include/filesys/filesys.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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
			f->R.rax = fork(f->R.rdi);
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
		
	}

}

pid_t fork (const char *thread_name) {
	check_address(thread_name);
	
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

int exec (const char *file) {
	check_address(file);
	
	return process_exec(file);
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

int wait(pid_t pid) {
	return process_wait(pid);
}

bool create(const char *file , unsigned initial_size) {
	check_address(file);

	bool result = filesys_create(file, initial_size);

	if (result) {
		return true;
	}
	return false;
}

bool remove(const char *file) {
	check_address(file);

	bool result = filesys_remove(file);

	if (result) {
		return true;
	}
	return false;
}

int filesize (int fd) {
	struct file *file_found = process_get_file(fd);	
	if (file_found == NULL) {
		return -1;
	}
	return file_length(file_found);
}

void seek (int fd, unsigned position) {
	if (fd < 2 || fd > 128) {
		return;
	}

	struct file *file_found = process_get_file(fd);	
	if (file_found == NULL) {
		return;
	}
	file_seek(file_found, position);
}

unsigned tell (int fd) {
	struct file *file_found = process_get_file(fd);	
	if (file_found == NULL) {
		return -1;
	}

	return file_tell(file_found);
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
	return file_read(file_found, buffer, length);

	return -1;
}

int write (int fd, const void *buffer, unsigned length) {
	check_address(buffer);
	
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
	
	return file_write(file_found, buffer, length);
}

int open (const char *file) {
	check_address(file);	
	struct file *file_opened = filesys_open(file);

	if (file_opened == NULL) {
		return -1;
	}

	int fd = process_add_file(file);

	return fd;	
}

void close (int fd) {
	if (fd < 2 || fd > 128) {
		return;
	}

	process_close_file(fd);	
}