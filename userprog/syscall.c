#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <stddef.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

static struct lock filesys_lock;

extern process process_list[128];

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  //printf ("system call!\n");
  
  /* Verify stack pointer is valid and get syscall number */
  struct thread *t = thread_current();
  uint32_t *pd = t->pagedir;
  void *sp = pagedir_get_page(pd, f->esp);
  uint32_t syscall_num;
  if(sp != NULL) {
  	syscall_num = *((uint32_t*)sp);
  } else {
  	t->exit_status = -1;
  	thread_exit();
  }
  
  if(syscall_num == SYS_HALT) {
  	shutdown_power_off();
  } else if(syscall_num == SYS_EXIT) {
  	int32_t *exit_code = (int32_t*)(sp + 4);
  
  	if(!is_user_vaddr(f->esp + 4)) {
  		t->exit_status = -1;
  	} else {
  		t->exit_status = *exit_code;
  	}
  	
  	thread_exit();
  } else if(syscall_num == SYS_EXEC) {
  	char* cmd_line = *((uint32_t*)(sp + 4));
  	
  	if((cmd_line == NULL) || (!is_user_vaddr(cmd_line)) || (pagedir_get_page(pd, cmd_line) == NULL)) {
  		t->exit_status = -1; 
  		thread_exit(); 
  	}
  	
  	lock_acquire(&filesys_lock);
  	tid_t new_thread = process_execute(cmd_line);
  	lock_release(&filesys_lock);
  	
  	f->eax = new_thread;
  	return;
  } else if(syscall_num == SYS_WAIT) {
  	int32_t pid = *((int32_t*)(sp + 4));
  	
  	f->eax = process_wait(pid);
  	return;
  } else if(syscall_num == SYS_CREATE) {
  	char* file_name = *((uint32_t*)(sp + 4));
  	int32_t init_size = *((int32_t*)(sp + 8));
  	
  	if((file_name == NULL) || (!is_user_vaddr(file_name)) || (pagedir_get_page(pd, file_name) == NULL)) { 
  		t->exit_status = -1;
  		thread_exit(); 
  	}
  	
  	lock_acquire(&filesys_lock);
  	f->eax = filesys_create(file_name, init_size);
  	lock_release(&filesys_lock);
  	
  	return;
  } else if(syscall_num == SYS_REMOVE) {
  	char* file_name = *((uint32_t*)(sp + 4));
  	
  	if((file_name == NULL) || (!is_user_vaddr(file_name)) || (pagedir_get_page(pd, file_name) == NULL)) { 
  		t->exit_status = -1;
  		thread_exit(); 
  	}
  	
  	lock_acquire(&filesys_lock);
  	f->eax = filesys_remove(file_name);
  	lock_release(&filesys_lock);
  	
  	return;
  } else if(syscall_num == SYS_OPEN) {
  	char* file_name = *((uint32_t*)(sp + 4));
  	
  	if((file_name == NULL) || (!is_user_vaddr(file_name)) || (pagedir_get_page(pd, file_name) == NULL)) { 
  		t->exit_status = -1;
  		thread_exit(); 
  	}
  	
  	lock_acquire(&filesys_lock);
  	struct file *f_ = filesys_open(file_name);
  	if(f_ == NULL) {
  		f->eax = -1;
  	} else {
  		f->eax = t->next_fd;
  		t->files[t->next_fd] = f_;
  		t->next_fd += 1;
  	}
  	lock_release(&filesys_lock);
  	
  	return;
  } else if(syscall_num == SYS_FILESIZE) {
  	int32_t fd = *((int32_t*)(sp + 4));
  	
  	if((fd < 0) || ((fd >= 2) && (t->files[fd] == 0))) {
  		t->exit_status = -1;
  		thread_exit();
  	}
  	
  	f->eax = file_length(t->files[fd]);
  	return;
  } else if(syscall_num == SYS_READ) {
  	int32_t fd = *((int32_t*)(sp + 4));
  	void *buffer = *((uint32_t*)(sp + 8));
  	uint32_t size = *((uint32_t*)(sp + 12));
  	
  	if((fd < 0) || (fd == 1) || (fd >= 50) || ((fd >= 2) && (t->files[fd] == 0)) || (buffer == NULL) || (!is_user_vaddr(buffer))) {
  		t->exit_status = -1;
  		thread_exit();
  	}
  	
  	/* Verify buffer points to valid location */
  	char *buf = (char*)pagedir_get_page(pd, buffer);
  	if(buf == NULL) { 
  		t->exit_status = -1;
  		thread_exit(); 
  	}
  	
  	if(fd == 0) {
  		uint32_t i = 0;
  		
  		lock_acquire(&filesys_lock);
  		while(i < size) {
  			*((char*)(buf + i)) = input_getc();
  			i += 1;
  		}
  		f->eax = size;
  		lock_release(&filesys_lock);
  		
  		return;
  	} else {
  		lock_acquire(&filesys_lock);
  		f->eax = file_read(t->files[fd], buf, size);
  		lock_release(&filesys_lock);
  		
  		return;
  	}
  } else if(syscall_num == SYS_WRITE) {
  	int32_t fd = *((int32_t*)(sp + 4));
  	void *buffer = *((uint32_t*)(sp + 8));
  	uint32_t size = *((uint32_t*)(sp + 12));
  	
  	if((fd < 0) || (fd == 0) || (fd >= 50) || ((fd >= 2) && (t->files[fd] == 0)) || (buffer == NULL) || (!is_user_vaddr(buffer))) {
  		t->exit_status = -1;
  		thread_exit();
  	}
  	
  	/* Verify buffer points to valid location */
  	char *buf = (char*)pagedir_get_page(pd, buffer);
  	if(buf == NULL) { 
  		t->exit_status = -1;
  		thread_exit(); 
  	}
  	
  	if(fd == 1) {
  		if(strlen(buf) < size) { size = strlen(buf); }
  		
  		lock_acquire(&filesys_lock);
  		putbuf(buf, size);
  		f->eax = size;
  		lock_release(&filesys_lock);
  		
  		return;
  	} else {
  		/* If file is in kernel's list of files, it is an executable, so no bytes should be written */
  		for(int i = 2; i < process_list[0].t->next_fd; i += 1) {
  			if(file_get_inode(process_list[0].t->files[i]) == file_get_inode(t->files[fd])) {
  				f->eax = 0;
  				return;
  			}
  		}
  	
  		lock_acquire(&filesys_lock);
  		f->eax = file_write(t->files[fd], buf, size);
  		lock_release(&filesys_lock);

  		return;
  	}
  } else if(syscall_num == SYS_SEEK) {
  	int32_t fd = *((int32_t*)(sp + 4));
  	uint32_t pos = *((uint32_t*)(sp + 12));
  	
  	if((fd < 0) || ((fd >= 2) && (t->files[fd] == 0))) {
  		t->exit_status = -1;
  		thread_exit();
  	}
  	
  	lock_acquire(&filesys_lock);
  	file_seek(t->files[fd], pos);
  	lock_release(&filesys_lock);
  	
  	return;
  } else if(syscall_num == SYS_TELL) {
  	int32_t fd = *((int32_t*)(sp + 4));
  	
  	if((fd < 0) || ((fd >= 2) && (t->files[fd] == 0))) {
  		t->exit_status = -1;
  		thread_exit();
  	}
  	
  	lock_acquire(&filesys_lock);
  	f->eax = file_tell(t->files[fd]);
  	lock_release(&filesys_lock);
  	
  	return;
  } else if(syscall_num == SYS_CLOSE) {
  	int32_t fd = *((int32_t*)(sp + 4));
  	
  	if((fd < 0) || ((fd >= 2) && (fd < 50) && (t->files[fd] == 0)) || (fd >= 50)) {
  		t->exit_status = -1;
  		thread_exit();
  	}
  	
  	lock_acquire(&filesys_lock);
  	file_close(t->files[fd]);
  	lock_release(&filesys_lock);
  	
  	t->files[fd] = 0;
  	return;
  }

  thread_exit ();
}
