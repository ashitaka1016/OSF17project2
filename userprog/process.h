#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/* Process struct created mainly to provide synchronization
   between parent and child processes */
typedef struct process_struct {
	int pid; 										// process id (tid of thread t or -1 to indicate error)
	int parent_pid; 						// pid of process' parent process
	int parent_index;						// index of parent process in process_list
	int exit_status;						// used for when thread is deallocated but status is still needed by wait
	int wait_flag;							// used for when thread is deallocated but wait for this pid is called more than once
	int exception_flag;					// used for same reason as above when a user exception occurs
	struct thread *t;						// thread associated with process (contains exit status and flags)
	struct semaphore wait_sema; // semaphore used to wait for child process to complete its execution
	struct semaphore load_sema;	// semaphore used to wait for child process to complete loading
	struct semaphore exec_sema; // semaphore used to wait for process to finish loading to see if error occurred
	
} process;

process process_list[128];

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void process_init(void);

#endif /* userprog/process.h */
