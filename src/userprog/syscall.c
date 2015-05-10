#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define MAX_ARGS 4

//need to create lock struct

static void syscall_handler (struct intr_frame *);
int user_to_kernel_ptr(const void *vaddr);

int process_add_file (struct file *f);
struct file* process_get_file (int fd);
void process_close_file (int fd);

void
syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
    int i, arg[MAX_ARGS];
    for (i = 0; i < MAX_ARGS; i++)
    {
        arg[i] = * ((int *) f->esp + i);
    }
    switch (arg[0])
    {
    case SYS_HALT:
        {
            halt();
            break;
        }
    case SYS_EXIT:
        {
            exit(arg[1]);
            break;
        }
    case SYS_EXEC:
        {
            arg[1] = user_to_kernel_ptr((const void *) arg[1]);
            exec((const char *) arg[1]);
            break;
        }
    case SYS_WAIT:
        {
            wait(arg[1]);
            break;
        }
    case SYS_CREATE:
        {
            arg[1] = user_to_kernel_ptr((const void *) arg[1]);
            create((const char *)arg[1], (unsigned) arg[2]);
            break;
        }
    case SYS_REMOVE:
        {
            arg[1] = user_to_kernel_ptr((const void *) arg[1]);
            remove((const char *) arg[1]);
            break;
        }
    case SYS_OPEN:
        {
            arg[1] = user_to_kernel_ptr((const void *) arg[1]);
            open((const char *) arg[1]);
            break;
        }
    case SYS_FILESIZE:
        {
            filesize(arg[1]);
            break;
        }
    case SYS_READ:
        {
            arg[2] = user_to_kernel_ptr((const void *) arg[2]);
            read(arg[1], (void *) arg[2], (unsigned) arg[3]);
            break;
        }
    case SYS_WRITE:
        {
            arg[2] = user_to_kernel_ptr((const void *) arg[2]);
            write(arg[1], (const void *) arg[2], (unsigned) arg[3]);
            break;
        }
    case SYS_SEEK:
        {
            seek(arg[1], (unsigned) arg[2]);
            break;
        }
    case SYS_TELL:
        {
            tell(arg[1]);
            break;
        }
    case SYS_CLOSE:
        {
            close(arg[1]);
            break;
        }
    }
}

void halt (void)
    {
        shutdown_power_off();
}

void exit (int status)
{
	struct thread *current = thread_current();
	if(thread_alive(current->parent))
	{
		current->cp->status;
	}
    printf ("%s: exit(%d)\n", current->name, status);
    thread_exit();
}

pid_t exec (const char *cmd_line)
{
	pid_t pid = process_execute(cmd_line);
	struct child_procces* cp = get_child_process(pid);
	while(cp->load == NOT_LOADED)
	{
		barrier();
	}
	if (cp->load == LOAD_FAIL)
	{
		return ERROR;
	}
	return pid;
}
   
}

int wait (pid_t pid)
{
	return process_wait(pid);
}


bool create (const char *file, unsigned initial_size)
{
	//need to create lock struct
   
}

bool remove (const char *file)
{
    
}

int open (const char *file)
{
    
}

int filesize (int fd)
{
    
}

int read (int fd, void *buffer, unsigned size)
{
}

int write (int fd, const void *buffer, unsigned size)
{
    
}

void seek (int fd, unsigned position)
{
    
}

unsigned tell (int fd)
{
    
}

void close (int fd)
{
    
}

int user_to_kernel_ptr(const void *vaddr)
{
    
}

int process_add_file (struct file *f)
{
    
}

struct file* process_get_file (int fd)
{
    
}

void process_close_file (int fd)
{
    
}
