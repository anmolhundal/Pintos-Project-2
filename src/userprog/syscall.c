#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define MAX_ARGS 4

struct lock sys_lock;

static void syscall_handler (struct intr_frame *);

//int process_add_file (struct file *f);
//struct file* process_get_file (int fd);
//void process_close_file (int fd);

int user_to_kernel_ptr(const void * vaddr)
{
	if(!is_user_vaddr(vaddr)){
		thread_exit();
		return 0;
	}
	void *ptr=pagedir_get_page(thread_current()->pagedir,vaddr);
	if(!ptr){
		thread_exit();
		return 0;
	}
	return (int) ptr;
}

void
syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&sys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
		printf("\nin syscall handler\n\n");
		int i, arg[MAX_ARGS];
		for(i=0;i<MAX_ARGS;i++)
		{
			arg[i]=*((int *) f->esp+1);
		}
        int * esp = f->esp;
        is_mapped(esp);
    
		//Dispatch syscall to handler	
		switch (*esp){
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
			is_mapped(esp+1);
          	exit(*(esp+1));
            break;
    	case SYS_EXEC:
			is_mapped(*(esp+1));
			f->eax = exec (*(esp+1));
            break;
        case SYS_WAIT:
			is_mapped(esp+1);
            f->eax = wait(*(esp+1));
            break;
        case SYS_CREATE:
			is_mapped(*(esp+1));
			is_mapped(esp+2);
			f->eax = create ( *(esp+1), (esp+2));
            break;
        case SYS_REMOVE:
			is_mapped(*(esp+1));
			f->eax = remove (*(esp+1));
            break;
        case SYS_OPEN:
			is_mapped(*(esp+1));
			f->eax = open (*(esp+1));
            break;
        case SYS_FILESIZE:
			is_mapped(esp+1);
			f->eax = filesize ( esp+1 );
            break;
        case SYS_READ:
			is_mapped(esp+1);
			is_mapped(*(esp+2));
			is_mapped(esp+3);
			f->eax = read ( (esp+1), *(esp+2), (esp+3) );
            break;
        case SYS_WRITE:
			//is_mapped(esp+1);
			//is_mapped(*(esp+2));
			//is_mapped(esp+3);
			//f->eax = write ( (esp+1), *(esp+2), (esp+3) );
			//void * arg2=user_to_kernel_ptr((const void *)(esp+2));
			//f->eax = write ( (esp+1), arg2, (esp+3) );
          	break;
        case SYS_SEEK:
			is_mapped(esp+1);
			is_mapped(esp+2);
			seek ( (esp+1), (esp+2) );
          	break;
        case SYS_TELL:
			is_mapped(esp+1);
			f->eax = tell ( (esp+1) );
          	break;
        case SYS_CLOSE:
			is_mapped(esp+1);
			close ( (esp+1) );
          	break;
        default:
			thread_exit();
			break;
    }
}

void halt (void)
{
  	shutdown_power_off();
}


void exit (int status)
{
	struct thread *cur = thread_current ();
	cur->exit_status = status;
	char *temp;   
	printf ("%s: exit(%d)\n", strtok_r(cur->name, " ", &temp), status);
	file_close (cur->file_keep); 
	close_all_files (); 
	thread_exit (); 
}
//
pid_t exec (const char *cmd_line)
{
	pid_t pid = process_execute(cmd_line);
	while(pid == 0)
	{
		barrier();
	}
	if (pid == -1)
	{
		return ERROR;
	}
	return pid;
}
//
int wait (pid_t pid)
{
	return process_wait(pid);
}

//
bool create (const char *file, unsigned initial_size)
{
	lock_acquire(&sys_lock);
	bool result = filesys_create(file, initial_size);
	lock_release(&sys_lock);
	return result;
   
}
//
bool remove (const char *file)
{
	lock_acquire(&sys_lock);
	bool result = filesys_remove (file);
	lock_release(&sys_lock);
	return result;
    
}
//
int open (const char *file)
{
	lock_acquire(&sys_lock);
	int result;
	struct thread *cur = thread_current();
	cur->file_pointers[cur->fd_index] = filesys_open(file);
	struct file *f = filesys_open(file);
	if(!f)
	{
		lock_release(&sys_lock);
		return ERROR;
	}
	
	result = (cur->file_pointers[cur->fd_index] == NULL) ? ERROR : cur->fd_index++;
	lock_release(&sys_lock);
	return result;

}

//
int filesize (int fd)
{
	lock_acquire(&sys_lock);
	int result = (fd > thread_current()->fd_index || fd < 2 ) ? 0 :
		file_length(thread_current()->file_pointers[fd]);
	lock_release(&sys_lock);
	return result;
}
//
int read (int fd, void *buffer, unsigned size)
{
	lock_acquire(&sys_lock);
	int result;
	struct thread *cur = thread_current();
	if(fd == STDIN_FILENO)
	{
		unsigned i;
		uint8_t *b_ptr = (uint8_t *) buffer;
		for(i = 0; i < size; i++)
		{
			b_ptr[i] = input_getc();
		}
		lock_release(&sys_lock);
		return size;
	}
	else if( fd > 1 && fd <= cur->fd_index && buffer != NULL)
	{
		result = file_read(cur->file_pointers[fd], buffer, size);
	}
	else
	{
		result = ERROR;
	}
	lock_release(&sys_lock);
	return result;	
}

int write (int fd, const void *buffer, unsigned size)
{
	printf("\nin write\n\n");
	//lock_acquire(&sys_lock);
	struct thread *cur = thread_current();
	if(fd > 0 && fd <= cur->fd_index && buffer != NULL)
	{
		//for writing to the console
		if(fd == STDOUT_FILENO)
		{
			putbuf(buffer, size);
			printf("\nprinted\n\n");
			//lock_release(&sys_lock);
			return size;
		}
		//for writing to a file
		if(fd != 0 && fd != STDOUT_FILENO)
		{
			struct file *f = cur->file_pointers[fd];
		
			//if(f->inode->is_dir == -1)
			//{
			//	lock_release(&sys_lock);
			//	return ERROR;
			//}
		
			int result = file_write(cur->file_pointers[fd], buffer, size);
			lock_release(&sys_lock);
			return result;
		}
		lock_release(&sys_lock);
		return size;
	}
	//if it had bad file descriptor
	return ERROR;   
}
//
void seek (int fd, unsigned position)
{
	lock_acquire(&sys_lock);
	struct thread *cur = thread_current();
	if( fd <= cur->fd_index && fd >= 2)
	{
		file_seek( cur->file_pointers[fd], position);
		lock_release(&sys_lock);
	}
	else
	{
		lock_release(&sys_lock);
		thread_exit();
	}
}
//
unsigned tell (int fd)
{
	lock_acquire(&sys_lock);
	struct thread *cur = thread_current();
	if(fd > cur->fd_index || fd < 2)
	{
		lock_release(&sys_lock);
		thread_exit();
	}
	unsigned result = file_tell(cur->file_pointers[fd]);
	lock_release(&sys_lock);
	return result;
}
//
void close (int fd)
{
	lock_acquire(&sys_lock);
	struct thread* cur = thread_current();
	if(fd <= cur->fd_index && fd > 2)
	{
		if(cur->file_pointers[fd] != NULL)
		{
			file_close(cur->file_pointers[fd]);
		}
	}
	lock_release(&sys_lock);
}
//
void
close_all_files()
{
	int i;
	for(i = 2; i < 150; i++)
	{
		close(i); 
	}  
}        
//
void
is_mapped(int* esp) 
{
	struct thread *cur = thread_current ();
	
	if(esp == NULL)
	{
		printf ("%s: exit(%d)\n", cur->name, cur->exit_status);
		thread_exit ();
	}
	
	if(is_kernel_vaddr (esp))
	{
		printf ("%s: exit(%d)\n", cur->name, cur->exit_status);
		thread_exit ();	
	}
    
    if( pagedir_get_page (cur->pagedir, esp) == NULL )
    {
		printf ("%s: exit(%d)\n", cur->name, cur->exit_status);
		thread_exit ();
	}
}
