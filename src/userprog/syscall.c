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


//need to create lock struct
struct lock sys_lock;

struct file_elements {
	struct list_elem elem;
	struct file *file;
	int fd;
};


static void syscall_handler (struct intr_frame *);
int user_to_kernel_ptr(const void *vaddr);

int process_add_file (struct file *f);
struct file* process_get_file (int fd);
void process_close_file (int fd);

//syscall prototypes
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);

void
syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock init(&sys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
    int *esp = f->esp;
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
			is_mapped(esp+1);
			is_mapped(*(esp+2));
			is_mapped(esp+3);
			f->eax = write ( (esp+1), *(esp+2), (esp+3) );
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
    }
}

void halt (void)
{
  shutdown_power_off();
}

//rtwilson
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

//rtwilson
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

int wait (pid_t pid)
{
	return process_wait(pid);
}


bool create (const char *file, unsigned initial_size)
{
	lock_aquire(&sys_lock);
	bool result = filesys_create(file, initial_size);
	lock_release(&sys_lock);
	return result;
   
}

bool remove (const char *file)
{
	lock_aquire(&sys_lock);
	bool result = filesys_remove (file);
	lock_release(&sys_lock);
	return result;
    
}

int open (const char *file)
{
	lock_aquire(&sys_lock);
	struct file *f = filesys_open(file);
	int fd = (!f) ? ERROR : process_add_file(f);
	lock_release(&sys_lock);
	return fd;

}

//not rtwilson
int filesize (int fd)
{
	lock_aquire(&sys_lock);
	int result = (fd > thread_current()->fd_index || fd < 2 ) ? 0 :
		file_length(thread_current()->file_pointers[fd]);
	lock_release(&sys_lock);
	return result;
}

int read (int fd, void *buffer, unsigned size)
{
	lock_aquire(&sys_lock);
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

//int write (int fd, const void *buffer, unsigned size)
//{
//    
//}
//
//void seek (int fd, unsigned position)
//{
//    
//}
//
unsigned tell (int fd)
{
	lock_aquire(&sys_lock);
	if(fd > thread_current()->fd_index || fd < 2)
	{
		lock_release(&sys_lock);
		thread_exit();
	}
	unsigned result = file_tell(thread_current()->file_pointers[fd]);
	lock_release(&sys_lock);
	return result;
}
//
void close (int fd)
{
	lock_aquire(&sys_lock);
	struct thread* a = thread_current();
	if(fd <= a->fd_index && fd > 2)
	{
		if(a->file_pointers[fd] != NULL)
		{
			file_close(a->file_pointers[fd]);
		}
	}
	lock_release(&sys_lock);
}

void
is_mapped(int *esp) 
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
