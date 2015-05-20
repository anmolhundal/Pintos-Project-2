#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define MAX_ARGS 4

struct lock filesys_lock;

struct process_file {
  struct file *file;
  int fd;
  struct list_elem elem;
};


static void syscall_handler (struct intr_frame *);

int process_add_file (struct file *f);
struct file* process_get_file (int fd);
void process_close_file (int fd);

int user_to_kernel_ptr(const void * vaddr)
{
	//if(!is_user_vaddr(vaddr)){
	//	thread_exit();
	//	return 0;
	//}
	void * ptr = pagedir_get_page ( thread_current()->pagedir, vaddr);
	//if(!ptr){
	//	thread_exit();
    //		return 0;
	//}
	return (int) ptr;
}

void
syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
		int i, arg[MAX_ARGS];
		for(i=0;i<MAX_ARGS;i++)
		{
			arg[i]=*((int *) f->esp+i);
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
			
           // is_mapped(esp+1);
			//is_mapped(*(esp+2));
			//is_mapped(esp+3);
			//f->eax = write ( (esp+1), *(esp+2), (esp+3) );
			arg[2]=user_to_kernel_ptr((const void *) arg[2]);
           // printf("Calling write\n");
			f->eax = write (arg[1], (const void *)arg[2], (unsigned) arg[3]);
          	
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
        //default:
		//	thread_exit();
		//	break;
    }
}

void halt (void)
{
  	shutdown_power_off();
}


void exit (int status)
{
	struct thread *cur = thread_current();
	if (thread_alive(cur->parent))
    {
      cur->cp->status = status;
    }
	printf ("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}
//
pid_t exec (const char *cmd_line)
{
	pid_t pid = process_execute(cmd_line);
	struct child_process* cp = get_child_process(pid);
	ASSERT(cp);
	while (cp->load == NOT_LOADED)
    {
      barrier();
    }
	if (cp->load == LOAD_FAIL)
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
	lock_acquire(&filesys_lock);
	bool result = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return result;
   
}
//
bool remove (const char *file)
{
	lock_acquire(&filesys_lock);
	bool result = filesys_remove (file);
	lock_release(&filesys_lock);
	return result;
    
}
//
int open (const char *file)
{
	lock_acquire(&filesys_lock);
	struct file *f = filesys_open(file);
	if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
	int fd = process_add_file(f);
	lock_release(&filesys_lock);
	return fd;
}

//
int filesize (int fd)
{
	lock_acquire(&filesys_lock);
	struct file *f = process_get_file(fd);
	if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
	int size = file_length(f);
	lock_release(&filesys_lock);
	return size;
}
//
int read (int fd, void *buffer, unsigned size)
{
	lock_acquire(&filesys_lock);
	int result;
	//struct thread *cur = thread_current();
	if(fd == STDIN_FILENO)
	{
		unsigned i;
		uint8_t *b_ptr = (uint8_t *) buffer;
		for(i = 0; i < size; i++)
		{
			b_ptr[i] = input_getc();
		}
		lock_release(&filesys_lock);
		return size;
	}
	struct file *f = process_get_file(fd);
	if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
	result = file_read(f, buffer, size);
	lock_release(&filesys_lock);
	return result;
}

int write (int fd, const void *buffer, unsigned size)
{
	//printf("\n in write\n\n");
	//printf("\nPassed fd is %d\n\n",fd);
	if (fd == STDOUT_FILENO)
    {
		//printf("\nGonna putbuf\n\n");
      putbuf(buffer, size);
      return size;
    }
	lock_acquire(&filesys_lock);
	struct file *f = process_get_file(fd);
	if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
	int bytes = file_write(f, buffer, size);
	lock_release(&filesys_lock);
	return bytes;  
}
//
void seek (int fd, unsigned position)
{
	lock_acquire(&filesys_lock);
	struct file *f = process_get_file(fd);
	if (!f)
    {
      lock_release(&filesys_lock);
      return;
    }
	file_seek(f, position);
	lock_release(&filesys_lock);

}
//
unsigned tell (int fd)
{
	lock_acquire(&filesys_lock);
	struct file *f = process_get_file(fd);
	if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
	off_t offset = file_tell(f);
	lock_release(&filesys_lock);
	return offset;

}
//
void close (int fd)
{
	lock_acquire(&filesys_lock);
	process_close_file(fd);
	lock_release(&filesys_lock);
}
//
//void
//close_all_files()
//{
//	int i;
//	for(i = 2; i < 150; i++)
//	{
//		close(i); 
//	}  
//}        
//
void
is_mapped(int* esp) 
{
	struct thread *cur = thread_current ();
	
	if(esp == NULL)
	{
		printf ("%s: exit(%d)\n", cur->name, cur->status);
		thread_exit ();
	}
	
	if(is_kernel_vaddr (esp))
	{
		printf ("%s: exit(%d)\n", cur->name, cur->status);
		thread_exit ();	
	}
    
    if( pagedir_get_page (cur->pagedir, esp) == NULL )
    {
		printf ("%s: exit(%d)\n", cur->name, cur->status);
		thread_exit ();
	}
}

struct child_process* add_child_process (int pid)
{
  struct child_process* cp = malloc(sizeof(struct child_process));
  cp->pid = pid;
  cp->load = NOT_LOADED;
  cp->wait = false;
  cp->exit = false;
  lock_init(&cp->wait_lock);
  list_push_back(&thread_current()->child_list,
		 &cp->elem);
  return cp;
}

struct child_process* get_child_process (int pid)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->child_list); e != list_end (&t->child_list);
       e = list_next (e))
        {
          struct child_process *cp = list_entry (e, struct child_process, elem);
          if (pid == cp->pid)
	    {
	      return cp;
	    }
        }
  return NULL;
}

void remove_child_process (struct child_process *cp)
{
  list_remove(&cp->elem);
  free(cp);
}

void remove_child_processes (void)
{
  struct thread *t = thread_current();
  struct list_elem *next, *e = list_begin(&t->child_list);

  while (e != list_end (&t->child_list))
    {
      next = list_next(e);
      struct child_process *cp = list_entry (e, struct child_process,
					     elem);
      list_remove(&cp->elem);
      free(cp);
      e = next;
    }
}

int process_add_file (struct file *f)
{
  struct process_file *pf = malloc(sizeof(struct process_file));
  pf->file = f;
  pf->fd = thread_current()->fd;
  thread_current()->fd++;
  list_push_back(&thread_current()->file_list, &pf->elem);
  return pf->fd;
}

struct file* process_get_file (int fd)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->file_list); e != list_end (&t->file_list);
       e = list_next (e))
        {
          struct process_file *pf = list_entry (e, struct process_file, elem);
          if (fd == pf->fd)
	    {
	      return pf->file;
	    }
        }
  return NULL;
}

void process_close_file (int fd)
{
  struct thread *t = thread_current();
  struct list_elem *next, *e = list_begin(&t->file_list);

  while (e != list_end (&t->file_list))
    {
      next = list_next(e);
      struct process_file *pf = list_entry (e, struct process_file, elem);
      if (fd == pf->fd || fd == CLOSE_ALL)
	{
	  file_close(pf->file);
	  list_remove(&pf->elem);
	  free(pf);
	  if (fd != CLOSE_ALL)
	    {
	      return;
	    }
	}
      e = next;
    }
}
