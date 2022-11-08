#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "user/syscall.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

/*#define SINGLE_ARG 1
#define TWO_ARGS 2*/
#define MAX_ARGS 3

static void syscall_handler (struct intr_frame *);

bool FILESYS_LOCK_ACQUIRE = false;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  if (!FILESYS_ACQUIRE)
  {
    lock_init(&file_sys_lock);
    FILESYS_ACQUIRE = true;
  }

  int esp = get_page_ptr((const void *) f->esp);

  struct something {
    * (int *) esp;

  }

  list_entry 


  switch (* (int *) esp) /* size of int bytes from mem, starting from esp */
  {
    case SYS_HALT:
      halt (); // DONE
      break;
    case SYS_EXIT:
      sys_exit (f); // DONE
      break;
    case SYS_EXEC:
      f->eax = exec (f); // DONE
      break;
    case SYS_WAIT:
      f->eax = wait (f); // DONE;
      break;
    case SYS_CREATE:
      f->eax = create (f); // DONE
      break;
    case SYS_REMOVE:
      f->eax = remove ((const char *) args[0]);
      break;
    case SYS_OPEN:
      get_stack_args(f, 1, &args[0]);

      /* check that arg[0] is valid */
      /* validate_str((const void*) arg[0])*/
      args[0] = get_page_ptr((const void *)args[0]);
      /* int open (const char *file) */
      f->eax = open ((const char *) args[0]);
      break;
    case SYS_FILESIZE:
      get_stack_args(f, 1, &args[0]);
      /* int filesize (int fd) */
      f->eax = filesize (args[0]);
      break;
    case SYS_READ:
      get_stack_args(f, 3, &args[0]);
      /* check that buffer is valid */
      /* validate_buffer((const void *) arg[1], (unsigned) arg[2])*/
      args[1] = get_page_ptr((const void *)args[0]);
      /* int read (int fd, void *buffer, unsigned size) */
      f->eax = read(args[0], (void *) args[1], (unsigned) args[2]);
      break;
    case SYS_WRITE:
      get_stack_args(f, 3, &args[0]);
      /* check that buffer is valid */
      /* validate_buffer((const void *) arg[1], (unsigned) arg[2])*/
      args[1] = get_page_ptr((const void *)arg[0]);
      /* int write (int fd, const void *buffer, unsigned size) */
      f->eax = syscall_write(args[0], (const void *) args[1], (unsigned) args[2]);
      break;
    case SYS_SEEK:
      get_stack_args(f, 2, &args[0]);
      /* void seek (int fd, unsigned position) */
      seek(args[0], (unsigned) args[1]);
      break;
    case SYS_TELL:
      get_stack_args(f, 1, &args[0]);
      /* unsigned tell (int fd) */
      f->eax = tell (args[0]);
      break;
    case SYS_CLOSE:
      get_stack_args(f, 1, &args[0]);
      /* void close (int fd) */
      close (args[0])
      break;
    default:
      break;

  }
  
  printf ("system call!\n");
  thread_exit ();
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
    : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Attempts to read user data from uaddr. 
   If access invalid returns -1. */
static int
mem_try_read (const uint8_t *uaddr)
{
  if (is_user_vaddr (uaddr))
    {
      return get_user (uaddr);
    }
  else
    {
      return -1;
    }
}

/* Attempts to write data byte to user address udst.
   Return true if successful and false otherwise. */
static bool
mem_try_write (uint8_t *udst, uint8_t byte)
{
  if (is_user_vaddr (udst))
    {
      return put_user (udst, byte);
    }
  else
  {
    return false;
  }
}

/* gets arguments from the stack and stores them in the array args */
void
get_stack_args (struct intr_frame *f, int *num_of_args, int *args)
{
  int i;
  int *pointer;
  for (i = 0; i < num_of_args; i++){
    pointer = (int *) f->esp + i + 1;
    // validate pointer
    args[i] = pointer;
  }
}	


/* gets page pointer using virtual address */
int get_page_ptr(const void *vaddr){
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr)
  {
    syscall_exit(ERROR);
  }
  return (int) ptr;


/* Terminates Pintos by calling 
   shutdown_power_off() 
*/
void halt (void){
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);
}

/* Terminates the current user program and sends exit status to kernel.
   A status of 0 is a success.
*/
void exit (struct intr_frame *f){
  get_stack_args (f, 1, &args[0]);
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);
  int status = arg[0];
}

/* Runs executable whose name is given in the command line, 
   passing given args and returns the new process's pid
*/
pid_t 
exec (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);
  get_stack_args(f, 1, &args[0]);

      /* check that arg[0] is valid */
      /* validate_str((const void*) arg[0])*/

      /* get page pointer */
      args[0] = get_page_ptr ((const void *)args[0]);
      /* pid_t exec (const char *cmd_line) */
      const char *cmd_line = (const char *) args[0];
      /* formerly passed into the function as an argument */
  return NULL;
}

/* Waits for a child process pid and retrieves the child’s exit status.
 
   If pid is alive, waits until it terminates and returns the status 
   the pid passed to exit.
 
   If pid is terminated by the kernel without exiting, wait fails returns -1.
 
   If pid is not a direct child of the calling process, wait fails and returns –1.

   If the process calling wait has already called it, wait fails and returns -1*/
int wait (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);
  get_stack_args(f, 1, &args[0]);
      /* int wait (pid t pid) */
  pid_t pid = arg[0]; /* previously passed as arg */
  return 0;
}

/* Creates a new file called file with size initial_size bytes.
   Returns true if successful and false otherwise. */
bool create (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);

  get_stack_args(f, 2, &args[0]);

  /* check that arg[0] is valid */
  /* validate_str((const void*) arg[0])*/
  args[0] = get_page_ptr((const void *)args[0]);
  /* bool create (const char *file, unsigned initial_size) */
  const char *file = (const char *) args[0];
  unsigned initial_size = (unsigned) args[1]);

  return false;
}


/* Deletes file 
   Returns true if successful and false otherwise.
   If the file is currently open, it remains open after removal */
bool remove (struct intr_frame *f, const char *file)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);

  get_stack_args(f, 1, &args[0]);
  /* check that arg[0] is valid */
  /* validate_str((const void*) arg[0])*/
  args[0] = get_page_ptr((const void *)args[0]);
  /* bool remove (const char *file) */
  return false;
}

/* Tries to open the file.
   If successful, the function returns -1.
   Otherwise, it returns the file descriptor. */
int open (struct intr_frame *f, const char *file)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);
  return 0;
}

/* Returns the size, in bytes, of the file open as fd.*/
int filesize (struct intr_frame *f, int fd)
{
  /* TO DO */
  return 0;
}

/* Reads size bytes from the file open as fd into buffer */
int read (struct intr_frame *f, int fd, void *buffer, unsigned size)
{
  /* TO DO */
  return 0;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
   written, which may be less than size if some bytes could not be written */
int write (struct intr_frame *f, int fd, const void *buffer, unsigned size)
{
  /* TO DO */
  return 0;
}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes
from the beginning of the file. */
void seek (struct intr_frame *f, int fd, unsigned position);

/* Returns the position of the next byte to be read or written in open file fd */
unsigned tell (struct intr_frame *f, int fd)
{
  /* TO DO */
  return NULL;
}

/* Closes file descriptor fd.*/
void close (struct intr_frame *f, int fd);


