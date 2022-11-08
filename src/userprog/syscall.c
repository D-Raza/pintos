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
  void (*sys_functions_arr[])(struct intr_frame *f) = {sys_halt,sys_exit, sys_exec, sys_wait, sys_create, sys_remove, sys_open,
  sys_filesize, sys_read, sys_write, sys_seek, sys_tell, sys_close};
  
  /* need to find a way to see which functions return a value and set f->eax to it */
  /* funcs returning a value are sys_exec, sys_wait, sys_create, sys_remove, 
  sys_open, sys_filesize, sys_read, sys_write, sys_tell */
  if ((* (int *) esp) < SYS_INUMBER)
  { /* checks that esp is an enum */
    (*sys_functions_arr[(* (int *) esp])(f) 
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
void sys_halt (void){
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);
}

/* Terminates the current user program and sends exit status to kernel.
   A status of 0 is a success.
*/
void sys_exit (struct intr_frame *f){
  get_stack_args (f, 1, &args[0]);
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);
  int status = arg[0];
}

/* Runs executable whose name is given in the command line, 
   passing given args and returns the new process's pid
*/
pid_t 
sys_exec (struct intr_frame *f)
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
int sys_wait (struct intr_frame *f)
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
bool sys_create (struct intr_frame *f)
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
bool sys_remove (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);

  get_stack_args(f, 1, &args[0]);
  /* check that arg[0] is valid */
  /* validate_str((const void*) arg[0])*/
  args[0] = get_page_ptr((const void *)args[0]);
  /* bool remove (const char *file) */
  const char *file = (const char *) args[0];
  return false;
}

/* Tries to open the file.
   If successful, the function returns -1.
   Otherwise, it returns the file descriptor. */
int sys_open (struct intr_frame *f, const char *file)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);

  get_stack_args(f, 1, &args[0]);

  /* check that arg[0] is valid */
  /* validate_str((const void*) arg[0])*/
  args[0] = get_page_ptr((const void *)args[0]);
  /* int open (const char *file) */
  const char *file = (const char *) args[0];

  return 0;
}

/* Returns the size, in bytes, of the file open as fd.*/
int sys_filesize (struct intr_frame *f, int fd)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);

  get_stack_args(f, 1, &args[0]);
  /* int filesize (int fd) */
  int fd = args[0];
  return 0;
}

/* Reads size bytes from the file open as fd into buffer */
int sys_read (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);

  get_stack_args(f, 3, &args[0]);
  /* check that buffer is valid */
  /* validate_buffer((const void *) arg[1], (unsigned) arg[2])*/
  args[1] = get_page_ptr((const void *)args[0]);
  /* int read (int fd, void *buffer, unsigned size) */
  int fd = args[0];
  void *buffer = (void *) args[1];
  unsigned size = (unsigned) args[2];
  // return value is set as f->eax;
  return 0;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
   written, which may be less than size if some bytes could not be written */
int sys_write (struct intr_frame *f, int fd, , unsigned size)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);

  get_stack_args(f, 3, &args[0]);
  /* check that buffer is valid */
  /* validate_buffer((const void *) arg[1], (unsigned) arg[2])*/
  args[1] = get_page_ptr((const void *)arg[0]);
  /* int write (int fd, const void *buffer, unsigned size) */
  int fd = args[0];
  const void *buffer = (const void *) args[1];
  unsigned size = (unsigned) args[2];
  return 0;
}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes
from the beginning of the file. */
void sys_seek (struct intr_frame *f) {
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);

  get_stack_args(f, 2, &args[0]);
  /* void seek (int fd, unsigned position) */
  int fd = args[0];
  unsigned position = (unsigned) args[1];
}

/* Returns the position of the next byte to be read or written in open file fd */
unsigned sys_tell (struct intr_frame *f, int fd)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);
  get_stack_args(f, 1, &args[0]);
  /* unsigned tell (int fd) */
  int fd = args[0];
  return NULL; /* f->eax */
}

/* Closes file descriptor fd.*/
void sys_close (struct intr_frame *f, int fd){
  int args[MAX_ARGS];
  int esp = get_page_ptr((const void *) f->esp);

  get_stack_args(f, 1, &args[0]);
  /* void close (int fd) */
  int fd = args[0];
}


