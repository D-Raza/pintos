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
static void sys_exit (struct intr_frame *f);

bool FILESYS_LOCK_ACQUIRE = false;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
static void
get_stack_args (struct intr_frame *f,  int *args, int num_of_args)
{
  int i;
  int *pointer;
  for (i = 0; i < num_of_args; i++){
    pointer = (int *) f->esp + i + 1;
    // validate pointer
    args[i] = *pointer;
  }
}	


/* gets page pointer using virtual address */
static int 
get_page_ptr(struct intr_frame *f)
{
  const void *vaddr = (const void *) f->esp;
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr)
  {
    sys_exit(f);
  }
  return (int) ptr;
}

/* Terminates Pintos by calling 
   shutdown_power_off() 
*/
static void 
sys_halt (void){
  shutdown_power_off();
}

/* Terminates the current user program and sends exit status to kernel.
   A status of 0 is a success.
*/
static void 
sys_exit (struct intr_frame *f){
  int args[MAX_ARGS];
  int esp = get_page_ptr(f);
  get_stack_args (f, &args[0], 1);
  int status = args[0];
}

/* Runs executable whose name is given in the command line, 
   passing given args and returns the new process's pid
*/
static void 
sys_exec (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr(f);
  get_stack_args(f, &args[0], 1);

  /* check that arg[0] is valid */
  /* validate_str((const void*) arg[0])*/
  /* get page pointer */
  args[0] = get_page_ptr (f);
  /* pid_t exec (const char *cmd_line) */
  const char *cmd_line = (const char *) args[0];
  /* formerly passed into the function as an argument */

  /* reset f->eax after the function is over */
  f->eax = -1;
}

/* Waits for a child process pid and retrieves the child’s exit status.
 
   If pid is alive, waits until it terminates and returns the status 
   the pid passed to exit.
 
   If pid is terminated by the kernel without exiting, wait fails returns -1.
 
   If pid is not a direct child of the calling process, wait fails and returns –1.

   If the process calling wait has already called it, wait fails and returns -1*/
static void 
sys_wait (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr(f);
  get_stack_args(f, &args[0], 1);
      /* int wait (pid t pid) */
  pid_t pid = args[0]; /* previously passed as arg */
  /* change the eax value (below) once sys_wait has been implemented */
  f->eax = -1;
}

/* Creates a new file called file with size initial_size bytes.
   Returns true if successful and false otherwise. */
static void 
sys_create (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr(f);

  get_stack_args(f, &args[0], 1);

  /* check that arg[0] is valid */
  /* validate_str((const void*) arg[0])*/
  args[0] = get_page_ptr (f);
  /* bool create (const char *file, unsigned initial_size) */
  const char *file = (const char *) args[0];
  unsigned initial_size = (unsigned) args[1];
  /* change eax val (below) once sys_create has been completed */
  f->eax = false;
}


/* Deletes file 
   Returns true if successful and false otherwise.
   If the file is currently open, it remains open after removal */
static void 
sys_remove (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr(f);

  get_stack_args(f, &args[0], 1);
  /* check that arg[0] is valid */
  /* validate_str((const void*) arg[0])*/
  args[0] = get_page_ptr(f);
  /* bool remove (const char *file) */
  const char *file = (const char *) args[0];
  /* change eax val (below) once sys_remove has been completed */
  f->eax = false;
}

/* Tries to open the file.
   If successful, the function returns -1.
   Otherwise, it returns the file descriptor. */
static void 
sys_open (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr(f);

  get_stack_args(f, &args[0], 1);

  /* check that arg[0] is valid */
  /* validate_str((const void*) arg[0])*/
  args[0] = get_page_ptr(f);
  /* int open (const char *file) */
  const char *file = (const char *) args[0];
  /* change eax val (below) once sys_open has been completed */
  f->eax = 0;
}

/* Returns the size, in bytes, of the file open as fd.*/
static void 
sys_filesize (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr(f);

  get_stack_args(f, &args[0], 1);
  /* int filesize (int fd) */
  int fd = args[0];
  /* change eax val (below) once sys_filesize has been completed */
  f->eax = 0;
}

/* Reads size bytes from the file open as fd into buffer */
static void 
sys_read (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr(f);

  get_stack_args(f, &args[0], 3);
  /* check that buffer is valid */
  /* validate_buffer((const void *) arg[1], (unsigned) arg[2])*/
  args[1] = get_page_ptr(f);
  /* int read (int fd, void *buffer, unsigned size) */

  /* Don't think I need the below
  int fd = args[0];
  void *buffer = (void *) args[1];
  unsigned size = (unsigned) args[2];*/
   /* change eax val (below) once sys_remove has been completed */
  f->eax = 0;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
   written, which may be less than size if some bytes could not be written */
static void 
sys_write (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr(f);

  get_stack_args(f, &args[0], 3);
  /* check that buffer is valid */
  /* validate_buffer((const void *) arg[1], (unsigned) arg[2])*/
  args[1] = get_page_ptr(f);
  /* int write (int fd, const void *buffer, unsigned size) */
  int fd = args[0];
  const void *buffer = (const void *) args[1];
  unsigned size = (unsigned) args[2];
  /* change eax val (below) once sys_remove has been completed */
  /* the below code has been commented out as there's no current mapping between file and fd */

  /* struct file *file = thread_current()->file_name; */
  int written_size = 0;
  if (fd == 1){
    while (size > 300){
      putbuf (buffer, 300);
      buffer += 300;
      written_size += 300;
    }
    putbuf (buffer, size - written_size);
    written_size = size;
  }
  /*
  else {
	  //file_write (struct file *file, const void *buffer, off_t size)
	written_size = file_write (file, (const void *) args[1], (unsigned) args[2]);
  } */

  f->eax = written_size;
}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes
from the beginning of the file. */
static void 
sys_seek (struct intr_frame *f) {
  int args[MAX_ARGS];
  int esp = get_page_ptr(f);

  get_stack_args(f, &args[0], 2);
  /* void seek (int fd, unsigned position) */
  int fd = args[0];
  unsigned position = (unsigned) args[1];
}

/* Returns the position of the next byte to be read or written in open file fd */
static void 
sys_tell (struct intr_frame *f)
{
  int args[MAX_ARGS];
  int esp = get_page_ptr(f);
  get_stack_args(f, &args[0], 1);
  /* unsigned tell (int fd) */
  int fd = args[0];
  /* change eax val (below) once sys_remove has been completed */
  f->eax = -1;
}

/* Closes file descriptor fd.*/
static void 
sys_close (struct intr_frame *f){
  int args[MAX_ARGS];
  int esp = get_page_ptr(f);

  get_stack_args(f, &args[0], 1);
  /* void close (int fd) */
  int fd = args[0];
}

static void
syscall_handler (struct intr_frame *f)
{
  if (!FILESYS_LOCK_ACQUIRE)
  {
    lock_init(&file_sys_lock);
    FILESYS_LOCK_ACQUIRE = true;
  }

  int esp = get_page_ptr(f);
  void (*sys_functions_arr[])(struct intr_frame *f) = {sys_halt, sys_exit, sys_exec, sys_wait,
	sys_create, sys_remove, sys_open, sys_filesize, sys_read, sys_write, sys_seek, sys_tell, sys_close};

  /* need to find a way to see which functions return a value and set f->eax to it */
  /* funcs returning a value are sys_exec, sys_wait, sys_create, sys_remove,
  sys_open, sys_filesize, sys_read, sys_write, sys_tell */

  if ((* (int *) esp) < SYS_INUMBER)
  { /* checks that esp is an enum */
    (*sys_functions_arr[(* (int *) esp)])(f);
  }

  printf ("system call!\n");
  thread_exit ();
}
