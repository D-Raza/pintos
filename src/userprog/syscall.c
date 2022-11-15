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
void validate_pointer (const void *vaddr, int args[]);

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
static int
get_stack_args (struct intr_frame *f,  int *args, int num_of_args)
{
  for (int i = 0; i < num_of_args; i++){
    int *pointer = (int *) (f->esp + i*4 + 4);
    validate_pointer ((const void *) pointer, args);
    args[i] = *pointer;
    // have some sort of error for invalid pointers
  }
  return 0;
}	

/* Terminates Pintos by calling 
   shutdown_power_off() 
*/
static int 
sys_halt (int args[]){
  shutdown_power_off();
  return 0;
}

/* Terminates the current user program and sends exit status to kernel.
   A status of 0 is a success.
*/
static int 
sys_exit (int args[]){
  int status = args[0];

  thread_current ()->wait_handler->exit_status = status;
  process_exit ();
  return 0;
}

/* Runs executable whose name is given in the command line, 
   passing given args and returns the new process's pid
*/
static pid_t 
sys_exec (int args[])
{
  const char *cmd_line = (const char *) args[0];

  // TODO

  return -1;
}

/* Waits for a child process pid and retrieves the child’s exit status.
 
   If pid is alive, waits until it terminates and returns the status 
   the pid passed to exit.
 
   If pid is terminated by the kernel without exiting, wait fails returns -1.
 
   If pid is not a direct child of the calling process, wait fails and returns –1.

   If the process calling wait has already called it, wait fails and returns -1*/
static int 
sys_wait (int args[])
{
  pid_t pid = args[0]; 
  // TODO
  return -1;
}

/* Creates a new file called file with size initial_size bytes.
   Returns true if successful and false otherwise. */
static int 
sys_create (int args[])
{
  const char *file = (const char *) args[0];
  unsigned initial_size = (unsigned) args[1];
  // TODO
  return 0; // as false is equivalent to 0 in c
}


/* Deletes file 
   Returns true if successful and false otherwise.
   If the file is currently open, it remains open after removal */
static int 
sys_remove (int args[])
{
  const char *file = (const char *) args[0];
  // TODO
  return 0;
}

/* Tries to open the file.
   If successful, the function returns -1.
   Otherwise, it returns the file descriptor. */
static int 
sys_open (int args[])
{
  const char *file = (const char *) args[0];
  // TODO
  return 0;
}

/* Returns the size, in bytes, of the file open as fd.*/
static int 
sys_filesize (int args[])
{
  int fd = args[0];
  // TODO
  return 0;
}

/* Reads size bytes from the file open as fd into buffer */
static int 
sys_read (int args[])
{
  int fd = args[0];
  void *buffer = (void *) args[1];
  unsigned size = (unsigned) args[2];
  // TODO
  int read_size = 0;
  return read_size;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
   written, which may be less than size if some bytes could not be written */
static int 
sys_write (int args[])
{
  int fd = (int) args[0];
  const void *buffer = (const void *) args[1];
  unsigned size = (unsigned) args[2];

  int written_size = 0;
  if (fd == STDOUT_FILENO){
    while (size > 300){
      putbuf (buffer, 300);
      buffer += 300;
      written_size += 300;
    }
    putbuf (buffer, size - written_size);
    written_size = size;
  }
  // TODO
  /*
  else {
        file_write (struct file *file, const void *buffer, off_t size)
	written_size = file_write (file, (const void *) args[1], (unsigned) args[2]);
  } */

  return written_size;
}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes
from the beginning of the file. */
static int
sys_seek (int args[]) {
  int fd = args[0];
  unsigned position = (unsigned) args[1];
  // TODO
  return 0;
}

/* Returns the position of the next byte to be read or written in open file fd */
static int 
sys_tell (int args[])
{
  int fd = args[0];
  
  // TODO
  return 0;
}

/* Closes file descriptor fd.*/
static int 
sys_close (int args[]){
  // TODO
  int fd = args[0];
  return 0;
}

void validate_pointer (const void *vaddr, int args[])
{
  if (vaddr < PHYS_BASE || !is_user_vaddr(vaddr)) 
  {
    sys_halt(args); // to change to sys_exit (currently unfinished)
  }
}

static void
syscall_handler (struct intr_frame *f)
{
  if (!FILESYS_LOCK_ACQUIRE)
  {
    lock_init(&file_sys_lock);
    FILESYS_LOCK_ACQUIRE = true;
  }

  struct syscalls sys_functions[] = {{sys_halt, 0}, {sys_exit, 1}, {sys_exec, 1}, {sys_wait, 1},
	  {sys_create, 2}, {sys_remove, 1}, {sys_open, 1}, {sys_filesize, 1}, {sys_read, 3},
	  {sys_write, 3}, {sys_seek, 2}, {sys_tell, 1}, {sys_close, 1}};

  /* funcs returning a value are sys_exec, sys_wait, sys_create, sys_remove,
  sys_open, sys_filesize, sys_read, sys_write, sys_tell */

  /* checks that esp is an enum */
  int syscall_no = * (int *) f->esp;
  if (syscall_no < SYS_INUMBER)
    {
      int args[sys_functions[syscall_no].num_of_args];
      get_stack_args(f, args, sys_functions[syscall_no].num_of_args);
      f->eax = (*sys_functions[syscall_no].sys_call)(args);
    }
}
