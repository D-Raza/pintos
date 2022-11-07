#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
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

/* Terminates Pintos by calling 
   shutdown_power_off() 
*/
void halt (void);

/* Terminates the current user program and sends exit status to kernel.
   A status of 0 is a success.
*/
void exit (int status);

/* Runs executable whose name is given in the command line, 
   passing given args and returns the new process's pid
*/
pid_t 
exec (const char *cmd_line)
{
  /* TO DO */
  return NULL;
}

/* Waits for a child process pid and retrieves the child’s exit status.
 
   If pid is alive, waits until it terminates and returns the status 
   the pid passed to exit.
 
   If pid is terminated by the kernel without exiting, wait fails returns -1.
 
   If pid is not a direct child of the calling process, wait fails and returns –1.

   If the process calling wait has already called it, wait fails and returns -1*/
int wait (pid t pid)
{
  /* TO DO */
  return 0;
}

/* Creates a new file called file with size initial_size bytes.
   Returns true if successful and false otherwise. */
bool create (const char *file, unsigned initial_size)
{
  /* TO DO */
  return false;
}


/* Deletes file 
   Returns true if successful and false otherwise.
   If the file is currently open, it remains open after removal */
bool remove (const char *file)
{
  /* TO DO */
  return false;
}

/* Tries to open the file.
   If successful, the function returns -1.
   Otherwise, it returns the file descriptor. */
int open (const char *file)
{
  /* TO DO */
  return 0;
}

/* Returns the size, in bytes, of the file open as fd.*/
int filesize (int fd)
{
  /* TO DO */
  return 0;
}

/* Reads size bytes from the file open as fd into buffer */
int read (int fd, void *buffer, unsigned size)
{
  /* TO DO */
  return 0;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
   written, which may be less than size if some bytes could not be written */
int write (int fd, const void *buffer, unsigned size)
{
  /* TO DO */
  return 0;
}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes
from the beginning of the file. */
void seek (int fd, unsigned position);

/* Returns the position of the next byte to be read or written in open file fd */
unsigned tell (int fd)
{
  /* TO DO */
  return NULL;
}

/* Closes file descriptor fd.*/
void close (int fd);


