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
#include "threads/malloc.h"
#include <list.h>
#include <string.h>
#include <debug.h>

#ifdef VM
#include "vm/frame.h"
#endif

#define MAPID_ERROR -1

static void syscall_handler (struct intr_frame *);
static bool validate_string (const char *str);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static bool mem_try_read_buffer (const void *buffer, unsigned size);
static bool  mem_try_write_buffer (const void *buffer, unsigned size);
static struct fd_to_file_mapping* get_map (int fd);
static struct file* get_file (int fd);
static int get_new_fd (void);
static int sys_halt (int args[] UNUSED);
static int sys_exit (int args[]);
static pid_t sys_exec (int args[]);
static int sys_wait (int args[]);
static int sys_create (int args[]);
static int sys_remove (int args[]);
static int sys_open (int args[]);
static int sys_filesize (int args[]);
static int sys_read (int args[]);
static int sys_write (int args[]);
static int sys_seek (int args[]);
static int sys_tell (int args[]);
static int sys_close (int args[]);
static int sys_mmap (int args[]);
static int sys_munmap (int args[]);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_sys_lock);
}

/* helper function to acquire the file_sys_lock */
void 
file_sys_lock_acquire (void)
{
  lock_acquire (&file_sys_lock);
}

/* helper function to release the file_sys_lock */
void
file_sys_lock_release (void)
{
  lock_release (&file_sys_lock);
}

/* Returns true if the address to the string is a user address
   and successfully returns its byte value,
   false if the address of the string is a kernel address
   or a segfault occurred when reading the byte value.   */
static bool
validate_string (const char *str)
{
  if (get_user((void *) str) == -1 || !is_user_vaddr (str))
    {
      return false;
    }
  while (*str != '\0')
    {
      if (get_user((void *) str) == -1 || !is_user_vaddr (str))
        {
          return false;
        }
      str++;
    }
  return true;
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

/* Checks if a buffer can be safely read.
   Returns true if successful and false if the buffer is null, 
   not a user virtual address or there is a segfault when reading
   a byte from the buffer*/
static bool
mem_try_read_buffer (const void *buffer, unsigned size)
{
  const uint8_t *buff = buffer;
  if (!size) 
    {
      return true;
    }
  if (!is_user_vaddr (buff + size))
    {
      return false;
    } 
  for (uint8_t *p = (uint8_t *) ((uintptr_t)buff / PGSIZE * PGSIZE);
       p <= buff; p += PGSIZE)
    {
      if (get_user ((void *) p) == -1)
        {
          return false;
        }
    }
  return true;
}

/* Checks if a buffer can be safely written to.
   Returns true if successful and false if the buffer is null, 
   if the end of the buffer is a user virtual address or there
   is a segfault when writing a byte to the buffer */
static bool 
mem_try_write_buffer (const void *buffer, unsigned size)
{
  const uint8_t *buff = buffer;
  if (!is_user_vaddr (buff + size))
    {
      return false;
    }
  if (!size) 
    {
      return true;
    }
  for (uint8_t *p = (uint8_t *)(((uintptr_t)buff / PGSIZE) * PGSIZE);
       p <= buff; p += PGSIZE)
    {
      if (!put_user (p, get_user (p)))
        {
          return false;
        }
    }
  return true;
}

/* Gets the struct mapping a file descriptor to its corresponding file pointer. 
   Returns null if the list of mappings of open files is empty
   or if the mapping cannot be found. */
static struct fd_to_file_mapping*
get_map (int fd)
{
  struct list *fds = &thread_current ()->open_fds;
  if (list_empty (fds))
    return NULL;
  struct list_elem *e;
  for (e = list_begin (fds); e != list_end (fds); e = list_next (e)) {
    struct fd_to_file_mapping *map = list_entry (e, struct fd_to_file_mapping, elem);
    if (map->fd == fd)
      {
        return map;
      } 
    else if (map->fd > fd)
      {
        return NULL; /* as the list is ordered by ascending fd*/
      }
  }
  return NULL;
}

/* Gets the file corresponding to the file descriptor argument using get_map ().
   Returns null if there is no map corresponding to the file descriptor.*/
static struct file*
get_file (int fd)
{
  struct fd_to_file_mapping *map = get_map (fd);
  if (map != NULL)
    {
      return map->file_struct;
    }
  return NULL;
}

/* Returns value of the next file descriptor available to use 
and sets it in the thread struct*/
static int get_new_fd (void)
{
  thread_current () -> next_free_fd++;
  return thread_current () ->next_free_fd;
}

/* Terminates Pintos by calling 
   shutdown_power_off() 
*/
static int 
sys_halt (int args[] UNUSED)
{
  shutdown_power_off();
  return 0;
}

/* Terminates the current user program and sends exit status to kernel.
   A status of 0 is a success.
*/
static int 
sys_exit (int args[])
{
  int status = args[0];

  thread_current ()->wait_handler->exit_status = status;
  thread_exit ();
  return 0;
}

/* Runs executable whose name is given in the command line, 
   passing given args and returns the new process's pid
*/
static pid_t 
sys_exec (int args[])
{
  const char *cmd_line = (const char *) args[0];
  if (!validate_string (cmd_line))
    {
      thread_exit ();
    }
  else 
    {
      return process_execute (cmd_line);
    }
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
  return process_wait (pid); 
}

/* Creates a new file called file with size initial_size bytes.
   Returns true if successful and false otherwise. */
static int 
sys_create (int args[])
{
  const char *file_name = (const char *) args[0];
  unsigned initial_size = (unsigned) args[1];

  if (!validate_string (file_name))
    {
      thread_exit ();
    }

  if (file_name == NULL)
    {
      return false;
    }

  /* Create new file struct containing file, which adds file to directory */
  file_sys_lock_acquire ();
  bool created = filesys_create (file_name, initial_size);
  file_sys_lock_release (); 
  return created; // as false is equivalent to 0 in c
}


/* Deletes file 
   Returns true if successful and false otherwise.
   If the file is currently open, it remains open after removal */
static int 
sys_remove (int args[])
{
  const char *file_name = (const char *) args[0];
  if (!validate_string (file_name))
    {
      thread_exit ();
    }
  file_sys_lock_acquire ();
  bool removed = filesys_remove (file_name);
  file_sys_lock_release ();
  return removed;
}

/* Tries to open the file.
   If successful, the function returns the file descriptor.
   Otherwise, it returns -1. */
static int 
sys_open (int args[])
{
  const char *file_name = (const char *) args[0];
  if (!validate_string (file_name))
    {
      thread_exit ();
    }
  file_sys_lock_acquire ();
  struct file *file = filesys_open (file_name);
  file_sys_lock_release ();
  if (file == NULL) {
    return -1;
  }
  struct fd_to_file_mapping *mapping = malloc (sizeof (struct fd_to_file_mapping));
  mapping->fd = get_new_fd ();
  mapping->file_struct = file;
  list_push_back (&thread_current ()->open_fds, &mapping->elem);
  return mapping->fd;
}

/* Returns the size, in bytes, of the file open as fd.*/
static int 
sys_filesize (int args[])
{
  int fd = args[0];
  struct file *fd_file = get_file (fd);
  file_sys_lock_acquire ();
  int size = file_length (fd_file);
  file_sys_lock_release ();
  return size;
}

/* Reads size bytes from the open file fd into buffer 
   and returns the number of bytes read into buffer.
   Returns -1 if reading from stdout (fd = 1) or
   if the file pointer is null*/
static int
sys_read (int args[])
{
  int fd = args[0];
  void *buffer = (void *) args[1];
  unsigned size = (unsigned) args[2];
  int read_size = 0;

  if (fd == STDOUT_FILENO)
    {
      return -1;
    }
  if (fd == STDIN_FILENO)
    {
      file_sys_lock_acquire ();
      uint8_t *local_buffer = (uint8_t *) buffer;
      for (int i = 0; i < (int) size; i++){
        local_buffer[i] = input_getc ();
      } 
      file_sys_lock_release ();
      return size;    
    }
  else 
    {
    struct file *fd_file = get_file (fd);
    if (!fd_file){
      return -1;
    }
    if (!mem_try_write_buffer (buffer, size))
      {
        thread_exit ();
      }
    file_sys_lock_acquire ();
    read_size = file_read (fd_file, buffer, size);
    file_sys_lock_release ();
    }
    return read_size;
}

/* Writes size bytes from buffer into open file fd
   and returns the number of bytes written from buffer.
   Returns -1 if the file descriptor is reading from stdout (fd is 1)
   or if the file pointer is null. */
static int 
sys_write (int args[])
{
  int fd = (int) args[0];
  const void *buffer = (const void *) args[1];
  unsigned size = (unsigned) args[2];
  int written_size = 0;

  if (fd == STDIN_FILENO)
    {
      return -1;
    }
  else if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, size - written_size);
      written_size = size;
      return written_size;
    }
  else {
    struct file *fd_file = get_file (fd);
    if (!fd_file){
      return -1;
    }
    if (!mem_try_read_buffer (buffer, size))
      {
        thread_exit ();
      }
    file_sys_lock_acquire ();
    written_size = file_write (fd_file, buffer, size);
    file_sys_lock_release ();
    return written_size;
  }
}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes
from the beginning of the file. */
static int
sys_seek (int args[]) 
{
  int fd = args[0];
  unsigned position = (unsigned) args[1];
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO){
    return -1;
  }
  struct file *fd_file = get_file (fd);
  if (!fd_file){
    return -1;
  }
  file_sys_lock_acquire ();
  file_seek (fd_file, position);
  file_sys_lock_release ();
  return 0;
}

/* Returns the position of the next byte to be read or written in open file fd */
static int 
sys_tell (int args[])
{
  int fd = args[0];
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
    {
      return -1;
    }
  struct file *fd_file = get_file (fd);
  if (!fd_file)
    {
      return -1;
    }
  file_sys_lock_acquire ();
  int position = file_tell (fd_file);
  file_sys_lock_release ();
  return position;
}

/* Closes file descriptor fd.*/
static int 
sys_close (int args[])
{
  int fd = args[0];
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
    {
      return -1;
    }
  struct fd_to_file_mapping *map = get_map (fd);
  if (map != NULL)
    {
      file_sys_lock_acquire ();
      file_close (map->file_struct);
      file_sys_lock_release ();
      list_remove (&map->elem);
      free (map);
    }
  return 0;
}

#ifdef VM

/* Returns value of the next mapId available to use 
and sets it in the thread struct*/
static int get_new_mapId (void)
{
  thread_current () -> next_free_mapId++;
  return thread_current () ->next_free_mapId;
}

/* Gets the struct mapping a mapId to its addresses. 
   Returns null if the list of mappings of open files is empty
   or if the mapping cannot be found. */
static struct mmap_file*
get_mmap_file (int mapId)
{
  struct list *mapIds = &thread_current ()->mmaped_files;
  if (list_empty (mapIds))
    return NULL;
  struct list_elem *e;
  for (e = list_begin (mapIds); e != list_end (mapIds); e = list_next (e)) {
    struct mmap_file *map = list_entry (e, struct mmap_file, elem);
    if (map->mapId == mapId)
      {
        return map;
      }
    else if (map->mapId > mapId)
      {
        return NULL; /* as the list is ordered by ascending fd*/
      }
  }
  return NULL;
}

/*  Maps the file open as fd into the process's consecutive 
    virtual memory pages starting at addr */
static int 
sys_mmap (int args[])
{
  int fd = args[0];
  void *addr = (void *) args[1];
  void *last_addr;
  struct thread *t = thread_current ();
  /* Validate fd and file */
  struct file *fd_file = get_file (fd);
  if (fd_file == NULL)
  {
    return MAPID_ERROR;
  } 
  file_sys_lock_acquire ();
  int file_size = file_length (fd_file);
  file_sys_lock_release ();
  if (file_size == 0)
  {
    return MAPID_ERROR;
  }
  /* Validate addr: not 0, page-aligned and clear range*/
  if (addr == NULL || ((int) addr & 0x7) != 0)
  {
    return MAPID_ERROR;
  } else {
    last_addr = pg_round_down (addr + file_size - 1);
    // TODO: validate last page not in stackspace
    struct sup_page_table *spt = t->sup_page_table;
    for (void * i = addr; i <= last_addr; i += PGSIZE)
    {
      struct sup_page_table_entry spte_aux = {.upage = i};

      if (hash_find (&spt->hash_spt_table, &spte_aux.hash_elem)!= NULL)
      {
        return MAPID_ERROR;
      }
    }
  }

  /* Make entries in SPT */
  void *upage = addr;
  int ofs = 0;
  bool success = true;
  while (file_size > 0)
  {
    size_t page_read_bytes = file_size < PGSIZE ? file_size : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
   
    success &= spt_add_mmap_page (t->sup_page_table, upage, true, fd_file, ofs, page_read_bytes, page_zero_bytes);
    upage = (void *) ((int) upage + PGSIZE);
    ofs =+ PGSIZE;
    file_size -= PGSIZE;
  } 
  if (!success)
  {
    //TODO Add sufficient clean up
    return MAPID_ERROR;
  }
  /* Record mapping */
  struct mmap_file *mapping = malloc (sizeof (struct mmap_file));
  if (mapping == NULL)
  {
    thread_exit ();
  }
  int mapId = get_new_mapId ();
  mapping->mapId = mapId;
  mapping->first_upage = addr;
  mapping->last_upage = last_addr;

  list_push_back (&t->mmaped_files, &mapping->elem);

  return mapId;
}

/* Cleans up the mapping corresponding to the map entry and removes it from the list */
void
clean_mmap (struct mmap_file *entry)
{
  uint32_t *pd = thread_current ()->pagedir;
  for (void *i = entry->first_upage; i <= entry->last_upage; i += PGSIZE)
  {
    if (pagedir_is_dirty (pd, i))
    {
      spt_save_page (pd, i);
    }
    void *frame = pagedir_get_page (pd, i);
    if (frame != NULL)
    {
      frame_free (frame);
      pagedir_clear_page (pd, i);
    }
    bool last = (i == entry->last_upage);
    spt_clear_entry (i, last);
  } 
  list_remove (&entry->elem);
  free (entry);
}


/* Unmaps the mapping designated by mapping */
static int
sys_munmap (int args[])
{
  mapid_t mapping = args[0];

  struct mmap_file *map = get_mmap_file (mapping);
  clean_mmap (map);

  return 0;
}
#endif

/* Calls system calls by using an array of function pointers to them and maps 
   syscall number to the appropriate function and number of arguments.
   If esp cannot be read or the syscall number is not valid, thread_exit is called.  */
static void
syscall_handler (struct intr_frame *f)
{
  /* Array of function pointers to system calls */
  static const int (*sys_functions[SYS_MUNMAP + 1]) (int args[]) = {
    [SYS_HALT] = sys_halt,
    [SYS_EXIT] = sys_exit,
    [SYS_EXEC] = sys_exec,
    [SYS_WAIT] = sys_wait,
    [SYS_CREATE] = sys_create,
    [SYS_REMOVE] = sys_remove,
    [SYS_OPEN] = sys_open,
    [SYS_FILESIZE] = sys_filesize,
    [SYS_READ] = sys_read,
    [SYS_WRITE] = sys_write,
    [SYS_SEEK] = sys_seek,
    [SYS_TELL] = sys_tell,
    [SYS_CLOSE] = sys_close

    #ifdef VM
    ,
    [SYS_MMAP] = sys_mmap,
    [SYS_MUNMAP] = sys_munmap
    #endif
  };
  
  #ifdef VM
  int max_sys_call_no = SYS_MUNMAP;
  #else
  int max_sys_call_no = SYS_MUNMAP;
  #endif

  struct thread* cur = thread_current ();
  cur->syscall = true;

  if (!mem_try_read_buffer (f->esp, sizeof (int)))
    {
      thread_exit ();
    }
  int syscall_no = * (int *) f->esp;
   
  if (syscall_no >= 0 && syscall_no <= max_sys_call_no)
    {
      int *args = f->esp + 4;
      f->eax = (sys_functions[syscall_no])(args);
      cur->syscall = false;
    }
  else 
    {
      thread_exit ();
    }
}
