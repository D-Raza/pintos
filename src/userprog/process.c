#include "userprog/process.h"
#include <debug.h>
#include <hash.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

#define MAX_CMDS_SIZE 4096

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static bool test_set (bool *b);
static void tokenize_args (char *file_name, char **argv);
static int get_argc (char *file_name);
static void push_to_stack (void *to_push, void **esp, bool is_str_push);
static void push_all_to_stack (char **argv, int argc, struct intr_frame *if_);
static int calc_total_size(char **argv, int argc);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmd) 
{
  char *cmd_copy;
  tid_t tid = TID_ERROR;

  struct thread *cur = thread_current ();
  struct wait_handler *wh = malloc (sizeof (struct wait_handler));

  if (wh) 
    {
      sema_init (&wh->wait_sema, 0);
      wh->tid = TID_ERROR;
      wh->destroy = 0;
      wh->exit_status = -1;
      list_push_back (&cur->child_processes, &wh->elem);

      char *save_ptr;
      cmd_copy = palloc_get_page (0);
      if (cmd_copy == NULL)
        {
          return TID_ERROR;
        }
      strlcpy (cmd_copy, cmd, PGSIZE);

      char *cmd_copy_2 = malloc(strlen(cmd) + 1);
      strlcpy (cmd_copy_2, cmd, strlen(cmd) + 1);
      char *file_name = strtok_r (cmd_copy_2, " ", &save_ptr);

      ASSERT (file_name != NULL);

      if (strlen (file_name) > 14)
        {
          return TID_ERROR;
        }

      file_sys_lock_acquire ();
      if (!filesys_open (file_name))
        {
          file_sys_lock_release ();
          return TID_ERROR;
        }
      file_sys_lock_release ();
      struct process_start_aux *psa = malloc (sizeof (struct process_start_aux));
      psa->filename = cmd_copy;
      psa->wait_handler = wh;
      tid = thread_create (file_name, PRI_DEFAULT, start_process, psa);

      if (tid != TID_ERROR)
        {
          free (cmd_copy_2);
          wh->tid = tid;
          sema_down (&psa->wait_handler->wait_sema);
          if (wh->tid == TID_ERROR)
            {
              list_remove (&wh->elem);
              if (test_set (&wh->destroy))
                {
                  free (wh);
                }
              tid = TID_ERROR;
            }
        }
      else 
        {
          palloc_free_page (cmd_copy);
        }  
    } 
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *psa_)
{
  struct process_start_aux *psa = psa_;
  char *file_name = (char *) psa->filename;
  struct intr_frame if_;
  bool success;

  /* Count the number of arguments */
  int argc = get_argc (file_name);

  /* Tokenize file_name into an array of strings */
  char *tokens[argc];
  tokenize_args (file_name, tokens);

  /* Check if number of args is a suitable amount (less than some macro) */
  /* If not, then free, and kill */
  if (calc_total_size(tokens, argc) > 1000) 
    {
      palloc_free_page (file_name);
      thread_exit ();
    }
  
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (tokens[0], &if_.eip, &if_.esp);

  thread_current ()->wait_handler = psa->wait_handler;
  if (!success)
    {
      psa->wait_handler->tid = TID_ERROR;
    }
  sema_up (&psa->wait_handler->wait_sema);

  /* If file loaded successfully, set up stack */
  if (success)  
    {
      /* Push args on stack in reverse order */
      /* Push argv[argc] = NULL (a null pointer) */  
      /* In reverse order, push pointers to args on stack */
      /* Push a pointer to the first pointer */
      /* Push number of args: argc */
      /* Push a fake return address (0) */
      /* All handled by push_all_to_stack */
    
      // set psa wait tid to current thread tid
      psa->wait_handler->tid = thread_current ()->tid;
      push_all_to_stack (tokens, argc, &if_);
    }
  

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) 
    {
      if (thread_current ()->pagedir == NULL)
        {
          if (test_set (&thread_current ()->wait_handler->destroy))
            {
              free (thread_current ()->wait_handler);
            }
        }
      thread_exit ();
    }
  
  free (psa);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status. 
 * If it was terminated by the kernel (i.e. killed due to an exception), 
 * returns -1.  
 * If TID is invalid or if it was not a child of the calling process, or if 
 * process_wait() has already been successfully called for the given TID, 
 * returns -1 immediately, without waiting.
 * 
 * This function will be implemented in task 2.
 * For now, it does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct list *child_processes = &thread_current ()->child_processes;
  struct wait_handler *child_process;

  for (struct list_elem *e = list_begin (child_processes); 
        e != list_end (child_processes); 
        e = list_next (e)) {
      child_process = list_entry (e, struct wait_handler, elem);
      if (child_process->tid == child_tid)
        {
          if (!child_process)
            {
              return -1;
            }
          sema_down (&child_process->wait_sema);
	        int exit_status = child_process->exit_status;
	        list_remove(&child_process->elem);
          if (test_set(&child_process->destroy))
            {
              free (child_process);
            }
          return exit_status;
        }
  }
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  #ifdef VM
  
  free_mmap_table (cur->mmaped_files);
  
  /* Free:
     The supplemental page table
     The mmap table(?) later
     All supplemental page table entries
     All frames held by the process
  */

  /* Free the supplemental page table and all frames held by the process */
  free_sp_table (cur->sup_page_table);
  #endif


  /* Free all processes in the child_processes list */
  while (!list_empty (&cur->child_processes)) 
    {
      struct wait_handler *child_process = list_entry 
                          (list_pop_front (&cur->child_processes), struct wait_handler, elem);
      if (test_set(&child_process->destroy))
        {
	        free (child_process);
        }
    }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      printf("%s: exit(%d)\n", cur->name, cur->wait_handler->exit_status);

      sema_up (&cur->wait_handler->wait_sema);

      if (test_set(&cur->wait_handler->destroy))
        {
          free(cur->wait_handler);
        }


      /* Iterate through all open files and close them. */
      while (!list_empty (&cur->open_fds)) 
        {
          struct fd_to_file_mapping *map = list_entry 
                    (list_pop_front (&cur->open_fds), struct fd_to_file_mapping, elem);
          if (map->file_struct != NULL)
            {
              file_sys_lock_acquire ();
              file_close (map->file_struct);
              file_sys_lock_release ();
            }
          list_remove (&map->elem);
          free (map);
        }
      
      file_sys_lock_acquire ();
      file_close (cur -> exe);
      file_sys_lock_release ();

      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate supplemental page table */
  #ifdef VM
  t->sup_page_table = sup_page_table_create ();
  t->mmaped_files = mmaped_files_table_create ();
  #endif

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file_sys_lock_acquire ();
  file = filesys_open (file_name);
  file_sys_lock_release ();
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  file_sys_lock_acquire ();
  file_deny_write (file);
  file_sys_lock_release ();

  
  /* Read and verify executable header. */
  file_sys_lock_acquire ();
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      file_sys_lock_release ();
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }
  file_sys_lock_release ();

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      file_sys_lock_acquire ();
      if (file_ofs < 0 || file_ofs > file_length (file))
        {
          file_sys_lock_release ();
          goto done;
        }
      file_sys_lock_release ();

      file_sys_lock_acquire ();
      file_seek (file, file_ofs);
      file_sys_lock_release ();

      file_sys_lock_acquire ();
      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        {
          file_sys_lock_release ();
          goto done;
        }
      file_sys_lock_release ();

      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
  t->exe = file;
  success = true;
  return success;

 done:
  file_sys_lock_acquire ();
  file_close (file);
  file_sys_lock_release ();
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  file_sys_lock_acquire ();
  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    {
      file_sys_lock_release ();
      return false;
    }
  file_sys_lock_release ();

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_sys_lock_acquire ();
  file_seek (file, ofs);
  file_sys_lock_release ();
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      /* Check if virtual page already allocated */
      struct thread *t = thread_current ();

#ifdef VM
      /* Lazy loading of page */
      
      /* If page already mapped, delete entry and rewrite loading data */   
      struct sup_page_table_entry spte_aux = {.upage = upage};
      hash_delete (&(t->sup_page_table->hash_spt_table), &(spte_aux.hash_elem));


      bool result = spt_add_exec_page (t->sup_page_table, upage, writable, file, ofs, page_read_bytes, page_zero_bytes);
      if (!result)
        {
          return false;
        }

#else

      uint8_t *kpage = pagedir_get_page (t->pagedir, upage);
      
      if (kpage == NULL){
        
        /* Get a new page of memory. */
        kpage = palloc_get_page (PAL_USER);
        if (kpage == NULL){
          return false;
        }
        
        /* Add the page to the process's address space. */
        if (!install_page (upage, kpage, writable)) 
          {
            palloc_free_page (kpage);
            return false; 
          } 
      } 

      else 
        {
          /* Check if writable flag for the page should be updated */
          if(writable && !pagedir_is_writable(t->pagedir, upage))
            {
              pagedir_set_writable(t->pagedir, upage, writable); 
            }
        }

      /* Load data into the page. */
      file_sys_lock_acquire ();
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          file_sys_lock_release ();
          return false; 
        }
      file_sys_lock_release ();

      memset (kpage + page_read_bytes, 0, page_zero_bytes);

#endif

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      #ifdef VM
      ofs += PGSIZE;
      #endif
    }

  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. 
   With VM only called for initial stack page */

static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();
  uint32_t *pd = t->pagedir;

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  bool result = !(pagedir_get_page (pd, upage)) && pagedir_set_page (pd, upage, kpage, writable);
  
  #ifdef VM
  result &= spt_add_frame_page (t->sup_page_table, upage, kpage);
  frame_install (kpage, upage, NULL);
  #endif

  return result;
}

/* Tokenizes the args into the array argv */
static void 
tokenize_args(char *file_name, char **argv) 
  {
    /* Use strlcpy to prevent mutation of original *file_name */
    char *file_name_copy = malloc(strlen(file_name) + 1);
    strlcpy (file_name_copy, file_name, strlen(file_name) + 1);
    char *token, *save_ptr;
    int i = 0;

    for (token = strtok_r(file_name_copy, " ", &save_ptr); token != NULL; 
         token = strtok_r(NULL, " ", &save_ptr)) 
      {
        argv[i] = token;
        i++;
      }
  } 

/* Returns the number of arguments + filename */
static int
get_argc (char *file_name)
  {
    /* Use strlcpy to prevent mutation of original *file_name */
    char *file_name_copy = malloc(strlen(file_name) + 1);
    strlcpy (file_name_copy, file_name, strlen(file_name) + 1);
    
    char *token, *save_ptr;

    /* Initialise the number of arguments to 0 */
    int argc = 0;

    /* Iterate through the tokens, splitting at spaces, and increment the number of arguments */
    for (token = strtok_r (file_name_copy, " ", &save_ptr); token != NULL;
         token = strtok_r (NULL, " ", &save_ptr)) 
      {
        argc++;
      }
    return argc; 
  }

static void 
push_to_stack (void *to_push, void **esp, bool is_str_push) {
   if (is_str_push) 
    {
      int size = strlen(to_push) + 1;
      *esp -= size;
      strlcpy ((char *) *esp, to_push, size);
    } 
   else 
    {
      *esp -= sizeof(to_push);
      * (void **) *esp = to_push;
    }
 }

/* Pushes all that is required onto the stack:
   1. arguments in reverse order
   2. A null pointer sentinel (0)
   3. Push pointers to args, in reverse order
   4. Push a pointer to the first pointer
   5. Push the number of arguments
   6. Push a fake return address (0) */

static void
push_all_to_stack (char **argv, int argc, struct intr_frame *if_) 
{
  void **esp = &if_->esp; 

  char *arg_ptrs[argc];

  /* Word-align stack */
  *esp -= (unsigned int) *esp % WORD_SIZE;

  /* Push the arguments, one by one, in reverse order */
  int count = argc - 1;
  while (count >= 0) 
    {
      push_to_stack(argv[count], esp, true);
      arg_ptrs[count] = *esp;
      count--;
    }

  /* Move esp so that the address is word-aligned */ 
  *esp -= (unsigned int) *esp % WORD_SIZE;

  /* Push sentinel entry */
  push_to_stack((void*) 0x00000000, esp, false);

  /* Push pointers to the arguments, one by one, in reverse order */
  count = argc - 1;
  while (count >= 0) 
    {
      push_to_stack(arg_ptrs[count], esp, false);      
      count--;
    }

  /* Push the pointer to the first pointer in argv, (esp at the time of calling) */
  push_to_stack(*esp, esp, false);

  /* Push the number of arguments */
  push_to_stack((void *) argc, esp, false);

  /* Push fake return address */
  push_to_stack((void *) FAKE_ADDRESS, esp, false);
}


static bool
test_set (bool *b) 
{
  return __sync_lock_test_and_set (b, true);
}


/* Calculates the total size that needs to be allocated in the stack for an argument passing operation */
static int
calc_total_size(char **argv, int argc) {
  int total_size = 0;
  const int MAX_SIZE_FOR_WORD_ALIGNMENT = 3;
  const int ESP_PTR_SIZE = 8;

  /* Add the sizes of the arguments */
  int count = argc - 1;
  while (count >= 0) {
    total_size += strlen(argv[count]);
    count--;
  }

  /* Add the maximum size needed in the stack for word-alignment after pushing the argument names to the stack */
  total_size += MAX_SIZE_FOR_WORD_ALIGNMENT;

  /* Add the size of the sentinel entry */
  total_size += sizeof(0x00000000);

  /* Add the size of the pointer to the first pointer in argv */
  total_size += sizeof(ESP_PTR_SIZE);

  /* Add the size of the pointers to the arguments */
  total_size += (argc * (ESP_PTR_SIZE));

  /* Add the size of the number of arguments */
  total_size += sizeof(argc);

  /* Add the size of the fake return address */
  total_size += sizeof(0xD0C0FFEE);

  return total_size;
}
