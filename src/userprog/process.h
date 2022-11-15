#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/file.c"
#include "threads/thread.h"
#include "threads/synch.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#define MAX_ARG_LIMIT 140
#define WORD_SIZE 4

/* Process struct */
struct wait_handler
{
  tid_t tid;                    /* tid of the process */
  struct semaphore wait_sema;   /* Semaphore for waiting for process to die. 1 = child alive, 0 = child dead.  */
  int exit_status;              /* Exit status */
  bool destroy;                 /* Whether to free */
  struct list_elem elem;        /* List element */
};

struct process_start_aux
{
  void *filename;
  struct wait_handler* wait_handler;
};

struct fd_to_file_mapping {
  int fd;                        /* file descriptor */
  struct file file_struct;       /* file struct corresponding to fd */
  struct list_elem elem;         /* List element */
};

#endif /* userprog/process.h */
