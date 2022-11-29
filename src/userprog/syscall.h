#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "filesys/file.h"
#include <list.h>

struct lock file_sys_lock;        /* locks section that modifies files */

struct fd_to_file_mapping {
  int fd;                         /* file descriptor */
  struct file *file_struct;       /* file struct corresponding to fd */
  struct list_elem elem;          /* List element */
};
void syscall_init (void);

void file_sys_lock_acquire (void); /* used to acquire file_sys_lock*/
void file_sys_lock_release (void); /* used to release file_sys_lock */

#ifdef VM
struct mmap_file {
  int mapId;                       /* mapID */
  void *first_upage;               /* start of virtual memory range allocated to the file */
  void *last_upage;                /* end of virtual memory range allocated to the file */
};
#endif

#endif /* userprog/syscall.h */
