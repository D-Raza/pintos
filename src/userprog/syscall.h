#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "filesys/file.h"
#include <list.h>
/* locks section that modifies files */
struct lock file_sys_lock;

struct fd_to_file_mapping {
  int fd;                        /* file descriptor */
  struct file *file_struct;      /* file struct corresponding to fd */
  struct list_elem elem;         /* List element */
};
void syscall_init (void);

void file_sys_lock_acquire (void);
void file_sys_lock_release (void);

#endif /* userprog/syscall.h */
