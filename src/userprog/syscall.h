#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "filesys/file.h"
#include <list.h>
/* locks section that modifies files */
struct lock file_sys_lock;

typedef int (*system_call)(int args[]);
struct syscalls
{
  system_call sys_call;
  int num_of_args;
};	

struct fd_to_file_mapping {
  int fd;                        /* file descriptor */
  struct file *file_struct;       /* file struct corresponding to fd */
  struct list_elem elem;         /* List element */
};
void syscall_init (void);

#endif /* userprog/syscall.h */
