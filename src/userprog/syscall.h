#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/* locks section that modifies files */
struct lock file_sys_lock;

typedef int (*system_call)(int args[]);
struct syscalls
{
  system_call sys_call;
  int num_of_args;
};	


void syscall_init (void);

#endif /* userprog/syscall.h */
