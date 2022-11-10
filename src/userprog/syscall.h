#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/* locks section that modifies files */
struct lock file_sys_lock;

void syscall_init (void);

#endif /* userprog/syscall.h */
