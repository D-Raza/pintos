#ifndef FRAME_H
#define FRAME_H

#include <hash.h>
#include <list.h>
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

struct frame_table_entry
{
    void *kpage;                  /* Kernel virtual address of the page */
    void *upage;                  /* User virtual address of the page */
    uint32_t *pd;                  /* Page directory of the thread that owns the page */
    struct hash_elem hash_elem;   /* Hash table element */
    struct list_elem list_elem;   /* List element for eviction */
    bool evictable;               /* Whether the page is evictable */
};


void frame_init (void);
void frame_free (void *kpage);
void* frame_get (enum palloc_flags f, void *upage);


#endif /* vm/frame.h */