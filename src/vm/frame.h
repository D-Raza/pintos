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
    struct list page_table_refs;  /* User pages that refer to the same frame (aliases) */  
    struct hash_elem hash_elem;   /* Hash table element */
    struct list_elem list_elem;   /* List element for eviction */
    bool evictable;               /* Whether the frame is evictable */
};

struct page_table_ref 
{
    void *pd;                     /* Page directory of the thread that owns the page */
    void *page;                   /* User page corresponding to pd */
    struct list_elem elem;        /* List Elem */
};

void frame_init (void);
void frame_free (void *kpage);

void* frame_get (enum palloc_flags f);
void frame_install (void *kpage, void *upage);


#endif /* vm/frame.h */