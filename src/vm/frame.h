#ifndef FRAME_H
#define FRAME_H

#include "userprog/pagedir.h"

struct frame_table_entry
{
    void *kpage;                  /* Kernel virtual address of the page */
    void *upage;                  /* User virtual address of the page */
    uint32_t *pd;                  /* Page directory of the thread that owns the page */
    struct hash_elem hash_elem;   /* Hash table element */
    struct list_elem list_elem;   /* List element for eviction */
    bool evictable;               /* Whether the page is evictable */
};

/* Frees the frame at kpage */
static void *frame_get (void);

/* Frees the frame at kpage */
static void frame_free (void *kpage);

#endif /* vm/frame.h */