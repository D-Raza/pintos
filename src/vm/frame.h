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
    struct shareable_page *shpage;/* Pointer to entry in sharable page table, null if page not shareable */
    struct list page_table_refs;  /* User pages that refer to the same frame (aliases) */  
    struct hash_elem hash_elem;   /* Hash table element */
    struct list_elem list_elem;   /* List element for eviction */
    bool evictable;               /* Whether the frame is evictable */
    struct thread *t;             /* Process that owns the frame */
    bool is_mmap;
};

struct page_table_ref 
{
    void *pd;                     /* Page directory of the thread that owns the page */
    void *page;                   /* User page corresponding to pd */
    struct list_elem elem;        /* List Elem */
};

struct shareable_page
{
    struct inode *file_inode;     /* Pointer to the file inode */
    off_t offset;                 /* Offset within the file */
    struct hash_elem elem;        /* Hash_elem for collection of shareable_pages */
    struct frame_table_entry *frame; /* Pointer to the corresponding frame table entry */
};

void frame_init (void);

void frame_free_process (void *kpage, uint32_t *pd, void *upage);
void frame_free (void *kpage);

void* frame_get (enum palloc_flags f);
void frame_install (void *kpage, void *upage, struct shareable_page *shpage, bool is_mmap);
void frame_augment (struct frame_table_entry* fte, uint32_t *pd, void *upage);

struct shareable_page* shareable_page_add (struct inode *file_inode, off_t offset);
struct frame_table_entry *find_shareable_page (struct inode *file_inode, off_t offset);

#endif /* vm/frame.h */
