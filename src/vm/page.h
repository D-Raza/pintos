#ifndef PAGE_H
#define PAGE_H

#include <hash.h>

enum page_type
  {
    PAGE_ALL_ZERO, /* All zero page*/
    PAGE_SWAP,     /* Swap page*/
    PAGE_EXEC,     /* Executable file */
    PAGE_MMAP,     /* Mapped to memory */
    PAGE_FRAME     /* On a frame */
  };

struct sup_page_table_entry 
{
    enum page_type type;           /* Type of page*/
    void *upage;                   /* User virtual address */
    void *kpage;                   /* Kernel page (used when type = PAGE_FRAME) */
    struct hash_elem hash_elem;    /* Page table entry */
    /* For PAGE_SWAP */
    // TODO:
};

struct sup_page_table 
{
    struct hash hash_spt_table;           /* The hash table*/
};

 
#endif /* vm/page.h */