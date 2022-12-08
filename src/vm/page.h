#ifndef PAGE_H
#define PAGE_H

#include <hash.h>
#include "filesys/off_t.h"
#include "filesys/file.h"


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

    /* Members for executable files */
    uint32_t read_bytes;           /* Number of bytes to read from file */
    uint32_t zero_bytes;           /* Number of bytes to zero out */
    bool writable;                 /* Writable page? */
    struct file *file;             /* File pointer */
    off_t offset;                  /* Offset */

    /* For PAGE_SWAP */
    size_t swap_slot ;             /* Swap slot */
};

struct sup_page_table 
{
    struct hash hash_spt_table;           /* The hash table*/
};
struct mmaped_files_table
{
    int next_free_mapId;                /* Counter to generate new MapIds */
    struct hash mmaped_files;           /* Hashmap of mmaped files */
};

struct sup_page_table *sup_page_table_create (void);
struct mmaped_files_table *mmaped_files_table_create (void);
bool spt_add_file (struct sup_page_table *sp_table, void *upage, bool writable, struct file *file, off_t ofs, uint32_t read_bytes, uint32_t zero_bytes, enum page_type entry_type);
bool spt_add_frame_page (struct sup_page_table *sp_table, void *upage, void *page, bool writable);
bool spt_add_all_zero_page (struct sup_page_table *sp_table, void *upage);
bool spt_load_handler (struct sup_page_table *sp_table, void *fault_addr, uint32_t *pd, bool write);
void free_sp_table (struct sup_page_table *sp_table);
void free_mmap_table (struct mmaped_files_table *mmap_table);
bool spt_clear_entry (void *upage, bool last);
bool spt_save_page (uint32_t *pd, void *upage);
bool set_page_to_swap (struct sup_page_table *sp_table, void *upage, size_t swap_slot);

#endif /* vm/page.h */
