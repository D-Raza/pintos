#include "vm/page.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include <hash.h>
#include <string.h>
#include <stdio.h>

static bool spt_hash_less_func (const struct hash_elem *h1_raw, const struct hash_elem *h2_raw, void *aux);
static unsigned spt_hash_hash_func (const struct hash_elem *hash_elem, void *aux);
static struct sup_page_table_entry *find_spte (struct sup_page_table *sp_table, void *upage);
static bool spt_load_exec (struct sup_page_table_entry *spt_entry, void *kpage);
static void free_spt_entry (struct hash_elem *he, void *aux UNUSED);

/* Creates a supplementary page table. */
struct sup_page_table*
sup_page_table_create (void)
{
    struct sup_page_table *sp_table = (struct sup_page_table *) malloc (sizeof (struct sup_page_table));
    if (sp_table)
      {
        hash_init (&sp_table->hash_spt_table, spt_hash_hash_func, spt_hash_less_func, NULL);
        return sp_table;
      }
    else 
      {
        free (sp_table);
        return NULL;
      }
}

bool 
spt_load_handler (struct sup_page_table *sp_table, void *fault_addr, uint32_t *pd)
{ 
  /* Get the page entry at fault address */
  struct sup_page_table_entry *spt_entry = find_spte (sp_table, fault_addr);
  if (!spt_entry) 
    {
      return false;
    }
  
   /* Get a frame for the page */
  void *kpage = frame_get (PAL_USER);
  if (!kpage)
    {
      printf("2");
      return false;
    }
  
  /* Load the page into the frame */
  bool writable = true;
  switch (spt_entry->type)
    {
      case PAGE_ALL_ZERO:
        PANIC ("PAGE_ALL_ZERO not implemented");
        break;
      case PAGE_SWAP:
        PANIC ("PAGE_SWAP not implemented");
        break;
      case PAGE_EXEC:
        if (!spt_load_exec (spt_entry, kpage))
          {
            frame_free (kpage);
            return false;
          }
        writable = spt_entry->writable;
        break;
      case PAGE_MMAP:
        if (!spt_load_exec (spt_entry, kpage))
          {
            frame_free (kpage);
            return false;
	  }
	break;
      case PAGE_FRAME:
        break;
      default:
        NOT_REACHED ();
    }
  if (!pagedir_set_page (pd, fault_addr, kpage, writable))
    {
      frame_free (kpage);
      return false;
    }
  spt_entry->type = PAGE_FRAME;
  spt_entry->kpage = kpage;
  frame_install (kpage, fault_addr);
  pagedir_set_dirty (pd, fault_addr, false);
  return true;
}

/* Adds a page from an executable file to the supplementary page table. 
   Returns true if successful, false otherwise. */
bool 
spt_add_exec_page (struct sup_page_table *sp_table, void *upage, bool writable, struct file *file, off_t ofs, uint32_t read_bytes, uint32_t zero_bytes)
{
  struct sup_page_table_entry *spt_entry = malloc (sizeof (struct sup_page_table_entry));
  if (spt_entry)
    {
      spt_entry->type = PAGE_EXEC;
      spt_entry->upage = upage; 
      spt_entry->file = file;
      spt_entry->offset = ofs; 
      spt_entry->read_bytes = read_bytes;
      spt_entry->zero_bytes = zero_bytes;
      spt_entry->writable = writable;

      struct hash_elem *h = hash_insert (&sp_table->hash_spt_table, &spt_entry->hash_elem);
      if (!h)
        {
          return true;
        }
      else 
        {
          free (spt_entry);
          return false;
        }
    }
  else 
    {
      return false;
    }
}


bool
spt_add_mmap_page (struct sup_page_table *sp_table, void *upage, bool writable, struct file *file, off_t ofs, uint32_t read_bytes, uint32_t zero_bytes)
{
  struct sup_page_table_entry *spt_entry = malloc (sizeof (struct sup_page_table_entry));
  if (spt_entry)
    {
      spt_entry->type = PAGE_MMAP;
      spt_entry->upage = upage;
      spt_entry->file = file;
      spt_entry->offset = ofs;
      spt_entry->read_bytes = read_bytes;
      spt_entry->zero_bytes = zero_bytes;
      spt_entry->writable = writable;

      struct hash_elem *h = hash_insert (&sp_table->hash_spt_table, &spt_entry->hash_elem);
      if (!h)
        {
          return true;
        }
      else
        {
          free (spt_entry);
          return false;
        }
    }
  else
    {
      return false;
    }
}


/* Adds a page from frame to the supplementary page table. 
   Returns true if successful, false otherwise. */

bool 
spt_add_frame_page (struct sup_page_table *sp_table, void *upage, void *kpage)
{
  struct sup_page_table_entry *spt_entry = malloc (sizeof (struct sup_page_table_entry));
  if (spt_entry)
    {
      spt_entry->type = PAGE_FRAME;
      spt_entry->upage = upage;
      spt_entry->kpage = kpage;

      struct hash_elem *h = hash_insert (&sp_table->hash_spt_table, &spt_entry->hash_elem);
      if (!h)
        {
          return true;
        }
      else 
        {
          free (spt_entry);
          return false;
        }
    }
  else 
    {
      return false;
    }
}

/* Frees a supplemental page table. */
void
free_sp_table (struct sup_page_table *sp_table)
{
  if (sp_table)
    {
      hash_destroy (&sp_table->hash_spt_table, free_spt_entry);
      free (sp_table);
    }
}

/* Frees a supplemental page table entry. */
static void
free_spt_entry (struct hash_elem *he, void *aux UNUSED)
{
  struct sup_page_table_entry *spt_entry = hash_entry (he, struct sup_page_table_entry, hash_elem);
  if (spt_entry)
    {
      switch (spt_entry->type)
        {
          case PAGE_ALL_ZERO:
            break;
          case PAGE_SWAP:
            break;
          case PAGE_EXEC:
            break;
          case PAGE_MMAP:
            break;
          case PAGE_FRAME:
            if (spt_entry->kpage)
              {
                frame_free (spt_entry->kpage);
              }
            break;
          default:
            NOT_REACHED ();
        }
      free (spt_entry);
    }
}

static bool 
spt_load_exec (struct sup_page_table_entry *spt_entry, void *kpage)
{
  file_seek (spt_entry->file, spt_entry->offset);
  if (file_read (spt_entry->file, kpage, spt_entry->read_bytes) != (int) spt_entry->read_bytes)
     {
       return false;
     }
  memset (kpage + spt_entry->read_bytes, 0, spt_entry->zero_bytes);
  return true;
}

static struct sup_page_table_entry*
find_spte (struct sup_page_table *sp_table, void *upage)
{
  struct sup_page_table_entry spte_aux = {.upage = upage};
  struct hash_elem *h = hash_find (&(sp_table->hash_spt_table), &(spte_aux.hash_elem));
  
  /* If the entry is found, return it, otherwise return NULL */
  if (h)
    {
      return hash_entry (h, struct sup_page_table_entry, hash_elem);
    }
  else 
    {
      return NULL;
    }
}

static bool 
spt_hash_less_func (const struct hash_elem *h1_raw, const struct hash_elem *h2_raw, void *aux UNUSED)
{   
    struct sup_page_table_entry *spte1 = hash_entry (h1_raw, struct sup_page_table_entry, hash_elem);
    struct sup_page_table_entry *spte2 = hash_entry (h2_raw, struct sup_page_table_entry, hash_elem);
    return (int) spte1->upage < (int) spte2->upage;
}

static unsigned 
spt_hash_hash_func (const struct hash_elem *hash_elem, void *aux UNUSED)
{
    struct sup_page_table_entry *spte = hash_entry (hash_elem, struct sup_page_table_entry, hash_elem);
    return hash_int ((int) spte->upage);
}
