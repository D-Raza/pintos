#include "vm/page.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include <hash.h>

static bool spt_hash_less_func (const struct hash_elem *h1_raw, const struct hash_elem *h2_raw, void *aux);
static unsigned spt_hash_hash_func (const struct hash_elem *hash_elem, void *aux);
static struct sup_page_table_entry *find_spte (struct sup_page_table *sp_table, void *upage);

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

static struct sup_page_table_entry*
find_spte (struct sup_page_table *sp_table, void *upage)
{
  struct sup_page_table_entry spte_aux;
  spte_aux.upage = upage;
  struct hash_elem *h = hash_find (&sp_table->hash_spt_table, &spte_aux.hash_elem);
  
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

