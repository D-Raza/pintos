#include <hash.h>
#include <list.h>
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"


/* The frame table */
static struct hash frame_table;

/* A circular list of used frames for eviction (Two-Handed clock algorithm) */
static struct list used_frames_list; 
static struct list_elem *examine_ptr;
static struct list_elem *reset_ptr;

/* Lock for the frame table */
static struct lock frame_table_lock;


static unsigned frame_hash_hash_func (const struct hash_elem *h, void *aux UNUSED);
static bool frame_hash_less_func (const struct hash_elem *h1_raw, const struct hash_elem *h2_raw, void *aux UNUSED);
static struct frame_table_entry* find_frame (void *kpage);

/* Initialises the frame table and associated structs. */
void
frame_init (void)
{   
    hash_init (&frame_table, frame_hash_hash_func, frame_hash_less_func, NULL);
    list_init (&used_frames_list);
    lock_init (&frame_table_lock);
    // examine_ptr = list_begin (&used_frames_list);
    // reset_ptr = list_begin (&used_frames_list);
}

void 
frame_install (void *kpage, void *upage)
{
  #ifdef VM

  lock_acquire (&frame_table_lock);
  /* Add entry to the frame table */
  // void *kpage = frame_get (f);
  struct frame_table_entry *fte = malloc (sizeof (struct frame_table_entry));

  if (fte)
    {
      /* Initialise frame table entry */
      fte->kpage = kpage;
      fte->upage = upage;
      list_init (&fte->page_table_refs);
      fte->evictable = false;

      /* Initialise page_table_ref and add to list */
      struct page_table_ref *pgtr = malloc (sizeof (struct page_table_ref));
      if (!pgtr) {
        PANIC ("Malloc failed for page table ref"); 
      }
      pgtr->pd = thread_current ()->pagedir;
      pgtr->page = upage;
      list_push_back (&fte->page_table_refs, &pgtr->elem);

      /* Add entries to page table and frame table*/
      // pagedir_set_page (pgtr->pd, upage, kpage, writable);
      hash_insert (&frame_table, &fte->hash_elem);
      lock_release (&frame_table_lock);
    } 
  else 
    {
      lock_release (&frame_table_lock);
      PANIC ("Malloc failed for frame table entry");
    }

  #endif
}

void*
frame_get (enum palloc_flags f)
{   
    #ifndef VM
    return palloc_get_page (f);
    #else

    /* Try to get memory page */
    void *kpage = palloc_get_page(PAL_USER | f);
    
    if (kpage == NULL) 
      {
        /* Evict a page if there are no more pages */
        /* For now panic kernel */
        /* TODO: Eviction */
        PANIC ("No more memory pages");
      }
    else
      {
        return kpage;
      }
    #endif
}


/* Frees all frames from frame table belonging to a process */
void
free_frame_table (struct thread *t)
{
  #ifdef userprog
  struct hash *ftPointer = &frame_table;
  if (ftPointer)
    {
      for (int i = 0; i < (int) ftPointer->bucket_cnt; i++)
        {
          struct list *bucket = &ftPointer->buckets[i];
          struct list_elem *elem, *next;
          for (elem = list_begin (bucket);
              elem != list_end (bucket); elem = next)
            {
	      struct frame_table_entry *fp = list_entry (elem, struct frame_table_entry, list_elem);
	      struct hash_elem *table_entry = list_entry(elem, struct hash_elem, list_elem);
	      if (table_entry != NULL)
	        {
	          struct list *pgtrs = &fp -> page_table_refs;
	          struct list_elem *pgtr, *pgtr_next;
	          for (pgtr = list_begin (pgtrs); pgtr != list_end (pgtrs); pgtr = pgtr_next)
	            {
		      struct page_table_ref *pgt_ref = list_entry (pgtr, struct page_table_ref, elem);
	              if (&pgt_ref->pd == thread_current () ->pagedir)
		        {
	                  frame_free (&fp -> kpage);
	                }
	            }
                }
	     }
        }
     }
  #endif
}

void 
frame_free (void *kpage)
{   
    #ifndef VM
    palloc_free_page (kpage);
    #else

    lock_acquire (&frame_table_lock);

    /* Ensure kpage is valid */
    ASSERT (kpage != NULL);
    ASSERT (is_kernel_vaddr (kpage));

    /* Find frame table entry */
    struct frame_table_entry *ft_entry = find_frame (kpage);

    if (ft_entry)
      {
        /* Delete the entry from the frame table */
        struct hash_elem *he = hash_delete (&frame_table, &ft_entry->hash_elem);
        if (he)
          {
            /* Clear the page table entries pointing to the frame and free the structs */
            struct list *prs = &ft_entry->page_table_refs;
             while (!list_empty(prs))
               {
                 struct page_table_ref *pr = list_entry 
                      (list_pop_front (prs), struct page_table_ref, elem);
                  pagedir_clear_page(pr->pd, pr->page);
                  list_remove (&pr->elem);
                  free (pr);
               }
           
            // list_remove (&fte_actual->list_elem); 
            palloc_free_page (kpage);
            free (ft_entry);
          }
      }
    /* Release the lock */
    lock_release (&frame_table_lock);
    #endif
}

static struct frame_table_entry*
find_frame (void *kpage)
{
  struct frame_table_entry fte_aux = {.kpage = kpage};
  struct hash_elem *he = hash_find (&frame_table, &fte_aux.hash_elem);
  if (he)
    {
      return hash_entry (he, struct frame_table_entry, hash_elem);
    }
  else 
    {
      return NULL;
    }
}

static unsigned 
frame_hash_hash_func (const struct hash_elem *h, void *aux UNUSED)
{
    struct frame_table_entry *fte = hash_entry (h, struct frame_table_entry, hash_elem);
    return hash_int ((int) fte->kpage);
}

static bool
frame_hash_less_func (const struct hash_elem *h1_raw, const struct hash_elem *h2_raw, void *aux UNUSED)
{
    struct frame_table_entry *h1 = hash_entry (h1_raw, struct frame_table_entry, hash_elem);
    struct frame_table_entry *h2 = hash_entry (h2_raw, struct frame_table_entry, hash_elem);
    return h1->kpage < h2->kpage;
}
