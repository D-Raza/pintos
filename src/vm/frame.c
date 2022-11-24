#include <hash.h>
#include <list.h>
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"


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
static void frame_free (void *kpage);

/* Initialises the frame table and associated structs. */
void
frame_init (void)
{   
    hash_init (&frame_table, frame_hash_hash_func, frame_hash_less_func, NULL);
    list_init (&used_frames_list);
    lock_init (&frame_table_lock);
}

static void*
frame_get (enum palloc_flags f, void *upage)
{
    /* Try to get memory page */
    void *kpage = palloc_get_page(PAL_USER);
    
    if (kpage == NULL) 
      {
        /* Evict a page if there are no more pages */
        /* For now panic kernel */
        /* TODO: Eviction */
        PANIC ("No more memory pages");
      }
    else
      {
        lock_acquire (&frame_table_lock);
        /* Add entry to the frame table */
        struct frame_table_entry *fte = malloc (sizeof (struct frame_table_entry));
        if (fte)
            {
                fte->kpage = kpage;
                fte->pd = thread_current ()->pagedir;
                fte->evictable = false;
                fte->upage = upage;
                
                hash_insert (&frame_table, &fte->hash_elem);
                return kpage;
            } 
        else 
          {
            lock_release (&frame_table_lock);
            return NULL;
          }
      }
}

static void 
frame_free (void *kpage)
{   
    lock_acquire (&frame_table_lock);

    /* Ensure kpage is valid */
    ASSERT (kpage != NULL);
    ASSERT (is_kernel_vaddr (kpage));

    /* Initialise a hash elem to lookup in frame table */
    struct frame_table_entry fte = {.kpage = kpage};
    struct hash_elem *hash_elem = hash_find (&frame_table, &fte.hash_elem);

    if (!hash_elem) {
        PANIC ("Trying to free a frame that is not in the frame table");
    }

    free (&fte);

    /* Find the actual frame table entry */
    struct frame_table_entry *fte_actual = hash_entry (hash_elem, struct frame_table_entry, hash_elem);
    
    /* Delete the frame table entry and remove it from the used frames list */
    hash_delete (&frame_table, &fte_actual->hash_elem);
    list_remove (&fte_actual->list_elem);

    /* Free the frame */
    free (fte_actual);
    palloc_free_page (kpage);

    /* Release the lock */
    lock_release (&frame_table_lock);
}






static unsigned 
frame_hash_hash_func (const struct hash_elem *h, void *aux UNUSED)
{
    struct frame_table_entry *fte = hash_entry (h, struct frame_table_entry, hash_elem);

}

static bool
frame_hash_less_func (const struct hash_elem *h1_raw, const struct hash_elem *h2_raw, void *aux UNUSED)
{
    struct frame_table_entry *h1 = hash_entry (h1_raw, struct frame_table_entry, hash_elem);
    struct frame_table_entry *h2 = hash_entry (h2_raw, struct frame_table_entry, hash_elem);
    return h1->kpage < h2->kpage;
}


