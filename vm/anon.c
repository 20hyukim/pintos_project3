/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */
#include <bitmap.h>
#include <stdlib.h>

#include "threads/mmu.h"
#include "vm/vm.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

struct bitmap *swap_table;
size_t slot_max;

/* Initialize the data for anonymous pages */
void vm_anon_init(void) {
    /* TODO: Set up the swap_disk. */
    swap_disk = disk_get(1, 1);
    slot_max = disk_size(swap_disk) / SLOT_SIZE;
    swap_table = bitmap_create(slot_max);
}


/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    /* 데이터를 모두 0으로 초기화 */
    struct uninit_page *uninit = &page->uninit;
    memset(uninit, 0, sizeof(struct uninit_page));

    page->operations = &anon_ops;

    struct anon_page *anon_page = &page->anon;
    /** Project 3: Swap In/Out - ERROR로 초기화  */
    anon_page->slot = BITMAP_ERROR;

    return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
