/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

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

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = NULL;
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) { // kva; kernel virtual address
	/* Set up the handler */
	/* <Pseudo>
	 * 페이지가 지금 UNINIT으로 설정되어 있으니까, 이를 페이지 type에 따라서 다르게 설정해 줌. */
	struct uninit_page *uninit = &page->uninit; // page의 union중 하나에서 설정되어 있는 uninit을 가지고 옴.
	memset(uninit, 0, sizeof(struct uninit_page)); // vm에서 페이지를 차지하고 있는 대상 uninit page에 대해서 0으로 초기화.

	page->operations = &anon_ops; // uninit과 관련된 operations에서 anon_ops operation을 설정해 줌.

	struct anon_page *anon_page = &page->anon;// page union에서 UNINIT이 아니라, anon을 가리키도록 설정.
	
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
