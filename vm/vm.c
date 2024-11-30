/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "lib/kernel/hash.h"

#include "vm/vm.h"
#include "vm/inspect.h"

static struct list frame_table;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init (); // 시스템 부팅 시 호출. VM과 관련된 설정
	vm_file_init (); // 시스템 부팅 시 호출. VM과 관련된 설정
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */

		/* [Pseudo]
		 * page 할당 -> malloc 이용 || uninit_new를 통해서 uninit를 상태로 가지는 페이지 만들기
		 * swap_in handler 설정 
		 * 초기화 함수(vm_initializer) 설정. page type에 따라, anon_initializer or. lazy_load_segment 
		 * spt에 field가 설정된 uninit페이지 추가 */
		struct page *page = (struct page *)malloc(sizeof(struct page));

		typedef bool (*initializerFunc)(struct page *, enum vm_type, void *);
		initializerFunc initializer = NULL;

		switch (VM_TYPE(type)) {
			case VM_ANON:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
		}

		uninit_new(page, upage, init, type, aux, initializer);
		page->writable = writable;

		return spt_insert_page(spt, page);

	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	/* [Pseudo]
	va에 해당하는 값이 spt에 있는 지 확인.
	  (true) -> 해당 페이지 반환
	  (false) -> NULL 반환

	  uint64_t hash_va = hash_bytes(va, sizeof(va)) -> 해시 값을 얻고,
	  spt -> hash -> buckets ... -> 여기서 해시값에 해당하는 위치 찾고 (이걸 어떻게 할지 조금 애매모호...)
      있으면? 해당 hash_elem을 &로, 참조해서 해당 페이지 반환.
	  없으면... NULL 반환
	 */
	struct page *page = (struct page *)malloc(sizeof(struct page)); // 가상 주소에 대응하는 해시 값 도출을 위해 새로운 페이지 할당
	page->va = pg_round_down(va); // 가상 주소의 시작 주소를 페이지의 va에 복제
	struct hash_elem *e = hash_find(&spt->spt_hash, &page->hash_elem); // spt hash 테이블에서 hash_elem과 같은 hash를 갖는 페이지를 찾아서 return
	free(page); // 복제한 페이지 삭제

	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	/* [Pseudo]
	spt에 va가 있는 지 확인.
	(true) -> 페이지 insert가 일어나선 안되겠지
	(false) -> spt에 va에 해당하는 페이지 할당

	사전 : spt_find_page()를 통해 va로 할당된 페이지 유무를 확인.
	(있다면) ..?
	(없다면) page->hash_elem을 통해 해시값을 찾고, 
	       해시값의 위치에 해당되는 supplemental page table 위치에 insertion을 한다.
	(결론) 성공 결과를 반환한다.
	 */

	return hash_insert(&spt->spt_hash, &page->hash_elem) ? false : true;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. 제거할 프레임을 넘기는 것.*/
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	struct thread *curr = thread_current();

	struct list_elem *e = list_begin(&frame_table);
	for (e; e != list_end(&frame_table); e = list_next(e)) {
		victim = list_entry(e, struct frame, frame_elem);
		if (pml4_is_accessed(curr->pml4, victim->page->va))
			pml4_set_accessed(curr->pml4, victim->page->va, false);
		else
			return victim;
	}
	return list_entry(list_begin(&frame_table), struct frame, frame_elem);
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim (); // 제거할 프레임을 선택하는 함수 vm_get_victim ^
	/* TODO: swap out the victim and return the evicted frame. */
	/* Pseudo code: 선언했던 frame_table에서, 제일 앞에 있는 frame 주소를 반환? */
	
	if (victim->page) // 해당 프레임에 페이지가 연결되어 있다면 swap_out을 시킨다. - 디스크의 swap 영역으로 보내는 함수.
		swap_out(victim->page);

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.
 * palloc()을 사용하여 프레임을 할당. 만약 사용할 수 있는 페이지가 없다면, 페이지를 교체하여 프레임을 반환.
 * 이 함수는 항상 유효한 주소를 반환해야 한다. 
 * if, 사용자 풀 메모리가 가득 찬 경우 -> vm_evict_frame을 이용해서 사용 가능한 메모리 공간을 확보
 */
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
	/* pseudo code
	 * 남은 메모리가 있는지 확인
	 * (남아있다면) lazy_load_segment를 호출하면 되는거 아닌가? 
	 * (남아있지 않다면) vm_evict_frame을 호출하고, lazy_load_segment */

	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
	ASSERT(frame != NULL);
	
	frame->kva = palloc_get_page(PAL_USER | PAL_ZERO); // 유저 풀(PM)에서 페이지를 할당 받음. 또한, 할당 받은 페이지를 0으로 선언.

	if (frame->kva == NULL)
		frame = vm_evict_frame(); // swap out 실행
	else
		list_push_back(&frame_table, &frame->frame_elem); // frame 구조체에 frame_elem 추가.
	
	frame->page = NULL; // 현 시점에는, 아직 page랑 연결된 게 아니므로, 명시적으로 NULL을 넣어주어 이를 표현해준다.
	ASSERT (frame->page == NULL);

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
/** Project 3: Memory Management - Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = spt_find_page(&thread_current()->spt, addr);

    /* TODO: Validate the fault */
    if (addr == NULL || is_kernel_vaddr(addr))
        return false;

    return vm_do_claim_page(page);  // demand page 수행
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED) {
    /* TODO: Fill this function */
    struct page *page = spt_find_page(&thread_current()->spt, va);

    if (page == NULL)
        return false;

    return vm_do_claim_page(page);
}

/** Project 3: Memory Management - PAGE를 요청하고 mmu를 설정하십시오. */
static bool vm_do_claim_page(struct page *page) {
    struct frame *frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable))
        return false;

    return swap_in(page, frame->kva);  // uninit_initialize
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	/* [pseudo]
	아마도,,, virtual page entry 개수 만큼의 리스트 할당. 이를 통해 spt 초기화
	*/
	hash_init(&spt->spt_hash, hash_func, less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
