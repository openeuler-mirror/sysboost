// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/sched/numa_balancing.h>
#include <linux/highmem.h>
#include <linux/hugetlb.h>
#include <linux/mmu_notifier.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/shrinker.h>
#include <linux/mm_inline.h>
#include <linux/swapops.h>
#include <linux/dax.h>
#include <linux/khugepaged.h>
#include <linux/freezer.h>
#include <linux/pfn_t.h>
#include <linux/mman.h>
#include <linux/memremap.h>
#include <linux/pagemap.h>
#include <linux/debugfs.h>
#include <linux/migrate.h>
#include <linux/hashtable.h>
#include <linux/userfaultfd_k.h>
#include <linux/page_idle.h>
#include <linux/shmem_fs.h>
#include <linux/oom.h>
#include <linux/numa.h>
#include <linux/page_owner.h>
#include <linux/dynamic_hugetlb.h>

#ifdef CONFIG_ARM64
#include <asm/tlb.h>
#endif
#include <asm/pgalloc.h>

#include "main.h"
#include "loader_device.h"

struct follow_page_context {
	struct dev_pagemap *pgmap;
	unsigned int page_mask;
};

struct page *follow_page_mask(struct vm_area_struct *vma,
			      unsigned long address, unsigned int flags,
			      struct follow_page_context *ctx);
vm_fault_t do_set_pmd(struct vm_fault *vmf, struct page *page);

#define proc_symbol(SYM)	typeof(SYM) *(SYM)
static struct global_symbols {
	proc_symbol(follow_page_mask);
	proc_symbol(__pud_alloc);
	proc_symbol(__anon_vma_prepare);
	proc_symbol(__pmd_alloc);
	proc_symbol(do_set_pmd);
#ifdef CONFIG_X86
	proc_symbol(__p4d_alloc);
	proc_symbol(pud_clear_bad);
#endif
} ppl_sym;

#define proc_symbol_char(x) #x
static char *global_symbol_names[] = {
	proc_symbol_char(follow_page_mask),
	proc_symbol_char(__pud_alloc),
	proc_symbol_char(__anon_vma_prepare),
	proc_symbol_char(__pmd_alloc),
	proc_symbol_char(do_set_pmd),
#ifdef CONFIG_X86
	proc_symbol_char(__p4d_alloc),
	proc_symbol_char(pud_clear_bad),
#endif
};

static int init_symbols(void)
{
	int ret;
	unsigned long *func_base = (unsigned long *)&ppl_sym;

	ret = do_init_symbols(func_base, global_symbol_names, ARRAY_SIZE(global_symbol_names));
	if (ret < 0)
		return ret;

	return 0;
}

static vm_fault_t __rto_do_huge_pmd_anonymous_page(struct vm_fault *vmf,
			struct page *page, gfp_t gfp)
{
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret = 0;

	VM_BUG_ON_PAGE(!PageCompound(page), page);

	if (debug)
		pr_info("vma->vm_start: %lx, vma->vm_end: %lx, vma->vm_pgoff: %lx\n",
			vma->vm_start, vma->vm_end, vma->vm_pgoff);
	ret = ppl_sym.do_set_pmd(vmf, page);
	return ret;
}

static inline int rto_anon_vma_prepare(struct vm_area_struct *vma)
{
	if (likely(vma->anon_vma))
		return 0;

	return ppl_sym.__anon_vma_prepare(vma);
}

vm_fault_t rto_do_huge_pmd_anonymous_page(struct vm_fault *vmf, struct page *hpage)
{
	struct vm_area_struct *vma = vmf->vma;
	gfp_t gfp;

	if (unlikely(rto_anon_vma_prepare(vma)))
		return VM_FAULT_OOM;

	return __rto_do_huge_pmd_anonymous_page(vmf, hpage, gfp);
}

static inline vm_fault_t create_huge_pmd(struct vm_fault *vmf, struct page *hpage)
{
	return rto_do_huge_pmd_anonymous_page(vmf, hpage);
}

static inline pud_t *rto_pud_alloc(struct mm_struct *mm, p4d_t *p4d,
		unsigned long address)
{
	return (unlikely(p4d_none(*p4d)) && ppl_sym.__pud_alloc(mm, p4d, address)) ?
		NULL : pud_offset(p4d, address);
}

static inline pmd_t *rto_pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && ppl_sym.__pmd_alloc(mm, pud, address))?
		NULL: pmd_offset(pud, address);
}

/*
 * By the time we get here, we already hold the mm semaphore
 *
 * The mmap_lock may have been released depending on flags and our
 * return value.  See filemap_fault() and __lock_page_or_retry().
 */
static vm_fault_t __rto_handle_mm_fault(struct vm_area_struct *vma,
		unsigned long address, unsigned int flags, struct page *hpage)
{
	struct vm_fault vmf = {
		.vma = vma,
		.address = address & PAGE_MASK,
		.flags = flags,
		.pgoff = linear_page_index(vma, address),
	};
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	vm_fault_t ret;

	pgd = pgd_offset(mm, address);
	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return VM_FAULT_OOM;

	vmf.pud = rto_pud_alloc(mm, p4d, address);
	if (!vmf.pud)
		return VM_FAULT_OOM;
retry_pud:
	vmf.pmd = rto_pmd_alloc(mm, vmf.pud, address);
	if (!vmf.pmd)
		return VM_FAULT_OOM;

	/* Huge pud page fault raced with pmd_alloc? */
	if (pud_trans_unstable(vmf.pud))
		goto retry_pud;

	// if (pmd_none(*vmf.pmd) && __transparent_hugepage_enabled(vma)) {
		ret = create_huge_pmd(&vmf, hpage);
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	// }
	

	return -ENOMEM;
}

/*
 * By the time we get here, we already hold the mm semaphore
 *
 * The mmap_lock may have been released depending on flags and our
 * return value.  See filemap_fault() and __lock_page_or_retry().
 */
static vm_fault_t rto_handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
	unsigned int flags, struct pt_regs *regs, struct page *hpage)
{
	vm_fault_t ret;

	__set_current_state(TASK_RUNNING);

	// TODO these 2 lines can be uncomment
	// count_vm_event(PGFAULT);
	// count_memcg_event_mm(vma->vm_mm, PGFAULT);

	/* do counter updates before entering really critical section. */

	/*
	 * Enable the memcg OOM handling for faults triggered in user
	 * space.  Kernel faults are handled more gracefully.
	 */
	if (flags & FAULT_FLAG_USER)
		mem_cgroup_enter_user_fault();

	ret = __rto_handle_mm_fault(vma, address, flags, hpage);

		/*
		 * The task may have entered a memcg OOM situation but
		 * if the allocation error was handled gracefully (no
		 * VM_FAULT_OOM), there is no need to kill anything.
		 * Just clean up the OOM state peacefully.
		 */

	return ret;
}

/*
 * mmap_lock must be held on entry.  If @locked != NULL and *@flags
 * does not include FOLL_NOWAIT, the mmap_lock may be released.  If it
 * is, *@locked will be set to 0 and -EBUSY returned.
 */
static int rto_faultin_page(struct vm_area_struct *vma,
	unsigned long address, unsigned int *flags, bool unshare, int *locked, struct page *hpage)
{
	unsigned int fault_flags = 0;
	vm_fault_t ret;

	/* mlock all present pages, but do not fault in new pages */
	if ((*flags & (FOLL_POPULATE | FOLL_MLOCK)) == FOLL_MLOCK)
		return -ENOENT;
	if (*flags & FOLL_WRITE)
		fault_flags |= FAULT_FLAG_WRITE;
	if (*flags & FOLL_REMOTE)
		fault_flags |= FAULT_FLAG_REMOTE;
	if (locked)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;
	if (*flags & FOLL_NOWAIT)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_RETRY_NOWAIT;
	if (*flags & FOLL_TRIED) {
		/*
		 * Note: FAULT_FLAG_ALLOW_RETRY and FAULT_FLAG_TRIED
		 * can co-exist
		 */
		fault_flags |= FAULT_FLAG_TRIED;
	}

	ret = rto_handle_mm_fault(vma, address, fault_flags, NULL, hpage);
	if (ret & VM_FAULT_ERROR) {
		int err = vm_fault_to_errno(ret, *flags);

		if (err)
			return err;
		BUG();
	}

	if (ret & VM_FAULT_RETRY) {
		if (locked && !(fault_flags & FAULT_FLAG_RETRY_NOWAIT))
			*locked = 0;
		return -EBUSY;
	}

	/*
	 * The VM_FAULT_WRITE bit tells us that do_wp_page has broken COW when
	 * necessary, even if maybe_mkwrite decided not to set pte_write. We
	 * can thus safely do subsequent page lookups as if they were reads.
	 * But only do so when looping for pte_write is futile: in some cases
	 * userspace may also be wanting to write to the gotten user page,
	 * which a read fault here might prevent (a readonly page might get
	 * reCOWed by userspace write).
	 */
	return 0;
}

/**
 * __get_user_pages() - pin user pages in memory
 * @mm:		mm_struct of target mm
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @gup_flags:	flags modifying pin behaviour
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long. Or NULL, if caller
 *		only intends to ensure the pages are faulted in.
 * @vmas:	array of pointers to vmas corresponding to each page.
 *		Or NULL if the caller does not require them.
 * @locked:     whether we're still with the mmap_lock held
 *
 * Returns either number of pages pinned (which may be less than the
 * number requested), or an error. Details about the return value:
 *
 * -- If nr_pages is 0, returns 0.
 * -- If nr_pages is >0, but no pages were pinned, returns -errno.
 * -- If nr_pages is >0, and some pages were pinned, returns the number of
 *    pages pinned. Again, this may be less than nr_pages.
 * -- 0 return value is possible when the fault would need to be retried.
 *
 * The caller is responsible for releasing returned @pages, via put_page().
 *
 * @vmas are valid only as long as mmap_lock is held.
 *
 * Must be called with mmap_lock held.  It may be released.  See below.
 *
 * __get_user_pages walks a process's page tables and takes a reference to
 * each struct page that each user address corresponds to at a given
 * instant. That is, it takes the page that would be accessed if a user
 * thread accesses the given user virtual address at that instant.
 *
 * This does not guarantee that the page exists in the user mappings when
 * __get_user_pages returns, and there may even be a completely different
 * page there in some cases (eg. if mmapped pagecache has been invalidated
 * and subsequently re faulted). However it does guarantee that the page
 * won't be freed completely. And mostly callers simply care that the page
 * contains data that was valid *at some point in time*. Typically, an IO
 * or similar operation cannot guarantee anything stronger anyway because
 * locks can't be held over the syscall boundary.
 *
 * If @gup_flags & FOLL_WRITE == 0, the page must not be written to. If
 * the page is written to, set_page_dirty (or set_page_dirty_lock, as
 * appropriate) must be called after the page is finished with, and
 * before put_page is called.
 *
 * If @locked != NULL, *@locked will be set to 0 when mmap_lock is
 * released by an up_read().  That can happen if @gup_flags does not
 * have FOLL_NOWAIT.
 *
 * A caller using such a combination of @locked and @gup_flags
 * must therefore hold the mmap_lock for reading only, and recognize
 * when it's been released.  Otherwise, it must be held for either
 * reading or writing and will not be released.
 *
 * In most cases, get_user_pages or get_user_pages_fast should be used
 * instead of __get_user_pages. __get_user_pages should be used only if
 * you need some special @gup_flags.
 */
static long rto_get_user_pages(struct mm_struct *mm,
		unsigned long start, unsigned long nr_pages,
		unsigned int gup_flags, struct page **pages,
		struct vm_area_struct **vmas, int *locked, struct list_head *hpages)
{
	long ret = 0, i = 0;
	struct vm_area_struct *vma = NULL;
	struct list_head *hpage_pos = hpages;

	if (!nr_pages)
		return 0;

	start = untagged_addr(start);

	VM_BUG_ON(!!pages != !!(gup_flags & (FOLL_GET | FOLL_PIN)));

	/*
	 * If FOLL_FORCE is set then do not force a full fault as the hinting
	 * fault information is unrelated to the reference behaviour of a task
	 * using the address space
	 */

	do {
		struct page *page = NULL, *hpage, *new_hpage;
		unsigned int foll_flags = gup_flags;
		unsigned int page_increm;

		hpage_pos = hpage_pos->next;
		// pr_info("hpage_pos: 0x%pK, addr: 0x%lx\n", hpage_pos, start);
		if (hpage_pos == hpages) {
			if (debug)
				pr_info("hpage used up\n");
			return 0;
		}

		/* first iteration or cross vma bound */
		if (!vma || start >= vma->vm_end) {
			vma = find_extend_vma(mm, start);

			if (!vma) {
				ret = -EFAULT;
				goto out;
			}

		}

		/*
		 * If we have a pending SIGKILL, don't keep faulting pages and
		 * potentially allocating memory.
		 */
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			goto out;
		}
		cond_resched();

		/* TODO try comment here to increase efficiency */
		hpage = list_entry(hpage_pos, struct page, lru);
		get_page(hpage);
		if (debug)
			pr_info("consume hpage 0x%pK, page: 0x%pK\n", hpage, page);
		if (!page) {
			ret = rto_faultin_page(vma, start, &foll_flags, PTR_ERR(page) == -EMLINK, locked, hpage);
			switch (ret) {
			case 0:
				// pr_info("retry\n");
				goto next_page;
				// goto retry;
			case -EBUSY:
			case -EAGAIN:
				ret = 0;
				fallthrough;
			case -EFAULT:
			case -ENOMEM:
			case -EHWPOISON:
				goto out;
			BUG();
			}
		}
next_page:

		page_increm = 0x200;
		if (page_increm > nr_pages)
			page_increm = nr_pages;
		i += page_increm;
		start += page_increm * PAGE_SIZE;
		nr_pages -= page_increm;
	} while (nr_pages);
out:
	return i ? i : ret;
}

/**
 * populate_vma_page_range() -  populate a range of pages in the vma.
 * @vma:   target vma
 * @start: start address
 * @end:   end address
 * @locked: whether the mmap_lock is still held
 *
 * This takes care of mlocking the pages too if VM_LOCKED is set.
 *
 * Return either number of pages pinned in the vma, or a negative error
 * code on error.
 *
 * vma->vm_mm->mmap_lock must be held.
 *
 * If @locked is NULL, it may be held for read or write and will
 * be unperturbed.
 *
 * If @locked is non-NULL, it must held for read only and may be
 * released.  If it's released, *@locked will be set to 0.
 */
long rto_populate_vma_page_range(struct vm_area_struct *vma,
		unsigned long start, unsigned long end, int *locked, struct list_head *hpages)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long nr_pages = (end - start) / PAGE_SIZE;
	int local_locked = 1;
	int gup_flags;
	long ret;

	VM_BUG_ON(!PAGE_ALIGNED(start));
	VM_BUG_ON(!PAGE_ALIGNED(end));
	VM_BUG_ON_VMA(start < vma->vm_start, vma);
	VM_BUG_ON_VMA(end   > vma->vm_end, vma);
	mmap_assert_locked(mm);

	/*
	 * Rightly or wrongly, the VM_LOCKONFAULT case has never used
	 * faultin_page() to break COW, so it has no work to do here.
	 */
	if (vma->vm_flags & VM_LOCKONFAULT)
		return nr_pages;

	gup_flags = FOLL_TOUCH;
	/*
	 * We want to touch writable mappings with a write fault in order
	 * to break COW, except for shared mappings because these don't COW
	 * and we would not want to dirty them for nothing.
	 */
	if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == VM_WRITE)
		gup_flags |= FOLL_WRITE;

	/*
	 * We want mlock to succeed for regions that have any permissions
	 * other than PROT_NONE.
	 */
	if (vma_is_accessible(vma))
		gup_flags |= FOLL_FORCE;

	/*
	 * We made sure addr is within a VMA, so the following will
	 * not result in a stack expansion that recurses back here.
	 */
	ret = rto_get_user_pages(mm, start, nr_pages, gup_flags,
				NULL, NULL, locked ? locked : &local_locked, hpages);
	return ret;
}

int rto_populate(struct file *file, unsigned long vaddr,
		 unsigned long offset, unsigned long size, struct loaded_seg *loaded_seg)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int ret, locked = 1;

	ret = -EINVAL;
	vma = find_vma(mm, vaddr);
	if (!vma)
		goto error;

	mmap_read_lock(mm);
	rto_populate_vma_page_range(vma, vaddr, vaddr + size, &locked, &loaded_seg->hpages);
	mmap_read_unlock(mm);

	return 0;
error:
	if (debug)
		pr_info("rto_populate fail, error: %d\n", ret);
	return ret;
}

int rto_populate_init(void)
{
	return init_symbols();
}
