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

#ifdef CONFIG_X86
// p4d_alloc -> __p4d_alloc
#define p4d_alloc rto_p4d_alloc
static inline p4d_t *rto_p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
		unsigned long address)
{
	return (unlikely(pgd_none(*pgd)) && ppl_sym.__p4d_alloc(mm, pgd, address)) ?
		NULL : p4d_offset(pgd, address);
}

// pud_trans_unstable()
//     pud_none_or_trans_huge_or_dev_or_clear_bad()
//         pud_clear_bad()
#define pud_trans_unstable rto_pud_trans_unstable

static inline int rto_pud_none_or_trans_huge_or_dev_or_clear_bad(pud_t *pud)
{
	pud_t pudval = READ_ONCE(*pud);

	if (pud_none(pudval) || pud_trans_huge(pudval) || pud_devmap(pudval))
		return 1;
	if (unlikely(pud_bad(pudval))) {
		ppl_sym.pud_clear_bad(pud);
		return 1;
	}
	return 0;
}

static inline int rto_pud_trans_unstable(pud_t *pud)
{
	return rto_pud_none_or_trans_huge_or_dev_or_clear_bad(pud);
}

#endif

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
	// pgtable_t pgtable;
	unsigned long haddr = vmf->address & HPAGE_PMD_MASK;
	vm_fault_t ret = 0;

// vma_set_anonymous(vma);

	VM_BUG_ON_PAGE(!PageCompound(page), page);

	// pr_info("enter __rto_do_huge_pmd_anonymous_page\n");
	if (debug)
		pr_info("vma->vm_start: %lx, vma->vm_end: %lx, vma->vm_pgoff: %lx\n",
			vma->vm_start, vma->vm_end, vma->vm_pgoff);
	ret = ppl_sym.do_set_pmd(vmf, page);
	// pr_info("__rto_do_huge_pmd_anonymous_page return %d\n", ret);
	return ret;

	// if (mem_cgroup_charge(page, vma->vm_mm, gfp)) {
	// 	put_page(page);
	// 	count_vm_event(THP_FAULT_FALLBACK);
	// 	count_vm_event(THP_FAULT_FALLBACK_CHARGE);
	// 	return VM_FAULT_FALLBACK;
	// }
	// cgroup_throttle_swaprate(page, gfp);

	// pgtable = pte_alloc_one(vma->vm_mm);
	// if (unlikely(!pgtable)) {
	// 	ret = VM_FAULT_OOM;
	// 	goto release;
	// }

	// clear_huge_page(page, vmf->address, HPAGE_PMD_NR);
	/*
	 * The memory barrier inside __SetPageUptodate makes sure that
	 * clear_huge_page writes become visible before the set_pmd_at()
	 * write.
	 */
	// __SetPageUptodate(page);

	vmf->ptl = pmd_lock(vma->vm_mm, vmf->pmd);
	if (unlikely(!pmd_none(*vmf->pmd))) {
		goto unlock_release;
	} else {
		pmd_t entry;

		ret = check_stable_address_space(vma->vm_mm);
		if (ret)
			goto unlock_release;

		/* Deliver the page fault to userland */
		// if (userfaultfd_missing(vma)) {
		// 	vm_fault_t ret2;

		// 	spin_unlock(vmf->ptl);
		// 	put_page(page);
		// 	pte_free(vma->vm_mm, pgtable);
		// 	ret2 = handle_userfault(vmf, VM_UFFD_MISSING);
		// 	VM_BUG_ON(ret2 & VM_FAULT_FALLBACK);
		// 	return ret2;
		// }

		entry = mk_huge_pmd(page, vma->vm_page_prot);
		// we don't need write access for text segment.
		// entry = maybe_pmd_mkwrite(pmd_mkdirty(entry), vma);

		// we don't need LRU.
		// page_add_new_anon_rmap(page, vma, haddr, true);
		// lru_cache_add_inactive_or_unevictable(page, vma);

		// we won't split thp, no need to deposit
		// pgtable_trans_huge_deposit(vma->vm_mm, vmf->pmd, pgtable);

		set_pmd_at(vma->vm_mm, haddr, vmf->pmd, entry);
		// pr_info("set_pmd_at entry: 0x%pK, entry_size: %d\n",
			// entry, sizeof(entry));
		// add_mm_counter(vma->vm_mm, MM_ANONPAGES, HPAGE_PMD_NR);
		// reliable_page_counter(page, vma->vm_mm, HPAGE_PMD_NR);
		mm_inc_nr_ptes(vma->vm_mm);
		spin_unlock(vmf->ptl);

		// count_vm_event(THP_FAULT_ALLOC);
		// count_memcg_event_mm(vma->vm_mm, THP_FAULT_ALLOC);
	}

	return 0;
unlock_release:
	spin_unlock(vmf->ptl);
// release:
	// if (pgtable)
	// 	pte_free(vma->vm_mm, pgtable);
	// put_page(page);
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
	// struct page *page;
	// unsigned long haddr = vmf->address & HPAGE_PMD_MASK;

	// we have checked boader outside, no need to double check
	// if (!transhuge_vma_suitable(vma, haddr))
	// 	return VM_FAULT_FALLBACK;
	if (unlikely(rto_anon_vma_prepare(vma)))
		return VM_FAULT_OOM;
	// if (unlikely(khugepaged_enter(vma, vma->vm_flags)))
	// 	return VM_FAULT_OOM;
	// if (!(vmf->flags & FAULT_FLAG_WRITE) &&
	// 		!mm_forbids_zeropage(vma->vm_mm) &&
	// 		transparent_hugepage_use_zero_page()) {
	// 	pgtable_t pgtable;
	// 	struct page *zero_page;
	// 	vm_fault_t ret;
	// 	pgtable = pte_alloc_one(vma->vm_mm);
	// 	if (unlikely(!pgtable))
	// 		return VM_FAULT_OOM;
	// 	zero_page = mm_get_huge_zero_page(vma->vm_mm);
	// 	if (unlikely(!zero_page)) {
	// 		pte_free(vma->vm_mm, pgtable);
	// 		count_vm_event(THP_FAULT_FALLBACK);
	// 		return VM_FAULT_FALLBACK;
	// 	}
	// 	vmf->ptl = pmd_lock(vma->vm_mm, vmf->pmd);
	// 	ret = 0;
	// 	if (pmd_none(*vmf->pmd)) {
	// 		ret = check_stable_address_space(vma->vm_mm);
	// 		if (ret) {
	// 			spin_unlock(vmf->ptl);
	// 			pte_free(vma->vm_mm, pgtable);
	// 		// } else if (userfaultfd_missing(vma)) {
	// 		// 	spin_unlock(vmf->ptl);
	// 		// 	pte_free(vma->vm_mm, pgtable);
	// 		// 	ret = handle_userfault(vmf, VM_UFFD_MISSING);
	// 		// 	VM_BUG_ON(ret & VM_FAULT_FALLBACK);
	// 		} else {
	// 			// set_huge_zero_page(pgtable, vma->vm_mm, vma,
	// 			// 		   haddr, vmf->pmd, zero_page);
	// 			spin_unlock(vmf->ptl);
	// 		}
	// 	} else {
	// 		spin_unlock(vmf->ptl);
	// 		pte_free(vma->vm_mm, pgtable);
	// 	}
	// 	return ret;
	// }
	// gfp = alloc_hugepage_direct_gfpmask(vma);

	// TODO
	// page = alloc_hugepage_vma(gfp, vma, haddr, HPAGE_PMD_ORDER);
	// if (unlikely(!page)) {
	// 	count_vm_event(THP_FAULT_FALLBACK);
	// 	return VM_FAULT_FALLBACK;
	// }
	// prep_transhuge_page(page);
	return __rto_do_huge_pmd_anonymous_page(vmf, hpage, gfp);
}

static inline vm_fault_t create_huge_pmd(struct vm_fault *vmf, struct page *hpage)
{
	// if (vma_is_anonymous(vmf->vma))
		return rto_do_huge_pmd_anonymous_page(vmf, hpage);
	// if (vmf->vma->vm_ops->huge_fault)
	// 	return vmf->vma->vm_ops->huge_fault(vmf, PE_SIZE_PMD);
	// return VM_FAULT_FALLBACK;
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
		// .gfp_mask = __get_fault_gfp_mask(vma),
	};
	// unsigned int dirty = flags & FAULT_FLAG_WRITE;
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
	// if (pud_none(*vmf.pud) && __transparent_hugepage_enabled(vma)) {
	// 	ret = create_huge_pud(&vmf);
	// 	if (!(ret & VM_FAULT_FALLBACK))
	// 		return ret;
	// } else {
	// 	pud_t orig_pud = *vmf.pud;

	// 	barrier();
	// 	if (pud_trans_huge(orig_pud) || pud_devmap(orig_pud)) {

	// 		/* NUMA case for anonymous PUDs would go here */

	// 		if (dirty && !pud_write(orig_pud)) {
	// 			ret = wp_huge_pud(&vmf, orig_pud);
	// 			if (!(ret & VM_FAULT_FALLBACK))
	// 				return ret;
	// 		} else {
	// 			huge_pud_set_accessed(&vmf, orig_pud);
	// 			return 0;
	// 		}
	// 	}
	// }

	pmd = pmd_offset(vmf.pud, address);
	// if (pmd)
		// pr_info("pmd: %pK\n", pmd);
	// else
		// pr_info("pmd is null\n");
	vmf.pmd = rto_pmd_alloc(mm, vmf.pud, address);
	if (!vmf.pmd)
		return VM_FAULT_OOM;
	
	if (!pmd_none(*vmf.pmd)) {
		// pr_info("vmf.pmd: %pK, value: 0x%lx, return\n", vmf.pmd, pmd_val(*vmf.pmd));
		return VM_FAULT_OOM;
	}

	/* Huge pud page fault raced with pmd_alloc? */
	if (pud_trans_unstable(vmf.pud))
		goto retry_pud;

	// if (pmd_none(*vmf.pmd) && __transparent_hugepage_enabled(vma)) {
		ret = create_huge_pmd(&vmf, hpage);
		if (debug) {
			if (vmf.pmd) {
				pr_info("vmf.pmd: %pK, value: 0x%llx, pmd_trans_huge: 0x%d\n",
					vmf.pmd, pmd_val(*vmf.pmd), pmd_trans_huge(*pmd));
			} else {
				pr_info("vmf.pmd is null\n");
			}
		}
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	// }
	

	BUG();
	return 0;
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
	// check_sync_rss_stat(current);

	// if (!arch_vma_access_permitted(vma, flags & FAULT_FLAG_WRITE,
	// 				    flags & FAULT_FLAG_INSTRUCTION,
	// 				    flags & FAULT_FLAG_REMOTE))
	// 	return VM_FAULT_SIGSEGV;

	/*
	 * Enable the memcg OOM handling for faults triggered in user
	 * space.  Kernel faults are handled more gracefully.
	 */
	if (flags & FAULT_FLAG_USER)
		mem_cgroup_enter_user_fault();

	// if (unlikely(is_vm_hugetlb_page(vma)))
	// 	ret = hugetlb_fault(vma->vm_mm, vma, address, flags);
	// else
		ret = __rto_handle_mm_fault(vma, address, flags, hpage);

	if (flags & FAULT_FLAG_USER) {
		mem_cgroup_exit_user_fault();
		/*
		 * The task may have entered a memcg OOM situation but
		 * if the allocation error was handled gracefully (no
		 * VM_FAULT_OOM), there is no need to kill anything.
		 * Just clean up the OOM state peacefully.
		 */
		// TODO don't consider oom now
		// if (task_in_memcg_oom(current) && !(ret & VM_FAULT_OOM))
		// 	mem_cgroup_oom_synchronize(false);
	}

	// mm_account_fault(regs, address, flags, ret);

	return ret;
}

/*
 * mmap_lock must be held on entry.  If @locked != NULL and *@flags
 * does not include FOLL_NOWAIT, the mmap_lock may be released.  If it
 * is, *@locked will be set to 0 and -EBUSY returned.
 */
static int rto_faultin_page(struct vm_area_struct *vma,
	unsigned long address, unsigned int *flags, int *locked, struct page *hpage)
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
	if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))
		*flags |= FOLL_COW;
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
	// struct follow_page_context ctx = { NULL };
	struct list_head *hpage_pos = hpages;

	// pr_info("start rto_get_user_pages, start: 0x%lx, nr_pages: 0x%lx\n",
		// start, nr_pages);

	if (!nr_pages)
		return 0;

	start = untagged_addr(start);

	VM_BUG_ON(!!pages != !!(gup_flags & (FOLL_GET | FOLL_PIN)));

	/*
	 * If FOLL_FORCE is set then do not force a full fault as the hinting
	 * fault information is unrelated to the reference behaviour of a task
	 * using the address space
	 */
	if (!(gup_flags & FOLL_FORCE))
		gup_flags |= FOLL_NUMA;

	do {
		struct page *page, *hpage, *new_hpage;
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
			// if (!vma && in_gate_area(mm, start)) {
			// 	ret = get_gate_page(mm, start & PAGE_MASK,
			// 			gup_flags, &vma,
			// 			pages ? &pages[i] : NULL);
			// 	if (ret)
			// 		goto out;
			// 	ctx.page_mask = 0;
			// 	goto next_page;
			// }

			// if (!vma || ppl_sym.check_vma_flags(vma, gup_flags)) {
			// 	ret = -EFAULT;
			// 	goto out;
			// }

			// if (is_vm_hugetlb_page(vma)) {
			// 	i = follow_hugetlb_page(mm, vma, pages, vmas,
			// 			&start, &nr_pages, i,
			// 			gup_flags, locked);
			// 	if (locked && *locked == 0) {
			// 		/*
			// 		 * We've got a VM_FAULT_RETRY
			// 		 * and we've lost mmap_lock.
			// 		 * We must stop here.
			// 		 */
			// 		BUG_ON(gup_flags & FOLL_NOWAIT);
			// 		BUG_ON(ret != 0);
			// 		goto out;
			// 	}
			// 	continue;
			// }
		}
// retry:
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
		// page = ppl_sym.follow_page_mask(vma, start, foll_flags, &ctx);
		hpage = list_entry(hpage_pos, struct page, lru);
		if (TestPageNeedCopy(hpage)) {
			int i;
			// pr_info("alloc new_hpage for page: 0x%pK\n", hpage);
			new_hpage = alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_COMP,
						HUGETLB_PAGE_ORDER);
			if (!new_hpage)
				BUG();
			for (i = 0; i < 1000; i++) {
				get_page(new_hpage);
			}
			memcpy(page_to_virt(new_hpage), page_to_virt(hpage), HPAGE_SIZE);
			hpage = new_hpage;
		} else {
			get_page(hpage);
		}
		if (debug)
			pr_info("consume hpage 0x%pK, page: 0x%pK\n", hpage, page);
		if (!page) {
			ret = rto_faultin_page(vma, start, &foll_flags, locked, hpage);
			switch (ret) {
			case 0:
				// pr_info("retry\n");
				goto next_page;
				// goto retry;
			case -EBUSY:
				ret = 0;
				fallthrough;
			case -EFAULT:
			case -ENOMEM:
			case -EHWPOISON:
				goto out;
			case -ENOENT:
				goto next_page;
			}
			BUG();
		} else if (PTR_ERR(page) == -EEXIST) {
			/*
			 * Proper page table entry exists, but no corresponding
			 * struct page.
			 */
			BUG();
			goto next_page;
		} else if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			goto out;
		}
		// if (pages) {
		// 	pages[i] = page;
		// 	flush_anon_page(vma, page, start);
		// 	flush_dcache_page(page);
		// 	ctx.page_mask = 0;
		// }
next_page:
		// if (vmas) {
		// 	vmas[i] = vma;
		// 	ctx.page_mask = 0;
		// }

		page_increm = 0x200;
		// page_increm = 1 + (~(start >> PAGE_SHIFT) & ctx.page_mask);
		// // pr_info("page_increm: %d, ctx.page_mask: 0x%x, i: %ld, nr_pages: %ld",
		// 	page_increm, ctx.page_mask, i, nr_pages);
		if (page_increm > nr_pages)
			page_increm = nr_pages;
		i += page_increm;
		start += page_increm * PAGE_SIZE;
		nr_pages -= page_increm;
	} while (nr_pages);
out:
	// if (ctx.pgmap)
	// 	put_dev_pagemap(ctx.pgmap);
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
static long rto_populate_vma_page_range(struct vm_area_struct *vma,
	unsigned long start, unsigned long end, int *locked, struct list_head *hpages)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long nr_pages = (end - start) / PAGE_SIZE;
	int gup_flags;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(end   & ~PAGE_MASK);
	VM_BUG_ON_VMA(start < vma->vm_start, vma);
	VM_BUG_ON_VMA(end   > vma->vm_end, vma);
	mmap_assert_locked(mm);

	gup_flags = FOLL_TOUCH | FOLL_POPULATE | FOLL_MLOCK;
	if (vma->vm_flags & VM_LOCKONFAULT)
		gup_flags &= ~FOLL_POPULATE;
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
	return rto_get_user_pages(mm, start, nr_pages, gup_flags,
				NULL, NULL, locked, hpages);
}

int rto_populate(struct file *file, unsigned long vaddr,
		 unsigned long offset, unsigned long size, struct loaded_seg *loaded_seg)
{
	struct mm_struct *mm = current->mm;
	// struct inode *inode = file->f_inode;
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
