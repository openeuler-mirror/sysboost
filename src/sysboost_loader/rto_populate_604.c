// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/spinlock.h>

#include <linux/mm.h>
#include <linux/memremap.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/secretmem.h>

#include <linux/sched/signal.h>
#include <linux/rwsem.h>
#include <linux/hugetlb.h>
#include <linux/migrate.h>
#include <linux/mm_inline.h>
#include <linux/sched/mm.h>
#include <linux/version.h>

#include <asm/mmu_context.h>
#include <asm/tlbflush.h>

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static struct vm_area_struct *gup_vma_lookup(struct mm_struct *mm,
	 unsigned long addr);

static int check_vma_flags(struct vm_area_struct *vma, unsigned long gup_flags);

struct vm_area_struct *find_extend_vma_locked(struct mm_struct *mm, unsigned long addr);
#endif

#define proc_symbol(SYM)	typeof(SYM) *(SYM)
static struct global_symbols {
	proc_symbol(follow_page_mask);
	proc_symbol(__pud_alloc);
	proc_symbol(__anon_vma_prepare);
	proc_symbol(__pmd_alloc);
	proc_symbol(do_set_pmd);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	proc_symbol(gup_vma_lookup);
	proc_symbol(check_vma_flags);
	proc_symbol(find_extend_vma_locked);
#endif

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	proc_symbol_char(gup_vma_lookup),
	proc_symbol_char(check_vma_flags),
	proc_symbol_char(find_extend_vma_locked),
#endif
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

enum {
	/* mark page accessed */
	FOLL_TOUCH = 1 << 16,
	/* a retry, previous pass started an IO */
	FOLL_TRIED = 1 << 17,
	/* we are working on non-current tsk/mm */
	FOLL_REMOTE = 1 << 18,
	/* pages must be released via unpin_user_page */
	FOLL_PIN = 1 << 19,
	/* gup_fast: prevent fall-back to slow gup */
	FOLL_FAST_ONLY = 1 << 20,
	/* allow unlocking the mmap lock */
	FOLL_UNLOCKABLE = 1 << 21,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	/* VMA lookup+checks compatible with MADV_POPULATE_(READ|WRITE) */
	FOLL_MADV_POPULATE = 1 << 22,
#endif
};

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
	// struct folio *folio;
	// unsigned long haddr = vmf->address & HPAGE_PMD_MASK;

	// if (!transhuge_vma_suitable(vma, haddr))
	// 	return VM_FAULT_FALLBACK;
	if (unlikely(rto_anon_vma_prepare(vma)))
		return VM_FAULT_OOM;
	// khugepaged_enter_vma(vma, vma->vm_flags);

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
	// 		} else if (userfaultfd_missing(vma)) {
	// 			spin_unlock(vmf->ptl);
	// 			pte_free(vma->vm_mm, pgtable);
	// 			ret = handle_userfault(vmf, VM_UFFD_MISSING);
	// 			VM_BUG_ON(ret & VM_FAULT_FALLBACK);
	// 		} else {
	// 			set_huge_zero_page(pgtable, vma->vm_mm, vma,
	// 					   haddr, vmf->pmd, zero_page);
	// 			update_mmu_cache_pmd(vma, vmf->address, vmf->pmd);
	// 			spin_unlock(vmf->ptl);
	// 		}
	// 	} else {
	// 		spin_unlock(vmf->ptl);
	// 		pte_free(vma->vm_mm, pgtable);
	// 	}
	// 	return ret;
	// }
	// gfp = vma_thp_gfp_mask(vma);
	// folio = vma_alloc_folio(gfp, HPAGE_PMD_ORDER, vma, haddr, true);
	// if (unlikely(!folio)) {
	// 	count_vm_event(THP_FAULT_FALLBACK);
	// 	return VM_FAULT_FALLBACK;
	// }
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
 * return value.  See filemap_fault() and __folio_lock_or_retry().
 */
static vm_fault_t __rto_handle_mm_fault(struct vm_area_struct *vma,
		unsigned long address, unsigned int flags, struct page *hpage)
{
	struct vm_fault vmf = {
		.vma = vma,
		.address = address & PAGE_MASK,
		.real_address = address,
		.flags = flags,
		.pgoff = linear_page_index(vma, address),
		// .gfp_mask = __get_fault_gfp_mask(vma),
	};
	struct mm_struct *mm = vma->vm_mm;
	// unsigned long vm_flags = vma->vm_flags;
	pgd_t *pgd;
	p4d_t *p4d;
	vm_fault_t ret;

	pgd = pgd_offset(mm, address);
	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return VM_FAULT_OOM;

	vmf.pud = rto_pud_alloc(mm, p4d, address);
	if (!vmf.pud)
		return VM_FAULT_OOM;
retry_pud:
	// if (pud_none(*vmf.pud) &&
	//     hugepage_vma_check(vma, vm_flags, false, true, true)) {
	// 	ret = create_huge_pud(&vmf);
	// 	if (!(ret & VM_FAULT_FALLBACK))
	// 		return ret;
	// } else {
	// 	pud_t orig_pud = *vmf.pud;

	// 	barrier();
	// 	if (pud_trans_huge(orig_pud) || pud_devmap(orig_pud)) {

	// 		/*
	// 		 * TODO once we support anonymous PUDs: NUMA case and
	// 		 * FAULT_FLAG_UNSHARE handling.
	// 		 */
	// 		if ((flags & FAULT_FLAG_WRITE) && !pud_write(orig_pud)) {
	// 			ret = wp_huge_pud(&vmf, orig_pud);
	// 			if (!(ret & VM_FAULT_FALLBACK))
	// 				return ret;
	// 		} else {
	// 			huge_pud_set_accessed(&vmf, orig_pud);
	// 			return 0;
	// 		}
	// 	}
	// }

	vmf.pmd = rto_pmd_alloc(mm, vmf.pud, address);
	if (!vmf.pmd)
		return VM_FAULT_OOM;

	/* Huge pud page fault raced with pmd_alloc? */
	if (pud_trans_unstable(vmf.pud))
		goto retry_pud;

	// if (pmd_none(*vmf.pmd) &&
	//     hugepage_vma_check(vma, vm_flags, false, true, true)) {
		ret = create_huge_pmd(&vmf, hpage);
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	// } else {
	// 	vmf.orig_pmd = *vmf.pmd;

	// 	barrier();
	// 	if (unlikely(is_swap_pmd(vmf.orig_pmd))) {
	// 		VM_BUG_ON(thp_migration_supported() &&
	// 				  !is_pmd_migration_entry(vmf.orig_pmd));
	// 		if (is_pmd_migration_entry(vmf.orig_pmd))
	// 			pmd_migration_entry_wait(mm, vmf.pmd);
	// 		return 0;
	// 	}
	// 	if (pmd_trans_huge(vmf.orig_pmd) || pmd_devmap(vmf.orig_pmd)) {
	// 		if (pmd_protnone(vmf.orig_pmd) && vma_is_accessible(vma))
	// 			return do_huge_pmd_numa_page(&vmf);

	// 		if ((flags & (FAULT_FLAG_WRITE|FAULT_FLAG_UNSHARE)) &&
	// 		    !pmd_write(vmf.orig_pmd)) {
	// 			ret = wp_huge_pmd(&vmf);
	// 			if (!(ret & VM_FAULT_FALLBACK))
	// 				return ret;
	// 		} else {
	// 			huge_pmd_set_accessed(&vmf);
	// 			return 0;
	// 		}
	// 	}
	// }

	return -ENOMEM;
}

/*
 * By the time we get here, we already hold the mm semaphore
 *
 * The mmap_lock may have been released depending on flags and our
 * return value.  See filemap_fault() and __folio_lock_or_retry().
 */
vm_fault_t rto_handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
			   unsigned int flags, struct pt_regs *regs, struct page *hpage)
{
	/* If the fault handler drops the mmap_lock, vma may be freed */
	// struct mm_struct *mm = vma->vm_mm;
	vm_fault_t ret;

	__set_current_state(TASK_RUNNING);

	//TODO if need?
	// ret = sanitize_fault_flags(vma, &flags);
	// if (ret)
	// 	goto out;

	// if (!arch_vma_access_permitted(vma, flags & FAULT_FLAG_WRITE,
	// 				    flags & FAULT_FLAG_INSTRUCTION,
	// 				    flags & FAULT_FLAG_REMOTE)) {
	// 	ret = VM_FAULT_SIGSEGV;
	// 	goto out;
	// }

	/*
	 * Enable the memcg OOM handling for faults triggered in user
	 * space.  Kernel faults are handled more gracefully.
	 */
	if (flags & FAULT_FLAG_USER)
		mem_cgroup_enter_user_fault();

	// lru_gen_enter_fault(vma);

	// if (unlikely(is_vm_hugetlb_page(vma)))
	// 	ret = hugetlb_fault(vma->vm_mm, vma, address, flags);
	// else
		ret = __rto_handle_mm_fault(vma, address, flags, hpage);

	// lru_gen_exit_fault();

	// if (flags & FAULT_FLAG_USER) {
		// mem_cgroup_exit_user_fault();
		/*
		 * The task may have entered a memcg OOM situation but
		 * if the allocation error was handled gracefully (no
		 * VM_FAULT_OOM), there is no need to kill anything.
		 * Just clean up the OOM state peacefully.
		 */
		// if (task_in_memcg_oom(current) && !(ret & VM_FAULT_OOM))
		// 	mem_cgroup_oom_synchronize(false);
	// }
// out:
	// mm_account_fault(mm, regs, address, flags, ret);

	return ret;
}

/*
 * mmap_lock must be held on entry.  If @flags has FOLL_UNLOCKABLE but not
 * FOLL_NOWAIT, the mmap_lock may be released.  If it is, *@locked will be set
 * to 0 and -EBUSY returned.
 */
static int rto_faultin_page(struct vm_area_struct *vma,
		unsigned long address, unsigned int *flags, bool unshare,
		int *locked, struct page *hpage)
{
	unsigned int fault_flags = 0;
	vm_fault_t ret;

	if (*flags & FOLL_NOFAULT)
		return -EFAULT;
	if (*flags & FOLL_WRITE)
		fault_flags |= FAULT_FLAG_WRITE;
	if (*flags & FOLL_REMOTE)
		fault_flags |= FAULT_FLAG_REMOTE;
	if (*flags & FOLL_UNLOCKABLE) {
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;
		/*
		 * FAULT_FLAG_INTERRUPTIBLE is opt-in. GUP callers must set
		 * FOLL_INTERRUPTIBLE to enable FAULT_FLAG_INTERRUPTIBLE.
		 * That's because some callers may not be prepared to
		 * handle early exits caused by non-fatal signals.
		 */
		if (*flags & FOLL_INTERRUPTIBLE)
			fault_flags |= FAULT_FLAG_INTERRUPTIBLE;
	}
	if (*flags & FOLL_NOWAIT)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_RETRY_NOWAIT;
	if (*flags & FOLL_TRIED) {
		/*
		 * Note: FAULT_FLAG_ALLOW_RETRY and FAULT_FLAG_TRIED
		 * can co-exist
		 */
		fault_flags |= FAULT_FLAG_TRIED;
	}
	if (unshare) {
		fault_flags |= FAULT_FLAG_UNSHARE;
		/* FAULT_FLAG_WRITE and FAULT_FLAG_UNSHARE are incompatible */
		VM_BUG_ON(fault_flags & FAULT_FLAG_WRITE);
	}

	ret = rto_handle_mm_fault(vma, address, fault_flags, NULL, hpage);

	if (ret & VM_FAULT_COMPLETED) {
		/*
		 * With FAULT_FLAG_RETRY_NOWAIT we'll never release the
		 * mmap lock in the page fault handler. Sanity check this.
		 */
		WARN_ON_ONCE(fault_flags & FAULT_FLAG_RETRY_NOWAIT);
		*locked = 0;

		/*
		 * We should do the same as VM_FAULT_RETRY, but let's not
		 * return -EBUSY since that's not reflecting the reality of
		 * what has happened - we've just fully completed a page
		 * fault, with the mmap lock released.  Use -EAGAIN to show
		 * that we want to take the mmap lock _again_.
		 */
		return -EAGAIN;
	}

	if (ret & VM_FAULT_ERROR) {
		int err = vm_fault_to_errno(ret, *flags);

		if (err)
			return err;
		BUG();
	}

	if (ret & VM_FAULT_RETRY) {
		if (!(fault_flags & FAULT_FLAG_RETRY_NOWAIT))
			*locked = 0;
		return -EBUSY;
	}

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
 * and subsequently re-faulted). However it does guarantee that the page
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
 * If FOLL_UNLOCKABLE is set without FOLL_NOWAIT then the mmap_lock may
 * be released. If this happens *@locked will be set to 0 on return.
 *
 * A caller using such a combination of @gup_flags must therefore hold the
 * mmap_lock for reading only, and recognize when it's been released. Otherwise,
 * it must be held for either reading or writing and will not be released.
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

	if (!nr_pages)
		return 0;

	start = untagged_addr_remote(mm, start);

	VM_BUG_ON(!!pages != !!(gup_flags & (FOLL_GET | FOLL_PIN)));

	do {
		struct page *page = NULL, *hpage;
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
			/*
			 * MADV_POPULATE_(READ|WRITE) wants to handle VMA
			 * lookups+error reporting differently.
			 */
			if (gup_flags & FOLL_MADV_POPULATE) {
				vma = vma_lookup(mm, start);
				if (!vma) {
					ret = -ENOMEM;
					goto out;
				}
				if (ppl_sym.check_vma_flags(vma, gup_flags)) {
					ret = -EINVAL;
					goto out;
				}
			} else {
				vma = ppl_sym.gup_vma_lookup(mm, start);
			}
#else
			vma = find_extend_vma(mm, start);
#endif
			// if (!vma && in_gate_area(mm, start)) {
			// 	ret = get_gate_page(mm, start & PAGE_MASK,
			// 			gup_flags, &vma,
			// 			pages ? &pages[i] : NULL);
			// 	if (ret)
			// 		goto out;
			// 	ctx.page_mask = 0;
			// 	goto next_page;
			// }

			if (!vma) {
				ret = -EFAULT;
				goto out;
			}
			// ret = check_vma_flags(vma, gup_flags);
			// if (ret)
			// 	goto out;

			// if (is_vm_hugetlb_page(vma)) {
			// 	i = follow_hugetlb_page(mm, vma, pages, vmas,
			// 			&start, &nr_pages, i,
			// 			gup_flags, locked);
			// 	if (!*locked) {
			// 		/*
			// 		 * We've got a VM_FAULT_RETRY
			// 		 * and we've lost mmap_lock.
			// 		 * We must stop here.
			// 		 */
			// 		BUG_ON(gup_flags & FOLL_NOWAIT);
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

		// page = follow_page_mask(vma, start, foll_flags, &ctx);
		hpage = list_entry(hpage_pos, struct page, lru);
		get_page(hpage);
		if (debug)
			pr_info("consume hpage 0x%pK, page: 0x%pK\n", hpage, page);
		// if (!page || PTR_ERR(page) == -EMLINK) {
			ret = rto_faultin_page(vma, start, &foll_flags,
					   PTR_ERR(page) == -EMLINK, locked, hpage);
			switch (ret) {
			case 0:
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
			}
			BUG();
		// } else if (PTR_ERR(page) == -EEXIST) {
		// 	/*
		// 	 * Proper page table entry exists, but no corresponding
		// 	 * struct page. If the caller expects **pages to be
		// 	 * filled in, bail out now, because that can't be done
		// 	 * for this page.
		// 	 */
		// 	if (pages) {
		// 		ret = PTR_ERR(page);
		// 		goto out;
		// 	}

		// 	goto next_page;
		// } else if (IS_ERR(page)) {
		// 	ret = PTR_ERR(page);
		// 	goto out;
		// }
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

	if (locked)
		gup_flags |= FOLL_UNLOCKABLE;

	/*
	 * We made sure addr is within a VMA, so the following will
	 * not result in a stack expansion that recurses back here.
	 */
	ret = rto_get_user_pages(mm, start, nr_pages, gup_flags,
				NULL, NULL, locked ? locked : &local_locked, hpages);
	// lru_add_drain();
	return ret;
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
		goto out;

	mmap_read_lock(mm);
	ret = rto_populate_vma_page_range(vma, vaddr, vaddr + size, &locked, &loaded_seg->hpages);
	mmap_read_unlock(mm);

out:
	if (debug && ret < 0)
		pr_info("rto_populate fail, error: %d\n", ret);
	return ret;
}

int rto_populate_init(void)
{
	return init_symbols();
}
