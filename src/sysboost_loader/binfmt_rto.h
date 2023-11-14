// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include <linux/file.h>
#include "loader_device.h"
#include "netlink_kernel.h"

int rto_populate(struct file *file, unsigned long vaddr,
                 unsigned long offset, unsigned long size, struct loaded_seg *loaded_seg);

int init_rto_binfmt(void);
void exit_rto_binfmt(void);
void *load_bprm_buf(struct file *file);
struct elf_phdr *load_elf_phdrs(const struct elfhdr *elf_ex,
				struct file *elf_file);
struct file *try_get_rto_file(struct file *file);

int rto_populate_init(void);

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN	PAGE_SIZE
#endif

#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#define ELF_HPAGESTART(_v) ((_v) & ~(unsigned long)(HPAGE_SIZE - 1))
#define ELF_HPAGEOFFSET(_v) ((_v) & (HPAGE_SIZE - 1))
#define ELF_HPAGEALIGN(_v) (((_v) + HPAGE_SIZE - 1) & ~(HPAGE_SIZE - 1))
