// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
//
// sysMaster is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "elf_link_common.h"
#include <si_debug.h>
#include <si_log.h>

#ifndef PF_HUGEPAGE
#define PF_HUGEPAGE (0x01000000)
#endif

#ifndef EF_AARCH64_SYMBOLIC_LINK
#define EF_AARCH64_SYMBOLIC_LINK (0x00010000U)
#endif

#ifndef EF_AARCH64_HUGEPAGE
#define EF_AARCH64_HUGEPAGE (0x00020000U)
#endif

#ifndef EF_AARCH64_RTO
#define EF_AARCH64_RTO (0x00040000U)
#endif

#ifndef EF_X86_64_SYMBOLIC_LINK
#define EF_X86_64_SYMBOLIC_LINK    (0x00010000U)
#endif

#ifndef EF_X86_64_HUGEPAGE
#define EF_X86_64_HUGEPAGE         (0x00020000U)
#endif

#ifndef EF_X86_64_RTO
#define EF_X86_64_RTO              (0x00040000U)
#endif

#ifdef __aarch64__
#define OS_SPECIFIC_FLAG_SYMBOLIC_LINK EF_AARCH64_SYMBOLIC_LINK
#define OS_SPECIFIC_FLAG_HUGEPAGE EF_AARCH64_HUGEPAGE
#define OS_SPECIFIC_FLAG_RTO EF_AARCH64_RTO
#else
#define OS_SPECIFIC_FLAG_SYMBOLIC_LINK EF_X86_64_SYMBOLIC_LINK
#define OS_SPECIFIC_FLAG_HUGEPAGE EF_X86_64_HUGEPAGE
#define OS_SPECIFIC_FLAG_RTO EF_X86_64_RTO
#endif
#define OS_SPECIFIC_MASK (0xffffffffU ^ OS_SPECIFIC_FLAG_SYMBOLIC_LINK ^ OS_SPECIFIC_FLAG_HUGEPAGE ^ OS_SPECIFIC_FLAG_RTO)

static int _elf_set_flags(char *path, unsigned int flags)
{
	elf_file_t *ef = malloc(sizeof(elf_file_t));
	if (ef == NULL) {
		SI_LOG_ERR("malloc fail\n");
		return -1;
	}

	int ret = elf_read_file(path, ef, false);
	if (ret != 0) {
		return -1;
	}

	ef->hdr->e_flags |= flags;

	elf_close_file(ef);
	free(ef);
	ef = NULL;
	return 0;
}

static int _elf_unset_flags(char *path, unsigned int flags)
{
	elf_file_t *ef = malloc(sizeof(elf_file_t));
	if (ef == NULL) {
		SI_LOG_ERR("malloc fail\n");
		return -1;
	}

	int ret = elf_read_file(path, ef, false);
	if (ret != 0) {
		return -1;
	}

	ef->hdr->e_flags &= (0xffffffffU ^ flags);

	elf_close_file(ef);
	free(ef);
	ef = NULL;
	return 0;
}

int elf_set_symbolic_link(char *path, bool state)
{
	if (state) {
		return _elf_set_flags(path, OS_SPECIFIC_FLAG_SYMBOLIC_LINK);
	}
	return _elf_unset_flags(path, OS_SPECIFIC_FLAG_SYMBOLIC_LINK);
}

int elf_set_rto(char *path, bool state)
{
	if (state) {
		return _elf_set_flags(path, OS_SPECIFIC_FLAG_RTO);
	}
	return _elf_unset_flags(path, OS_SPECIFIC_FLAG_RTO);
}

void elf_set_hugepage(elf_link_t *elf_link)
{
	int i, exec_only = 1;
	elf_file_t *ef = &elf_link->out_ef;
	int count = ef->hdr->e_phnum;
	Elf64_Phdr *phdr = (Elf64_Phdr *)ef->hdr_Phdr;

	for (i = 0; i < count; i++) {
		if (phdr[i].p_type != PT_LOAD) {
			continue;
		}
		if (exec_only && !(phdr[i].p_flags & PF_X)) {
			continue;
		}
		phdr[i].p_flags |= PF_HUGEPAGE;
	}

	ef->hdr->e_flags |= OS_SPECIFIC_FLAG_HUGEPAGE;
	if (is_direct_vdso_optimize(elf_link)) {
		ef->hdr->e_flags |= OS_SPECIFIC_FLAG_RTO;
	}
}
