// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
//
// sysboost is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

#ifndef _ELF_WRITE_ELF_H
#define _ELF_WRITE_ELF_H

#include <elf.h>
#include <stdbool.h>
#include <string.h>

#include "elf_link_common.h"

// old ld.so can not compat to R_X86_64_NONE in .rela.plt
static inline void elf_clear_rela(Elf64_Rela *dst_rela)
{
	(void)memset(dst_rela, 0, sizeof(*dst_rela));
}

void elf_modify_file_zero(elf_link_t *elf_link, unsigned long offset, unsigned long len);
void elf_modify_section_zero(elf_link_t *elf_link, char *secname);

void *write_elf_file(elf_link_t *elf_link, void *src, unsigned int len);
void *write_elf_file_zero(elf_link_t *elf_link, unsigned int len);
void *write_elf_file_section(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec, Elf64_Shdr *dst_sec);

unsigned int elf_align_file(elf_link_t *elf_link, unsigned int align);
unsigned int elf_align_file_segment(elf_link_t *elf_link);
unsigned int elf_align_file_section(elf_link_t *elf_link, Elf64_Shdr *sec, bool is_align_file_offset);

// write section
void copy_from_old_elf(elf_link_t *elf_link);
void merge_text_sections(elf_link_t *elf_link);
void merge_rodata_sections(elf_link_t *elf_link);
void merge_data_relro_sections(elf_link_t *elf_link);
void merge_rwdata_sections(elf_link_t *elf_link);

Elf64_Shdr *merge_libc_ef_section(elf_link_t *elf_link, const char *sec_name);
Elf64_Shdr *merge_template_ef_section(elf_link_t *elf_link, const char *sec_name);
Elf64_Shdr *merge_all_ef_section(elf_link_t *elf_link, const char *name);

int create_elf_file(char *file_name, elf_file_t *elf_file);
void truncate_elf_file(elf_link_t *elf_link);

#endif /* _ELF_WRITE_ELF_H */
