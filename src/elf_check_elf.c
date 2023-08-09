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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <si_debug.h>
#include <si_log.h>

#include "elf_link_common.h"

static void check_bss_addr(elf_file_t *out_ef)
{
	// in kernel, bss addr = data segment + filesize
	Elf64_Shdr *sec = elf_find_section_by_name(out_ef, ".bss");
	Elf64_Phdr *p = out_ef->data_Phdr;

	if (sec->sh_addr != (p->p_paddr + p->p_filesz)) {
		si_panic(".bss addr wrong\n");
	}
}

static void check_data_section_addr(elf_file_t *out_ef)
{
	Elf64_Shdr *sec = elf_find_section_by_name(out_ef, ".data");

	// .data section addr align 2M
	if (sec->sh_addr % ELF_SEGMENT_ALIGN != 0) {
		si_panic(".data addr wrong\n");
	}

	// GNU_RELRO end align 2M
	Elf64_Phdr *p = out_ef->relro_Phdr;
	if ((p->p_paddr + p->p_memsz) % ELF_SEGMENT_ALIGN != 0) {
		si_panic("GNU_RELRO end addr wrong\n");
	}
}

static bool is_dynsym_valid(Elf64_Sym *sym, const char *name)
{
	if (is_symbol_maybe_undefined(name)) {
		return true;
	}

	if (sym->st_shndx == SHN_UNDEF) {
		return false;
	}

	return true;
}

static void check_rela_dyn(elf_link_t *elf_link, elf_file_t *out_ef)
{
	if (is_share_mode(elf_link)) {
		return;
	}

	// static mode only some dynsym can be UND
	Elf64_Shdr *sec = elf_find_section_by_name(out_ef, ".rela.dyn");
	int len = sec->sh_size / sec->sh_entsize;
	Elf64_Rela *relas = (void *)out_ef->hdr + sec->sh_offset;
	Elf64_Rela *rela = NULL;

	for (int i = 0; i < len; i++) {
		rela = &relas[i];
		if (ELF64_R_SYM(rela->r_info) == 0) {
			continue;
		}
		Elf64_Sym *sym = elf_get_dynsym_by_rela(out_ef, rela);
		const char *sym_name = elf_get_sym_name(out_ef, sym);
		if (is_dynsym_valid(sym, sym_name) == false
                        && !is_static_nolibc_mode(elf_link)) {
			SI_LOG_EMERG("%s is UND\n", sym_name);
		}
	}
}

static void check_dynamic(elf_link_t *elf_link, elf_file_t *out_ef)
{
	Elf64_Dyn *dyn_arr = NULL;
	Elf64_Dyn *dyn = NULL;
	int dyn_count = 0;
	Elf64_Shdr *sec = elf_find_section_by_name(out_ef, ".dynamic");

	if (is_share_mode(elf_link) == false) {
		return;
	}

	// dyn mode must be DT_BIND_NOW
	dyn_count = sec->sh_size / sec->sh_entsize;
	dyn_arr = ((void *)out_ef->hdr) + sec->sh_offset;
	for (int i = 0; i < dyn_count; i++) {
		dyn = &dyn_arr[i];
		if (dyn->d_tag == DT_BIND_NOW) {
			return;
		}
	}
	si_panic("DT_BIND_NOW is needed\n");
}

// .rela.init_array no use, .init_array will set by .rely.dyn in ld.so
static void check_func(elf_file_t *out_ef, unsigned long func_point)
{
	Elf64_Rela *rela = elf_get_rela_by_addr(out_ef, func_point);

	// 00000000001222d0  0000000000000008 R_X86_64_RELATIVE                         30720
	// rela must be type R_X86_64_RELATIVE
	if (!elf_rela_is_relative(rela)) {
		si_panic("rela type wrong, r_info %lx r_addend %lx\n", rela->r_info, rela->r_addend);
	}

	// addr must in symbol table
	Elf64_Sym *sym = elf_find_symbol_by_addr(out_ef, rela->r_addend);
	if (sym == NULL) {
		si_panic("function addr is wrong, %lx\n", rela->r_addend);
	}
	const char *sym_name = elf_get_sym_name(out_ef, sym);
	SI_LOG_DEBUG("    %s\n", sym_name);
}

static void check_func_array(elf_file_t *out_ef, char *sec_name)
{
	SI_LOG_DEBUG("check func addr in %s:\n", sec_name);
	Elf64_Shdr *sec = elf_find_section_by_name(out_ef, sec_name);
	int count = sec->sh_size / sizeof(unsigned long);
	for (int i = 0; i < count; i++) {
		unsigned long addr = sec->sh_addr + (i * sizeof(unsigned long));
		check_func(out_ef, addr);
	}
}

// .init_array .fini_array is func addr
static void check_init_fini_array(elf_file_t *out_ef)
{
	check_func_array(out_ef, ".init_array");
	check_func_array(out_ef, ".fini_array");
}

void elf_check_elf(elf_link_t *elf_link)
{
	elf_file_t *out_ef = &elf_link->out_ef;
	check_bss_addr(out_ef);
	check_data_section_addr(out_ef);
	check_rela_dyn(elf_link, out_ef);
	check_dynamic(elf_link, out_ef);
	check_init_fini_array(out_ef);
}
