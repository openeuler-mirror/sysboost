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
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <si_debug.h>
#include <si_log.h>
#include "si_array.h"

#include "elf_check_elf.h"
#include "elf_hugepage.h"
#include "elf_link_elf.h"
#include "elf_relocation.h"
#include "elf_write_elf.h"

#ifdef __aarch64__
#define LD_SO_PATH "/lib/ld-linux-aarch64.so.1"
#else
#define LD_SO_PATH "/lib64/ld-linux-x86-64.so.2"
#endif

#define EXTEND_SIZE   2

elf_link_t *elf_link_new(void)
{
	elf_link_t *elf_link = NULL;

	// This process is a oneshot process. The release of variable elf_link
	// depends on the process exit
	elf_link = malloc(sizeof(elf_link_t));
	if (!elf_link) {
		SI_LOG_ERR("malloc fail\n");
		return NULL;
	}
	bzero(elf_link, sizeof(elf_link_t));

	// prepare temp secs for link
	elf_link->out_ef.sechdrs = elf_link->tmp_sechdrs_buf;

	elf_link->symbol_mapping_arr = si_array_new(sizeof(elf_symbol_mapping_t));

	elf_link->sec_mapping_arr = si_array_new(sizeof(elf_sec_mapping_t));
	elf_link->obj_mapping_arr = si_array_new(sizeof(elf_obj_mapping_t));

	elf_link->rela_plt_arr = si_array_new(sizeof(elf_obj_mapping_t));
	elf_link->rela_dyn_arr = si_array_new(sizeof(elf_obj_mapping_t));

	elf_link->hook_func = false;
	elf_link->direct_call_optimize = false;
	elf_link->direct_vdso_optimize = false;
	elf_link->delete_symbol_version = true;

	// out file not create
	elf_link->out_ef.fd = -1;

	return elf_link;
}

char *elf_link_mode_str(unsigned int mode)
{
	switch (mode) {
	case ELF_LINK_STATIC:
		return ELF_LINK_STATIC_S;
	case ELF_LINK_STATIC_NOLIBC:
		return ELF_LINK_STATIC_NOLIBC_S;
	case ELF_LINK_STATIC_NOLD:
		return ELF_LINK_STATIC_NOLD_S;
	default:
		return ELF_LINK_SHARE_S;
	}
}

int elf_link_set_mode(elf_link_t *elf_link, unsigned int mode)
{
	elf_file_t *ef = NULL;

	elf_link->link_mode = mode;
	if (mode == ELF_LINK_SHARE) {
		return 0;
	}
	if (mode > ELF_LINK_STATIC_NOLD) {
		return -1;
	}

	elf_link->direct_call_optimize = true;

	if (elf_link->in_ef_nr != 0) {
		SI_LOG_ERR("set mode must before add elf file\n");
		return -1;
	}

	if (mode == ELF_LINK_STATIC_NOLD) {
		int ret = elf_read_file(LD_SO_PATH, &elf_link->ld_ef, true);
		if (ret != 0) {
			SI_LOG_ERR("elf_read_file fail, %s\n", LD_SO_PATH);
			return -1;
		}
		// in this mode, ld.so and vdso layout must fixed
		elf_link->direct_vdso_optimize = true;
		return 0;
	}

	// static mode use template
	if (mode == ELF_LINK_STATIC_NOLIBC) {
		ef = elf_link_add_infile(elf_link, RELOCATION_ROOT_DIR "/sysboost_static_template.relocation");
	} else {
		ef = elf_link_add_infile(elf_link, LD_SO_PATH);
	}

	if (ef == NULL) {
		SI_LOG_ERR("template file init fail\n");
		return -1;
	}

	return 0;
}

static int elf_link_prepare(elf_link_t *elf_link)
{
	char name[PATH_MAX] = {0};

	if (elf_link->link_mode == ELF_LINK_SHARE && elf_link->hook_func) {
		elf_link->hook_func_ef = elf_link_add_infile(elf_link, RELOCATION_ROOT_DIR "/libhook.so.relocation");
		if (elf_link->hook_func_ef == NULL) {
			return -1;
		}
	}

	if (elf_link->out_ef.fd != -1) {
		return 0;
	}

	// out file name is app.rto (RunTime Optimization)
	elf_file_t *main_ef = get_main_ef(elf_link);
	(void)snprintf(name, sizeof(name) - 1, "%s.rto", main_ef->file_name);
	return create_elf_file(name, &elf_link->out_ef);
}

elf_file_t *elf_link_add_infile(elf_link_t *elf_link, char *path)
{
	elf_file_t *ef = &elf_link->in_efs[elf_link->in_ef_nr];
	int ret = elf_read_file_relocation(path, ef);
	if (ret != 0) {
		return NULL;
	}
	elf_link->in_ef_nr++;

	// TODO: clean code, do not use libc_ef
	if (strncmp("libc.so", si_basename(path), sizeof("libc.so") - 1) == 0) {
		elf_link->libc_ef = ef;
	}

	// TODO: feature, zk--- recursion add dep lib

	return ef;
}

void copy_elf_file(elf_file_t *in, off_t in_offset, elf_file_t *out, off_t out_offset, size_t len)
{
	void *src = ((void *)in->hdr) + in_offset;
	void *dest = ((void *)out->hdr) + out_offset;

	(void)memcpy(dest, src, len);
}

// .interp is needed by dyn-mode, staitc-mode template do not have
static char *needed_sections[] = {
    ".interp",
    ".note.gnu.build-id",
    ".note.ABI-tag",
    ".gnu.hash",
    ".dynsym",
    ".dynstr",
    ".rela.dyn",
    ".rela.plt",
    ".text",
    ".rodata",
    ".eh_frame_hdr", // this section's header is not modified, is it really needed?
    ".tdata",
    ".tbss",
    ".init_array",
    ".fini_array",
    ".data.rel.ro",
    ".dynamic",
    ".got",
    ".data",
    ".bss",
    ".symtab",
    ".strtab",
    ".shstrtab",
};
#define NEEDED_SECTIONS_LEN (sizeof(needed_sections) / sizeof(needed_sections[0]))

static bool is_section_needed(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec)
{
	char *name = elf_get_section_name(ef, sec);

	// first section name is empty
	if (name == NULL || *name == '\0') {
		return true;
	}

	// no use .plt, so delete .rela.plt
	if (is_direct_call_optimize(elf_link) == true) {
		if (!strcmp(name, ".rela.plt")) {
			return false;
		}
	}

	for (unsigned i = 0; i < NEEDED_SECTIONS_LEN; i++) {
		if (!strcmp(name, needed_sections[i])) {
			return true;
		}
	}

	if (is_delete_symbol_version(elf_link) == false) {
		if (!strcmp(name, ".gnu.version") || !strcmp(name, ".gnu.version_r")) {
			return true;
		}
	}

	return false;

	/*
	TODO: clean code, below is original implementation, don't have any effect now
	if ((sec->sh_type == SHT_RELA) && (!(sec->sh_flags & SHF_ALLOC)))
		return false;
	if (sec->sh_type == SHT_GNU_versym || sec->sh_type == SHT_GNU_verdef ||
	    sec->sh_type == SHT_GNU_verneed)
		return false;
	if (elf_is_debug_section(ef, sec))
		return false;

	return true;
	*/
}

static Elf64_Shdr *add_tmp_section(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *src_sec)
{
	if (is_section_needed(elf_link, ef, src_sec) == false) {
		return NULL;
	}

	int j = elf_link->out_ef.hdr->e_shnum;
	if (j == MAX_ELF_SECTION - 1) {
		si_panic("not more new elf sections can be created\n");
	}

	Elf64_Shdr *dst_sec = &elf_link->out_ef.sechdrs[j];
	if (src_sec != NULL) {
		memcpy(dst_sec, src_sec, sizeof(Elf64_Shdr));
		append_obj_mapping(elf_link, ef, NULL, src_sec, dst_sec);
	}

	j++;
	elf_link->out_ef.hdr->e_shnum = j;

	// sec name change after .shstrtab
	return dst_sec;
}

static Elf64_Shdr *add_tmp_section_by_name(elf_link_t *elf_link, const char *name)
{
	Elf64_Shdr *tmp_sec = NULL;
	elf_file_t *ef = get_template_ef(elf_link);
	int count = elf_link->in_ef_nr;
	Elf64_Shdr *sec = NULL;

	// find in template elf, then find in other elfs
	sec = elf_find_section_by_name(ef, name);
	if (sec != NULL) {
		goto out;
	}

	// copy sec_struct to tmp
	for (int i = 0; i < count; i++) {
		ef = &elf_link->in_efs[i];
		sec = elf_find_section_by_name(ef, name);
		if (sec == NULL) {
			continue;
		}
		// found
		break;
	}
	if (sec == NULL) {
		return NULL;
	}

out:
	tmp_sec = add_tmp_section(elf_link, ef, sec);
	return tmp_sec;
}

static void copy_old_sections(elf_link_t *elf_link)
{
	Elf64_Shdr *src_sec = NULL;
	elf_file_t *template_ef = get_template_ef(elf_link);

	// copy first section
	elf_link->out_ef.hdr->e_shnum = 0;
	src_sec = template_ef->sechdrs;
	(void)add_tmp_section(elf_link, template_ef, src_sec);
}

static Elf64_Shdr *elf_merge_section(elf_link_t *elf_link, Elf64_Shdr *tmp_sec, const char *name)
{
	elf_file_t *ef;
	int count = elf_link->in_ef_nr;
	Elf64_Shdr *sec = NULL;
	elf_obj_mapping_t obj_rel = {0};
	void *dst = NULL;
	si_array_t *arr = NULL;

	tmp_sec->sh_offset = elf_align_file(elf_link, tmp_sec->sh_addralign);
	tmp_sec->sh_addr = elf_link->next_mem_addr;
	SI_LOG_DEBUG("section %s at 0x%lx\n", name, tmp_sec->sh_offset);

	for (int i = 0; i < count; i++) {
		if (!strcmp(name, ".init_array")) {
			ef = &elf_link->in_efs[count - 1 - i];
		} else {
			ef = &elf_link->in_efs[i];
		}
		sec = elf_find_section_by_name(ef, name);
		if (sec == NULL) {
			continue;
		}

		elf_align_file(elf_link, sec->sh_addralign);
		dst = write_elf_file_section(elf_link, ef, sec, tmp_sec);

		void *src = ((void *)ef->hdr) + sec->sh_offset;

		if (strcmp(name, ".rela.plt") == 0) {
			arr = elf_link->rela_plt_arr;
		} else if (strcmp(name, ".rela.dyn") == 0) {
			arr = elf_link->rela_dyn_arr;
		} else {
			continue;
		}
		int obj_nr = sec->sh_size / sec->sh_entsize;
		for (int j = 0; j < obj_nr; j++) {
			obj_rel.src_ef = ef;
			obj_rel.src_sec = sec;
			obj_rel.src_obj = src;
			obj_rel.dst_obj = dst;
			si_array_append(arr, &obj_rel);
			src = src + sec->sh_entsize;
			dst = dst + sec->sh_entsize;
		}
	}

	if (tmp_sec->sh_flags & SHF_ALLOC) {
		tmp_sec->sh_size = elf_link->next_mem_addr - tmp_sec->sh_addr;
	} else {
		tmp_sec->sh_size = elf_link->next_file_offset - tmp_sec->sh_offset;
	}
	return tmp_sec;
}

static Elf64_Shdr *write_merge_section(elf_link_t *elf_link, const char *name)
{
	Elf64_Shdr *tmp_sec = add_tmp_section_by_name(elf_link, name);
	if (tmp_sec == NULL) {
		si_panic("section is not needed, %s\n", name);
		return NULL;
	}
	return elf_merge_section(elf_link, tmp_sec, name);
}

static void append_section(elf_link_t *elf_link, Elf64_Shdr *dst_sec, elf_file_t *ef, Elf64_Shdr *sec)
{
	bool is_align_file_offset = true;

	// bss sections middle no need change file offset
	if (dst_sec->sh_offset != 0 && sec->sh_type == SHT_NOBITS && !(sec->sh_flags & SHF_TLS)) {
		is_align_file_offset = false;
	}
	// offset in PAGE inherit from in ELF
	elf_align_file_section(elf_link, sec, is_align_file_offset);

	// first in section to dst section
	if (dst_sec->sh_offset == 0) {
		dst_sec->sh_offset = elf_link->next_file_offset;
		dst_sec->sh_addr = elf_link->next_mem_addr;
	}

	write_elf_file_section(elf_link, ef, sec, dst_sec);
}

static void merge_section(elf_link_t *elf_link, Elf64_Shdr *dst_sec, elf_file_t *ef, Elf64_Shdr *sec)
{
	// in append_section, the first section need change this
	dst_sec->sh_offset = 0;
	dst_sec->sh_addr = 0;

	append_section(elf_link, dst_sec, ef, sec);
	dst_sec->sh_size = elf_link->next_mem_addr - dst_sec->sh_addr;
}

static void merge_section_with_name(elf_link_t *elf_link, char *sec_name)
{
	elf_file_t *ef = get_template_ef(elf_link);
	Elf64_Shdr *sec = elf_find_section_by_name(ef, sec_name);
	Elf64_Shdr *dst_sec = add_tmp_section(elf_link, ef, sec);
	if (dst_sec == NULL) {
		return;
	}

	merge_section(elf_link, dst_sec, ef, sec);
	SI_LOG_DEBUG("section %-20s %08lx %08lx %06lx\n",
			sec_name, dst_sec->sh_addr, dst_sec->sh_offset, dst_sec->sh_size);
}

static void merge_filter_section(elf_link_t *elf_link, Elf64_Shdr *dst_sec, elf_file_t *ef, section_filter_func filter)
{
	int count = ef->hdr->e_shnum;
	Elf64_Shdr *secs = ef->sechdrs;
	int i = 0;

	// skip 0
	for (i = 1; i < count; i++) {
		if (filter(ef, &secs[i]) == false) {
			continue;
		}

		append_section(elf_link, dst_sec, ef, &secs[i]);
	}
}

static void merge_filter_sections(elf_link_t *elf_link, char *sec_name, section_filter_func filter)
{
	elf_file_t *ef = NULL;
	int count = elf_link->in_ef_nr;
	Elf64_Shdr *dst_sec = add_tmp_section_by_name(elf_link, sec_name);

	if (dst_sec == NULL) {
		si_panic("section is not needed, %s\n", sec_name);
	}

	// in append_section, the first section need change this
	dst_sec->sh_offset = 0;
	dst_sec->sh_addr = 0;

	// do with all in ELFs
	for (int i = 0; i < count; i++) {
		ef = &elf_link->in_efs[i];
		merge_filter_section(elf_link, dst_sec, ef, filter);
	}

	dst_sec->sh_size = elf_link->next_mem_addr - dst_sec->sh_addr;
	SI_LOG_DEBUG("section %-20s %08lx %08lx %06lx\n", sec_name, dst_sec->sh_addr, dst_sec->sh_offset, dst_sec->sh_size);
}

static void merge_text_sections(elf_link_t *elf_link)
{
	merge_filter_sections(elf_link, ".text", text_section_filter);
}

static void merge_rodata_sections(elf_link_t *elf_link)
{
	merge_filter_sections(elf_link, ".rodata", rodata_section_filter);
}

static void merge_got_section(elf_link_t *elf_link)
{
	merge_filter_sections(elf_link, ".got", got_section_filter);
}

static void merge_rwdata_sections(elf_link_t *elf_link)
{
	merge_filter_sections(elf_link, ".data", rwdata_section_filter);

	// .bss __libc_freeres_ptrs
	merge_filter_sections(elf_link, ".bss", bss_section_filter);
}

static int foreach_merge_section_by_name(const void *item, void *pridata)
{
	const char *name = item;
	elf_link_t *elf_link = pridata;

	write_merge_section(elf_link, name);
	return 0;
}

static void merge_relro_sections(elf_link_t *elf_link)
{
	elf_file_t *ef = NULL;
	int count = elf_link->in_ef_nr;
	// sec name list
	si_array_t *arr = si_array_new_strings();

	// do with all in ELFs
	for (int i = 0; i < count; i++) {
		ef = &elf_link->in_efs[i];

		int num = ef->hdr->e_shnum;
		Elf64_Shdr *secs = ef->sechdrs;

		// skip 0
		for (int j = 1; j < num; j++) {
			if (elf_is_relro_section(ef, &secs[j]) == false) {
				continue;
			}
			// .got section not do here
			if (got_section_filter(ef, &secs[j]) == true) {
				continue;
			}

			char *name = elf_get_section_name(ef, &secs[j]);
			si_array_append_strings_uniq(arr, name);
		}
	}

	si_array_foreach_strings(arr, foreach_merge_section_by_name, elf_link);

	si_array_free_strings(arr);
}

static void modify_section_link(elf_link_t *elf_link)
{
	elf_file_t *template_ef = get_template_ef(elf_link);
	int count = template_ef->hdr->e_shnum;
	int j = elf_link->out_ef.hdr->e_shnum;
	Elf64_Shdr *find_sec = NULL;
	Elf64_Shdr *src_sec = template_ef->sechdrs;
	Elf64_Shdr *sec = NULL;

	// fix link
	for (int i = 1; i < j; i++) {
		sec = &elf_link->out_ef.sechdrs[i];
		if (sec->sh_link != 0 && (int)sec->sh_link < count) {
			find_sec = find_tmp_section_by_src(elf_link, &src_sec[sec->sh_link]);
			if (find_sec == NULL) {
				si_panic("find sec fail\n");
			}
			sec->sh_link = find_sec - elf_link->out_ef.sechdrs;
		}
		if (sec->sh_info != 0 && (int)sec->sh_info < count) {
			find_sec = find_tmp_section_by_src(elf_link, &src_sec[sec->sh_info]);
			if (find_sec == NULL) {
				// when .plt merge to .text, can not find .plt
				sec->sh_info = 0;
				continue;
			}
			sec->sh_info = find_sec - elf_link->out_ef.sechdrs;
		}
	}
}

static void copy_from_old_elf(elf_link_t *elf_link)
{
	elf_file_t *out_ef = &elf_link->out_ef;
	elf_file_t *template_ef = get_template_ef(elf_link);

	// copy elf header and segment
	elf_link->next_file_offset = template_ef->hdr->e_phoff + template_ef->hdr->e_phentsize * template_ef->hdr->e_phnum;
	copy_elf_file(template_ef, 0, out_ef, 0, elf_link->next_file_offset);
	elf_link->next_mem_addr = elf_link->next_file_offset;

	// reserve 3 segment space, main ELF may not have TLS segment
	write_elf_file_zero(elf_link, template_ef->hdr->e_phentsize * 3);

	// copy old sections, remove RELA
	copy_old_sections(elf_link);
	elf_link->out_ef.shstrtab_data = template_ef->shstrtab_data;
	elf_link->out_ef.strtab_data = template_ef->strtab_data;

	// use old phdr
	elf_read_elf_phdr(&elf_link->out_ef);

	// ELF must pie
	if (elf_link->out_ef.hdr_Phdr->p_vaddr != 0UL) {
		si_panic("ELF must compile with pie\n");
	}
}

static void modify_PHDR_segment(elf_link_t *elf_link)
{
	elf_file_t *out_ef = &elf_link->out_ef;

	// PHDR segment is first segment
	Elf64_Phdr *p = &out_ef->segments[0];
	if (p->p_type != PT_PHDR) {
		return;
	}

	// PHDR segment offset is 64, no change
	p->p_filesz = out_ef->hdr->e_phentsize * out_ef->hdr->e_phnum;
	p->p_memsz = p->p_filesz;
}

static void modify_INTERP_segment(elf_link_t *elf_link)
{
	elf_file_t *out_ef = &elf_link->out_ef;

	// INTERP segment is second segment
	Elf64_Phdr *p = &out_ef->segments[1];
	if (p->p_type != PT_INTERP) {
		si_panic("INTERP segment no exist\n");
		return;
	}

	Elf64_Shdr *tmp_sec = find_tmp_section_by_name(elf_link, ".interp");
	p->p_offset = tmp_sec->sh_offset;
	p->p_vaddr = p->p_offset;
	p->p_paddr = p->p_offset;
	p->p_filesz = tmp_sec->sh_size;
	p->p_memsz = p->p_filesz;
}

static void modify_GNU_EH_FRAME_segment(elf_link_t *elf_link)
{
	elf_file_t *out_ef = &elf_link->out_ef;
	Elf64_Phdr *p = out_ef->frame_Phdr;

	if (p == NULL) {
		return;
	}

	Elf64_Shdr *tmp_sec = find_tmp_section_by_name(elf_link, ".eh_frame_hdr");
	p->p_offset = tmp_sec->sh_offset;
	p->p_vaddr = p->p_offset;
	p->p_paddr = p->p_offset;
	p->p_filesz = tmp_sec->sh_size;
	p->p_memsz = p->p_filesz;
}

static void write_so_path_struct(elf_link_t *elf_link)
{
	elf_file_t *ef;
	int count = elf_link->in_ef_nr;

	// write count of so path, do not big than 3 Byte, tail Byte set null
	elf_link->so_path_struct =
		(unsigned long)write_elf_file(elf_link, &count, sizeof(int)) - ((unsigned long)elf_link->out_ef.hdr);
	for (int i = 0; i < count; i++) {
		ef = &elf_link->in_efs[i];
		const char *filename = si_basename(ef->file_name);
		int len = strlen(filename);
		write_elf_file(elf_link, (void *)filename, len + 1);
	}
}

/*
static void write_sysboost_section(elf_link_t *elf_link)
{
	if (is_static_mode(elf_link) == false) {
		return;
	}

	// add .sysboost_data section to record APP entry addr
	elf_link->sysboost_data = (elf_sysboost_data_t *)write_elf_file_zero(elf_link, sizeof(elf_sysboost_data_t));
	elf_link->sysboost_data->version = SYSBOOST_DATA_VERSION;

	Elf64_Shdr *sec = add_tmp_section(elf_link, NULL, NULL);
	// name index will modify after name string ready
	sec->sh_name = 0;
	sec->sh_type = SHT_NOTE;
	sec->sh_flags = SHF_ALLOC;
	sec->sh_addr = (unsigned long)elf_link->sysboost_data - ((unsigned long)elf_link->out_ef.hdr);
	sec->sh_offset = sec->sh_addr;
	sec->sh_size = sizeof(elf_sysboost_data_t);
	sec->sh_link = 0;
	sec->sh_info = 0;
	sec->sh_addralign = SYSBOOST_DATA_ALIGN;
	sec->sh_entsize = 0;
	elf_link->sysboost_data_sec = sec;
}
*/

// call after .text ready
/*static void modify_app_entry_addr(elf_link_t *elf_link)
{
	if (is_static_mode(elf_link) == false) {
		return;
	}

	elf_file_t *main_ef = get_main_ef(elf_link);
	unsigned long old_sym_addr = find_sym_old_addr(main_ef, "main");
	unsigned long new_sym_addr = get_new_addr_by_old_addr(elf_link, main_ef, old_sym_addr);
	elf_link->sysboost_data->entry_addr = new_sym_addr;
}*/

// call after .shstrtab ready
/*static void append_sysboost_sec_name(elf_link_t *elf_link)
{
	if (is_static_mode(elf_link) == false) {
		return;
	}

	write_elf_file(elf_link, SYSBOOST_DATA_SEC_NAME, sizeof(SYSBOOST_DATA_SEC_NAME));
	unsigned int index = elf_link->out_ef.shstrtab_sec->sh_size;
	elf_link->sysboost_data_sec->sh_name = index;
	elf_link->out_ef.shstrtab_sec->sh_size += sizeof(SYSBOOST_DATA_SEC_NAME);
}*/

// main ELF and libc.so have .interp, need to ignore it
// .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag
static void write_interp_and_note(elf_link_t *elf_link)
{
	elf_file_t *template_ef = get_template_ef(elf_link);
	Elf64_Shdr *sec = NULL;
	Elf64_Shdr *begin_sec = NULL;
	Elf64_Shdr *end_sec = NULL;
	char *name = NULL;

	begin_sec = elf_find_section_by_name(template_ef, ".interp");
	// end is before .gnu.hash
	end_sec = elf_find_section_by_name(template_ef, ".gnu.hash");

	if (begin_sec == NULL || end_sec == NULL) {
		si_panic("section not found\n");
	}

	for (sec = begin_sec; sec < end_sec; sec = sec + 1) {
		name = elf_get_section_name(template_ef, sec);
		merge_section_with_name(elf_link, name);
	}
}

// .interp .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt
static void write_first_LOAD_segment(elf_link_t *elf_link)
{
	Elf64_Phdr *p = NULL;
	char *name = NULL;
	elf_file_t *template_ef = get_template_ef(elf_link);
	int count = template_ef->hdr->e_shnum;
	Elf64_Shdr *secs = template_ef->sechdrs;

	// main ELF and libc.so have .interp, need to ignore it
	// .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag
	write_interp_and_note(elf_link);

	// first sec is .gnu.hash, end by SHF_EXECINSTR
	Elf64_Shdr *sec = elf_find_section_by_name(template_ef, ".gnu.hash");
	int i = sec - secs;
	for (; i < count; i++) {
		if (secs[i].sh_flags & SHF_EXECINSTR) {
			break;
		}

		// write after NOTE section, so it can load in first PAGE memory
		/*if ((sechdrs[i - 1].sh_type == SHT_NOTE) && (sechdrs[i].sh_type != SHT_NOTE)) {
			write_sysboost_section(elf_link);
		}*/

		name = elf_get_section_name(template_ef, &secs[i]);
		if (is_direct_call_optimize(elf_link) && (strcmp(name, ".rela.plt") == 0)) {
			continue;
		}
		if (is_delete_symbol_version(elf_link) && ((strcmp(name, ".gnu.version")) == 0
					|| (strcmp(name, ".gnu.version_r")) == 0)) {
			continue;
		}

		write_merge_section(elf_link, name);
	}

	// after merge section, .dynstr put new addr
	Elf64_Shdr *tmp_sec = find_tmp_section_by_name(elf_link, ".dynstr");
	if (tmp_sec) {
		elf_link->out_ef.dynstr_data = (char *)elf_link->out_ef.hdr + tmp_sec->sh_offset;
	}

	// write at end of first segment
	if (elf_link->hook_func) {
		write_so_path_struct(elf_link);
	}

	// first LOAD segment
	elf_file_t *out_ef = &elf_link->out_ef;
	p = out_ef->hdr_Phdr;
	p->p_filesz = elf_link->next_file_offset;
	p->p_memsz = p->p_filesz;
	p->p_align = SI_HUGEPAGE_ALIGN_SIZE;
}

static bool elf_is_four_segment(elf_file_t *ef)
{
	if (ef->text_Phdr != ef->hdr_Phdr) {
		return true;
	}
	return false;
}

// .init .plt .plt.got .text.hot .text .fini
static void write_text(elf_link_t *elf_link)
{
	unsigned int start = 0;
	Elf64_Phdr *p;

	if (elf_is_four_segment(&elf_link->out_ef)) {
		start = elf_align_file_segment(elf_link);
	}

	// section with SHF_EXECINSTR
	merge_text_sections(elf_link);

	p = elf_link->out_ef.text_Phdr;
	if (elf_is_four_segment(&elf_link->out_ef)) {
		p->p_offset = start;
		p->p_vaddr = start;
		p->p_paddr = start;
	} else {
		start = p->p_vaddr;
	}
	p->p_filesz = elf_link->next_file_offset - start;
	p->p_memsz = p->p_filesz;
	p->p_align = SI_HUGEPAGE_ALIGN_SIZE;
}

// .rodata .eh_frame_hdr .eh_frame
static void write_rodata(elf_link_t *elf_link)
{
	unsigned int start = 0;
	Elf64_Phdr *p;

	if (elf_is_four_segment(&elf_link->out_ef)) {
		start = elf_align_file_segment(elf_link);
	}

	merge_rodata_sections(elf_link);
	write_merge_section(elf_link, ".eh_frame_hdr");

	// rodata
	elf_file_t *out_ef = &elf_link->out_ef;
	p = out_ef->rodata_Phdr;
	if (elf_is_four_segment(&elf_link->out_ef)) {
		p->p_offset = start;
		p->p_vaddr = start;
		p->p_paddr = start;
	} else {
		p = out_ef->hdr_Phdr;
		start = p->p_vaddr;
	}
	p->p_filesz = elf_link->next_file_offset - start;
	p->p_memsz = p->p_filesz;
	p->p_align = SI_HUGEPAGE_ALIGN_SIZE;
}

// .tdata .tbss .init_array .fini_array .data.rel.ro .dynamic .got
static void write_data_relro(elf_link_t *elf_link)
{
	merge_relro_sections(elf_link);

	// .got offset in PAGE need no change
	merge_got_section(elf_link);
}

static void modify_segment(elf_link_t *elf_link, Elf64_Phdr *p, char *begin, char *end)
{
	Elf64_Shdr *begin_sec = NULL;
	Elf64_Shdr *end_sec = NULL;

	begin_sec = find_tmp_section_by_name(elf_link, begin);
	end_sec = find_tmp_section_by_name(elf_link, end);

	if (begin_sec == NULL) {
		begin_sec = end_sec;
	}

	p->p_offset = begin_sec->sh_offset;
	p->p_vaddr = begin_sec->sh_offset;
	p->p_paddr = begin_sec->sh_offset;
	if (end_sec == NULL) {
		p->p_filesz = begin_sec->sh_size;
		p->p_memsz = begin_sec->sh_size;
		return;
	}
	p->p_filesz = end_sec->sh_offset - begin_sec->sh_offset;
	p->p_memsz = p->p_filesz + end_sec->sh_size;
}

static void modify_tls_segment(elf_link_t *elf_link)
{
	elf_file_t *out_ef = &elf_link->out_ef;

	if (out_ef->tls_Phdr == NULL) {
		Elf64_Shdr *begin_sec = NULL;
		Elf64_Shdr *end_sec = NULL;

		begin_sec = find_tmp_section_by_name(elf_link, ".tdata");
		end_sec = find_tmp_section_by_name(elf_link, ".tbss");

		if (begin_sec == NULL && end_sec == NULL) {
			return;
		}

		// add tls segment
		Elf64_Phdr *p = &out_ef->segments[out_ef->hdr->e_phnum];
		p->p_type = PT_TLS;
		p->p_flags = PF_R;
		p->p_offset = 0;
		p->p_vaddr = 0;
		p->p_paddr = 0;
		p->p_filesz = 0;
		p->p_memsz = 0;
		p->p_align = SI_CACHE_LINE_SIZE;

		out_ef->hdr->e_phnum += 1;
		out_ef->tls_Phdr = p;
	}

	modify_segment(elf_link, out_ef->tls_Phdr, ".tdata", ".tbss");
}

// .tdata .init_array .fini_array .dynamic .got    .got.plt .data .bss
static void write_data(elf_link_t *elf_link)
{
	unsigned int start;
	Elf64_Phdr *p;
	elf_file_t *out_ef = &elf_link->out_ef;

	// GNU_RELRO area change RW -> RO, need split by PAGE
	start = elf_align_file_segment(elf_link);
	write_data_relro(elf_link);

	// TLS segment, .tdata .tbss
	modify_tls_segment(elf_link);

	// GNU_RELRO segment, .tdata .init_array .fini_array .dynamic .got
	// GNU_RELRO end align 2M
	elf_align_file_segment(elf_link);
	p = out_ef->relro_Phdr;
	p->p_offset = start;
	p->p_vaddr = start;
	p->p_paddr = start;
	p->p_filesz = elf_link->next_file_offset - start;
	p->p_memsz = p->p_filesz;

	// .got.plt .data
	merge_rwdata_sections(elf_link);

	// data segment
	p = out_ef->data_Phdr;
	p->p_offset = start;
	p->p_vaddr = start;
	p->p_paddr = start;
	p->p_filesz = elf_link->next_file_offset - start;
	p->p_memsz = elf_link->next_mem_addr - start;
	p->p_align = SI_HUGEPAGE_ALIGN_SIZE;
}

static bool is_lib_in_elf(elf_link_t *elf_link, char *name)
{
	elf_file_t *ef;
	int count = elf_link->in_ef_nr;

	for (int i = 0; i < count; i++) {
		ef = &elf_link->in_efs[i];
		if (strcmp(name, si_basename(ef->file_name)) == 0) {
			return true;
		}
	}

	return false;
}

static bool is_lib_had_insert(elf_link_t *elf_link, char *name, Elf64_Dyn *dyn_arr, int count)
{
	Elf64_Dyn *dyn = NULL;

	if (count == 0) {
		return false;
	}

	for (int i = 0; i < count; i++) {
		dyn = &dyn_arr[i];
		char *tmp_name = elf_link->out_ef.dynstr_data + dyn->d_un.d_val;
		if (strcmp(name, tmp_name) == 0) {
			return true;
		}
	}

	return false;
}

static int dynamic_merge_lib_one(elf_link_t *elf_link, elf_file_t *ef, Elf64_Dyn *begin_dyn, int len)
{
	Elf64_Shdr *sec = NULL;
	Elf64_Dyn *dyn_arr = NULL;
	Elf64_Dyn *dyn = NULL;
	Elf64_Dyn *dst_dyn = NULL;
	int dyn_count = 0;

	sec = elf_find_section_by_name(ef, ".dynamic");
	if (sec == NULL) {
		return len;
	}
	dyn_arr = ((void *)ef->hdr) + sec->sh_offset;
	dyn_count = sec->sh_size / sec->sh_entsize;
	dst_dyn = &begin_dyn[len];
	for (int j = 0; j < dyn_count; j++) {
		dyn = &dyn_arr[j];
		if (dyn->d_tag != DT_NEEDED) {
			continue;
		}
		// delete library in this ELF
		char *name = ef->dynstr_data + dyn->d_un.d_val;
		if (is_lib_in_elf(elf_link, name)) {
			continue;
		}
		if (is_lib_had_insert(elf_link, name, begin_dyn, len)) {
			continue;
		}
		// In static-pic mode, all DT_NEEDED should be deleted.
		if (!is_share_mode(elf_link))
			continue;
		*dst_dyn = *dyn;
		// fix name index
		dst_dyn->d_un.d_val = get_new_name_offset(elf_link, ef, ef->dynstr_sec, dyn->d_un.d_val);
		dst_dyn++;
		len++;
	}

	return len;
}

static int dynamic_merge_lib(elf_link_t *elf_link, Elf64_Dyn *begin_dyn, int len)
{
	elf_file_t *ef;
	int count = elf_link->in_ef_nr;

	// merge library
	for (int i = 0; i < count; i++) {
		ef = &elf_link->in_efs[i];
		len = dynamic_merge_lib_one(elf_link, ef, begin_dyn, len);
	}

	return len;
}

static int dynamic_copy_obj(elf_link_t *elf_link, Elf64_Dyn *begin_dyn, int len)
{
	elf_file_t *ef;
	Elf64_Shdr *sec = NULL;
	Elf64_Dyn *dyn_arr = NULL;
	Elf64_Dyn *dyn = NULL;
	Elf64_Dyn *dst_dyn = NULL;
	int dyn_count = 0;

	dst_dyn = &begin_dyn[len];
	ef = &elf_link->in_efs[0];
	sec = elf_find_section_by_name(ef, ".dynamic");
	dyn_count = sec->sh_size / sec->sh_entsize;
	dyn_arr = ((void *)ef->hdr) + sec->sh_offset;
	for (int i = 0; i < dyn_count; i++) {
		unsigned long new_d_val;
		dyn = &dyn_arr[i];
		switch (dyn->d_tag) {
		case DT_NEEDED:
			continue;
		case DT_RUNPATH:
			// fix name index
			new_d_val = get_new_name_offset(elf_link, ef, ef->dynstr_sec, dyn->d_un.d_val);
			break;
		case DT_VERNEED:
		case DT_VERSYM:
			if (is_delete_symbol_version(elf_link)) {
				continue;
			}
			fallthrough;
		case DT_INIT:
		case DT_FINI:
		case DT_GNU_HASH:
		case DT_STRTAB:
		case DT_SYMTAB:
		case DT_PLTGOT:
		case DT_RELA:
			new_d_val = get_new_addr_by_old_addr(elf_link, ef, dyn->d_un.d_val);
			break;
		case DT_RELASZ:
			// size of .rela.dyn
			sec = find_tmp_section_by_name(elf_link, ".rela.dyn");
			new_d_val = sec->sh_size;
			break;
		case DT_JMPREL:
			if (is_direct_call_optimize(elf_link) == true) {
				continue;
			}
			new_d_val = get_new_addr_by_old_addr(elf_link, ef, dyn->d_un.d_val);
			break;
		case DT_PLTREL:
			if (is_direct_call_optimize(elf_link) == true) {
				continue;
			}
			*dst_dyn = *dyn;
			dst_dyn++;
			len++;
			continue;
		case DT_PLTRELSZ:
			if (is_direct_call_optimize(elf_link) == true) {
				continue;
			}
			// size of .rela.plt
			sec = find_tmp_section_by_name(elf_link, ".rela.plt");
			new_d_val = sec->sh_size;
			break;
		case DT_STRSZ:
			// size of .dynstr
			sec = find_tmp_section_by_name(elf_link, ".dynstr");
			new_d_val = sec->sh_size;
			break;
		case DT_INIT_ARRAY:
			sec = find_tmp_section_by_name(elf_link, ".init_array");
			new_d_val = sec->sh_addr;
			break;
		case DT_FINI_ARRAY:
			sec = find_tmp_section_by_name(elf_link, ".fini_array");
			new_d_val = sec->sh_addr;
			break;
		case DT_INIT_ARRAYSZ:
			sec = find_tmp_section_by_name(elf_link, ".init_array");
			new_d_val = sec->sh_size;
			break;
		case DT_FINI_ARRAYSZ:
			sec = find_tmp_section_by_name(elf_link, ".fini_array");
			new_d_val = sec->sh_size;
			break;
		case DT_VERNEEDNUM:
			if (is_delete_symbol_version(elf_link)) {
				continue;
			}
			// TODO: feature, symbol version DT_VERNEEDNUM
			fallthrough;
		default:
			*dst_dyn = *dyn;
			dst_dyn++;
			len++;
			continue;
		}
		*dst_dyn = *dyn;
		dst_dyn->d_un.d_val = new_d_val;
		dst_dyn++;
		len++;
	}

	return len;
}

// after .dynstr is ready
static void scan_dynamic(elf_link_t *elf_link)
{
	Elf64_Shdr *tmp_sec = find_tmp_section_by_name(elf_link, ".dynamic");
	Elf64_Dyn *begin_dyn = NULL;
	int len = 0;

	begin_dyn = ((void *)elf_link->out_ef.hdr) + tmp_sec->sh_offset;
	len = dynamic_merge_lib(elf_link, begin_dyn, len);

	// new addr of INIT FINI  STRTAB  SYMTAB
	len = dynamic_copy_obj(elf_link, begin_dyn, len);

	// modify len
	tmp_sec->sh_size = tmp_sec->sh_entsize * len;
}

static void modify_dynamic(elf_link_t *elf_link)
{
	Elf64_Phdr *p;
	elf_file_t *out_ef = &elf_link->out_ef;

	scan_dynamic(elf_link);

	// DYNAMIC
	Elf64_Shdr *sec = find_tmp_section_by_name(elf_link, ".dynamic");
	p = out_ef->dynamic_Phdr;
	p->p_offset = sec->sh_addr;
	p->p_vaddr = sec->sh_addr;
	p->p_paddr = sec->sh_addr;
	p->p_filesz = sec->sh_size;
	p->p_memsz = sec->sh_size;
}

static int get_local_symbol_count(elf_file_t *ef, Elf64_Shdr *sec)
{
	int count = sec->sh_size / sizeof(Elf64_Sym);
	Elf64_Sym *base = ((void *)ef->hdr) + sec->sh_offset;
	int local_count = 0;

	for (int i = 0; i < count; i++) {
		Elf64_Sym *sym = &base[i];
		if (ELF64_ST_BIND(sym->st_info) == STB_LOCAL) {
			local_count++;
		}
	}

	return local_count;
}

static int sym_cmp_func(const void *src_sym_a_, const void *src_sym_b_)
{
	const Elf64_Sym *src_sym_a = src_sym_a_;
	const int is_local_a = ELF64_ST_BIND(src_sym_a->st_info) == STB_LOCAL;
	const Elf64_Sym *src_sym_b = src_sym_b_;
	const int is_local_b = ELF64_ST_BIND(src_sym_b->st_info) == STB_LOCAL;

	if (is_local_a != is_local_b) {
		return is_local_b - is_local_a;
	}
	return src_sym_a->st_shndx - src_sym_b->st_shndx;
}

static inline Elf64_Addr get_symbol_new_value(elf_link_t *elf_link, elf_file_t *ef,
					      Elf64_Sym *sym, char *name)
{
	// _get_new_elf_addr will be unable to find symbol addr if
	// it is the boundary of two sections and no shndx is available.
	// _DYNAMIC is the the start of .dynamic
	// _GLOBAL_OFFSET_TABLE_ is ok if compiled with -znow
	if (sym->st_shndx == SHN_ABS) {
		if (elf_is_same_symbol_name("_DYNAMIC", name))
			return elf_link->out_ef.dynamic_Phdr->p_vaddr;
	}

	// STT_TLS symbol st_value is offset to TLS segment begin
	if (ELF64_ST_TYPE(sym->st_info) == STT_TLS) {
		return elf_get_new_tls_offset(elf_link, ef, sym->st_value);
	}

	/*
	 * __stop___libc_atexit is on the boundary of __libc_atexit and .bss,
	 * treat it specially.
	 */
	if (elf_is_same_symbol_name(name, "__stop___libc_atexit")) {
		Elf64_Shdr *sec = elf_find_section_by_name(ef, "__libc_atexit");
		if (sec == NULL) {
			si_panic("elf_find_section_by_name fail: __libc_atexit\n");
		}
		unsigned long old_start_addr = sec->sh_addr;
		unsigned long new_start_addr = _get_new_elf_addr(elf_link, ef, old_start_addr);
		return new_start_addr + sec->sh_size;
	}

	return _get_new_elf_addr(elf_link, ef, sym->st_value);
}

static inline Elf32_Section get_symbol_new_section(elf_link_t *elf_link, elf_file_t *ef,
						   Elf64_Sym *sym)
{
	Elf64_Section shndx = sym->st_shndx;

	if (shndx >= SHN_LORESERVE) {
		return shndx;
	}
	return get_new_section_index(elf_link, ef, shndx);
}

static inline Elf64_Word get_symbol_new_name(elf_link_t *elf_link, elf_file_t *ef,
					     Elf64_Sym *sym, Elf64_Word sh_link)
{
	Elf64_Word name = sym->st_name;
	Elf64_Shdr *strtab = &ef->sechdrs[sh_link];

	if (!name) {
		return 0;
	}
	return get_new_name_offset(elf_link, ef, strtab, name);
}

// after dst_sym->st_name modify, then elf_get_symbol_name for the out_ef can use
static void modify_symbol(elf_link_t *elf_link, Elf64_Shdr *sec, bool is_dynsym)
{
	int len = sec->sh_size / sizeof(Elf64_Sym);
	Elf64_Sym *base = ((void *)elf_link->out_ef.hdr) + sec->sh_offset;

	for (int i = 0; i < len; i++) {
		Elf64_Sym *dst_sym = &base[i];
		elf_sec_mapping_t *m = elf_find_sec_mapping_by_dst(elf_link, dst_sym);

		dst_sym->st_shndx = get_symbol_new_section(elf_link, m->src_ef, dst_sym);
		dst_sym->st_name = get_symbol_new_name(elf_link, m->src_ef, dst_sym, m->src_sec->sh_link);

		// after dst_sym->st_name modify, then elf_get_symbol_name for the out_ef can use
		char *name = NULL;
		if (is_dynsym == true) {
			name = elf_get_dynsym_name(&elf_link->out_ef, dst_sym);
		} else {
			name = elf_get_symbol_name(&elf_link->out_ef, dst_sym);
		}
		SI_LOG_DEBUG("modify_symbol: %s\n", name);

		dst_sym->st_value = get_symbol_new_value(elf_link, m->src_ef, dst_sym, name);
	}
}

static Elf64_Sym *find_defined_symbol(elf_file_t *ef, Elf64_Shdr *sec, char *sym_name)
{
	int count = sec->sh_size / sizeof(Elf64_Sym);
	Elf64_Sym *base = ((void *)ef->hdr) + sec->sh_offset;

	for (int i = 0; i < count; i++) {
		Elf64_Sym *dst_sym = &base[i];
		if (dst_sym->st_shndx == SHN_UNDEF || dst_sym->st_name == 0) {
			continue;
		}
		char *name = elf_get_dynsym_name(ef, dst_sym);
		if (elf_is_same_symbol_name(sym_name, name)) {
			return dst_sym;
		}
	}

	return NULL;
}

static void delete_undefined_symbol(elf_file_t *ef, Elf64_Shdr *sec)
{
	int count = sec->sh_size / sizeof(Elf64_Sym);
	Elf64_Sym *base = ((void *)ef->hdr) + sec->sh_offset;

	for (int i = 0; i < count; i++) {
		Elf64_Sym *dst_sym = &base[i];
		if (dst_sym->st_shndx != SHN_UNDEF || dst_sym->st_name == 0) {
			continue;
		}
		char *name = elf_get_dynsym_name(ef, dst_sym);
		Elf64_Sym *find = find_defined_symbol(ef, sec, name);
		if (find != NULL) {
			(void)memset(dst_sym, 0, sizeof(Elf64_Sym));
		}
	}
}

static void sort_symbol_table(elf_file_t *ef, Elf64_Shdr *sec)
{
	int count = sec->sh_size / sizeof(Elf64_Sym);
	void *base = ((void *)ef->hdr) + sec->sh_offset;

	qsort(base, count, sizeof(Elf64_Sym), sym_cmp_func);
}

// no glibc header for .gnu.hash section ,this is only used in modify_hash
typedef struct {
	uint32_t nbuckets;
	uint32_t symbias;
	uint32_t bitmask_nwords;
	uint32_t shift;
	uint64_t *bitmask;
	uint32_t *buckets;
	uint32_t *chain;
} hash_t;

static uint32_t elf_hash(char *str)
{
	uint32_t h = 5381;

	for (; *str; str++) {
		h = (h << 5) + h + *str;
	}

	return h;
}

static void modify_hash(elf_file_t *elf_file, Elf64_Shdr *sec, Elf64_Shdr *dyn, char *dynstr_data)
{
	uint32_t *sec_data = (uint32_t *)((char *)elf_file->hdr + sec->sh_offset);
	Elf64_Sym *dyn_start = (Elf64_Sym *)((char *)elf_file->hdr + dyn->sh_offset);
	Elf64_Sym *sym = dyn_start + dyn->sh_info;

	unsigned count = dyn->sh_size / dyn->sh_entsize;
	while (sym->st_shndx == STN_UNDEF) {
		++sym;
	}

	hash_t hash;
	// put everything into one bucket
	*sec_data++ = hash.nbuckets = 1;
	*sec_data++ = hash.symbias = sym - dyn_start;
	if (count == hash.symbias) {
		return;
	}
	// skip bloom filter by setting bloom words to all ones
	*sec_data++ = hash.bitmask_nwords = 1;
	*sec_data++ = hash.shift = 0;
	hash.bitmask = (uint64_t *)sec_data;
	for (int i = 0; i < (int)hash.bitmask_nwords; ++i) {
		hash.bitmask[i] = ~0;
	}
	sec_data += EXTEND_SIZE * hash.bitmask_nwords;
	hash.buckets = sec_data;
	hash.buckets[0] = hash.symbias;
	sec_data += hash.nbuckets;
	hash.chain = sec_data;
	for (unsigned i = hash.symbias; i < count; ++i) {
		hash.chain[i - hash.symbias] = elf_hash(sym->st_name + dynstr_data) & ~1;
		++sym;
	}
	// last bit is 1 iff its last symbol in the bucket
	hash.chain[count - 1 - hash.symbias] |= 1;
}

static void modify_dynsym(elf_link_t *elf_link)
{
	SI_LOG_DEBUG("modify_dynsym: \n");
	Elf64_Shdr *sec = find_tmp_section_by_name(elf_link, ".dynsym");
	modify_symbol(elf_link, sec, true);

	// delete undefined symbol, so dlsym can find the addr
	delete_undefined_symbol(&elf_link->out_ef, sec);

	sort_symbol_table(&elf_link->out_ef, sec);

	// sh_info is STB_LOCAL symbol count
	sec->sh_info = get_local_symbol_count(&elf_link->out_ef, sec);

	Elf64_Shdr *dyn = sec;
	sec = find_tmp_section_by_name(elf_link, ".gnu.hash");
	modify_hash(&elf_link->out_ef, sec, dyn, elf_link->out_ef.dynstr_data);
}

static void modify_symtab(elf_link_t *elf_link)
{
	SI_LOG_DEBUG("modify_symtab: \n");
	Elf64_Shdr *sec = find_tmp_section_by_name(elf_link, ".symtab");
	modify_symbol(elf_link, sec, false);

	sort_symbol_table(&elf_link->out_ef, sec);

	// sh_info is STB_LOCAL symbol count
	sec->sh_info = get_local_symbol_count(&elf_link->out_ef, sec);
}

static void write_symtab(elf_link_t *elf_link)
{
	char *sec_name = ".symtab";
	write_merge_section(elf_link, sec_name);
}

static void write_strtab(elf_link_t *elf_link)
{
	char *sec_name = ".strtab";
	Elf64_Shdr *tmp_sec = write_merge_section(elf_link, sec_name);
	elf_link->out_ef.strtab_data = (char *)elf_link->out_ef.hdr + tmp_sec->sh_offset;
}

// .shstrtab is no need LOAD, only use string offset, no need mapping
// use tmp_shstrtab in processing, copy to out_ef
static void write_shstrtab(elf_link_t *elf_link)
{
	char *sec_name = ".shstrtab";
	Elf64_Shdr *sec = write_merge_section(elf_link, sec_name);

	elf_link->out_ef.shstrtab_data = (char *)elf_link->out_ef.hdr + sec->sh_offset;

	//append_sysboost_sec_name(elf_link);
}

static void modify_section_name_index(elf_link_t *elf_link)
{
	elf_file_t *ef = &elf_link->out_ef;
	Elf64_Shdr *secs = ef->sechdrs;
	int sec_count = ef->hdr->e_shnum;

	// modify section link index, elf_read_elf_sections use link
	modify_section_link(elf_link);

	// sec points needed by modify_rela_dyn
	elf_read_elf_sections(ef);

	Elf64_Shdr *find_sec = find_tmp_section_by_name(elf_link, ".shstrtab");
	if (find_sec == NULL) {
		si_panic("find sec .shstrtab fail\n");
	}
	ef->hdr->e_shstrndx = find_sec - secs;

	// modify section name index, skip first one
	for (int i = 1; i < sec_count; i++) {
		if (secs[i].sh_name == 0) {
			continue;
		}
		elf_obj_mapping_t *obj_mapping = elf_get_mapping_by_dst(elf_link, &secs[i]);
		secs[i].sh_name = get_new_name_offset(elf_link, obj_mapping->src_ef,
					obj_mapping->src_ef->shstrtab_sec, secs[i].sh_name);
	}

	elf_show_sections(ef);
}

static void modify_elf_header(elf_link_t *elf_link)
{
	Elf64_Ehdr *hdr = elf_link->out_ef.hdr;
	int len = sizeof(Elf64_Shdr) * elf_link->out_ef.hdr->e_shnum;
	void *src = elf_link->out_ef.sechdrs;

	// write sections
	// addr point to sections
	hdr->e_shoff = elf_link->next_file_offset;
	write_elf_file(elf_link, src, len);

	// .text offset
	elf_file_t *template_ef = get_template_ef(elf_link);
	hdr->e_entry = get_new_addr_by_old_addr(elf_link, template_ef, hdr->e_entry);

	//modify_app_entry_addr(elf_link);

	// set hugepage flag
	elf_set_hugepage(elf_link);
}

// .init_array first func is frame_dummy, frame_dummy call register_tm_clones
// .fini_array first func is __do_global_dtors_aux, __do_global_dtors_aux call deregister_tm_clones
char *disabled_funcs[] = {
    "frame_dummy",
    "__do_global_dtors_aux",
};
#define DISABLED_FUNCS_LEN (sizeof(disabled_funcs) / sizeof(disabled_funcs[0]))
#define AARCH64_INSN_RET 0xD65F03C0U
#define X86_64_INSN_RET 0xC3
static void modify_init_and_fini(elf_link_t *elf_link)
{
	if (is_share_mode(elf_link) == true) {
		return;
	}
	Elf64_Ehdr *hdr = elf_link->out_ef.hdr;
	if (hdr->e_machine != EM_AARCH64 && hdr->e_machine != EM_X86_64) {
		si_panic("e_machine not support\n");
	}

	elf_file_t *out_ef = &elf_link->out_ef;

	// In .init_array and .fini_array, static-pie mode the EXEC ELF no need run
	// so we need to disable such functions in EXEC ELF
	elf_file_t *ef = get_main_ef(elf_link);
	for (unsigned j = 0; j < DISABLED_FUNCS_LEN; j++) {
		Elf64_Sym *sym = elf_find_symbol_by_name(ef, disabled_funcs[j]);
		unsigned long addr = get_new_addr_by_sym(elf_link, ef, sym);
		if (hdr->e_machine == EM_AARCH64) {
			elf_write_u32(out_ef, addr, AARCH64_INSN_RET);
		} else {
			elf_write_u8(out_ef, addr, X86_64_INSN_RET);
		}
	}
}

static void do_special_adapts(elf_link_t *elf_link)
{
	modify_init_and_fini(elf_link);
	correct_stop_libc_atexit(elf_link);
}

// merge per section
// .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .rela.dyn .rela.plt
// merge segment, keep offset in page
// .init .plt .text __libc_freeres_fn .fini
// merge segment, keep offset in page, split text and data
// .rodata .stapsdt.base .eh_frame_hdr .eh_frame .gcc_except_table
// merge per section, RW -> RO
// .tdata .init_array .fini_array .data.rel.ro .dynamic
// merge segment, keep offset in page, RW -> RO
// .got
// merge segment, keep offset in page
// .data .tm_clone_table __libc_subfreeres __libc_IO_vtables __libc_atexit .bss __libc_freeres_ptrs
static void elf_link_write_sections(elf_link_t *elf_link)
{
	// .interp .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt
	write_first_LOAD_segment(elf_link);

	// .init .plt .text __libc_freeres_fn .fini
	write_text(elf_link);

	// .rodata .stapsdt.base .eh_frame_hdr .eh_frame .gcc_except_table
	write_rodata(elf_link);

	// .tdata .tbss .init_array .fini_array .data.rel.ro .dynamic .got .got.plt .data .bss
	write_data(elf_link);

	// .dynamic
	modify_dynamic(elf_link);

	// .symtab
	write_symtab(elf_link);

	// .strtab
	write_strtab(elf_link);

	// .shstrtab
	write_shstrtab(elf_link);

	/*
	 * .comment is useless, it's used to hold comments about the generated ELF
	 * (details such as compiler version and execution platform).
	 */
}

int elf_link_write(elf_link_t *elf_link)
{
	if (elf_link_prepare(elf_link) < 0) {
		return -1;
	}

	// copy ELF header and PHDR segment
	copy_from_old_elf(elf_link);

	elf_link_write_sections(elf_link);

	// modify PHDR and INTERP segment
	if (is_share_mode(elf_link) || is_static_nold_mode(elf_link)) {
		modify_PHDR_segment(elf_link);
		modify_INTERP_segment(elf_link);
	}

	/*
	 * Notes segment is not processed.
	 * ELF notes allow for appending arbitrary information for the system to use.
	 * For example, the GNU tool chain uses ELF notes to pass
	 * information from the linker to the C library.
	 */

	modify_GNU_EH_FRAME_segment(elf_link);
	elf_show_segments(&elf_link->out_ef);

	modify_section_name_index(elf_link);

	// all section must had write, modify symbol need new text addr
	// dynsym st_name need fix before get_new_sym_index
	// .dynsym
	modify_dynsym(elf_link);
	// .symtab
	modify_symtab(elf_link);

	// sort symbol must before get_new_sym_index

	// symbol addr ready before rela use it
	init_symbol_mapping(elf_link);

	// .rela.dyn
	modify_rela_dyn(elf_link);
	// .rela.plt .plt.got
	modify_got(elf_link);

	// modify local call to use jump
	// .rela.init .rela.text .rela.rodata .rela.tdata .rela.init_array .rela.data
	modify_local_call(elf_link);

	// modify ELF header and write sections
	modify_elf_header(elf_link);

	do_special_adapts(elf_link);

	truncate_elf_file(elf_link);

	elf_check_elf(elf_link);

	return 0;
}
