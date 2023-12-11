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

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/user.h>

#include "elf_link_common.h"
#include "elf_read_elf.h"
#include <si_common.h>
#include <si_debug.h>
#include <si_log.h>

unsigned int elf_align_file(elf_link_t *elf_link, unsigned int align)
{
	elf_link->next_file_offset = ALIGN(elf_link->next_file_offset, align);
	elf_link->next_mem_addr = ALIGN(elf_link->next_mem_addr, align);
	return elf_link->next_file_offset;
}

unsigned int elf_align_file_segment(elf_link_t *elf_link)
{
	return elf_align_file(elf_link, ELF_SEGMENT_ALIGN);
}

// .text offset in PAGE inherit from in ELF
unsigned int elf_align_file_section(elf_link_t *elf_link, Elf64_Shdr *sec, bool is_align_file_offset)
{
	unsigned long old_offset_in_page = sec->sh_addr & (~PAGE_MASK);
	unsigned long cur = elf_link->next_mem_addr & (~PAGE_MASK);
	if (cur <= old_offset_in_page) {
		if (is_align_file_offset) {
			elf_link->next_file_offset = (elf_link->next_file_offset & PAGE_MASK) + old_offset_in_page;
		}
		elf_link->next_mem_addr = (elf_link->next_mem_addr & PAGE_MASK) + old_offset_in_page;
	} else {
		// use next PAGE
		if (is_align_file_offset) {
			elf_link->next_file_offset = ALIGN(elf_link->next_file_offset, PAGE_SIZE);
			elf_link->next_file_offset += old_offset_in_page;
		}
		elf_link->next_mem_addr = ALIGN(elf_link->next_mem_addr, PAGE_SIZE);
		elf_link->next_mem_addr += old_offset_in_page;
	}

	return elf_link->next_file_offset;
}

void print_memory(void *dest, size_t num_bytes) {
    unsigned char *ptr = (unsigned char *)dest;
    for (size_t i = 0; i < num_bytes; i++) {
        printf("%02X ", ptr[i]);
    }
    printf("\n");
}

void *write_elf_file(elf_link_t *elf_link, void *src, unsigned int len)
{
	void *dest = ((void *)elf_link->out_ef.hdr) + elf_link->next_file_offset;
	(void)memcpy(dest, src, len);

	elf_link->next_file_offset += len;
	// TODO debug should not change next_mem_addr?
	elf_link->next_mem_addr += len;

	return dest;
}

void *write_elf_file_zero(elf_link_t *elf_link, unsigned int len)
{
	void *dest = ((void *)elf_link->out_ef.hdr) + elf_link->next_file_offset;
	(void)memset(dest, 0, len);

	elf_link->next_file_offset += len;
	elf_link->next_mem_addr += len;

	return dest;
}

void *write_elf_file_section(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec, Elf64_Shdr *dst_sec)
{
	// dst_sec is uesd by _get_new_elf_addr, to get new vaddr
	append_sec_mapping(elf_link, ef, sec, dst_sec);

	void *src = ((void *)ef->hdr) + sec->sh_offset;
	unsigned int len = sec->sh_size;

	if (sec->sh_type == SHT_NOBITS) {
		// if .tbss area is empty, get new offset addr will conflict
		// .tbss fill zero
		if (sec->sh_flags & SHF_TLS) {
			dst_sec->sh_type = SHT_PROGBITS;
			return write_elf_file_zero(elf_link, len);
		} else {
			// .bss
			elf_link->next_mem_addr += sec->sh_size;
			return 0;
		}
	}

	return write_elf_file(elf_link, src, len);
}

void elf_modify_file_zero(elf_link_t *elf_link, unsigned long offset, unsigned long len)
{
	void *dest = ((void *)elf_link->out_ef.hdr) + offset;
	(void)memset(dest, 0, len);
}

void elf_modify_section_zero(elf_link_t *elf_link, char *secname)
{
	Elf64_Shdr *sec = find_tmp_section_by_name(elf_link, secname);
	void *dest = ((void *)elf_link->out_ef.hdr) + sec->sh_offset;
	(void)memset(dest, 0, sec->sh_size);
}


void copy_elf_file(elf_file_t *in, off_t in_offset, elf_file_t *out, off_t out_offset, size_t len)
{
	void *src = ((void *)in->hdr) + in_offset;
	void *dest = ((void *)out->hdr) + out_offset;

	(void)memcpy(dest, src, len);
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

static Elf64_Shdr *find_sec_exclude_main_ef(elf_link_t *elf_link, const char *name, elf_file_t **lef)
{
	int in_ef_nr = elf_link->in_ef_nr;
	elf_file_t *ef = NULL;
	Elf64_Shdr *sec = NULL;
	elf_file_t *main_ef = get_main_ef(elf_link);

	for (int i = 0; i < in_ef_nr; i++) {
		ef = &elf_link->in_efs[i];
		if (ef == main_ef) {
			continue;
		}
		sec = elf_find_section_by_name(ef, name);
		if (sec == NULL) {
			continue;
		}
		*lef = ef;
		return sec;
	}

	return NULL;
}

static Elf64_Shdr *add_tmp_section_by_name(elf_link_t *elf_link, const char *name)
{
	int in_ef_nr = elf_link->in_ef_nr;
	Elf64_Shdr *sec = NULL;

	// find in template elf, then find in other elfs
	elf_file_t *ef = get_template_ef(elf_link);
	sec = elf_find_section_by_name(ef, name);
	if (sec != NULL) {
		return add_tmp_section(elf_link, ef, sec);
	}
	for (int i = 0; i < in_ef_nr; i++) {
		ef = &elf_link->in_efs[i];
		sec = elf_find_section_by_name(ef, name);
		if (sec == NULL) {
			continue;
		}
		// found
		break;
	}

	// move _init_first to .preinit_array
	if (is_need_preinit(elf_link) && is_preinit_name(name)) {
		if (sec) {
			si_panic(".preinit_array not supported\n");
		}
		sec = find_sec_exclude_main_ef(elf_link, ".init_array", &ef);
		if (sec == NULL) {
			return NULL;
		}
		elf_link->preinit_sec = add_tmp_section(elf_link, ef, sec);
		return elf_link->preinit_sec;
	}

	if (sec == NULL) {
		return NULL;
	}

	return add_tmp_section(elf_link, ef, sec);
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

void copy_from_old_elf(elf_link_t *elf_link)
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

static void record_rela_arr(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec, void *dst)
{
	si_array_t *arr = NULL;
	char *name = elf_get_section_name(ef, sec);

	void *src = ((void *)ef->hdr) + sec->sh_offset;

	if (elf_is_rela_plt_name(name)) {
		arr = elf_link->rela_plt_arr;
	} else if (elf_is_rela_dyn_name(name)) {
		arr = elf_link->rela_dyn_arr;
	} else {
		return;
	}

	int obj_nr = sec->sh_size / sec->sh_entsize;
	for (int j = 0; j < obj_nr; j++) {
		elf_obj_mapping_t obj_rel = {0};
		obj_rel.src_ef = ef;
		obj_rel.src_sec = sec;
		obj_rel.src_obj = src;
		obj_rel.dst_obj = dst;
		si_array_append(arr, &obj_rel);
		src = src + sec->sh_entsize;
		dst = dst + sec->sh_entsize;
	}
}

static unsigned long elf_get_sh_size(elf_link_t *elf_link, Elf64_Shdr *tmp_sec)
{
	if (tmp_sec->sh_flags & SHF_ALLOC) {
		// .text .bss
		return elf_link->next_mem_addr - tmp_sec->sh_addr;
	} else {
		// .symtab is not ALLOC, so not need mem addr
		// it is at end of file, it get mem space is OK too
		return elf_link->next_file_offset - tmp_sec->sh_offset;
	}
}

static bool is_merge_libc_first(elf_link_t *elf_link, Elf64_Shdr *tmp_sec, const char *name)
{
	if (!is_static_nold_mode(elf_link)) {
		return false;
	}

	if (elf_is_dynsym_sec(tmp_sec)) {
		return true;
	}

	if (elf_is_dynstr_name(name)) {
		return true;
	}

	if (is_init_name(name)) {
		return true;
	}

	return false;
}

static Elf64_Shdr *elf_merge_section(elf_link_t *elf_link, Elf64_Shdr *tmp_sec, const char *name, bool skip_main_ef)
{
	elf_file_t *ef = NULL;
	int in_ef_nr = elf_link->in_ef_nr;
	Elf64_Shdr *sec = NULL;
	void *dst = NULL;
	elf_file_t *main_ef = get_main_ef(elf_link);

	tmp_sec->sh_offset = elf_align_file(elf_link, tmp_sec->sh_addralign);
	tmp_sec->sh_addr = elf_link->next_mem_addr;
	SI_LOG_DEBUG("section %s at 0x%lx\n", name, tmp_sec->sh_offset);

	// libc .dynsym .dynstr need put first, so version section no change
	bool is_first_libc = is_merge_libc_first(elf_link, tmp_sec, name);
	elf_file_t *libc_ef = get_libc_ef(elf_link);
	if (is_first_libc) {
		ef = libc_ef;
		sec = elf_find_section_by_name(ef, name);
		elf_align_file(elf_link, sec->sh_addralign);
		write_elf_file_section(elf_link, ef, sec, tmp_sec);
	}

	for (int i = 0; i < in_ef_nr; i++) {
		// TODO: order by deps lib
		// ef = &elf_link->in_efs[in_ef_nr - 1 - i];
		ef = &elf_link->in_efs[i];
		if (skip_main_ef && (ef == main_ef)) {
			continue;
		}
		if (is_first_libc && (ef == libc_ef)) {
			continue;
		}
		sec = elf_find_section_by_name(ef, name);
		if (sec == NULL) {
			continue;
		}

		elf_align_file(elf_link, sec->sh_addralign);
		dst = write_elf_file_section(elf_link, ef, sec, tmp_sec);
		record_rela_arr(elf_link, ef, sec, dst);
	}

	tmp_sec->sh_size = elf_get_sh_size(elf_link, tmp_sec);
	return tmp_sec;
}

Elf64_Shdr *merge_all_ef_section(elf_link_t *elf_link, const char *name)
{
	Elf64_Shdr *tmp_sec = add_tmp_section_by_name(elf_link, name);
	if (tmp_sec == NULL) {
		si_panic("section is not needed, %s\n", name);
		return NULL;
	}

	return elf_merge_section(elf_link, tmp_sec, name, false);
}

Elf64_Shdr *merge_libs_ef_section(elf_link_t *elf_link, const char *dst_name, const char *src_name)
{
	Elf64_Shdr *tmp_sec = add_tmp_section_by_name(elf_link, dst_name);
	if (tmp_sec == NULL) {
		si_panic("section is not needed, %s\n", dst_name);
		return NULL;
	}

	return elf_merge_section(elf_link, tmp_sec, src_name, true);
}

static void append_section(elf_link_t *elf_link, Elf64_Shdr *dst_sec, elf_file_t *ef, Elf64_Shdr *sec)
{
	bool is_align_file_offset = true;

	// bss sections middle no need change file offset
	if (dst_sec->sh_offset != 0 && sec->sh_type == SHT_NOBITS && !(sec->sh_flags & SHF_TLS)) {
		is_align_file_offset = false;
	}
	// TODO clean code
	char *name = elf_get_section_name(ef, sec);
	if (strstr(name, "debug") != NULL) {
		is_align_file_offset = false;
	}
	// offset in PAGE inherit from in ELF
	elf_align_file_section(elf_link, sec, is_align_file_offset);

	// first in section to dst section
	if (dst_sec->sh_offset == 0) {
		dst_sec->sh_offset = elf_link->next_file_offset;
		if (elf_is_debug_section(ef, dst_sec) || elf_is_rela_debug_section(ef, dst_sec)) {
			dst_sec->sh_addr = 0;
		} else {
			dst_sec->sh_addr = elf_link->next_mem_addr;
		}
	}

	write_elf_file_section(elf_link, ef, sec, dst_sec);
}

static void merge_section(elf_link_t *elf_link, Elf64_Shdr *dst_sec, elf_file_t *ef, Elf64_Shdr *sec)
{
	// in append_section, the first section need change this
	dst_sec->sh_offset = 0;
	dst_sec->sh_addr = 0;

	append_section(elf_link, dst_sec, ef, sec);
	dst_sec->sh_size = elf_get_sh_size(elf_link, dst_sec);
}

static Elf64_Shdr *merge_ef_section_by_name(elf_link_t *elf_link, elf_file_t *ef, const char *sec_name)
{
	Elf64_Shdr *sec = elf_find_section_by_name(ef, sec_name);
	if (sec == NULL) {
		return NULL;
	}
	Elf64_Shdr *dst_sec = add_tmp_section(elf_link, ef, sec);
	if (dst_sec == NULL) {
		return NULL;
	}

	merge_section(elf_link, dst_sec, ef, sec);
	SI_LOG_DEBUG("section %-20s %08lx %08lx %06lx\n",
			sec_name, dst_sec->sh_addr, dst_sec->sh_offset, dst_sec->sh_size);
	return dst_sec;
}

Elf64_Shdr *merge_libc_ef_section(elf_link_t *elf_link, const char *sec_name)
{
	elf_file_t *libc_ef = get_libc_ef(elf_link);
	if (libc_ef == NULL) {
		si_panic("need libc.so\n");
	}

	return merge_ef_section_by_name(elf_link, libc_ef, sec_name);
}

Elf64_Shdr *merge_template_ef_section(elf_link_t *elf_link, const char *sec_name)
{
	elf_file_t *ef = get_template_ef(elf_link);
	return merge_ef_section_by_name(elf_link, ef, sec_name);
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

	dst_sec->sh_size = elf_get_sh_size(elf_link, dst_sec);
	SI_LOG_DEBUG("section %-20s %08lx %08lx %06lx\n", sec_name, dst_sec->sh_addr, dst_sec->sh_offset, dst_sec->sh_size);
}

void merge_debug_sections(elf_link_t *elf_link)
{
	merge_filter_sections(elf_link, ".debug_info", debug_info_section_filter);
	merge_filter_sections(elf_link, ".debug_abbrev", debug_abbrev_section_filter);
	merge_filter_sections(elf_link, ".debug_line", debug_line_section_filter);
	merge_filter_sections(elf_link, ".debug_str", debug_str_section_filter);
	merge_filter_sections(elf_link, ".debug_line_str", debug_line_str_section_filter);
}

void merge_text_sections(elf_link_t *elf_link)
{
	merge_filter_sections(elf_link, ".text", text_section_filter);
}

void merge_rodata_sections(elf_link_t *elf_link)
{
	merge_filter_sections(elf_link, ".rodata", rodata_section_filter);
}

static void merge_got_section(elf_link_t *elf_link)
{
	merge_filter_sections(elf_link, ".got", got_section_filter);
}

void merge_rwdata_sections(elf_link_t *elf_link)
{
	merge_filter_sections(elf_link, ".data", rwdata_section_filter);

	// .bss __libc_freeres_ptrs
	merge_filter_sections(elf_link, ".bss", bss_section_filter);
}

static int foreach_merge_section_by_name(const void *item, void *pridata)
{
	const char *name = item;
	elf_link_t *elf_link = pridata;

	// add .preinit_array section for libc init func
	if (is_need_preinit(elf_link) && is_init_name(name)) {
		merge_libs_ef_section(elf_link, ".preinit_array", ".init_array");

		// .init_array
		merge_template_ef_section(elf_link, name);
		return 0;
	}

	merge_all_ef_section(elf_link, name);
	return 0;
}

static void merge_relro_sections(elf_link_t *elf_link)
{
	elf_file_t *ef = NULL;
	int count = elf_link->in_ef_nr;
	// sec name list
	si_array_t *arr = si_array_new_strings();

	// get sec name from all ELFs
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

// .tdata .tbss .init_array .fini_array .data.rel.ro .dynamic .got
void merge_data_relro_sections(elf_link_t *elf_link)
{
	merge_relro_sections(elf_link);

	// .got offset in PAGE need no change
	merge_got_section(elf_link);
}

int create_elf_file(char *file_name, elf_file_t *elf_file, mode_t mode, uid_t owner, gid_t group)
{
// max output file len
#define MAX_ELF_FILE_LEN (0x100000 * 512)

	size_t len = MAX_ELF_FILE_LEN;
	int fd = open(file_name, O_CREAT | O_RDWR, mode);
	size_t ret;

	if (fd == -1) {
		si_panic("open fail %d\n ", errno);
		return -1;
	}

	if (fchown(fd, owner, group) != 0) {
		si_panic("fchown fail %d\n ", errno);
		close(fd);
		return -1;
	}

	elf_file->fd = fd;
	elf_file->file_name = strdup(file_name);
	lseek(fd, len - 1, SEEK_SET);
	ret = write(fd, "", 1);
	if (ret == -1UL) {
		si_panic("%s write fail\n", __func__);
	}

	elf_file->hdr = mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (elf_file->hdr == MAP_FAILED) {
		si_panic("mmap fail %d\n ", errno);
		close(fd);
		return -1;
	}

	return 0;
	// file need truncate when finish
}

void truncate_elf_file(elf_link_t *elf_link)
{
	elf_file_t *out_ef = &elf_link->out_ef;
	int ret = ftruncate(out_ef->fd, elf_link->next_file_offset);
	if (ret == -1) {
		si_panic("%s ftruncate fail\n", __func__);
	}
}
