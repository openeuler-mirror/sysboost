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
#include <si_array.h>

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

		// in this mode, ld.so lookup libc sym need symbol version
		elf_link->delete_symbol_version = false;

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
	char path[PATH_MAX] = {0};

	if (elf_link->link_mode == ELF_LINK_SHARE && elf_link->hook_func) {
		elf_link->hook_func_ef = elf_link_add_infile(elf_link, RELOCATION_ROOT_DIR "/libhook.so.relocation");
		if (elf_link->hook_func_ef == NULL) {
			return -1;
		}
	}

	if (elf_link->out_ef.fd != -1) {
		return 0;
	}

	// sysboostd 指定ouput临时路径, 避免使用ELF文件的并发操作
	bool is_empty = is_empty_path(elf_link->out_ef.file_name);
	elf_file_t *main_ef = get_main_ef(elf_link);
	if (is_empty) {
		// out file name is app.rto (RunTime Optimization)
		(void)snprintf(path, sizeof(path) - 1, "%s.rto", main_ef->file_name);
	} else {
		(void)strncpy(path, elf_link->out_ef.file_name, PATH_MAX - 1);
	}

	// mode and owner no change
	struct stat sb;
	int ret = fstat(main_ef->fd, &sb);
	if (ret != 0) {
		SI_LOG_ERR("fstat fail, %d\n", errno);
		return -1;
	}

	return create_elf_file(path, &elf_link->out_ef, sb.st_mode, sb.st_uid, sb.st_gid);
}

elf_file_t *elf_link_add_infile(elf_link_t *elf_link, char *path)
{
	elf_file_t *ef = &elf_link->in_efs[elf_link->in_ef_nr];
	int ret = elf_read_file_relocation(path, ef);
	if (ret != 0) {
		return NULL;
	}
	elf_link->in_ef_nr++;

	if (strncmp("libc.so", si_basename(path), sizeof("libc.so") - 1) == 0) {
		elf_link->libc_ef = ef;
	}

	return ef;
}

static int get_new_sec_index_by_old(elf_link_t *elf_link, Elf64_Shdr *dst_sec, int old_index)
{
	if (old_index == 0) {
		return 0;
	}

	elf_obj_mapping_t *obj_mapping = elf_get_mapping_by_dst(elf_link, dst_sec);
	elf_file_t *src_ef = obj_mapping->src_ef;
	//Elf64_Shdr *src_sec = (Elf64_Shdr *)obj_mapping->src_obj;

	// is not section index, do not change
	if (old_index >= src_ef->hdr->e_shnum) {
		return old_index;
	}
	Elf64_Shdr *old_sec = &src_ef->sechdrs[old_index];
	Elf64_Shdr *new_sec = find_tmp_section_by_src(elf_link, old_sec);
	if (new_sec == NULL) {
		// old sec struct may not copy to dst
		char *sec_name = elf_get_section_name(src_ef, old_sec);
		new_sec = find_tmp_section_by_name(elf_link, sec_name);
		if (new_sec == NULL) {
			si_panic("find sec fail old %s %s\n", src_ef->file_name, sec_name);
		}
	}

	return new_sec - elf_link->out_ef.sechdrs;
}

// .dynsym段是动态符号表, sh_info字段表示该段中符号表的第一个非本地符号的索引
// .gnu.version_r段是用于动态链接的版本控制信息的段, sh_info指定了版本表中默认版本的索引
// .gnu.version_d段, sh_info表示自定义version个数
static bool elf_is_need_fix_sh_info(Elf64_Shdr *sec)
{
	// SHT_RELA sh_info is index of text code section
	if (sec->sh_type == SHT_RELA) {
		return true;
	}

	return false;
}

static void modify_section_link(elf_link_t *elf_link)
{
	int out_sec_count = elf_link->out_ef.hdr->e_shnum;
	Elf64_Shdr *sec = NULL;

	// fix sh_link and sh_info
	for (int i = 1; i < out_sec_count; i++) {
		sec = &elf_link->out_ef.sechdrs[i];
		sec->sh_link = get_new_sec_index_by_old(elf_link, sec, sec->sh_link);

		if (elf_is_need_fix_sh_info(sec)) {
			sec->sh_info = get_new_sec_index_by_old(elf_link, sec, sec->sh_info);
		}
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
	elf_file_t *out_ef = get_out_ef(elf_link);

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
	elf_file_t *out_ef = get_out_ef(elf_link);
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
	unsigned long old_sym_addr = elf_find_symbol_addr_by_name(main_ef, "main");
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
// .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr
// .gnu.version .gnu.version_d .gnu.version_r .rela.dyn .rela.plt
static elf_section_t hdr_segment_section_arr[] = {
	{".interp", merge_template_ef_section},
	{".note.gnu.property", merge_template_ef_section},
	{".note.gnu.build-id", merge_template_ef_section},
	{".note.ABI-tag", merge_template_ef_section},
	{".gnu.hash", merge_all_ef_section},
	{".dynsym", merge_all_ef_section},
	{".dynstr", merge_all_ef_section},
	{".gnu.version", NULL},
	{".gnu.version_d", NULL},
	{".gnu.version_r", NULL},
	{".rela.dyn", merge_all_ef_section},
	{".rela.plt", merge_all_ef_section},
};
#define HDR_SEGMENT_SECTION_ARR_LEN (sizeof(hdr_segment_section_arr) / sizeof(hdr_segment_section_arr[0]))

static void write_hdr_segment_section_arr(elf_link_t *elf_link)
{
	for (unsigned i = 0; i < HDR_SEGMENT_SECTION_ARR_LEN; i++) {
		elf_section_t *sec_obj = &hdr_segment_section_arr[i];
		if (sec_obj->func == NULL) {
			continue;
		}
		sec_obj->func(elf_link, sec_obj->sec_name);
	}
}

static void fix_section_merge_func(elf_link_t *elf_link)
{
	for (unsigned i = 0; i < HDR_SEGMENT_SECTION_ARR_LEN; i++) {
		elf_section_t *sec_obj = &hdr_segment_section_arr[i];

		// .gnu.hash
		if (is_static_nold_mode(elf_link) && elf_is_gnu_hash_sec_name(sec_obj->sec_name)) {
			sec_obj->func = merge_libc_ef_section;
			continue;
		}

		// .dynsym
		if (is_static_nold_mode(elf_link) && elf_is_dynsym_sec_name(sec_obj->sec_name)) {
			sec_obj->func = merge_libc_ef_section;
			continue;
		}

		// .gnu.version .gnu.version_d .gnu.version_r
		if (elf_is_version_sec_name(sec_obj->sec_name)) {
			if (is_delete_symbol_version(elf_link) == false) {
				// nold mode copy from libc
				sec_obj->func = merge_libc_ef_section;
				continue;
			}
		}

		if (is_direct_call_optimize(elf_link) && elf_is_rela_plt_name(sec_obj->sec_name)) {
			sec_obj->func = NULL;
			continue;
		}
	}
}

// .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_d .gnu.version_r .rela.dyn .rela.plt
static void write_first_LOAD_segment(elf_link_t *elf_link)
{
	fix_section_merge_func(elf_link);
	write_hdr_segment_section_arr(elf_link);

	// write after NOTE section, so it can load in first PAGE memory
	/*if ((sechdrs[i - 1].sh_type == SHT_NOTE) && (sechdrs[i].sh_type != SHT_NOTE)) {
		write_sysboost_section(elf_link);
	}*/

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
	Elf64_Phdr *p = out_ef->hdr_Phdr;
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
	merge_all_ef_section(elf_link, ".eh_frame_hdr");

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
	// .tbss is set type Alloc when merge secion
	p->p_filesz = begin_sec->sh_size + end_sec->sh_size;
	p->p_memsz = p->p_filesz;
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
		p->p_align = begin_sec->sh_addralign;

		// align will impact tls len
		if (p->p_align != sizeof(unsigned long)) {
			si_panic("tls align must be 8\n");
		}

		out_ef->hdr->e_phnum += 1;
		out_ef->tls_Phdr = p;
	}

	modify_segment(elf_link, out_ef->tls_Phdr, ".tdata", ".tbss");
}

static void write_debug_info(elf_link_t *elf_link)
{
	merge_debug_sections(elf_link);
}

// .tdata .init_array .fini_array .dynamic .got    .got.plt .data .bss
static void write_data(elf_link_t *elf_link)
{
	unsigned int start;
	Elf64_Phdr *p;
	elf_file_t *out_ef = &elf_link->out_ef;

	// GNU_RELRO area change RW -> RO, need split by PAGE
	start = elf_align_file_segment(elf_link);
	merge_data_relro_sections(elf_link);

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
	Elf64_Dyn *dyn = NULL;

	Elf64_Shdr *sec = elf_find_section_by_name(ef, ".dynamic");
	if (sec == NULL) {
		return len;
	}

	Elf64_Dyn *dyn_arr = elf_get_section_data(ef, sec);
	int dyn_count = sec->sh_size / sizeof(Elf64_Dyn);
	Elf64_Dyn *dst_dyn = &begin_dyn[len];
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
		if (!is_share_mode(elf_link)) {
			continue;
		}
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

// .dynamic is merge all elf, so mem space is enough
static int dynamic_add_preinit(elf_link_t *elf_link, Elf64_Dyn *begin_dyn, int len)
{
	if (is_need_preinit(elf_link) == false) {
		return len;
	}

	Elf64_Shdr *sec = elf_link->preinit_sec;
	if (sec == NULL) {
		si_panic("not found .preinit_array\n");
	}

	Elf64_Dyn *dst_dyn = &begin_dyn[len];
	dst_dyn->d_tag = DT_PREINIT_ARRAY;
	dst_dyn->d_un.d_val = sec->sh_addr;
	len++;

	dst_dyn++;
	dst_dyn->d_tag = DT_PREINIT_ARRAYSZ;
	dst_dyn->d_un.d_val = sec->sh_size;
	len++;

	return len;
}

static void dynamic_copy_dyn(elf_link_t *elf_link, elf_file_t *src_ef, Elf64_Dyn *src_dyn, Elf64_Dyn *dst_dyn)
{
	dst_dyn->d_tag = src_dyn->d_tag;

	switch (src_dyn->d_tag) {
	case DT_NEEDED:
	case DT_SONAME:
		// fix name index
		dst_dyn->d_un.d_val = get_new_name_offset(elf_link, src_ef, src_ef->dynstr_sec, src_dyn->d_un.d_val);
		break;
	case DT_VERDEF:
	case DT_VERNEED:
	case DT_VERSYM:
	case DT_GNU_HASH:
	case DT_STRTAB:
	case DT_SYMTAB:
		dst_dyn->d_un.d_val = get_new_addr_by_old_addr(elf_link, src_ef, src_dyn->d_un.d_val);
		break;
	case DT_VERDEFNUM:
	case DT_VERNEEDNUM:
		// do not change nr, just copy from libc
		dst_dyn->d_un.d_val = src_dyn->d_un.d_val;
		break;
	default:
		si_panic("error dyn %lu\n", dst_dyn->d_tag);
		break;
	}
}

static Elf64_Dyn *dynamic_copy_dyn_by_type(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long dt, Elf64_Dyn *dst_dyn)
{
	Elf64_Dyn *src_dyn = elf_find_dyn_by_type(src_ef, dt);
	if (src_dyn == NULL) {
		si_panic("need dyn %lu\n", dt);
		return NULL;
	}

	dynamic_copy_dyn(elf_link, src_ef, src_dyn, dst_dyn);
	return dst_dyn;
}

// 0x0000000000000001 (NEEDED)             Shared library: [ld-linux-x86-64.so.2]
// 0x000000000000000e (SONAME)             Library soname: [libc.so.6]
// 0x000000006ffffffc (VERDEF)             0x23a70
// 0x000000006ffffffd (VERDEFNUM)          36
// 0x000000006ffffffe (VERNEED)            0x23f70
// 0x000000006fffffff (VERNEEDNUM)         1
// 0x000000006ffffff0 (VERSYM)             0x222de
// 0x000000006ffffef5 (GNU_HASH)           0x42e0
// 0x0000000000000005 (STRTAB)             0x1a470
// 0x0000000000000006 (SYMTAB)             0x89c8
static unsigned long libc_dt_arr[] = {
	DT_NEEDED,
	DT_SONAME,
	DT_VERDEF,
	DT_VERDEFNUM,
	DT_VERNEED,
	DT_VERNEEDNUM,
	DT_VERSYM,
	DT_GNU_HASH,
	DT_STRTAB,
	DT_SYMTAB,
};
#define LIBC_DT_ARR_LEN (sizeof(libc_dt_arr) / sizeof(libc_dt_arr[0]))

// .dynamic is merge all elf, so mem space is enough
// libc is merge to APP, so let libc_map = main_map in dl_main()
static int dynamic_add_obj_from_libc(elf_link_t *elf_link, Elf64_Dyn *begin_dyn, int len)
{
	if (!is_static_nold_mode(elf_link)) {
		return len;
	}

	elf_file_t *libc_ef = get_libc_ef(elf_link);
	if (libc_ef == NULL) {
		si_panic("need libc.so\n");
		return len;
	}

	Elf64_Dyn *dst_dyn = &begin_dyn[len];
	for (unsigned i = 0; i < LIBC_DT_ARR_LEN; i++) {
		(void)dynamic_copy_dyn_by_type(elf_link, libc_ef, libc_dt_arr[i], dst_dyn);
		len++;
		dst_dyn++;
	}

	return len;
}

static int dynamic_copy_obj(elf_link_t *elf_link, Elf64_Dyn *begin_dyn, int len)
{
	Elf64_Dyn *dst_dyn = &begin_dyn[len];
	elf_file_t *ef = get_template_ef(elf_link);
	Elf64_Shdr *sec = elf_find_section_by_name(ef, ".dynamic");
	Elf64_Dyn *dyn_arr = elf_get_section_data(ef, sec);
	Elf64_Dyn *dyn = NULL;
	int dyn_count = sec->sh_size / sec->sh_entsize;

	for (int i = 0; i < dyn_count; i++) {
		unsigned long new_d_val;
		dyn = &dyn_arr[i];
		switch (dyn->d_tag) {
		case DT_NEEDED:
		case DT_SONAME:
		case DT_VERDEF:
		case DT_VERNEED:
		case DT_VERSYM:
		case DT_VERDEFNUM:
		case DT_VERNEEDNUM:
			// have done before, here do nothing
			continue;
		case DT_RUNPATH:
			// fix name index
			new_d_val = get_new_name_offset(elf_link, ef, ef->dynstr_sec, dyn->d_un.d_val);
			break;
		case DT_GNU_HASH:
		case DT_STRTAB:
		case DT_SYMTAB:
			if (is_static_nold_mode(elf_link)) {
				// have done before
				continue;
			}
			fallthrough;
		case DT_INIT:
		case DT_FINI:
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

	// DT_SONAME
	len = dynamic_add_obj_from_libc(elf_link, begin_dyn, len);

	// DT_PREINIT_ARRAY
	len = dynamic_add_preinit(elf_link, begin_dyn, len);

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
	if (elf_is_symbol_type_section(sym)) {
		// section may be delete in out ef, so section symbol can not get new value
		return get_new_addr_by_old_addr_ok(elf_link, ef, sym->st_value);
	}

	// _get_new_elf_addr will be unable to find symbol addr if
	// it is the boundary of two sections and no shndx is available.
	// _DYNAMIC is the the start of .dynamic
	// _GLOBAL_OFFSET_TABLE_ is ok if compiled with -znow
	if (sym->st_shndx == SHN_ABS) {
		if (elf_is_same_symbol_name("_DYNAMIC", name)) {
			return elf_link->out_ef.dynamic_Phdr->p_vaddr;
		}
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
			si_panic("fail: __libc_atexit\n");
		}
		unsigned long old_start_addr = sec->sh_addr;
		unsigned long new_start_addr = get_new_addr_by_old_addr(elf_link, ef, old_start_addr);
		return new_start_addr + sec->sh_size;
	}

	return get_new_addr_by_old_addr(elf_link, ef, sym->st_value);
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

static inline Elf64_Sym *get_src_sym_by_dst(elf_link_t *elf_link, Elf64_Sym *dst_sym, elf_sec_mapping_t *m)
{
	unsigned long out_ef_sec_begin = ((unsigned long)elf_link->out_ef.hdr) + m->dst_file_offset;
	unsigned long offset_to_sec = (unsigned long)dst_sym - out_ef_sec_begin;
	void *sec_data = elf_get_section_data(m->src_ef, m->src_sec);
	return (Elf64_Sym *)(sec_data + offset_to_sec);
}

static void modify_symbol(elf_link_t *elf_link, Elf64_Shdr *sec)
{
	int len = sec->sh_size / sizeof(Elf64_Sym);
	Elf64_Sym *base = elf_get_section_data(&elf_link->out_ef, sec);

	for (int i = 0; i < len; i++) {
		Elf64_Sym *dst_sym = &base[i];
		elf_sec_mapping_t *m = elf_find_sec_mapping_by_dst(elf_link, dst_sym);
		Elf64_Sym *src_sym = get_src_sym_by_dst(elf_link, dst_sym, m);

		dst_sym->st_shndx = get_symbol_new_section(elf_link, m->src_ef, src_sym);
		dst_sym->st_name = get_symbol_new_name(elf_link, m->src_ef, src_sym, m->src_sec->sh_link);

		char *name = elf_get_sym_name(m->src_ef, src_sym);
		SI_LOG_DEBUG("sym name: %s %s\n", m->src_ef->file_name, name);

		dst_sym->st_value = get_symbol_new_value(elf_link, m->src_ef, src_sym, name);
	}
}

static Elf64_Sym *find_defined_symbol(elf_file_t *ef, Elf64_Shdr *sec, char *sym_name)
{
	int count = sec->sh_size / sizeof(Elf64_Sym);
	Elf64_Sym *base = elf_get_section_data(ef, sec);

	for (int i = 0; i < count; i++) {
		Elf64_Sym *dst_sym = &base[i];
		if (dst_sym->st_shndx == SHN_UNDEF || dst_sym->st_name == 0) {
			continue;
		}
		char *name = elf_get_sym_name(ef, dst_sym);
		if (elf_is_same_symbol_name(sym_name, name)) {
			return dst_sym;
		}
	}

	return NULL;
}

static void delete_undefined_symbol(elf_file_t *ef, Elf64_Shdr *sec)
{
	int count = sec->sh_size / sizeof(Elf64_Sym);
	Elf64_Sym *base = elf_get_section_data(ef, sec);

	for (int i = 0; i < count; i++) {
		Elf64_Sym *dst_sym = &base[i];
		if (dst_sym->st_shndx != SHN_UNDEF || dst_sym->st_name == 0) {
			continue;
		}
		char *name = elf_get_sym_name(ef, dst_sym);
		Elf64_Sym *find = find_defined_symbol(ef, sec, name);
		if (find != NULL) {
			(void)memset(dst_sym, 0, sizeof(Elf64_Sym));
		}
	}
}

static void sort_symbol_table(elf_file_t *ef, Elf64_Shdr *sec)
{
	int count = sec->sh_size / sizeof(Elf64_Sym);
	void *base = elf_get_section_data(ef, sec);

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
	SI_LOG_DEBUG("modify dynsym: \n");
	Elf64_Shdr *sec = find_tmp_section_by_name(elf_link, ".dynsym");
	modify_symbol(elf_link, sec);

	// defined and undefined symbol from elfs all in dynsym
	// delete undefined symbol, so dlsym can find the addr
	delete_undefined_symbol(&elf_link->out_ef, sec);

	// sh_info is STB_LOCAL symbol count
	sec->sh_info = get_local_symbol_count(&elf_link->out_ef, sec);

	// nold mode, libc gun_hash no change, dynsym no sort
	if (is_static_nold_mode(elf_link)) {
		return;
	}

	sort_symbol_table(&elf_link->out_ef, sec);

	Elf64_Shdr *dyn = sec;
	sec = find_tmp_section_by_name(elf_link, ".gnu.hash");
	modify_hash(&elf_link->out_ef, sec, dyn, elf_link->out_ef.dynstr_data);
}

static void modify_symtab(elf_link_t *elf_link)
{
	SI_LOG_DEBUG("modify symtab: \n");
	Elf64_Shdr *sec = find_tmp_section_by_name(elf_link, ".symtab");
	modify_symbol(elf_link, sec);

	sort_symbol_table(&elf_link->out_ef, sec);

	// sh_info is STB_LOCAL symbol count
	sec->sh_info = get_local_symbol_count(&elf_link->out_ef, sec);
}

static void write_symtab(elf_link_t *elf_link)
{
	char *sec_name = ".symtab";
	merge_all_ef_section(elf_link, sec_name);
}

static void write_strtab(elf_link_t *elf_link)
{
	char *sec_name = ".strtab";
	Elf64_Shdr *tmp_sec = merge_all_ef_section(elf_link, sec_name);
	elf_link->out_ef.strtab_data = (char *)elf_link->out_ef.hdr + tmp_sec->sh_offset;
}

// .shstrtab is no need LOAD, only use string offset, no need mapping
// use tmp_shstrtab in processing, copy to out_ef
static void write_shstrtab(elf_link_t *elf_link)
{
	char *sec_name = ".shstrtab";
	Elf64_Shdr *sec = merge_all_ef_section(elf_link, sec_name);

	elf_link->out_ef.shstrtab_data = (char *)elf_link->out_ef.hdr + sec->sh_offset;

	//append_sysboost_sec_name(elf_link);

	// TODO: add name for .preinit_array
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

/* debug modify start */

#include <libdwarf.h>
#include <dwarf.h>
#include <dwarf_util.h>
#include <dwarf_error.h>
#include <dwarf_base_types.h>
#include <dwarf_opaque.h>
#include <dwarf_die_deliv.h>

struct dwarf_unit_header
{
	uint32_t length;
	uint16_t version;
	uint8_t unit_type;
	uint8_t pointer_size;
	uint32_t abbrev_offset;
};

void check_unit_header(struct dwarf_unit_header *unit_header)
{
	/*
	 * 32-bit DWARF format's length must < 0xfffffff0,
	 * we only support 32-bit now.
	 */
	if (unit_header->length >= 0xfffffff0)
		si_panic("64-bit DWARF format is not supported\n");

	if (unit_header->version != 5)
		si_panic("only support DWARF version 5\n");
	
	if (unit_header->pointer_size != 8)
		si_panic("only support 64-bit target machine\n");
}

void check_cu_header(struct dwarf_unit_header *cu_header)
{
	check_unit_header(cu_header);

	if (cu_header->unit_type != DW_UT_compile)
		si_panic("current unit_header is not cu_header\n");
}

/* modify abbrev offset stored in .debug_info */
void modify_debug_info_abbrev_offset(elf_link_t *elf_link)
{
	elf_file_t *ef;
	uint32_t da_offset = 0;
	void *di_base = elf_find_section_ptr_by_name(get_out_ef(elf_link), ".debug_info");
	uint32_t cu_offset = 0;

	foreach_infile(elf_link, ef) {
		Elf64_Shdr *di_sec = elf_find_section_by_name(ef, ".debug_info");
		Elf64_Shdr *da_sec = elf_find_section_by_name(ef, ".debug_abbrev");
		uint32_t in_ef_cu_offset = 0;

		while (in_ef_cu_offset < di_sec->sh_size) {
			struct dwarf_unit_header *cu_header = di_base + cu_offset;
			check_cu_header(cu_header);
			cu_header->abbrev_offset += da_offset;
			/*
			 * each cu have additional 4 bytes,
			 * because length doesn't count itself's space.
			 */
			cu_offset += cu_header->length + 4;
			in_ef_cu_offset += cu_header->length + 4;
		}

		da_offset += da_sec->sh_size;
	}
}

Dwarf_Debug dwarf_init(const char *path)
{
	static char true_pathbuf[FILENAME_MAX];
	Dwarf_Debug dbg = 0;
	int res;

	res = dwarf_init_path(
		path, true_pathbuf,
		FILENAME_MAX, DW_GROUPNUMBER_ANY, NULL,
		NULL, &dbg, NULL
	);

	if (res != DW_DLV_OK)
		return NULL;

	return dbg;
}

int dwarf_get_first_die_of_next_cu(Dwarf_Debug dbg, Dwarf_Die* first_die)
{
	int ret;
	// Dwarf_Error error;
	ret = dwarf_next_cu_header_d(dbg, true, NULL, NULL, NULL, NULL, 
		NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	/* no next cu */
	if (ret == DW_DLV_NO_ENTRY)
		return ret;

	if (ret != DW_DLV_OK) {
		si_panic("dwarf_next_cu_header_d ERROR, ret: %d\n", ret);
		return ret;
	}
	//  else printf("OK\n");

	ret = dwarf_siblingof_b(dbg, NULL, true, first_die, NULL);
	/*
	 * if there is no entry, dwarf_siblingof_b will return DW_DLV_NO_ENTRY,
	 * but now we just ignore this condition for quick dev.
	 */
	if (ret != DW_DLV_OK) {
		si_panic("dwarf_siblingof_b ERROR %d\n", ret);
		return ret;
	}
	return ret;
}

struct dwarf_bias_info {
	uint64_t text;
	uint64_t debug_str;
	uint64_t debug_line_str;
};

int dwarf_modify_di_abbrev(Dwarf_Die die, void *di_ptr, struct dwarf_bias_info *bias_info)
{
	Dwarf_Debug dbg = die->di_cu_context->cc_dbg;
	Dwarf_Byte_Ptr die_info_end =
		_dwarf_calculate_info_section_end_ptr(die->di_cu_context);
	void *abbrev_ptr = die->di_debug_ptr;
	Dwarf_Error error;

	Dwarf_Unsigned unused = 0;
	Dwarf_Unsigned len;
	int ret = dwarf_decode_leb128(
		abbrev_ptr, &len, &unused, (char *)die_info_end
	);
	if (ret != DW_DLV_OK)
		return ret;
	abbrev_ptr += len;
	void *di_base = dbg->de_debug_info.dss_data;

	for (Dwarf_Unsigned i = 0; i < die->di_abbrev_list->abl_abbrev_count; i++) {
		Dwarf_Unsigned attr_form = die->di_abbrev_list->abl_form[i];
		Dwarf_Unsigned sov = 0;
		int ret;

		/* todo test if this is needed */
		if (attr_form == DW_FORM_implicit_const) {
			continue;
		}

		ret = _dwarf_get_size_of_val(
			dbg, attr_form,
			die->di_cu_context->cc_version_stamp,
			die->di_cu_context->cc_address_size,
			abbrev_ptr,
			die->di_cu_context->cc_length_size,
			&sov,
			die_info_end,
			&error
		);
		if (ret != DW_DLV_OK)
			si_panic("_dwarf_get_size_of_val fail, ret: %d\n", ret);

		uint32_t *dst_ptr = di_ptr + (abbrev_ptr - di_base);
		switch (die->di_abbrev_list->abl_form[i]) {
			case DW_FORM_addr:
				*dst_ptr += bias_info->text;
				break;
			case DW_FORM_line_strp:
				*dst_ptr += bias_info->debug_line_str;
				break;
			case DW_FORM_strp:
				*dst_ptr += bias_info->debug_str;
				// printf("offset: %lx, *abbrev_ptr: %x *dst_ptr: %x\n",
				// 	(abbrev_ptr - di_base), 
				// 	*(uint32_t *)abbrev_ptr, *dst_ptr);
				break;
			case DW_FORM_data1:
			case DW_FORM_data2:
			case DW_FORM_data4:
			case DW_FORM_data8:
				/* no need to modify */
				break;
			case DW_FORM_block2:
			case DW_FORM_string:
			case DW_FORM_sdata:
			case DW_FORM_ref4:
			case DW_FORM_implicit_const:
			case DW_FORM_exprloc:
			case DW_FORM_flag_present:
			case DW_FORM_sec_offset:
				/* TODO */
				break;
			case DW_FORM_block4:
			case DW_FORM_block:
			case DW_FORM_block1:
			case DW_FORM_flag:
			case DW_FORM_udata:
			case DW_FORM_ref_addr:
			case DW_FORM_ref1:
			case DW_FORM_ref2:
			case DW_FORM_ref8:
			case DW_FORM_ref_udata:
			case DW_FORM_indirect:
			case DW_FORM_strx:
			case DW_FORM_addrx:
			case DW_FORM_addrx1:
			case DW_FORM_addrx2:
			case DW_FORM_addrx3:
			case DW_FORM_addrx4:
			case DW_FORM_ref_sup4:
			case DW_FORM_strp_sup:
			case DW_FORM_data16:
			case DW_FORM_loclistx:
			case DW_FORM_rnglistx:
			case DW_FORM_ref_sup8:
			case DW_FORM_strx1:
			case DW_FORM_strx2:
			case DW_FORM_strx3:
			case DW_FORM_strx4:
			case DW_FORM_ref_sig8:
				/* not present in bash */
				si_panic("unsupported die FORM 0x%x\n",
					die->di_abbrev_list->abl_form[i]);
				break;
			default:
				si_panic("unknown die FORM 0x%x\n",
					die->di_abbrev_list->abl_form[i]);
				break;
		}
		abbrev_ptr += sov;
	}

	return DW_DLV_OK;
}

int dwarf_traverse_die(Dwarf_Debug dbg, Dwarf_Die parent_die,
		       void *di_ptr, struct dwarf_bias_info *bias_info)
{
	Dwarf_Die son_die;
	int res;

	dwarf_modify_di_abbrev(parent_die, di_ptr, bias_info);

	res = dwarf_child(parent_die, &son_die, NULL);
	while (res == DW_DLV_OK) {
		dwarf_traverse_die(dbg, son_die, di_ptr, bias_info);
		res = dwarf_siblingof_b(dbg, son_die, true, &son_die, NULL);
	}
	if (res == DW_DLV_NO_ENTRY) {
		// no more child
		return DW_DLV_OK;
	} else {
		printf("dwarf_child or dwarf_siblingof_b ERROR\n");
		return res;
	}
}

void dwarf_traverse_cu(Dwarf_Debug dbg, void *di_ptr, struct dwarf_bias_info *bias_info)
{
	int res = 0;

	Dwarf_Die first_die;
	for (;;) {
		res = dwarf_get_first_die_of_next_cu(dbg, &first_die);
		if (res == DW_DLV_NO_ENTRY) {
			/* no entry */
			break;
		}
		dwarf_traverse_die(dbg, first_die, di_ptr, bias_info);
	}
}

/* delete it later */
char *temp_get_file_name(char *name)
{
	char *result = malloc(strlen(name));
	memset(result, 0, strlen(name));
	memcpy(result, name, strlen(name) - 11);
	return result;
}

void prep_bias_info(elf_link_t *elf_link, elf_file_t *ef, struct dwarf_bias_info *bias_info)
{
	/* .text starts from .init */
	unsigned long text_base_addr =
		elf_find_section_by_name(ef, ".init")->sh_addr;
	unsigned long ds_base_offset =
		elf_find_section_by_name(get_out_ef(elf_link), ".debug_str")->sh_offset;
	unsigned long dls_base_offset =
		elf_find_section_by_name(get_out_ef(elf_link), ".debug_line_str")->sh_offset;

	Elf64_Shdr *text_sec = elf_find_section_by_name(ef, ".init");
	unsigned long text_addr = get_new_addr_by_old_addr(
		elf_link, ef, text_sec->sh_addr
	);
	Elf64_Shdr *ds_sec = elf_find_section_by_name(ef, ".debug_str");
	unsigned long ds_offset = get_new_offset_by_old_offset(
		elf_link, ef, ds_sec->sh_offset
	);
	Elf64_Shdr *dls_sec = elf_find_section_by_name(ef, ".debug_line_str");
	unsigned long dls_offset = get_new_offset_by_old_offset(
		elf_link, ef, dls_sec->sh_offset
	);

	bias_info->text = text_addr - text_base_addr;
	bias_info->debug_str = ds_offset - ds_base_offset;
	bias_info->debug_line_str = dls_offset - dls_base_offset;
	SI_LOG_DEBUG("%s, text: %lx, debug_str: %lx, debug_line_str: %lx\n",
		ef->file_name,
		bias_info->text, bias_info->debug_str, bias_info->debug_line_str);
	SI_LOG_DEBUG("text_addr: %lx, out_text_base_addr: %lx\n",
		text_addr, text_base_addr);
}

int modify_debug_info(elf_link_t *elf_link)
{
	elf_file_t *ef;
	char *temp_path;
	struct dwarf_bias_info bias_info;

	foreach_infile(elf_link, ef) {
		Elf64_Shdr *di_sec = elf_find_section_by_name(ef, ".debug_info");
		unsigned long dst_offset = get_new_offset_by_old_offset(
			elf_link, ef, di_sec->sh_offset
		);
		void *di_ptr = get_out_ef(elf_link)->data + dst_offset;
		prep_bias_info(elf_link, ef, &bias_info);

		temp_path = temp_get_file_name(ef->file_name);
		Dwarf_Debug dbg = dwarf_init(temp_path);
		if (!dbg)
			si_panic("dwarf_init fail, file: %s\n", temp_path);
		dwarf_traverse_cu(dbg, di_ptr, &bias_info);
		dwarf_finish(dbg);
	}
	return 0;
}

static void modify_debug(elf_link_t *elf_link)
{
	modify_debug_info_abbrev_offset(elf_link);
	modify_debug_info(elf_link);
}

/* debug modify end */

// .init_array first func is frame_dummy, frame_dummy call register_tm_clones
// .fini_array first func is __do_global_dtors_aux, __do_global_dtors_aux call deregister_tm_clones
char *disabled_funcs[] = {
    "frame_dummy",
    "__do_global_dtors_aux",
};

#define DISABLED_FUNCS_LEN (sizeof(disabled_funcs) / sizeof(disabled_funcs[0]))
#define AARCH64_INSN_RET 0xD65F03C0U
#define X86_64_INSN_RET 0xC3

static void modify_init_and_fini_ef(elf_link_t *elf_link, elf_file_t *ef)
{
	Elf64_Ehdr *hdr = elf_link->out_ef.hdr;
	elf_file_t *out_ef = &elf_link->out_ef;

	// In .init_array and .fini_array, static-pie mode the EXEC ELF no need run
	// so we need to disable such functions in EXEC ELF
	for (unsigned j = 0; j < DISABLED_FUNCS_LEN; j++) {
		Elf64_Sym *sym = elf_find_symbol_by_name(ef, disabled_funcs[j]);
		if (sym == NULL) {
			// do nothing
			continue;
		}
		unsigned long addr = get_new_addr_by_symobj(elf_link, ef, sym);
		if (hdr->e_machine == EM_AARCH64) {
			elf_write_u32(out_ef, addr, AARCH64_INSN_RET);
		} else {
			elf_write_u8(out_ef, addr, X86_64_INSN_RET);
		}
	}
}

static void modify_init_and_fini(elf_link_t *elf_link)
{
	if (is_share_mode(elf_link) == true) {
		return;
	}
	Elf64_Ehdr *hdr = elf_link->out_ef.hdr;
	if (hdr->e_machine != EM_AARCH64 && hdr->e_machine != EM_X86_64) {
		si_panic("e_machine not support\n");
	}

	elf_file_t *ef;
	int in_ef_nr = elf_link->in_ef_nr;
	for (int i = 0; i < in_ef_nr; i++) {
		ef = &elf_link->in_efs[i];
		modify_init_and_fini_ef(elf_link, ef);
	}
}

static void do_special_adapts(elf_link_t *elf_link)
{
	modify_init_and_fini(elf_link);
	// correct_stop_libc_atexit(elf_link);
}

/*
 * There are 2 kinds of merge in elfmerge:
 * 1. merge per section:
 *        merge same sections in each binary into one section.
 * [.tdata a] [.init_array a] =>     new .tdata            new .init_array
 * [.tdata b] [.init_array b] => [.data a, .data b] [.init_array a, .init_array b]
 *
 * 2. merge segment:
 *        merge multiple sections in same segments in each binary all into one section.
 * [.plt a,  .plt b ] =>             new .text
 * [.text a, .text b] => [.plt a, .text a, .plt b, .text b]
 */
static void elf_link_write_sections(elf_link_t *elf_link)
{
	/*
	 * merge per section for below sections:
	 * .interp .note.gnu.build-id .note.ABI-tag .gnu.hash
	 * .dynsym .dynstr .rela.dyn .rela.plt
	 */
	write_first_LOAD_segment(elf_link);

	/*
	 * merge segment for below sections:
	 * .init .plt .text __libc_freeres_fn .fini
	 * all into .text in new elf.
	 */
	write_text(elf_link);

	/*
	 * merge segment for below sections:
	 * .rodata .stapsdt.base .eh_frame_hdr .eh_frame .gcc_except_table
	 * all into .rodata in new elf.
	 */
	write_rodata(elf_link);

	/*
	 * merge per section for below sections:
	 * .tdata .tbss .init_array .fini_array .data.rel.ro .dynamic .got .got.plt .data .bss
	 */
	write_data(elf_link);

	/* .dynamic (merge per section) */
	modify_dynamic(elf_link);

	/* .symtab (merge per section) */
	write_symtab(elf_link);

	/* .strtab (merge per section) */
	write_strtab(elf_link);

	/* .shstrtab (merge per section) */
	write_shstrtab(elf_link);

	/*
	 * merge per section for below sections:
	 * .debug_info .debug_line .debug_str .debug_line_str .debug_abbrev
	 */
	write_debug_info(elf_link);

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

	modify_debug(elf_link);	

	// modify ELF header and write sections
	modify_elf_header(elf_link);

	do_special_adapts(elf_link);

	truncate_elf_file(elf_link);

	elf_check_elf(elf_link);

	return 0;
}
