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

#include "elf_link_common.h"

#include <dlfcn.h>
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
#include <sys/user.h>

#include <si_common.h>
#include <si_debug.h>
#include <si_log.h>

#include "elf_link_common.h"
#include "elf_ext.h"

#define INDEX_ZERO  0
#define INDEX_ONE   1
#define INDEX_TWO   2
#define INDEX_THREE 3
#define INDEX_FOUR  4
#define INDEX_FIVE  5
#define INDEX_SIX   6
#define INDEX_SEVEN 7

static char *special_dynsyms[] = {
    "__pointer_chk_guard",
    "_ITM_deregisterTMCloneTable",
    "__cxa_finalize",
    "__gmon_start__",
    "_ITM_registerTMCloneTable",
    "__pthread_initialize_minimal",
    "__call_tls_dtors",
    "__pthread_unwind",
    "__mq_notify_fork_subprocess",
    "__timer_fork_subprocess",
};
#define SPECIAL_DYNSYMS_LEN (sizeof(special_dynsyms) / sizeof(special_dynsyms[0]))

bool is_symbol_maybe_undefined(const char *name)
{
	// some special symbols are ok even if they are undefined, skip them
	for (unsigned i = 0; i < SPECIAL_DYNSYMS_LEN; i++) {
		if (elf_is_same_symbol_name(name, special_dynsyms[i])) {
			return true;
		}
	}

	return false;
}

bool is_gnu_weak_symbol(Elf64_Sym *sym)
{
	// IN normal ELF
	// 5: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.17 (3)
	if ((ELF64_ST_BIND(sym->st_info) == STB_WEAK) && (sym->st_shndx == SHN_UNDEF)) {
		return true;
	}
	// IN libc ELF
	// 3441: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND _ITM_registerTMCloneTable
	if ((ELF64_ST_TYPE(sym->st_info) == STT_NOTYPE) && (sym->st_shndx == SHN_UNDEF)) {
		return true;
	}

	return false;
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

bool is_section_needed(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec)
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

// symbol_name string can not change
void append_symbol_mapping(elf_link_t *elf_link, const char *symbol_name, unsigned long symbol_addr)
{
	elf_symbol_mapping_t sym_map = {0};

	sym_map.symbol_name = symbol_name;
	sym_map.symbol_addr = symbol_addr;

	si_array_append(elf_link->symbol_mapping_arr, &sym_map);
}

unsigned long get_new_addr_by_symbol_mapping(elf_link_t *elf_link, char *symbol_name)
{
	int len = elf_link->symbol_mapping_arr->len;
	elf_symbol_mapping_t *sym_maps = elf_link->symbol_mapping_arr->data;
	elf_symbol_mapping_t *sym_map = NULL;

	for (int i = 0; i < len; i++) {
		sym_map = &sym_maps[i];
		if (elf_is_same_symbol_name(sym_map->symbol_name, symbol_name) == true) {
			return sym_map->symbol_addr;
		}
	}

	return NOT_FOUND;
}

void show_symbol_mapping(elf_link_t *elf_link)
{
	int len = elf_link->symbol_mapping_arr->len;
	elf_symbol_mapping_t *sym_maps = elf_link->symbol_mapping_arr->data;
	elf_symbol_mapping_t *sym_map = NULL;

	SI_LOG_DEBUG("symbol_name                      symbol_addr\n");
	for (int i = 0; i < len; i++) {
		sym_map = &sym_maps[i];
		SI_LOG_DEBUG("%-32s %016lx\n", sym_map->symbol_name, sym_map->symbol_addr);
	}
}

static void append_symbol_mapping_by_name(elf_link_t *elf_link, char *key, elf_file_t *ef, char *sym_name)
{
	unsigned long old_sym_addr = elf_find_symbol_addr_by_name(ef, sym_name);
	unsigned long new_sym_addr = get_new_addr_by_old_addr(elf_link, ef, old_sym_addr);
	append_symbol_mapping(elf_link, key, new_sym_addr);
}

static void init_hook_func_symbol_change(elf_link_t *elf_link)
{
	if (is_hook_func(elf_link) == false) {
		return;
	}

	// jump hook func, in libhook do not hook it, use real func
	elf_file_t *ef = elf_link->hook_func_ef;
	append_symbol_mapping_by_name(elf_link, "dlopen", ef, "__hook_dlopen");
	append_symbol_mapping_by_name(elf_link, "dlclose", ef, "__hook_dlclose");
	append_symbol_mapping_by_name(elf_link, "dlsym", ef, "__hook_dlsym");
}

static void init_static_mode_symbol_change(elf_link_t *elf_link)
{
	if (is_static_mode(elf_link) == false) {
		return;
	}

	// static mode, template or ld.so need jump to app main func
	elf_file_t *ef = get_main_ef(elf_link);
	append_symbol_mapping_by_name(elf_link, "main", ef, "main");

	// Here is an inelegant optimization for bash that cancels all resource release procedures in the
	// exit process, and directly calls the _Exit function to end the process.
	ef = get_template_ef(elf_link);
	append_symbol_mapping_by_name(elf_link, "exit", ef, "_exit");
}

// layout for vdso and app and ld.so
// ld.so | vvar | vdso | app
// without ld.so
// vvar | vdso | app
static unsigned long ld_hdr_addr_to_main_elf(elf_file_t *ef)
{
	Elf64_Phdr *p = ef->data_Phdr;
	if (p == NULL) {
		si_panic("ld.so data segment is NULL\n");
	}
	if (p->p_align != PAGE_SIZE) {
		si_panic("ld.so is not align 4K\n");
	}
	unsigned long load_len = p->p_vaddr + p->p_memsz;
	load_len = ALIGN(load_len, PAGE_SIZE);
	return 0UL - ELF_VVAR_AND_VDSO_LEN - load_len;
}

static unsigned long ld_get_new_addr(unsigned long hdr_addr, Elf64_Sym *sym)
{
	return hdr_addr + (unsigned long)sym->st_value;
}

static unsigned long vdso_get_new_addr(Elf64_Sym *sym)
{
	// user space PAGE_SIZE is 4K
	return 0UL - ELF_VDSO_LEN + (unsigned long)sym->st_value;
}

#ifdef __aarch64__
// __kernel_clock_gettime
#define VDSO_PREFIX_LEN (sizeof("__kernel_") - 1)
#define DL_SYSINFO_DSO_OFFSET (0x2e8)
#else
// __vdso_clock_gettime
#define VDSO_PREFIX_LEN (sizeof("__vdso_") - 1)
#define DL_SYSINFO_DSO_OFFSET (0x2e8)
#endif

static char *vdso_name_to_syscall_name(char *name)
{
	return name + VDSO_PREFIX_LEN;
}

// AT_SYSINFO_EHDR is addr of vdso header
// it can not use dlsym to find vdso symbol
static unsigned long vdso_hdr_addr_cur()
{
	// _rtld_global_ro->_dl_sysinfo_dso, offset is fixed by libc
	unsigned long addr = (unsigned long)dlsym(0, "_rtld_global_ro");
	char *error = dlerror();
	if (error != NULL) {
		si_panic("%s\n", error);
	}
	addr = addr + DL_SYSINFO_DSO_OFFSET;
#ifdef __aarch64__
	si_panic("TODO: DL_SYSINFO_DSO_OFFSET is need check\n");
#endif
	return *(unsigned long *)addr;
}

void init_vdso_symbol_addr(elf_link_t *elf_link)
{
	elf_file_t *vdso_ef = &elf_link->vdso_ef;

	vdso_ef->file_name = "vdso";
	vdso_ef->hdr = (Elf64_Ehdr *)vdso_hdr_addr_cur();
	elf_parse_hdr(vdso_ef);

	if (vdso_ef->dynsym_sec == NULL) {
		si_panic(".dynsym not exist\n");
	}

	elf_show_dynsym(vdso_ef);

	int sym_count = elf_get_dynsym_count(vdso_ef);
	Elf64_Sym *syms = elf_get_dynsym_array(vdso_ef);
	for (int j = 0; j < sym_count; j++) {
		Elf64_Sym *sym = &syms[j];
		char *name = elf_get_sym_name(vdso_ef, sym);
		// vdso func __kernel_clock_getres
		if (name == NULL || name[0] != '_') {
			continue;
		}
		char *symbol_name = vdso_name_to_syscall_name(name);
		unsigned long symbol_addr = vdso_get_new_addr(sym);
		append_symbol_mapping(elf_link, symbol_name, symbol_addr);
	}

	return;
}

void init_ld_symbol_addr(elf_link_t *elf_link)
{
	elf_file_t *ef = &elf_link->ld_ef;

	if (ef->dynsym_sec == NULL) {
		si_panic(".dynsym not exist\n");
	}

	elf_show_dynsym(ef);

	// addr relative to main ELF
	unsigned long hdr_addr = ld_hdr_addr_to_main_elf(ef);

	int sym_count = elf_get_dynsym_count(ef);
	Elf64_Sym *syms = elf_get_dynsym_array(ef);
	for (int j = 0; j < sym_count; j++) {
		Elf64_Sym *sym = &syms[j];
		char *name = elf_get_sym_name(ef, sym);
		if (name == NULL || name[0] == '\0') {
			continue;
		}
		unsigned long symbol_addr = ld_get_new_addr(hdr_addr, sym);
		append_symbol_mapping(elf_link, name, symbol_addr);
	}

	return;
}

void init_symbol_mapping(elf_link_t *elf_link)
{
	init_static_mode_symbol_change(elf_link);
	init_hook_func_symbol_change(elf_link);

	if (is_direct_call_optimize(elf_link) && is_static_nold_mode(elf_link)) {
		init_ld_symbol_addr(elf_link);
	}
	if (is_direct_vdso_optimize(elf_link) == true) {
		init_vdso_symbol_addr(elf_link);
	}

	show_symbol_mapping(elf_link);
}

void show_sec_mapping(elf_link_t *elf_link)
{
	int len = elf_link->sec_mapping_arr->len;
	elf_sec_mapping_t *sec_rels = elf_link->sec_mapping_arr->data;
	elf_sec_mapping_t *sec_rel = NULL;

	SI_LOG_INFO("dst_addr  dst_off   dst_sec_addr         src_sec_addr         src_sec_name         src_file\n");
	for (int i = 0; i < len; i++) {
		sec_rel = &sec_rels[i];
		char *name = elf_get_section_name(sec_rel->src_ef, sec_rel->src_sec);
		const char *fname = si_basename(sec_rel->src_ef->file_name);
		SI_LOG_INFO("%08lx  %08lx  %08lx - %08lx  %08lx - %08lx  %-20s %-20s\n",
			    sec_rel->dst_mem_addr, sec_rel->dst_file_offset,
			    sec_rel->dst_sec->sh_addr, sec_rel->dst_sec->sh_addr + sec_rel->dst_sec->sh_size,
			    sec_rel->src_sec->sh_addr, sec_rel->src_sec->sh_addr + sec_rel->src_sec->sh_size,
			    name, fname);
	}
}

// if sec not SHF_ALLOC, has no addr, get_new_name_offset will use that sec
void append_sec_mapping(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec, Elf64_Shdr *dst_sec)
{
	elf_sec_mapping_t sec_rel = {0};

	sec_rel.src_ef = ef;
	sec_rel.src_sec = sec;
	sec_rel.dst_sec = dst_sec;
	sec_rel.dst_mem_addr = (unsigned long)elf_link->next_mem_addr;
	sec_rel.dst_file_offset = (unsigned long)elf_link->next_file_offset;
	si_array_append(elf_link->sec_mapping_arr, &sec_rel);

	char *name = elf_get_section_name(ef, sec);
	SI_LOG_DEBUG("add section map: %-20s dst_file_offset 0x%08lx dst_addr 0x%08lx src_addr 0x%08lx\n",
		     name, sec_rel.dst_file_offset, dst_sec->sh_addr, sec->sh_addr);
}

elf_sec_mapping_t *elf_find_sec_mapping_by_srcsec(elf_link_t *elf_link, Elf64_Shdr *src_sec)
{
	int len = elf_link->sec_mapping_arr->len;
	elf_sec_mapping_t *sec_rels = elf_link->sec_mapping_arr->data;
	elf_sec_mapping_t *sec_rel = NULL;

	for (int i = 0; i < len; i++) {
		sec_rel = &sec_rels[i];
		if (sec_rel->src_sec != src_sec) {
			continue;
		}
		return sec_rel;
	}

	return NULL;
}

int get_new_section_index(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int sec_index)
{
	elf_sec_mapping_t *sec_rel = NULL;

	if (sec_index == 0) {
		return 0;
	}

	Elf64_Shdr *src_sec = &src_ef->sechdrs[sec_index];

	sec_rel = elf_find_sec_mapping_by_srcsec(elf_link, src_sec);
	if (sec_rel == NULL) {
		// some sec is no need in out ELF
		return 0;
	}

	return sec_rel->dst_sec - elf_link->out_ef.sechdrs;
}

elf_sec_mapping_t *elf_find_sec_mapping_by_dst(elf_link_t *elf_link, void *_dst_offset)
{
	int len = elf_link->sec_mapping_arr->len;
	elf_sec_mapping_t *sec_rels = elf_link->sec_mapping_arr->data;
	elf_sec_mapping_t *sec_rel = NULL;
	unsigned long dst_offset = _dst_offset - (void *)elf_link->out_ef.hdr;

	for (int i = 0; i < len; i++) {
		sec_rel = &sec_rels[i];

		// bss is no memory space, so out elf offset no need
		if (sec_rel->src_sec->sh_type == SHT_NOBITS) {
			continue;
		}

		if (dst_offset >= sec_rel->dst_file_offset && dst_offset < sec_rel->dst_file_offset + sec_rel->src_sec->sh_size) {
			return sec_rel;
		}
	}

	// section can not be NULL
	si_log_set_global_level(SI_LOG_LEVEL_DEBUG);
	show_sec_mapping(elf_link);
	si_panic("section can not be NULL, dst_offset: %lx\n", dst_offset);
	return NULL;
}

void append_obj_mapping(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec, void *src_obj, void *dst_obj)
{
	elf_obj_mapping_t obj_mapping = {0};

	obj_mapping.src_ef = ef;
	obj_mapping.src_sec = sec;
	obj_mapping.src_obj = src_obj;
	obj_mapping.dst_obj = dst_obj;
	si_array_append(elf_link->obj_mapping_arr, &obj_mapping);
}

static elf_obj_mapping_t *elf_get_mapping_by_src(elf_link_t *elf_link, void *src_obj)
{
	int len = elf_link->obj_mapping_arr->len;
	elf_obj_mapping_t *obj_mappings = elf_link->obj_mapping_arr->data;
	elf_obj_mapping_t *obj_mapping = NULL;

	for (int i = 0; i < len; i++) {
		obj_mapping = &obj_mappings[i];
		if (obj_mapping->src_obj != src_obj) {
			continue;
		}
		return obj_mapping;
	}

	return NULL;
}

elf_obj_mapping_t *elf_get_mapping_by_dst(elf_link_t *elf_link, void *dst_obj)
{
	int len = elf_link->obj_mapping_arr->len;
	elf_obj_mapping_t *obj_mappings = elf_link->obj_mapping_arr->data;
	elf_obj_mapping_t *obj_mapping = NULL;

	for (int i = 0; i < len; i++) {
		obj_mapping = &obj_mappings[i];
		if (obj_mapping->dst_obj != dst_obj) {
			continue;
		}
		return obj_mapping;
	}

	return NULL;
}

static void *elf_get_mapping_dst_obj(elf_link_t *elf_link, void *src_obj)
{
	elf_obj_mapping_t *obj_mapping = elf_get_mapping_by_src(elf_link, src_obj);
	if (obj_mapping == NULL) {
		return NULL;
	}

	return obj_mapping->dst_obj;
}

char *elf_get_tmp_section_name(elf_link_t *elf_link, Elf64_Shdr *shdr)
{
	if (shdr->sh_name == 0) {
		return NULL;
	}

	// sh_name maybe not change, use old elf string
	elf_obj_mapping_t *obj_mapping = elf_get_mapping_by_dst(elf_link, shdr);

	return obj_mapping->src_ef->shstrtab_data + ((Elf64_Shdr *)obj_mapping->src_obj)->sh_name;
}

Elf64_Shdr *find_tmp_section_by_src(elf_link_t *elf_link, Elf64_Shdr *shdr)
{
	return (Elf64_Shdr *)elf_get_mapping_dst_obj(elf_link, shdr);
}

Elf64_Shdr *find_tmp_section_by_name(elf_link_t *elf_link, const char *sec_name)
{
	Elf64_Shdr *sechdrs = elf_link->out_ef.sechdrs;
	unsigned int shnum = elf_link->out_ef.hdr->e_shnum;
	unsigned int i;
	Elf64_Shdr *shdr = NULL;
	char *name = NULL;

	for (i = 1; i < shnum; i++) {
		shdr = &sechdrs[i];
		name = elf_get_tmp_section_name(elf_link, shdr);
		if (name == NULL) {
			continue;
		}
		if (strcmp(name, sec_name) == 0) {
			return shdr;
		}
	}

	return NULL;
}

static unsigned long _get_new_elf_addr(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long addr)
{
	int len = elf_link->sec_mapping_arr->len;
	elf_sec_mapping_t *sec_rels = elf_link->sec_mapping_arr->data;
	elf_sec_mapping_t *sec_rel = NULL;
	elf_sec_mapping_t *end_sec_rel = NULL;
	bool found = false;
	unsigned long tmp = 0;

	// rela will point to ELF header, first section not map, so sec_rels[0] is section[1]
	if (addr < src_ef->sechdrs[1].sh_addr) {
		return addr;
	}

	for (int i = 0; i < len; i++) {
		sec_rel = &sec_rels[i];
		if (sec_rel->src_ef != src_ef) {
			continue;
		}
		if (addr < sec_rel->src_sec->sh_addr || addr > sec_rel->src_sec->sh_addr + sec_rel->src_sec->sh_size) {
			continue;
		}
		if (addr == sec_rel->src_sec->sh_addr + sec_rel->src_sec->sh_size) {
			end_sec_rel = sec_rel;
			continue;
		}
		// section like .symtab has no addr
		if (!(sec_rel->src_sec->sh_flags & SHF_ALLOC)) {
			continue;
		}
		// .tbss has the same offset as .init_array, e.g.
		//   [22] .tbss             NOBITS           00000000007ffd18  005ffd18
		//        0000000000000004  0000000000000000 WAT       0     0     4
		//   [23] .init_array       INIT_ARRAY       00000000007ffd18  005ffd18
		//        0000000000000010  0000000000000008  WA       0     0     8
		// check the combination of SHT_NOBITS and SHF_TLS
		if ((sec_rel->src_sec->sh_type == SHT_NOBITS) && (sec_rel->src_sec->sh_flags & SHF_TLS)) {
			continue;
		}
		found = true;
		break;
	}

	// _end symbol
	if (!found && end_sec_rel != NULL) {
		sec_rel = end_sec_rel;
		found = true;
	}

	if (found) {
		// out elf must be pic
		tmp = (addr - sec_rel->src_sec->sh_addr) + (unsigned long)sec_rel->dst_mem_addr;
		if (sec_rel->src_sec->sh_addr == 0) {
			si_log_set_global_level(SI_LOG_LEVEL_DEBUG);
			show_sec_mapping(elf_link);
			SI_LOG_DEBUG("dst_file_offset %lx  dst_sec->sh_offset %lx  dst_sec->sh_addr %lx  src_sec->sh_addr %lx\n",
				     sec_rel->dst_file_offset, sec_rel->dst_sec->sh_offset, sec_rel->dst_sec->sh_addr, sec_rel->src_sec->sh_addr);
			si_panic("%s %lx %lx\n", src_ef->file_name, addr, tmp);
		}
		return tmp;
	}

	return NOT_FOUND;
}

static bool is_in_sec_mapping(elf_link_t *elf_link, elf_file_t *src_ef, Elf64_Shdr *src_sec)
{
	int len = elf_link->sec_mapping_arr->len;
	elf_sec_mapping_t *sec_rels = elf_link->sec_mapping_arr->data;
	elf_sec_mapping_t *sec_rel = NULL;

	for (int i = 0; i < len; i++) {
		sec_rel = &sec_rels[i];
		if (sec_rel->src_ef != src_ef) {
			continue;
		}
		if (sec_rel->src_sec == src_sec) {
			return true;
		}
	}
	return false;
}

// .note.gnu.property section is delete, so can not find
unsigned long get_new_addr_by_old_addr(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long addr)
{
	unsigned long ret = _get_new_elf_addr(elf_link, src_ef, addr);
	SI_LOG_DEBUG("get addr: %s %lx %lx\n", src_ef->file_name, addr, ret);
	if (ret != NOT_FOUND) {
		return ret;
	}

	// if section delete, ignore error
	Elf64_Shdr *sec = elf_find_section_by_addr(src_ef, addr);
	if (sec == NULL) {
		goto out;
	}
	char *sec_name = elf_get_section_name(src_ef, sec);
	SI_LOG_DEBUG("sec name: %s\n", sec_name);
	if (is_in_sec_mapping(elf_link, src_ef, sec) == false) {
		return 0UL;
	}

out:
	// something wrong had happen
	si_log_set_global_level(SI_LOG_LEVEL_DEBUG);
	show_sec_mapping(elf_link);
	si_panic("get addr fail: %s addr %lx ret %lx\n", src_ef->file_name, addr, ret);
	return NOT_FOUND;
}

unsigned long get_new_addr_by_old_addr_ok(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long addr)
{
	unsigned long ret = _get_new_elf_addr(elf_link, src_ef, addr);
	SI_LOG_DEBUG("get addr: %s %lx %lx\n", src_ef->file_name, addr, ret);
	if (ret != NOT_FOUND) {
		return ret;
	}
	// ignore NOT_FOUND
	return 0;
}

unsigned long get_new_offset_by_old_offset(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long offset)
{
	// addr != offset after .rodata segment, .tdata is not eq
	Elf64_Phdr *p = src_ef->data_Phdr;
	if (offset >= p->p_offset) {
		si_panic("error: %s offset %lx\n", src_ef->file_name, offset);
	}

	return get_new_addr_by_old_addr(elf_link, src_ef, offset);
}

static unsigned long get_ifunc_new_addr(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym, const char *sym_name);

static unsigned long _get_new_addr_by_sym_name(elf_link_t *elf_link, char *sym_name)
{
	int in_ef_nr = elf_link->in_ef_nr;
	elf_file_t *ef = NULL;
	Elf64_Sym *sym = NULL;
	int sym_count;

	// find in all ELF symtab, find template elf after
	int i = 0;
	if (is_static_nolibc_mode(elf_link)) {
		i = 1;
	}
	for (; i < in_ef_nr; i++) {
		ef = &elf_link->in_efs[i];
		sym_count = ef->symtab_sec->sh_size / sizeof(Elf64_Sym);
		Elf64_Sym *syms = (Elf64_Sym *)(((void *)ef->hdr) + ef->symtab_sec->sh_offset);
		for (int j = 0; j < sym_count; j++) {
			sym = &syms[j];
			char *name = elf_get_sym_name(ef, sym);
			if (elf_is_same_symbol_name(sym_name, name) && sym->st_shndx != SHN_UNDEF) {
				goto out;
			}
		}
	}

	// find in template elf
	ef = get_template_ef(elf_link);
	sym_count = ef->symtab_sec->sh_size / sizeof(Elf64_Sym);
	Elf64_Sym *syms = (Elf64_Sym *)(((void *)ef->hdr) + ef->symtab_sec->sh_offset);
	for (int j = 0; j < sym_count; j++) {
		sym = &syms[j];
		char *name = elf_get_sym_name(ef, sym);
		if (elf_is_same_symbol_name(sym_name, name) && sym->st_shndx != SHN_UNDEF) {
			goto out;
		}
	}

	// static mode need find symbol
	if (is_share_mode(elf_link) == false) {
		si_log_set_global_level(SI_LOG_LEVEL_DEBUG);
		show_symbol_mapping(elf_link);
		si_panic("not found symbol %s\n", sym_name);
	}

out:
	if (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
		return get_ifunc_new_addr(elf_link, ef, sym, sym_name);
	}

	return get_new_addr_by_old_addr(elf_link, ef, sym->st_value);
}

// lookup symbol in order
// scope: /usr/bin/bash /usr/lib64/libtinfo.so.6 /usr/lib64/libc.so.6 /lib64/ld-linux-x86-64.so.2
static unsigned long get_new_addr_by_lookup(elf_link_t *elf_link, elf_file_t *src_ef, Elf64_Sym *sym)
{
	char *sym_name = elf_get_sym_name(src_ef, sym);

	if (sym->st_shndx == SHN_UNDEF) {
		goto out;
	}

	// find in main ELF
	elf_file_t *ef = get_main_ef(elf_link);
	Elf64_Sym *lookup_sym = elf_find_dynsym_by_name(ef, sym_name);
	if ((lookup_sym != NULL) && (lookup_sym->st_shndx != SHN_UNDEF)) {
		return get_new_addr_by_old_addr(elf_link, ef, lookup_sym->st_value);
	}

	// use self ELF sym
	return get_new_addr_by_old_addr(elf_link, src_ef, sym->st_value);

out:
	// find sym in other merge ELF
	return _get_new_addr_by_sym_name(elf_link, sym_name);
}

Elf64_Sym *elf_lookup_symbol_by_rela(elf_link_t *elf_link, elf_file_t *src_ef, Elf64_Rela *src_rela, elf_file_t **lookup_ef)
{
	Elf64_Sym *sym = elf_get_dynsym_by_rela(src_ef, src_rela);
	char *sym_name = elf_get_sym_name(src_ef, sym);

	int type = ELF64_R_TYPE(src_rela->r_info);
	if (type != R_X86_64_COPY) {
		si_panic("type wrong %s %lx\n", src_ef->file_name, src_rela->r_offset);
		return NULL;
	}

	// feature: find order need deps lib
	int in_ef_nr = elf_link->in_ef_nr;
	elf_file_t *ef = NULL;
	Elf64_Sym *syms = NULL;
	int sym_count;

	for (int i = 1; i < in_ef_nr; i++) {
		ef = &elf_link->in_efs[i];
		if (ef == src_ef) {
			// dont find src ELF, src ELF is main ELF
			continue;
		}

		syms = elf_get_dynsym_array(ef);
		sym_count = elf_get_dynsym_count(ef);
		for (int j = 0; j < sym_count; j++) {
			sym = &syms[j];
			char *name = elf_get_sym_name(ef, sym);
			if (elf_is_same_symbol_name(sym_name, name) && sym->st_shndx != SHN_UNDEF) {
				*lookup_ef = ef;
				return sym;
			}
		}
	}

	return NULL;
}

static char *get_ifunc_nice_name(char *sym_name)
{
	if (sym_name == NULL) {
		return sym_name;
	}

	// ignore prefix of __memchr __strlen __GI_strlen __GI___strnlen __libc_memmove
	// direct cmp char for performace, compile will optimize branch
	if ((sym_name[INDEX_ZERO] == '_') && (sym_name[INDEX_ONE] == '_') && (sym_name[INDEX_TWO] == 'G')
		       	&& (sym_name[INDEX_THREE] == 'I') && (sym_name[INDEX_FOUR] == '_')
			&& (sym_name[INDEX_FIVE] == '_') && (sym_name[INDEX_SIX] == '_')) {
		return sym_name + INDEX_SEVEN;
	}
	if ((sym_name[INDEX_ZERO] == '_') && (sym_name[INDEX_ONE] == '_') && (sym_name[INDEX_TWO] == 'G')
			&& (sym_name[INDEX_THREE] == 'I') && (sym_name[INDEX_FOUR] == '_')) {
		return sym_name + INDEX_FIVE;
	}
	if ((sym_name[INDEX_ZERO] == '_') && (sym_name[INDEX_ONE] == '_') && (sym_name[INDEX_TWO] == 'l')
			&& (sym_name[INDEX_THREE] == 'i') && (sym_name[INDEX_FOUR] == 'b')
			&& (sym_name[INDEX_FIVE] == 'c') && (sym_name[INDEX_SIX] == '_')) {
		return sym_name + INDEX_SEVEN;
	}
	if ((sym_name[INDEX_ZERO] == '_') && (sym_name[INDEX_ONE] == '_')) {
		return sym_name + INDEX_TWO;
	}
	return sym_name;
}

static unsigned long _get_ifunc_new_addr_by_dl(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym, char *sym_name)
{
	// find ifunc real addr
	// dlopen cannot dynamically load position-independent executable
	elf_file_t *template_ef = get_template_ef(elf_link);
	if (template_ef == ef) {
		// ld.so just have one IFUNC
		// 701: 0000000000015ec0    40 IFUNC   LOCAL  DEFAULT   13 __x86_cpu_features
		return get_new_addr_by_old_addr(elf_link, ef, sym->st_value);
	}
	void *handle = dlopen(ef->file_name, RTLD_NOW);
	if (!handle) {
		si_panic("%s\n", dlerror());
	}
	dlerror();

	// lookup function from lib
	unsigned long func = (unsigned long)dlsym(handle, sym_name);
	char *error = dlerror();
	if (error != NULL) {
		// libc.so has func __memchr __strlen __GI_strlen, but dlsym can not found it
		sym_name = get_ifunc_nice_name(sym_name);
		func = (unsigned long)dlsym(handle, sym_name);
		error = dlerror();
		if (error != NULL) {
			si_panic("%s\n", error);
		}
	}

	// handle point to link_map, link_map->l_addr is base addr of ELF
	unsigned long old_addr = func - *(unsigned long *)handle;
	SI_LOG_DEBUG("func %s %016lx\n", sym_name, old_addr);

	return get_new_addr_by_old_addr(elf_link, ef, old_addr);
}

static char *ifunc_mapping[][2] = {
    {"memmove", "__memmove_generic"},
    {"memchr", "__memchr_generic"},
    {"__memchr", "__memchr_generic"},
    {"memset", "__memset_kunpeng"},
    {"strlen", "__strlen_asimd"},
    {"__strlen", "__strlen_asimd"},
    {"memcpy", "__memcpy_generic"},
};
#define IFUNC_MAPPING_LEN (sizeof(ifunc_mapping) / sizeof(ifunc_mapping[0]))

static unsigned long _get_ifunc_new_addr(elf_link_t *elf_link, char *sym_name)
{
	SI_LOG_DEBUG("ifunc to real func %s\n", sym_name);

	// func in PIE app, can not dl, so find by name
	for (unsigned i = 0; i < IFUNC_MAPPING_LEN; i++) {
		if (elf_is_same_symbol_name(sym_name, ifunc_mapping[i][0])) {
			return _get_new_addr_by_sym_name(elf_link, ifunc_mapping[i][1]);
		}
	}

	si_panic("ifunc %s is not known\n", sym_name);
	return 0;
}

static void elf_gen_nice_name(char *sym_name)
{
	if (sym_name == NULL) {
		return;
	}

	char *c = index(sym_name, '@');
	if (c) {
		*c = '\0';
	}
}

// ifunc is in ELFs, so it can not init when start
// Assume that ifunc function name is unique
static unsigned long get_ifunc_new_addr(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym, const char *sym_name)
{
	// sym name may have version, strpbrk@GLIBC_2.2.5
	char nice_sym_name[ELF_MAX_SYMBOL_NAME_LEN] = { 0 };
	(void)strncpy(nice_sym_name, sym_name, ELF_MAX_SYMBOL_NAME_LEN - 1);
	elf_gen_nice_name(nice_sym_name);

	unsigned long ret;
	if (is_static_nolibc_mode(elf_link)) {
		ret = _get_ifunc_new_addr(elf_link, nice_sym_name);
	} else {
		// use ifunc return value
		ret = _get_ifunc_new_addr_by_dl(elf_link, ef, sym, nice_sym_name);
	}

	// symbol name string can not change
	append_symbol_mapping(elf_link, sym_name, ret);
	SI_LOG_DEBUG("ifunc %-30s %16lx\n", sym_name, ret);

	return ret;
}

static unsigned long _get_new_addr_by_sym(elf_link_t *elf_link, elf_file_t *ef,
					  Elf64_Sym *sym)
{
	char *sym_name = elf_get_sym_name(ef, sym);

	// WEAK func is used by GNU debug, libc do not have that func
	if (is_gnu_weak_symbol(sym) == true) {
		return NOT_FOUND;
	}

	if (is_symbol_maybe_undefined(sym_name)) {
		return NOT_FOUND;
	}

	unsigned long ret = get_new_addr_by_symbol_mapping(elf_link, sym_name);
	if (ret != NOT_FOUND) {
		return ret;
	}
	if (is_direct_call_optimize(elf_link) && (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC)) {
		return get_ifunc_new_addr(elf_link, ef, sym, sym_name);
	}

	// lookup order
	return get_new_addr_by_lookup(elf_link, ef, sym);
}

unsigned long get_new_addr_by_symobj_ok(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym)
{
	unsigned long ret = _get_new_addr_by_sym(elf_link, ef, sym);
	if (ret == NOT_FOUND) {
		return 0;
	}
	return ret;
}

unsigned long get_new_addr_by_symobj(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym)
{
	return _get_new_addr_by_sym(elf_link, ef, sym);
}

unsigned long elf_get_new_tls_offset(elf_link_t *elf_link, elf_file_t *ef, unsigned long obj_tls_offset)
{
	// STT_TLS symbol st_value is offset to TLS segment begin
	Elf64_Shdr *obj_tls_sec = elf_find_section_by_tls_offset(ef, obj_tls_offset);
	elf_sec_mapping_t *map_tls = elf_find_sec_mapping_by_srcsec(elf_link, obj_tls_sec);
	// obj old addr
	unsigned long obj_addr = obj_tls_offset + ef->tls_Phdr->p_paddr;
	unsigned long obj_sec_offset = obj_addr - obj_tls_sec->sh_addr;
	// .tbss not in old file, can not use get_new_elf_addr
	obj_addr = map_tls->dst_file_offset + obj_sec_offset;

	return obj_addr - elf_link->out_ef.tls_Phdr->p_paddr;
}

// after merge .dynstr or .strtab
unsigned long get_new_name_offset(elf_link_t *elf_link, elf_file_t *src_ef, Elf64_Shdr *src_sec, unsigned long offset)
{
	int len = elf_link->sec_mapping_arr->len;
	elf_sec_mapping_t *sec_rels = elf_link->sec_mapping_arr->data;
	elf_sec_mapping_t *sec_rel = NULL;
	unsigned long tmp = 0;

	// printf("get_new_name_offset: %s\n", ((char *)src_ef->hdr) + src_sec->sh_offset + offset);

	for (int i = 0; i < len; i++) {
		sec_rel = &sec_rels[i];
		if (sec_rel->src_ef != src_ef || sec_rel->src_sec != src_sec) {
			continue;
		}
		// offset in merge section
		tmp = (unsigned long)sec_rel->dst_file_offset - sec_rel->dst_sec->sh_offset;
		tmp = tmp + offset;
		return tmp;
	}

	si_panic("get_new_name_offset fail\n");
	return 0;
}

int get_new_sym_index_no_clear(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int old_index)
{
	if (old_index == 0) {
		return 0;
	}

	const char *name = elf_get_dynsym_name_by_index(src_ef, old_index);

	return find_dynsym_index_by_name(&elf_link->out_ef, name, false);
}

int get_new_sym_index(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int old_index)
{
	if (old_index == 0) {
		return 0;
	}

	const char *name = elf_get_dynsym_name_by_index(src_ef, old_index);

	return find_dynsym_index_by_name(&elf_link->out_ef, name, true);
}
