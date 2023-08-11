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

#ifndef _ELF_LINK_COMMON_H
#define _ELF_LINK_COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "elf_read_elf.h"
#include <si_array.h>
#include <si_common.h>
#include <si_debug.h>

// aarch64 header file is not define PAGE_SIZE
#ifndef PAGE_SHIFT
#define PAGE_SHIFT              12
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE               (1UL << PAGE_SHIFT)
#endif
#ifndef PAGE_MASK
#define PAGE_MASK               (~(PAGE_SIZE-1))
#endif

#define ELF_SEGMENT_ALIGN (0x200000)

#define SKIP_ONE_RELA (1)
#define SKIP_TWO_RELA (2)
#define SKIP_THREE_RELA (3)

#define NOT_FOUND (-1UL)

#define MAX_ELF_FILE 512
#define MAX_ELF_SECTION 128

#define LIBHOOK "libhook.so"

#define ELF_LINK_SHARE_S "share"
#define ELF_LINK_STATIC_S "static"
#define ELF_LINK_STATIC_NOLIBC_S "static-nolibc"
#define ELF_LINK_STATIC_NOLD_S "static-nold"

enum RtoMode {
	ELF_LINK_SHARE = 0,
	ELF_LINK_STATIC,
	ELF_LINK_STATIC_NOLIBC,
	ELF_LINK_STATIC_NOLD,
};

/*
#define SYSBOOST_DATA_ALIGN (8)
#define SYSBOOST_DATA_VERSION (1)
#define SYSBOOST_DATA_SEC_NAME ".sysboost_data"

// | Byte0   | Byte1 ... Byte7 |
// | version | pad             |
// | APP entry addr            |
typedef struct {
	uint8_t version;
	char pad[7];
	unsigned long entry_addr;
} elf_sysboost_data_t;
*/

typedef struct {
	elf_file_t in_efs[MAX_ELF_FILE];
	elf_file_t out_ef;
	unsigned int in_ef_nr;
	unsigned int link_mode;

	elf_file_t vdso_ef;
	elf_file_t ld_ef;
	elf_file_t *hook_func_ef;
	elf_file_t *libc_ef;

	Elf64_Shdr tmp_sechdrs_buf[MAX_ELF_SECTION];

	si_array_t *sec_mapping_arr;
	si_array_t *obj_mapping_arr;

	si_array_t *rela_plt_arr;
	si_array_t *rela_dyn_arr;

	// direct symbol mapping
	si_array_t *symbol_mapping_arr;

	unsigned int next_mem_addr;
	unsigned int next_file_offset;

	bool delete_symbol_version;
	bool direct_call_optimize;
	bool direct_vdso_optimize;
	bool direct_point_var_optimize;

	// use libhook func to hook libc
	bool hook_func;
	unsigned long so_path_struct;

	//elf_sysboost_data_t *sysboost_data;
	Elf64_Shdr *sysboost_data_sec;
} elf_link_t;

typedef struct {
	const char *symbol_name;
	unsigned long symbol_addr;
} elf_symbol_mapping_t;

typedef struct {
	elf_file_t *src_ef;
	Elf64_Shdr *src_sec;
	Elf64_Shdr *dst_sec;
	unsigned long dst_mem_addr;
	unsigned long dst_file_offset;
} elf_sec_mapping_t;

typedef struct {
	elf_file_t *src_ef;
	Elf64_Shdr *src_sec;
	void *src_obj;
	void *dst_obj;
} elf_obj_mapping_t;

typedef Elf64_Shdr *(*meger_section_func)(elf_link_t *elf_link, const char *sec_name);

typedef struct {
	const char *sec_name;
	meger_section_func func;
} elf_section_t;

static inline bool is_share_mode(elf_link_t *elf_link)
{
	return elf_link->link_mode == ELF_LINK_SHARE;
}

static inline bool is_static_mode(elf_link_t *elf_link)
{
	return elf_link->link_mode == ELF_LINK_STATIC;
}

static inline bool is_static_nolibc_mode(elf_link_t *elf_link)
{
#ifndef __aarch64__
	if (elf_link->link_mode == ELF_LINK_STATIC_NOLIBC) {
		si_panic("static-nolibc mode not support x86\n");
	}
#endif

	return elf_link->link_mode == ELF_LINK_STATIC_NOLIBC;
}

// libc _init_first is in .init_array, must run before _start
// libc __libc_early_init need init before .init_array
// dl_main(phdr, phnum, user_entry, auxv)
//     _dl_call_libc_early_init (GL(dl_ns)[LM_ID_BASE].libc_map, true);
//         __libc_early_init(true)

// this mode merge all ELFs exclude ld.so
// ld.so parse env and parameter, rtld_global_ro share to libc.so
// ld.so have some init process for libc, soname need call libc.so
// ld.so will lookup some func by GUN_HASH, some section need like libc.so
// .gnu.hash .dynsym .gnu.version .gnu.version_d .gnu.version_r
static inline bool is_static_nold_mode(elf_link_t *elf_link)
{
	return elf_link->link_mode == ELF_LINK_STATIC_NOLD;
}

static inline bool is_hook_func(elf_link_t *elf_link)
{
	return elf_link->hook_func;
}

// no use .plt, so clear .plt .rela.plt
static inline bool is_direct_call_optimize(elf_link_t *elf_link)
{
	return elf_link->direct_call_optimize;
}

static inline bool is_direct_vdso_optimize(elf_link_t *elf_link)
{
	return elf_link->direct_vdso_optimize;
}

static inline bool is_direct_point_var_optimize(elf_link_t *elf_link)
{
	return elf_link->direct_point_var_optimize;
}

static inline bool is_delete_symbol_version(elf_link_t *elf_link)
{
	return elf_link->delete_symbol_version;
}

static inline elf_file_t *get_template_ef(elf_link_t *elf_link)
{
	// use first ef as template
	return &elf_link->in_efs[0];
}

static inline elf_file_t *get_main_ef(elf_link_t *elf_link)
{
	if (is_share_mode(elf_link) || is_static_nold_mode(elf_link)) {
		return &elf_link->in_efs[0];
	}

	// static mode use second ef as main ef, which contains main function we need.
	return &elf_link->in_efs[1];
}

static inline elf_file_t *get_out_ef(elf_link_t *elf_link)
{
	return &elf_link->out_ef;
}

static inline elf_file_t *get_libc_ef(elf_link_t *elf_link)
{
	return elf_link->libc_ef;
}

static inline void elf_write_u32(elf_file_t *ef, unsigned long addr_, unsigned value)
{
	unsigned *addr = ((void *)ef->hdr + (unsigned long)addr_);
	*addr = value;
}

static inline void elf_write_u8(elf_file_t *ef, unsigned long addr_, uint8_t value)
{
	uint8_t *addr = ((void *)ef->hdr + (unsigned long)addr_);
	*addr = value;
}

static inline void elf_write_value(elf_file_t *ef, unsigned long addr_, void *val, unsigned int len)
{
	void *addr = ((void *)ef->hdr + (unsigned long)addr_);
	memcpy(addr, val, len);
}

static inline void modify_elf_file(elf_link_t *elf_link, unsigned long loc, void *val, int len)
{
	void *dst = (void *)elf_link->out_ef.hdr + loc;
	memcpy(dst, val, len);
}

// symbol
bool is_symbol_maybe_undefined(const char *name);
bool is_gnu_weak_symbol(Elf64_Sym *sym);
int get_new_sym_index(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int old_index);
int get_new_sym_index_or_clear(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int old_index);
Elf64_Sym *elf_lookup_symbol_by_rela(elf_link_t *elf_link, elf_file_t *src_ef, Elf64_Rela *src_rela, elf_file_t **lookup_ef);

// addr
unsigned long get_new_addr_by_old_addr(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long addr);
unsigned long get_new_addr_by_old_addr_ok(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long addr);
unsigned long get_new_addr_by_symobj_ok(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym);
unsigned long get_new_addr_by_symobj(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym);
unsigned long get_new_offset_by_old_offset(elf_link_t *elf_link, elf_file_t *src_ef, unsigned long offset);

// tls
unsigned long elf_get_new_tls_offset(elf_link_t *elf_link, elf_file_t *ef, unsigned long obj_tls_offset);

// section
bool is_section_needed(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec);
int get_new_section_index(elf_link_t *elf_link, elf_file_t *src_ef, unsigned int sec_index);
unsigned long get_new_name_offset(elf_link_t *elf_link, elf_file_t *src_ef, Elf64_Shdr *src_sec, unsigned long offset);

// temp sections
char *elf_get_tmp_section_name(elf_link_t *elf_link, Elf64_Shdr *shdr);
Elf64_Shdr *find_tmp_section_by_name(elf_link_t *elf_link, const char *sec_name);
Elf64_Shdr *find_tmp_section_by_src(elf_link_t *elf_link, Elf64_Shdr *shdr);

// section map
void show_sec_mapping(elf_link_t *elf_link);
void append_sec_mapping(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec, Elf64_Shdr *dst_sec);
void append_obj_mapping(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *sec, void *src_obj, void *dst_obj);
elf_obj_mapping_t *elf_get_mapping_by_dst(elf_link_t *elf_link, void *dst_obj);
elf_sec_mapping_t *elf_find_sec_mapping_by_dst(elf_link_t *elf_link, void *_dst_offset);
elf_sec_mapping_t *elf_find_sec_mapping_by_srcsec(elf_link_t *elf_link, Elf64_Shdr *src_sec);

// symbol map
void append_symbol_mapping(elf_link_t *elf_link, const char *symbol_name, unsigned long symbol_addr);
unsigned long get_new_addr_by_symbol_mapping(elf_link_t *elf_link, char *symbol_name);
void init_symbol_mapping(elf_link_t *elf_link);

#endif /* _ELF_LINK_COMMON_H */
