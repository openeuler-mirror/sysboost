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

#ifndef _ELF_READ_ELF_H
#define _ELF_READ_ELF_H

#include <elf.h>
#include <stdbool.h>

#define NOT_FOUND_SYM (-1U)

#define NEED_CLEAR_RELA (-2)
#define RELOCATION_ROOT_DIR "/usr/lib/relocation"

typedef struct {
	Elf64_Ehdr *hdr;
	Elf64_Phdr *segments;

	Elf64_Shdr *sechdrs;
	Elf64_Shdr *shstrtab_sec;
	Elf64_Shdr *symtab_sec;
	Elf64_Shdr *dynsym_sec;
	Elf64_Shdr *dynstr_sec;

	Elf64_Phdr *hdr_Phdr;
	Elf64_Phdr *text_Phdr;
	Elf64_Phdr *rodata_Phdr;
	Elf64_Phdr *data_Phdr;
	Elf64_Phdr *dynamic_Phdr;
	Elf64_Phdr *frame_Phdr;
	Elf64_Phdr *relro_Phdr;
	Elf64_Phdr *tls_Phdr;

	char *shstrtab_data;
	char *strtab_data;
	char *dynstr_data;

	int fd;
	unsigned long length;
	bool is_xz_file;
	char *file_name;
	char *build_id;
} elf_file_t;

static inline void *elf_get_section_data(elf_file_t *ef, Elf64_Shdr *sec)
{
	return (((void *)ef->hdr) + sec->sh_offset);
}

static inline char *elf_get_section_name(const elf_file_t *ef, const Elf64_Shdr *sec)
{
	return ef->shstrtab_data + sec->sh_name;
}

static inline char *elf_get_dynsym_name(elf_file_t *ef, Elf64_Sym *sym)
{
	return ef->dynstr_data + sym->st_name;
}

static inline bool elf_is_symbol_type_section(Elf64_Sym *sym)
{
	if (ELF64_ST_TYPE(sym->st_info) == STT_SECTION) {
		return true;
	}

	return false;
}

static inline char *elf_get_symbol_name(elf_file_t *ef, Elf64_Sym *sym)
{
	if (elf_is_symbol_type_section(sym)) {
		Elf64_Shdr *sec = &ef->sechdrs[sym->st_shndx];
		return elf_get_section_name(ef, sec);
	}

	return ef->strtab_data + sym->st_name;
}

static inline Elf64_Sym *elf_get_symtab_array(elf_file_t *ef)
{
	return (Elf64_Sym *)elf_get_section_data(ef, ef->symtab_sec);
}

static inline int elf_get_symtab_count(elf_file_t *ef)
{
	return ef->symtab_sec->sh_size / sizeof(Elf64_Sym);
}

static inline Elf64_Sym *elf_get_dynsym_array(elf_file_t *ef)
{
	return (Elf64_Sym *)elf_get_section_data(ef, ef->dynsym_sec);
}

static inline int elf_get_dynsym_count(elf_file_t *ef)
{
	return ef->dynsym_sec->sh_size / sizeof(Elf64_Sym);
}

static inline unsigned int elf_get_dynsym_index(elf_file_t *ef, Elf64_Sym *sym)
{
	Elf64_Sym *syms = elf_get_dynsym_array(ef);
	return sym - syms;
}

static inline char *elf_get_dynsym_name_by_index(elf_file_t *ef, unsigned int index)
{
	Elf64_Sym *syms = elf_get_dynsym_array(ef);
	return elf_get_dynsym_name(ef, &syms[index]);
}

static inline bool elf_is_dynsym(elf_file_t *ef, Elf64_Sym *sym)
{
	unsigned long begin = (unsigned long)elf_get_dynsym_array(ef);
	unsigned long end = begin + ef->dynsym_sec->sh_size;
	unsigned long addr = (unsigned long)sym;
	if ((addr >= begin) && (addr < end)) {
		return true;
	}

	return false;
}

static inline char *elf_get_sym_name(elf_file_t *ef, Elf64_Sym *sym)
{
	char *sym_name = NULL;
	bool is_dynsym = elf_is_dynsym(ef, sym);
	if (is_dynsym == true) {
		sym_name = elf_get_dynsym_name(ef, sym);
	} else {
		sym_name = elf_get_symbol_name(ef, sym);
	}
	return sym_name;
}

static inline int elf_get_symbol_index(Elf64_Rela *rela)
{
	return ELF64_R_SYM(rela->r_info);
}

static inline bool elf_is_rela_symbol_null(Elf64_Rela *rela)
{
	int index = elf_get_symbol_index(rela);
	if (index == 0) {
		return true;
	}
	return false;
}

static inline Elf64_Sym *elf_get_symtab_by_rela(elf_file_t *ef, Elf64_Rela *rela)
{
	return (Elf64_Sym *)((void *)ef->hdr + ef->symtab_sec->sh_offset) + ELF64_R_SYM(rela->r_info);
}

static inline Elf64_Sym *elf_get_dynsym_by_rela(elf_file_t *ef, Elf64_Rela *rela)
{
	return elf_get_dynsym_array(ef) + ELF64_R_SYM(rela->r_info);
}

unsigned long elf_va_to_offset(elf_file_t *ef, unsigned long va);

static inline int elf_read_s32(elf_file_t *ef, unsigned long offset)
{
	void *addr = ((void *)ef->hdr + (unsigned long)offset);
	return *(int *)addr;
}

static inline int elf_read_s32_va(elf_file_t *ef, unsigned long va)
{
	return elf_read_s32(ef, elf_va_to_offset(ef, va));
}

static inline unsigned elf_read_u32(elf_file_t *ef, unsigned long offset)
{
	void *addr = ((void *)ef->hdr + (unsigned long)offset);
	return *(unsigned *)addr;
}

static inline unsigned elf_read_u32_va(elf_file_t *ef, unsigned long va)
{
	return elf_read_u32(ef, elf_va_to_offset(ef, va));
}

static inline unsigned long elf_read_u64(elf_file_t *ef, unsigned long offset)
{
	void *addr = ((void *)ef->hdr + (unsigned long)offset);
	return *(unsigned long *)addr;
}

static inline unsigned long elf_read_u64_va(elf_file_t *ef, unsigned long va)
{
	return elf_read_u64(ef, elf_va_to_offset(ef, va));
}

static inline void elf_write_u64(elf_file_t *ef, unsigned long addr_, unsigned long value)
{
	unsigned long *addr = ((void *)ef->hdr + (unsigned long)addr_);
	*addr = value;
}

int elf_find_func_range_by_name(elf_file_t *ef, const char *func_name,
				unsigned long *start, unsigned long *end);

// symbol
bool elf_is_same_symbol_name(const char *a, const char *b);
bool elf_is_symbol_at_libc(elf_file_t *ef, Elf64_Sym *sym);
unsigned elf_find_symbol_index_by_name(elf_file_t *ef, const char *name);
Elf64_Sym *elf_find_symbol_by_name(elf_file_t *ef, const char *sym_name);
Elf64_Sym *elf_find_symbol_by_addr(elf_file_t *ef, unsigned long addr);
unsigned long elf_find_symbol_addr_by_name(elf_file_t *ef, char *sym_name);
Elf64_Sym *elf_find_dynsym_by_name(elf_file_t *ef, const char *name);
int elf_find_dynsym_index_by_name(elf_file_t *ef, const char *name);
char *elf_get_dynsym_name_by_index(elf_file_t *ef, unsigned int index);

// rela
static inline bool elf_rela_is_relative(Elf64_Rela *rela)
{
	int type = ELF64_R_TYPE(rela->r_info);
	if ((type == R_X86_64_RELATIVE) || (type == R_AARCH64_RELATIVE)) {
		return true;
	}

	return false;
}

Elf64_Rela *elf_get_rela_by_addr(elf_file_t *ef, unsigned long addr);

// dyn
Elf64_Dyn *elf_find_dyn_by_type(elf_file_t *ef, unsigned long dt);

// section
Elf64_Shdr *elf_find_section_by_tls_offset(elf_file_t *ef, unsigned long obj_tls_offset);
Elf64_Shdr *elf_find_section_by_name(elf_file_t *ef, const char *sec_name);
Elf64_Shdr *elf_find_section_by_addr(elf_file_t *ef, unsigned long addr);
typedef bool (*section_filter_func)(const elf_file_t *ef, const Elf64_Shdr *sec);
bool elf_is_relro_section(const elf_file_t *ef, const Elf64_Shdr *sechdr);
bool text_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec);
bool rodata_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec);
bool got_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec);
bool rwdata_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec);
bool bss_section_filter(const elf_file_t *ef, const Elf64_Shdr *sec);
bool elf_is_debug_section(elf_file_t *ef, Elf64_Shdr *sechdr);
bool elf_is_same_area(const elf_file_t *ef, const Elf64_Shdr *a, const Elf64_Shdr *b);

// ELF
void elf_parse_hdr(elf_file_t *ef);
void elf_read_elf_phdr(elf_file_t *ef);
void elf_read_elf_sections(elf_file_t *ef);
int elf_read_file(char *file_name, elf_file_t *ef, bool is_readonly);
int elf_read_file_relocation(char *file_name, elf_file_t *ef);
void elf_close_file(elf_file_t *ef);

// debug
void elf_show_dynsym(elf_file_t *ef);
void elf_show_sections(elf_file_t *ef);
void elf_show_segments(elf_file_t *ef);

// elf_read_elf_xz.c
bool elf_is_xz_file(elf_file_t *ef);
int elf_load_xz(elf_file_t *ef);
void elf_unload_xz(elf_file_t *ef);

#endif /* _ELF_READ_ELF_H */
