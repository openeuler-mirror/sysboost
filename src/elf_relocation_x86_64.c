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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <si_debug.h>
#include <si_log.h>

#include "elf_link_common.h"
#include "elf_instruction.h"
#include "elf_write_elf.h"

#define BYTES_NOP1 0x90

#define INDIRECT_CALL_INSN_OP_SIZE 2

#define CALL_INSN_SIZE 5
#define CALL_INSN_OPCODE 0xE8

#define JMP32_INSN_SIZE 5
#define JMP32_INSN_OPCODE 0xE9

#define MAX_INSN_OFFSET 2147483647L
#define MIN_INSN_OFFSET -2147483648L

#define POKE_MAX_OPCODE_SIZE 10

#define INDEX_FIVE 5

union text_poke_insn {
	unsigned char text[POKE_MAX_OPCODE_SIZE];
	struct {
		unsigned char opcode;
		int disp;
	} __attribute__((packed));
};

#define THREAD_VAR_INSN_OP_SIZE 12
#define THREAD_VAR_INSN_SIZE 16

union thread_var_insn {
	unsigned char text[THREAD_VAR_INSN_SIZE];
	struct {
		unsigned char opcode[THREAD_VAR_INSN_OP_SIZE];
		int offset;
	} __attribute__((packed));
};

static void modify_insn_offset(elf_link_t *elf_link, unsigned long loc, unsigned long sym_addr, int addend)
{
	int val = (long)sym_addr - (long)loc + addend;
	modify_elf_file(elf_link, loc, &val, sizeof(int));
}

static void elf_write_jmp_addr(elf_file_t *ef, unsigned long addr_, unsigned long sym_addr_)
{
	// relative jump has 4 Byte value, calculate from end of insn
	int val = sym_addr_ - addr_ - 4;
	int *addr = ((void *)ef->hdr + (unsigned long)addr_);
	*addr = val;
}

static int modify_insn_direct_jmp(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	unsigned long loc = get_new_addr_by_old_addr(elf_link, ef, rela->r_offset);
	unsigned long sym_addr = get_new_addr_by_symobj_ok(elf_link, ef, sym);
	if (sym_addr == 0) {
		return -1;
	}
	long disp = (long)sym_addr - (long)(loc - INDIRECT_CALL_INSN_OP_SIZE + CALL_INSN_SIZE);
	if ((disp > MAX_INSN_OFFSET) || (disp < MIN_INSN_OFFSET)) {
		return -1;
	}

	union text_poke_insn *insn;
	insn = (union text_poke_insn *)((void *)elf_link->out_ef.hdr + loc - INDIRECT_CALL_INSN_OP_SIZE);
	// ff 15 00 00 00 00       callq  *0x00(%rip)
	if ((insn->text[0] != 0xff) || (insn->text[1] != 0x15)) {
		return -1;
	}
	insn->opcode = CALL_INSN_OPCODE;
	insn->disp = disp;
	insn->text[INDEX_FIVE] = BYTES_NOP1;

	return 0;
}

static int get_new_tls_insn_offset(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym)
{
	unsigned long obj_tls_offset = elf_get_new_tls_offset(elf_link, ef, sym->st_value);
	elf_file_t *out_ef = &elf_link->out_ef;
	Elf64_Phdr *p = out_ef->tls_Phdr;
	unsigned long obj_addr = obj_tls_offset + p->p_paddr;

	return -(int)(p->p_paddr + p->p_memsz - obj_addr);
}

static void modify_tls_insn_use_fs(elf_link_t *elf_link, unsigned long loc, int offset_in_insn)
{
	union thread_var_insn *insn;
	insn = (union thread_var_insn *)((void *)elf_link->out_ef.hdr + loc);
	insn->opcode[0] = 0x64;
	insn->opcode[1] = 0x48;
	insn->opcode[2] = 0x8b;
	insn->opcode[3] = 0x04;
	insn->opcode[4] = 0x25;
	insn->opcode[5] = 0x00;
	insn->opcode[6] = 0x00;
	insn->opcode[7] = 0x00;
	insn->opcode[8] = 0x00;
	insn->opcode[9] = 0x48;
	insn->opcode[10] = 0x8d;
	insn->opcode[11] = 0x80;
	insn->offset = offset_in_insn;
}

static void modify_tls_insn(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	// TLS (thread local storage) use two rela
	// first insn point to got, have 16 Byte struct, modid and offset
	// second insn call __tls_get_addr to get thread var addr
	// 66 48 8d 3d c6 fe 5f 00    data16 lea 0x5ffec6(%rip),%rdi        <g_thread_lib2>
	// 66 66 48 e8 06 ff ff ff    data16 data16 rex.W call 200030       <__tls_get_addr@plt>
	// in the template ELF modid is zero, use fs to optimize insn, skip this and next rela
	// fs is percpu point to TLS end addr
	// 64 48 8b 04 25 00 00       mov    %fs:0x0,%rax         R_X86_64_TLSGD, st_value is offset to TLS area
	// 00 00
	// 48 8d 80 fc ff ff ff       lea    -0x4(%rax),%rax      R_X86_64_PLT32

	unsigned long loc;

	// .rela.dyn R_X86_64_DTPOFF64 sym->st_value is offset from .tdata begin
	// .rela.text R_X86_64_TLSGD sym->st_value is offset from .tdata begin
	// new insn offset
	int offset_in_insn = get_new_tls_insn_offset(elf_link, ef, sym);
	// thread var have 16 Byte insn space, rela offset is 4 Byte from insn begin
	loc = get_new_offset_by_old_offset(elf_link, ef, rela->r_offset) - 4;
	modify_tls_insn_use_fs(elf_link, loc, offset_in_insn);
}

static void modify_tls_insn_data_offset(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	// first insn imm addr nend change
	// 20ee30:	48 c7 c0 88 ff ff ff 	mov    $0xffffffffffffff88,%rax
	// 20ee37:	64 48 8b 00          	mov    %fs:(%rax),%rax
	// 20ee3b:	48 8b 10             	mov    (%rax),%rdx
	// 000000000020ee33  00000fe800000016 R_X86_64_GOTTPOFF      0000000000000050 _nl_current_LC_IDENTIFICATION - 4
	int offset_in_insn = get_new_tls_insn_offset(elf_link, ef, sym);
	unsigned long loc = get_new_offset_by_old_offset(elf_link, ef, rela->r_offset);
	elf_write_u32(&elf_link->out_ef, loc, offset_in_insn);
}

static unsigned char *get_insn_begin_by_offset(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela)
{
	unsigned long new_offset = get_new_offset_by_old_offset(elf_link, ef, rela->r_offset);
	unsigned long insn_begin = new_offset - ELF_INSN_OP_LEN;
	return elf_insn_offset_to_addr(&elf_link->out_ef, insn_begin);
}

static void modify_tls_insn_got(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	// relative address points to .got, store thread variable offset
	// may be use rbx or rax or rbp
	// case 1:
	// 9a796:	48 8b 1d f3 65 15 00 	mov    0x1565f3(%rip),%rbx        # 1f0d90 <_GLOBAL_OFFSET_TABLE_+0x1d0>
	// 9a79d:	64 48 8b 13          	mov    %fs:(%rbx),%rdx
	// 000000000009a799  0000051400000016 R_X86_64_GOTTPOFF      0000000000000048 tcache - 4
	// 1300: 0000000000000048     8 TLS     LOCAL  DEFAULT   29 tcache
	// [35] .got              PROGBITS        00000000001f0bc0 1efbc0 000428 08  WA  0   0  8
	// case 2:
	// 00000000000368f8  0000139e00000016 R_X86_64_GOTTPOFF      0000000000000028 __libc_tsd_CTYPE_B - 4
	// 368f5:	48 8b 2d e4 a4 1b 00 	mov    0x1ba4e4(%rip),%rbp        # 1f0de0 <_GLOBAL_OFFSET_TABLE_+0x220>
	// case 3:
	// 975b9:	48 8b 05 c8 97 15 00 	mov    0x1597c8(%rip),%rax        # 1f0d88 <_GLOBAL_OFFSET_TABLE_+0x1c8>
	// 975c7:	64 48 89 08          	mov    %rcx,%fs:(%rax)
	// 00000000000975bc  000004f000000016 R_X86_64_GOTTPOFF      0000000000000058 thread_arena - 4
	// 1264: 0000000000000058     8 TLS     LOCAL  DEFAULT   29 thread_arena
	// this case, modify insn and then modify TLS offset
	unsigned char *insn = get_insn_begin_by_offset(elf_link, ef, rela);
	if (elf_insn_is_reg_addr_mov(insn)) {
		elf_insn_change_got_to_imm(insn);
	} else if (is_tls_insn_imm_offset(insn) == false) {
		si_panic("%s %lx\n", ef->file_name, rela->r_offset);
	}

	// 32 bit signed PC relative offset to GOT entry for IE symbol
	// 20ee30:	48 c7 c0 88 ff ff ff 	mov    $0xffffffffffffff88,%rax
	// 20ee37:	64 48 8b 00          	mov    %fs:(%rax),%rax
	// 20ee3b:	48 8b 10             	mov    (%rax),%rdx
	// 000000000020ee33  00000fe800000016 R_X86_64_GOTTPOFF      0000000000000050 _nl_current_LC_IDENTIFICATION - 4
	// this case, just modify TLS offset
	modify_tls_insn_data_offset(elf_link, ef, rela, sym);
}

// string symbol may have some name, change offset use insn direct value
static void modify_insn_data_offset(elf_link_t *elf_link, elf_file_t *ef, unsigned long loc, int addend)
{
	int offset_in_insn = elf_read_s32_va(ef, loc);
	unsigned long old_obj_addr = offset_in_insn + loc - addend;
	unsigned long new_obj_addr = get_new_addr_by_old_addr(elf_link, ef, old_obj_addr);
	unsigned long new_loc = get_new_addr_by_old_addr(elf_link, ef, loc);

	modify_insn_offset(elf_link, new_loc, new_obj_addr, addend);
}

static bool is_need_change_addr(elf_link_t *elf_link, elf_file_t *ef, Elf64_Sym *sym)
{
	// static mode do not have plt, so func need direct call
	// 7753f:	e8 14 4e fb ff       	call   2c358 <malloc@plt>
	// 0000000000077540  00002bc800000004 R_X86_64_PLT32         000000000009a760 malloc - 4
	// 11208: 000000000009a760   604 FUNC    GLOBAL DEFAULT   15 malloc
	if (is_direct_call_optimize(elf_link)) {
		return true;
	}

	if (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
		return true;
	}

	char *sym_name = elf_get_sym_name(ef, sym);
	unsigned long ret = get_new_addr_by_symbol_mapping(elf_link, sym_name);
	if (ret != NOT_FOUND) {
		return true;
	}

	// local func call used offset in same section, do nothing
	// e8 4d 02 00 00          call   200330 <run_b>
	if (sym->st_shndx != SHN_UNDEF) {
		return false;
	}

	return true;
}

// static mode, direct exit to _exit
// 000000000020195d  0000098e00000004 R_X86_64_PLT32         0000000000215020 exit - 4
// 2446: 0000000000215020    32 FUNC    LOCAL  DEFAULT   13 exit
// 20195c:	e8 bf 36 01 00       	call   215020 <exit>
static void modify_insn_func_offset(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	int val = 0;

	if (is_need_change_addr(elf_link, ef, sym) == false) {
		return;
	}

	// This is where to make the change
	unsigned long loc = get_new_addr_by_old_addr(elf_link, ef, rela->r_offset);
	unsigned long sym_addr = get_new_addr_by_symobj(elf_link, ef, sym);
	if (sym_addr == NOT_FOUND) {
		// share mode libc func is use plt, no need change
		if (is_share_mode(elf_link)) {
			return;
		}

		const char *sym_name = elf_get_sym_name(ef, sym);
		if (is_symbol_maybe_undefined(sym_name)) {
			sym_addr = 0UL;
			goto out;
		}
		si_panic("find func fail %s %016lx\n", sym_name, rela->r_offset);
		return;
	}

out:
	val = (long)sym_addr - (long)loc + rela->r_addend;
	modify_elf_file(elf_link, loc, &val, sizeof(int));
}

static void fix_main_for_static_mode(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	if (is_static_mode(elf_link) == false) {
		return;
	}

	// _start call __libc_start_main, set main func as arg0, change it to real addr
	// 00000000002011fb  00000dd500000002 R_X86_64_PC32          0000000000200af0 main - 4
	// 3541: 0000000000200af0  1763 FUNC    GLOBAL DEFAULT   13 main
	// 2011f8:	48 8d 3d f1 f8 ff ff 	lea    -0x70f(%rip),%rdi        # 200af0 <main>
	char *name = elf_get_sym_name(ef, sym);
	if (elf_is_same_symbol_name(name, "main")) {
		modify_insn_func_offset(elf_link, ef, rela, sym);
	}
}

static void modify_insn_for_pc32(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	// STT_FUNC no need reloc
	if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC) {
		fix_main_for_static_mode(elf_link, ef, rela, sym);
		return;
	}

	// feature: if layout not random, use imm value, do not use lea

	// data is use offset, STT_OBJECT
	// global var, change insn offset
	// lea    0x5fff75(%rip),%rax
	modify_insn_data_offset(elf_link, ef, rela->r_offset, rela->r_addend);
}

// rela r_addend not have offset to symbol, so get offset form insn imm value
// 00000000000398fb  000024440000002a R_X86_64_REX_GOTPCRELX 00000000001ec648 __ctype_b@GLIBC_2.2.5 - 4
// 9284: 00000000001ec648     8 OBJECT  GLOBAL DEFAULT   36 __ctype_b@GLIBC_2.2.5
// 398f8:	48 8b 0d 81 25 1b 00 	mov    0x1b2581(%rip),%rcx        # 1ebe80 <__ctype_b@GLIBC_2.2.5-0x7c8>
// 0x1ec648 - 0x7c8 = 1ebe80
static void modify_insn_imm_offset(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	(void)sym;
	modify_insn_data_offset(elf_link, ef, rela->r_offset, rela->r_addend);
}

// retrun value tell skip num
int modify_local_call_rela(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela)
{
	Elf64_Sym *sym = NULL;
	int ret = 0;

	sym = elf_get_symtab_by_rela(ef, rela);

	switch (ELF64_R_TYPE(rela->r_info)) {
	case R_X86_64_NONE:
		break;
	case R_X86_64_TLSGD:
		// TLS (thread local storage) use two rela
		// first insn point to got, have 16 Byte struct, modid and offset
		// second insn call __tls_get_addr to get thread var addr
		// 66 48 8d 3d c6 fe 5f 00    data16 lea 0x5ffec6(%rip),%rdi        <g_thread_lib2>
		// 66 66 48 e8 06 ff ff ff    data16 data16 rex.W call 200030       <__tls_get_addr@plt>
		// in the template ELF modid is zero, use fs to optimize insn, skip this and next rela
		// fs is percpu point to TLS end addr
		// mov    %fs:0x0,%rax         R_X86_64_TLSGD, st_value is offset to TLS area
		// lea    -0x4(%rax),%rax      R_X86_64_PLT32
		modify_tls_insn(elf_link, ef, rela, sym);
		return SKIP_ONE_RELA;
	case R_X86_64_TLSLD:
		// 48 8d 3d d3 e0 c9 00    lea    0xc9e0d3(%rip),%rdi        # 13ff498 <.got>   R_X86_64_TLSLD
		// e8 e6 0c ea ff          callq  6020b0 <__tls_get_addr@plt>                   R_X86_64_PLT32
		// 48 8b 80 00 00 00 00    mov    0x0(%rax),%rax                                R_X86_64_DTPOFF32
		// this time just modify immediate data
		// TODO: feature, change insn to use fs
		modify_insn_data_offset(elf_link, ef, rela->r_offset, rela->r_addend);
		return SKIP_TWO_RELA;
	case R_X86_64_GOTTPOFF:
		modify_tls_insn_got(elf_link, ef, rela, sym);
		break;
	case R_X86_64_TPOFF32:
		// Offset in initial TLS block
		// 22cb1b:	64 48 8b 04 25 d0 ff 	mov    %fs:0xffffffffffffffd0,%rax
		// 22cb22:	ff ff
		// 000000000022cb20  0000030900000017 R_X86_64_TPOFF32       0000000000000098 tcache + 0
		modify_tls_insn_data_offset(elf_link, ef, rela, sym);
		break;
	case R_X86_64_DTPOFF32:
		// insn may move by optimize
		// this insn is offset to TLS block begin, no need change
		break;
	case R_X86_64_PLT32:
		// call func in plt, change to direct jump
		// e8 74 ff ff ff          call   200070 <lib1_add@plt>
		// jmp and ret, change direct value
		// e9 ee fc ff ff          jmp    200040 <printf@plt>
		modify_insn_func_offset(elf_link, ef, rela, sym);
		break;
	case R_X86_64_GOTPCRELX:
		// call func use got, change to direct jump
		// ff 15 00 00 00 00       callq  *0x00(%rip)
		ret = modify_insn_direct_jmp(elf_link, ef, rela, sym);
		if (ret == 0) {
			break;
		}

		// data var, just change offset
		// 48 83 3d d2 fe 5f 00    cmpq   $0x0,0x5ffed2(%rip)
		modify_insn_data_offset(elf_link, ef, rela->r_offset, rela->r_addend);
		break;
	case R_X86_64_PC32:
		modify_insn_for_pc32(elf_link, ef, rela, sym);
		break;
	case R_X86_64_GOTPCREL:
	case R_X86_64_REX_GOTPCRELX:
		modify_insn_imm_offset(elf_link, ef, rela, sym);
		break;
	case R_X86_64_64:
	case R_X86_64_32S:
		// direct value, data is already write
		break;
	default:
		SI_LOG_INFO("invalid type %2d r_offset %016lx r_addend %016lx sym_index %4d\n",
			    (int)ELF64_R_TYPE(rela->r_info), rela->r_offset, rela->r_addend, (int)ELF64_R_SYM(rela->r_info));
		SI_LOG_INFO(" st_value %016lx\n", sym->st_value);
		si_panic("invalid type\n");
		return -1;
	}

	return 0;
}

#define ADDRESS_OF_FOUR_BYTES  4
#define ADDRESS_OF_SIX_BYTES   6
void modify_rela_plt(elf_link_t *elf_link, si_array_t *arr)
{
	int len = arr->len;
	elf_obj_mapping_t *obj_rels = arr->data;
	elf_obj_mapping_t *obj_rel = NULL;
	Elf64_Rela *src_rela = NULL;
	Elf64_Rela *dst_rela = NULL;
	elf_file_t *out_ef = &elf_link->out_ef;

	elf_file_t *template_ef = get_template_ef(elf_link);
	Elf64_Shdr *find_sec = elf_find_section_by_name(template_ef, ".plt");
	unsigned long new_plt_start_addr = get_new_addr_by_old_addr(elf_link, template_ef, find_sec->sh_offset);

	for (int i = 0; i < len; i++) {
		obj_rel = &obj_rels[i];
		src_rela = obj_rel->src_obj;
		dst_rela = obj_rel->dst_obj;

		// old sym index to new index of .dynsym
		unsigned int old_index = ELF64_R_SYM(src_rela->r_info);
		int new_index = get_new_sym_index_no_clear(elf_link, obj_rel->src_ef, old_index);
		// func in this ELF need clear rela
		if (new_index == NEED_CLEAR_RELA) {
			elf_clear_rela(dst_rela);
			continue;
		}
		dst_rela->r_info = ELF64_R_INFO(new_index, ELF64_R_TYPE(src_rela->r_info));

		// old got addr to new addr
		dst_rela->r_offset = get_new_addr_by_old_addr(elf_link, obj_rel->src_ef, src_rela->r_offset);

		SI_LOG_DEBUG("old r_offset %016lx r_info %016lx r_addend %016lx -> new r_offset %016lx r_info %016lx r_addend %016lx\n",
			     src_rela->r_offset, src_rela->r_info, src_rela->r_addend,
			     dst_rela->r_offset, dst_rela->r_info, dst_rela->r_addend);

		// got[n+2] is plt next insn
		unsigned long old_plt_addr = elf_read_u64(out_ef, (unsigned long)dst_rela->r_offset);
		unsigned long new_plt_addr = get_new_addr_by_old_addr(elf_link, obj_rel->src_ef, old_plt_addr);
		elf_write_u64(out_ef, (unsigned long)dst_rela->r_offset, new_plt_addr);

		// ff 25 82 ff 5f 00       jmp    *0x5fff82(%rip)
		// 68 00 00 00 00          pushq  $0x0
		// e9 e0 ff ff ff          jmpq   200020 <.plt>
		// change jmp insn offset to new
		modify_insn_offset(elf_link, new_plt_addr - ADDRESS_OF_FOUR_BYTES, (unsigned long)dst_rela->r_offset, -1 * ADDRESS_OF_FOUR_BYTES);
		// change sym index, pushq has 1 Byte cmd
		// index of .rela.plt
		elf_write_value(out_ef, new_plt_addr + 1, &i, sizeof(unsigned int));
		// relative jump to begin of .plt
		// pushq has 5 Byte, jmpq has 1 Byte cmd
		elf_write_jmp_addr(out_ef, new_plt_addr + ADDRESS_OF_SIX_BYTES, new_plt_start_addr);
	}

	if (is_share_mode(elf_link) == false)
		return;

	// TODO: feature, change addr for lazy lookup sym, this time not support lazy
	// 0000000000001020 <.plt>:
	//    1020:	ff 35 e2 2f 00 00    	pushq  0x2fe2(%rip)        # 4008 <_GLOBAL_OFFSET_TABLE_+0x8>
	//    1026:	ff 25 e4 2f 00 00    	jmpq   *0x2fe4(%rip)        # 4010 <_GLOBAL_OFFSET_TABLE_+0x10>
	//    102c:	0f 1f 40 00          	nopl   0x0(%rax)
}

void modify_plt_got(elf_link_t *elf_link)
{
	// no rela for .plt.got, do this by scan insn
	// every ELF have .plt.got secsion, just modify first one
	elf_file_t *ef = get_template_ef(elf_link);

	// ff 25 82 ff 5f 00       jmp    *0x5fff82(%rip)        # 7ffff8 <__cxa_finalize>
	Elf64_Shdr *sec = elf_find_section_by_name(ef, ".plt.got");
	if (!sec) {
		return;
	}
	unsigned long loc = sec->sh_offset;

	// insn have 2 op code, direct value have 4 Byte
	loc = loc + 2;
	modify_insn_data_offset(elf_link, ef, loc, -1 * ADDRESS_OF_FOUR_BYTES);
}

void correct_stop_libc_atexit(elf_link_t *elf_link)
{
	(void)elf_link;
}
