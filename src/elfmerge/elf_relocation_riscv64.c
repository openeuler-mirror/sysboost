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
#include <si_log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "elf_link_common.h"
#include "elf_link_elf.h"
#include "elf_write_elf.h"
#include <si_debug.h>

#define unlikely(x) __builtin_expect((x), 0)

#define OPCODE_MASK 0x0000007F
#define INST_LEN_BYTE 4
#define RVC_INST_LEN_BYTE 2
#define TWO_INST 2
#define MAX_PLT_ADDR 0x100000000UL

static signed sign_extend_32(signed val, unsigned len)
{
	unsigned mask = 1 << (len - 1);
	return (val ^ mask) - mask;
}

static bool is_compressed_instruction(unsigned short insn)
{
	return (insn & 0x3) != 0x3;
}

// C.J instruction format (compressed, CJ-type):
// |	imm[11|4|9:8|10|6|7|3:1|5] (11 bits)	|	opcode (5 bits)	|

#define CJ_FUNCT3_MASK 0xE003 // mask for funct3 + opcode
#define CJ_FUNCT3_BITS 0xA001 // bits[15:13]=101, bits[1:0]=01
#define CJ_MAX_OFFSET 2046
#define CJ_MIN_OFFSET -2048

static bool is_cj_insn(unsigned short binary)
{
	return (binary & CJ_FUNCT3_MASK) == CJ_FUNCT3_BITS;
}

static unsigned get_cj_addr(unsigned short binary, unsigned offset)
{
	signed imm = 0;
	imm |= ((binary >> 12) & 0x1) << 11;
	imm |= ((binary >> 11) & 0x1) << 4;
	imm |= ((binary >> 9) & 0x3) << 8;
	imm |= ((binary >> 8) & 0x1) << 10;
	imm |= ((binary >> 7) & 0x1) << 6;
	imm |= ((binary >> 6) & 0x1) << 7;
	imm |= ((binary >> 3) & 0x7) << 1;
	imm |= ((binary >> 2) & 0x1) << 5;

	// Sign-extend 12-bit immediate
	if (imm & 0x800) {
		imm |= ~0x7FF;
	}

	return offset + imm;
}

static unsigned short gen_cj_binary(unsigned obj_addr, unsigned insn_offset, unsigned short binary)
{
	signed imm = obj_addr - insn_offset;

	if (imm < CJ_MIN_OFFSET || imm > CJ_MAX_OFFSET) {
		si_panic("Error: Offset %d out of range for C.J instruction\n", imm);
		return 0xFFFF;
	}

	unsigned short cj_insn = binary & CJ_FUNCT3_MASK;
	unsigned uimm = imm & 0xFFF;

	cj_insn |= ((uimm >> 11) & 0x1) << 12;
	cj_insn |= ((uimm >> 4) & 0x1) << 11;
	cj_insn |= ((uimm >> 8) & 0x3) << 9;
	cj_insn |= ((uimm >> 10) & 0x1) << 8;
	cj_insn |= ((uimm >> 6) & 0x1) << 7;
	cj_insn |= ((uimm >> 7) & 0x1) << 6;
	cj_insn |= ((uimm >> 1) & 0x7) << 3;
	cj_insn |= ((uimm >> 5) & 0x1) << 2;

	return cj_insn;
}

// C.BEQZ/C.BNEZ instruction format (CB-type, compressed):
// | funct3 (3 bits) | imm[8|4:3] (3 bits) | rs1' (3 bits) | imm[7:6|2:1|5] (5 bits) | opcode (2 bits) |
// where:
// 	funct3: 110 for C.BEQZ, 111 for C.BNEZ

#define CB_FUNCT3_MASK 0xE003 // mask for funct3 + opcode
#define CB_RS1_MASK 0x0380
#define CBEQZ_FUNCT3_BITS 0xC001
#define CBNEZ_FUNCT3_BITS 0xE001
#define CB_MAX_OFFSET 254
#define CB_MIN_OFFSET -256

static bool is_cbeqz_insn(unsigned short binary)
{
	return (binary & CB_FUNCT3_MASK) == CBEQZ_FUNCT3_BITS;
}

static bool is_cbnez_insn(unsigned short binary)
{
	return (binary & CB_FUNCT3_MASK) == CBNEZ_FUNCT3_BITS;
}

static unsigned get_cb_addr(unsigned short binary, unsigned offset)
{
	signed imm = 0;
	imm |= ((binary >> 12) & 0x1) << 8;
	imm |= ((binary >> 10) & 0x3) << 3;
	imm |= ((binary >> 5) & 0x3) << 6;
	imm |= ((binary >> 3) & 0x3) << 1;
	imm |= ((binary >> 2) & 0x1) << 5;

	// Sign-extend 9-bit immediate
	if (imm & 0x100) {
		imm |= ~0x1FF;
	}

	return offset + imm;
}

static unsigned short gen_cb_binary(unsigned obj_addr, unsigned insn_offset, unsigned short binary)
{
	signed imm = obj_addr - insn_offset;

	if (imm < CB_MIN_OFFSET || imm > CB_MAX_OFFSET) {
		si_panic("Error: Offset %d out of range for CB-type instruction\n", imm);
		return 0xFFFF;
	}

	unsigned short cb_insn = (binary & (CB_FUNCT3_MASK | CB_RS1_MASK));

	unsigned uimm = imm & 0x1FF;

	cb_insn |= ((uimm >> 8) & 0x1) << 12;
	cb_insn |= ((uimm >> 3) & 0x3) << 10;
	cb_insn |= ((uimm >> 6) & 0x3) << 5;
	cb_insn |= ((uimm >> 1) & 0x3) << 3;
	cb_insn |= ((uimm >> 5) & 0x1) << 2;

	return cb_insn;
}

// ADDI instruction format (I-type):
// | imm[11:0] (12 bits) | rs1 (5 bits) | funct3 (3 bits) | rd (5 bits) | opcode (7 bits) |

#define ADDI_OPCODE 0x00000013
#define ADDI_FUNCT3 0x00000000
#define ADDI_FUNCT3_MASK 0x00007000
#define ADDI_RD_MASK 0x00000F80
#define ADDI_RS1_MASK 0x000F8000
#define ADDI_IMM_MASK 0xFFF00000
#define ADDI_IMM_SHIFT 20

static bool is_addi_insn(unsigned insn)
{
	return ((insn & OPCODE_MASK) == ADDI_OPCODE) &&
	       ((insn & ADDI_FUNCT3_MASK) == ADDI_FUNCT3);
}

static signed get_addi_addr(unsigned insn)
{
	signed imm = (signed)(insn & ADDI_IMM_MASK) >> ADDI_IMM_SHIFT;
	return imm;
}

static unsigned gen_addi_binary(unsigned obj_addr, unsigned insn_offset, unsigned binary)
{
	signed offset = (signed)(obj_addr - insn_offset);

	signed imm12 = offset & 0xFFF;
	// Sign-extend 12-bit immediate
	if (imm12 & 0x800) {
		imm12 |= 0xFFFFF000;
	}

	unsigned new_binary = binary & ~ADDI_IMM_MASK;
	new_binary |= ((unsigned)(imm12 & 0xFFF) << ADDI_IMM_SHIFT);

	return new_binary;
}

// AUIPC instruction format (U-type):
// | imm[31:12] (20 bits) | rd (5 bits) | opcode (7 bits) |
#define AUIPC_IMM_MASK 0xFFFFF000
#define AUIPC_OPCODE 0x00000017
#define AUIPC_RD_MASK 0x00000F80
#define AUIPC_IMM_SHIFT 12

static bool is_auipc_insn(unsigned insn)
{
	return (insn & OPCODE_MASK) == AUIPC_OPCODE;
}

static unsigned get_auipc_addr(unsigned binary, unsigned long offset)
{
	unsigned imm = (binary & AUIPC_IMM_MASK);

	// AUIPC calculates: rd = pc + (imm << 12)
	// Already offset 12 bits
	return offset + imm;
}

static unsigned gen_auipc_binary(unsigned obj_addr, unsigned insn_offset, unsigned binary)
{
	signed offset = (signed)(obj_addr - insn_offset);

	// Split offset into high 20 bits (AUIPC) and low 12 bits (LD)
	// The high 20 bits are (offset + 0x800) >> 12 to handle rounding correctly
	signed offset_hi = (offset + 0x800) >> AUIPC_IMM_SHIFT;
	unsigned rd = binary & AUIPC_RD_MASK;

	return AUIPC_OPCODE | (offset_hi << AUIPC_IMM_SHIFT) | rd;
}

// RISC-V load instruction format (I-type):
// | imm[11:0] (12 bits) | rs1 (5 bits) | funct3 (3 bits) | rd (5 bits) | opcode (7 bits) |

#define OPCODE_LOAD 0x00000003
#define IMM_MASK_LD 0xFFF00000
#define FUNCT3_LD_MASK (0x7 << 12)
#define FUNCT3_LD_BITS (0x3 << 12)
#define LD_IMM_SHIFT 20

static bool is_ld_insn(unsigned insn)
{
	return ((insn & OPCODE_MASK) == OPCODE_LOAD) &&
	       ((insn & FUNCT3_LD_MASK) == FUNCT3_LD_BITS);
}

static signed get_ld_addr(unsigned binary)
{
	if (!is_ld_insn(binary)) {
		si_panic("Error: Not a load instruction (opcode=0x%x)\n", binary & OPCODE_LOAD);
		return -1;
	}

	return (signed)(binary & IMM_MASK_LD) >> LD_IMM_SHIFT;
}

static unsigned gen_ld_binary(unsigned obj_addr, unsigned insn_offset, unsigned binary)
{
	signed offset = (signed)(obj_addr - insn_offset);

	int32_t offset_lo = offset & 0xFFF;
	// Sign-extend 12-bit immediate
	if (offset_lo & 0x800) {
		offset_lo |= 0xFFFFF000;
	}

	unsigned new_binary = binary & ~IMM_MASK_LD;
	new_binary |= ((offset_lo & 0xFFF) << LD_IMM_SHIFT);

	return new_binary;
}

// RISC-V JAL instruction format (J-type):
// | imm[20|10:1|11|19:12] (20 bits) | rd (5 bits) | opcode (7 bits=1101111) |

#define OPCODE_JAL 0x0000006F
#define JAL_RD_MASK 0x00000F80
#define JAL_IMM_BITS 21
#define JAL_MAX_OFFSET 1048574	// +1MB-2
#define JAL_MIN_OFFSET -1048576 // -1MB

static bool is_jal_insn(unsigned binary)
{
	return (binary & 0x7F) == OPCODE_JAL;
}

static unsigned get_jal_addr(unsigned binary, unsigned offset)
{
	signed imm = 0;
	imm |= ((binary >> 31) & 0x1) << 20;
	imm |= ((binary >> 21) & 0x3FF) << 1;
	imm |= ((binary >> 20) & 0x1) << 11;
	imm |= ((binary >> 12) & 0xFF) << 12;
	imm = sign_extend_32(imm, JAL_IMM_BITS);

	return offset + imm;
}

static unsigned gen_jal_binary(unsigned obj_addr, unsigned insn_offset, unsigned binary)
{
	unsigned jal_insn = binary & JAL_RD_MASK;
	signed imm = obj_addr - insn_offset;

	if (imm < JAL_MIN_OFFSET || imm > JAL_MAX_OFFSET) {
		si_panic("Error: Offset %d out of range for JAL instruction\n", imm);
		return -1;
	}

	jal_insn |= OPCODE_JAL;
	jal_insn |= ((imm >> 20) & 0x1) << 31;
	jal_insn |= ((imm >> 1) & 0x3FF) << 21;
	jal_insn |= ((imm >> 11) & 0x1) << 20;
	jal_insn |= ((imm >> 12) & 0xFF) << 12;
	return jal_insn;
}

// RISC-V B-type instruction format (Branch):
// | imm[12|10:5] (7 bits) | rs2 (5) | rs1 (5) | funct3 (3) | imm[4:1|11] (5 bits) | opcode (7 bits=1100011)

#define OPCODE_BRANCH 0x63
#define BRANCH_FUNCT3_MASK 0x00007000
#define BRANCH_RS1_MASK 0x000F8000
#define BRANCH_RS2_MASK 0x01F00000
#define BRANCH_CORE_MASK (BRANCH_FUNCT3_MASK | BRANCH_RS1_MASK | BRANCH_RS2_MASK | OPCODE_BRANCH)
#define BRANCH_MAX_OFFSET 4094	// +4KB-2
#define BRANCH_MIN_OFFSET -4096 // -4KB

static bool is_branch_insn(unsigned binary)
{
	return (binary & 0x7F) == OPCODE_BRANCH;
}

static unsigned get_branch_addr(unsigned binary, unsigned offset)
{
	signed imm = 0;

	imm |= ((binary >> 31) & 0x1) << 12;
	imm |= ((binary >> 25) & 0x3F) << 5;
	imm |= ((binary >> 8) & 0xF) << 1;
	imm |= ((binary >> 7) & 0x1) << 11;

	// Inline sign-extend 13 bits
	if (imm & 0x1000) {
		imm |= 0xFFFFE000;
	}

	return offset + imm;
}

static unsigned gen_branch_binary(unsigned obj_addr, unsigned insn_offset, unsigned binary)
{
	if (!is_branch_insn(binary)) {
		si_panic("Error: Not a branch instruction (opcode=0x%x)\n", binary & OPCODE_MASK);
		return -1;
	}

	unsigned new_insn = binary & BRANCH_CORE_MASK; // preserve funct3, rs1, rs2
	signed imm = obj_addr - insn_offset;

	if (imm < BRANCH_MIN_OFFSET || imm > BRANCH_MAX_OFFSET) {
		si_panic("Error: Offset %d out of range for BRANCH instruction\n", imm);
		return -1;
	}

	new_insn |= ((imm >> 12) & 0x1) << 31;
	new_insn |= ((imm >> 5) & 0x3F) << 25;
	new_insn |= ((imm >> 1) & 0xF) << 8;
	new_insn |= ((imm >> 11) & 0x1) << 7;

	return new_insn;
}

// Mirrors AArch64 structure (unused but retained)
int init_insn_table(void)
{
	return 0;
}

/* Temporary implementation for RISC-V porting compatibility
 * (ARM version under development) */
int modify_text_section(elf_link_t *elf_link)
{
	(void)elf_link;
	return 0;
}

// Mirrors AArch64 structure (unused but retained)
int modify_by_rela_dyn(elf_link_t *elf_link, elf_file_t *ef, Elf64_Shdr *dyn_sec, Elf64_Shdr *sec)
{
	(void)elf_link;
	(void)ef;
	(void)dyn_sec;
	(void)sec;
	return 0;
}

// Mirrors AArch64 structure (unused but retained)
void modify_data_section(elf_link_t *elf_link)
{
	(void)elf_link;
	return;
}

static void modify_add_sub_data(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	//   Offset          Info           Type           Sym. Value    Sym. Name + Addend
	// 000000000730  002300000023 R_RISCV_ADD32     0000000000000622 .L0  + 0
	// 000000000730  002200000027 R_RISCV_SUB32     0000000000000600 .L0  + 0

	Elf64_Rela *next_rela = NULL;
	Elf64_Sym *next_sym = NULL;
	if (ELF64_R_TYPE(rela->r_info) == R_RISCV_ADD32) {
		next_rela = rela + 1;
		if (ELF64_R_TYPE(next_rela->r_info) != R_RISCV_SUB32) {
			si_panic("Error: R_RISCV_ADD32 not followed by R_RISCV_SUB32. Type =  %lx\n", (next_rela->r_info));
			return;
		}
	}

	unsigned long old_add_offset = 0, old_sub_offset = 0, new_offset = 0;
	unsigned old_data = 0, new_data = 0, old_add_value = 0, old_sub_value = 0, new_add_value = 0, new_sub_value = 0;
	elf_file_t *out_ef = &elf_link->out_ef;
	old_add_offset = rela->r_offset;
	old_sub_offset = next_rela->r_offset;
	if (old_add_offset != old_sub_offset) {
		si_panic("Error: R_RISCV_ADD32 and R_RISCV_SUB32 offsets do not match (%lx vs %lx)\n",
			 old_add_offset, old_sub_offset);
		return;
	}

	old_data = elf_read_u32_va(ef, old_add_offset);
	next_sym = elf_get_symtab_by_rela(ef, next_rela);
	old_add_value = sym->st_value + rela->r_addend;
	old_sub_value = next_sym->st_value + next_rela->r_addend;
	if (old_data != (old_add_value - old_sub_value)) {
		si_panic("Error: Data at %lx (0x%x) does not match expected ADD32-SUB32 result (0x%lx - 0x%lx)\n",
			 old_add_offset, old_data, old_add_value, old_sub_value);
		return;
	}

	new_offset = get_new_addr_by_old_addr(elf_link, ef, old_add_offset);
	new_add_value = get_new_addr_by_old_addr(elf_link, ef, old_add_value);
	new_sub_value = get_new_addr_by_old_addr(elf_link, ef, old_sub_value);
	new_data = new_add_value - new_sub_value;
	elf_write_u32(out_ef, new_offset, new_data);
	SI_LOG_DEBUG("R_RISCV_ADD32/SUB32 modify from 0x%lx to 0x%lx at offset %lx\n", old_data, new_data, new_offset);
}

static void modify_rvc_branch_insn(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	//   Offset          Info           Type           Sym. Value    Sym. Name + Addend
	// 00000000064a  00300000002c R_RISCV_RVC_BRANC 000000000000064e .L1 + 0
	// 00000000068e  00370000002c R_RISCV_RVC_BRANC 000000000000069a .L15 + 0

	// 64a:	c391                	beqz	a5,64e <.L1>
	// 68e:	e791                	bnez	a5,69a <.L15>

	unsigned long old_offset = 0, old_addr = 0, new_offset = 0, new_addr = 0;
	unsigned short old_insn = 0, new_insn = 0;
	elf_file_t *out_ef = &elf_link->out_ef;

	old_offset = rela->r_offset;
	old_insn = elf_read_u16_va(ef, old_offset);
	if (!is_cbeqz_insn(old_insn) && !is_cbnez_insn(old_insn)) {
		si_panic("Error: Expected compressed C.BEQZ / C.BNEZ instruction at %lx, found 0x%x\n", old_offset, old_insn);
		return;
	}
	old_addr = get_cb_addr(old_insn, old_offset);
	new_addr = get_new_addr_by_old_addr(elf_link, ef, old_addr);
	new_offset = get_new_addr_by_old_addr(elf_link, ef, old_offset);
	new_insn = gen_cb_binary(new_addr, new_offset, old_insn);
	elf_write_u16(out_ef, new_offset, new_insn);
	SI_LOG_DEBUG("R_RISCV_RVC_BRANCH modify the address %lx\n", new_addr);

	(void)sym;
	return;
}

static void modify_branch_insn(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	//   Offset          Info           Type           Sym. Value    Sym. Name + Addend
	// 00000000063e  003000000010 R_RISCV_BRANCH    000000000000064e .L1 + 0

	//  63e:	00a78863          	beq	a5,a0,64e <.L1>

	unsigned long old_offset = 0, old_addr = 0, new_offset = 0, new_addr = 0;
	unsigned old_insn = 0, new_insn = 0;
	elf_file_t *out_ef = &elf_link->out_ef;

	old_offset = rela->r_offset;
	old_insn = elf_read_u32_va(ef, old_offset);
	if (!is_branch_insn(old_insn)) {
		si_panic("Error: Expected branch instruction at %lx, found 0x%x\n", old_offset, old_insn);
		return;
	}
	old_addr = get_branch_addr(old_insn, old_offset);
	new_addr = get_new_addr_by_old_addr(elf_link, ef, old_addr);
	new_offset = get_new_addr_by_old_addr(elf_link, ef, old_offset);
	new_insn = gen_branch_binary(new_addr, new_offset, old_insn);
	elf_write_u32(out_ef, new_offset, new_insn);
	SI_LOG_DEBUG("R_RISCV_BRANCH modify the address %lx\n", new_addr);

	(void)sym;
}

// R_RISCV_PCREL_HI20 is always paired with R_RISCV_PCREL_LO12_I optionally separated by R_RISCV_RELAX.
static void modify_auipc_addiORld_insn(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	//   Offset          Info           Type           Sym. Value    Sym. Name + Addend
	// 000000000622  005400000017 R_RISCV_PCREL_HI2 0000000000002800 __global_pointer$ + 0
	// 000000000626  002100000018 R_RISCV_PCREL_LO1 0000000000000622 .L0  + 0

	// 0000000000000622 <load_gp>:
	// 622:	00002197          	auipc	gp,0x2
	// 626:	1de18193          	add	gp,gp,478 # 2800 <__global_pointer$>

	unsigned long old_auipc_offset = 0, old_second_offset = 0, old_addr = 0, new_addr = 0;
	unsigned long new_auipc_offset = 0, new_second_offset = 0;
	unsigned old_auipc_insn = 0, new_auipc_insn = 0, old_second_insn = 0, new_second_insn = 0;
	bool is_addi = false, is_ld = false;
	elf_file_t *out_ef = &elf_link->out_ef;

	old_auipc_offset = rela->r_offset;
	old_second_offset = old_auipc_offset + INST_LEN_BYTE;
	old_auipc_insn = elf_read_u32_va(ef, old_auipc_offset);
	old_second_insn = elf_read_u32_va(ef, old_second_offset);

	if (!is_auipc_insn(old_auipc_insn)) {
		si_panic("Error: Expected auipc  instruction at %lx, found 0x%x\n", old_auipc_offset, old_auipc_insn);
		return;
	} else if (is_addi_insn(old_second_insn)) {
		is_addi = true;
	} else if (is_ld_insn(old_second_insn)) {
		is_ld = true;
	} else {
		si_panic("Error: Expected addi or ld instruction at %lx, found 0x%x\n", old_second_offset, old_second_insn);
		return;
	}

	// If addend is zero: The symbol does not point to a valid address but is used as an optimization anchor.
	// Don't attempt direct address resolution; handle as a special case.
	// If addend is non-zero: The symbol points to a valid address and can be resolved normally.
	char *sym_name = elf_get_sym_name(ef, sym);
	if (elf_is_same_symbol_name("__global_pointer$", sym_name) && rela->r_addend == 0) {
		Elf64_Sym *new_sym = elf_find_symbol_by_name(out_ef, "__global_pointer$");
		new_addr = new_sym->st_value;
		SI_LOG_INFO("find __global_pointer offset by new_sym, new_offset = 0x%lx\n", new_sym->st_value);
	} else {
		old_addr = get_auipc_addr(old_auipc_insn, old_auipc_offset);
		if (is_addi) {
			old_addr += get_addi_addr(old_second_insn);
		} else if (is_ld) {
			old_addr += get_ld_addr(old_second_insn);
		}
		new_addr = get_new_addr_by_old_addr(elf_link, ef, old_addr);
	}

	new_auipc_offset = get_new_addr_by_old_addr(elf_link, ef, old_auipc_offset);
	new_second_offset = get_new_addr_by_old_addr(elf_link, ef, old_second_offset);
	if (new_second_offset - new_auipc_offset != INST_LEN_BYTE) {
		si_panic("Error: auipc and addi instruction not 4 bytes apart after relocation\n");
	}
	new_auipc_insn = gen_auipc_binary(new_addr, new_auipc_offset, old_auipc_insn);
	if (is_addi) {
		new_second_insn = gen_addi_binary(new_addr, new_auipc_offset, old_second_insn);
	} else if (is_ld) {
		new_second_insn = gen_ld_binary(new_addr, new_auipc_offset, old_second_insn);
	}

	elf_write_u32(out_ef, new_auipc_offset, new_auipc_insn);
	elf_write_u32(out_ef, new_second_offset, new_second_insn);

	SI_LOG_DEBUG("R_RISCV_PCREL_HI20 with R_RISCV_PCREL_LO12_I combine the address %lx\n", new_addr);
}

// R_RISCV_GOT_HI20 is always paired with R_RISCV_PCREL_LO12_I to load from the GOT.
// The address of the targeted GOT entry can only be retrieved from the instruction.
// I cannot find any other information that indicates the location of the GOT.
static void modify_got_ld_insn(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	//  Offset          Info           Type           Sym. Value    Sym. Name + Addend
	// 000000000606  005700000014 R_RISCV_GOT_HI20  00000000000006a4 main + 0
	// 00000000060a  002000000018 R_RISCV_PCREL_LO1 0000000000000606 .L0  + 0

	//  606:	00002517          	auipc	a0,0x2
	//  60a:	a4253503          	ld	a0,-1470(a0) # 2048 <_GLOBAL_OFFSET_TABLE_+0x18>
	unsigned long old_auipc_offset = 0, old_ld_offset = 0, old_addr = 0, new_addr = 0;
	unsigned long new_auipc_offset = 0, new_ld_offset = 0;
	unsigned old_auipc_insn = 0, new_auipc_insn = 0, old_ld_insn = 0, new_ld_insn = 0;
	elf_file_t *out_ef = &elf_link->out_ef;

	old_auipc_offset = rela->r_offset;
	old_ld_offset = old_auipc_offset + INST_LEN_BYTE;
	old_auipc_insn = elf_read_u32_va(ef, old_auipc_offset);
	old_ld_insn = elf_read_u32_va(ef, old_ld_offset);
	if (!is_ld_insn(old_ld_insn) || !is_auipc_insn(old_auipc_insn)) {
		si_panic("Error: Expected auipc and load instruction at %lx, found 0x%x and 0x%x\n",
			 old_auipc_offset, old_auipc_insn, old_ld_insn);
		return;
	}

	old_addr = get_auipc_addr(old_auipc_insn, old_auipc_offset);
	old_addr += get_ld_addr(old_ld_insn);

	new_addr = get_new_addr_by_old_addr(elf_link, ef, old_addr);
	new_auipc_offset = get_new_addr_by_old_addr(elf_link, ef, old_auipc_offset);
	new_ld_offset = get_new_addr_by_old_addr(elf_link, ef, old_ld_offset);
	if (new_ld_offset - new_auipc_offset != INST_LEN_BYTE) {
		si_panic("Error: auipc and load instruction not 4 bytes apart after relocation\n");
	}

	new_auipc_insn = gen_auipc_binary(new_addr, new_auipc_offset, old_auipc_insn);
	new_ld_insn = gen_ld_binary(new_addr, new_auipc_offset, old_ld_insn);

	elf_write_u32(out_ef, new_auipc_offset, new_auipc_insn);
	elf_write_u32(out_ef, new_ld_offset, new_ld_insn);

	SI_LOG_DEBUG("R_RISCV_GOT_HI20 ld at %lx\n", new_addr);

	(void)sym;
}

static void modify_rvc_j_insn(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	//   Offset          Info           Type           Sym. Value    Sym. Name + Addend
	// 0000000006a2  00280000002d R_RISCV_RVC_JUMP  0000000000000650 register_tm_clones + 0

	// 00000000000006a2 <frame_dummy>:
	//  6a2:	b77d                	j	650 <register_tm_clones>
	unsigned long old_offset = 0, old_addr = 0, new_offset = 0, new_addr = 0;
	unsigned short old_insn = 0, new_insn = 0;
	elf_file_t *out_ef = &elf_link->out_ef;

	old_offset = rela->r_offset;
	old_insn = elf_read_u16_va(ef, old_offset);
	if (!is_compressed_instruction(old_insn) || !is_cj_insn(old_insn)) {
		si_panic("Error: Expected compressed C.J instruction at %lx, found 0x%x\n", old_offset, old_insn);
		return;
	}
	old_addr = get_cj_addr(old_insn, old_offset);
	new_addr = get_new_addr_by_old_addr(elf_link, ef, old_addr);
	new_offset = get_new_addr_by_old_addr(elf_link, ef, old_offset);
	new_insn = gen_cj_binary(new_addr, new_offset, old_insn);
	elf_write_u16(out_ef, new_offset, new_insn);
	SI_LOG_DEBUG("R_RISCV_RVC_JUMP modify the address %lx\n", new_addr);

	(void)sym;
	return;
}

static void modify_jal_insn(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela, Elf64_Sym *sym)
{
	// 000000000600  001f00000011 R_RISCV_JAL       0000000000000622 load_gp + 0

	// 0000000000000600 <_start>:
	// 600:	022000ef          	jal	622 <load_gp>
	unsigned long old_insn = 0, old_sym_addr = 0, old_offset = 0;
	unsigned long new_insn = 0, new_sym_addr = 0, new_offset = 0;
	elf_file_t *out_ef = &elf_link->out_ef;

	old_offset = rela->r_offset;
	old_insn = elf_read_u32_va(ef, old_offset);
	if (!is_jal_insn(old_insn)) {
		si_panic("Error: Expected JAL instruction at %lx, found 0x%x\n", old_offset, old_insn);
		return;
	}

	if (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
		si_panic("TODO:RISCV STT_GNU_IFUNC modify_jal_insn\n");
		return;
	}

	char *name = elf_get_sym_name(ef, sym);
	if (unlikely(elf_is_same_symbol_name(name, "main"))) {
		elf_file_t *main_ef = get_main_ef(elf_link);
		old_sym_addr = elf_find_symbol_addr_by_name(main_ef, "main");
		new_sym_addr = get_new_addr_by_old_addr(elf_link, main_ef, old_sym_addr);
		goto out;
	}

	// get old addr from insn
	if (!new_sym_addr) {
		old_sym_addr = get_jal_addr(old_insn, old_offset);
		new_sym_addr = get_new_addr_by_old_addr(elf_link, ef, old_sym_addr);
	}

out:
	new_offset = get_new_addr_by_old_addr(elf_link, ef, old_offset);
	new_insn = gen_jal_binary(new_sym_addr, new_offset, old_insn);
	elf_write_u32(out_ef, new_offset, new_insn);
	SI_LOG_DEBUG("R_RISCV_JAL modify the address %lx\n", new_sym_addr);
}

int modify_local_call_rela(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela)
{
	Elf64_Sym *sym = NULL;
	unsigned long old_addr = 0, new_addr = 0, binary;
	unsigned long old_offset = rela->r_offset;
	unsigned long new_offset = get_new_addr_by_old_addr(elf_link, ef, old_offset);
	elf_file_t *out_ef = &elf_link->out_ef;
	int r_type = ELF64_R_TYPE(rela->r_info);

	sym = elf_get_symtab_by_rela(ef, rela);

	switch (r_type) {
	case R_RISCV_NONE:
		// No relocation needed
		break;
	case R_RISCV_32_PCREL:
		// S + A - P
		// sym.value + added = offset + (PC-relative 32-bit)
		old_addr = sym->st_value + rela->r_addend;
		new_addr = get_new_addr_by_old_addr(elf_link, ef, old_addr);
		// negative number less than 32 bit
		binary = new_addr - new_offset;
		elf_write_u32(out_ef, new_offset, binary);
		break;
	case R_RISCV_64:
		// S + A
		old_addr = sym->st_value + rela->r_addend;
		new_addr = get_new_addr_by_old_addr(elf_link, ef, old_addr);
		if (new_addr == -1UL) {
			si_panic("R_RISCV_64: addr is missing\n");
			return -1;
		}
		SI_LOG_DEBUG("change offset %lx->%lx content %lx->%lx\n", old_offset, new_offset, old_addr, new_addr);
		elf_write_u64(out_ef, new_offset, new_addr);
		break;
	case R_RISCV_JAL:
		// S + A - P
		modify_jal_insn(elf_link, ef, rela, sym);
		break;
	case R_RISCV_RVC_JUMP:
		// S + A - P
		modify_rvc_j_insn(elf_link, ef, rela, sym);
		break;
	case R_RISCV_GOT_HI20:
		// G + GOT + A - P
		modify_got_ld_insn(elf_link, ef, rela, sym);
		return SKIP_ONE_RELA; // skip R_RISCV_PCREL_LO12_I, although sometime the next entry is R_RISCV_RELAX
	case R_RISCV_PCREL_LO12_I:
		// The entry has been modified by the R_RISCV_PCREL_HI20 or R_RISCV_GOT_HI20 relocation.
		break;
	case R_RISCV_RELAX:
		// Nothing to do with R_RISCV_RELAX
		break;
	case R_RISCV_PCREL_HI20:
		// S + A - P
		modify_auipc_addiORld_insn(elf_link, ef, rela, sym);
		return SKIP_ONE_RELA; // skip R_RISCV_PCREL_LO12_I, although sometime the next entry is R_RISCV_RELAX
	case R_RISCV_BRANCH:
		// S + A - P
		modify_branch_insn(elf_link, ef, rela, sym);
		break;
	case R_RISCV_RVC_BRANCH:
		// S + A - P
		modify_rvc_branch_insn(elf_link, ef, rela, sym);
		break;
	case R_RISCV_ADD32:
		// V + S + A
		modify_add_sub_data(elf_link, ef, rela, sym);
		return SKIP_ONE_RELA; // skip the paired R_RISCV_SUB32
	case R_RISCV_SUB32:
		// V - S - A
		si_panic("R_RISCV_SUB32 should be handled with the paired R_RISCV_ADD32\n");
		break;
	default:
		si_panic("Unsupported RISCV relocation type in modify_local_call_rela: %d\n", r_type);
		return 0;
	}
	return 0;
}

// first entry is different from other entrys
void modify_plt_jump(elf_link_t *elf_link, elf_file_t *ef, unsigned long old_offset, bool is_first_entry)
{
	// The first entry of a shared object PLT is a special entry that calls
	//  _dl_runtime_resolve to resolve the GOT offset for the called function.
	// 0000000000031cc0 <faccessat@plt-0x20>:
	//    31cc0:	000d6397          	auipc	t2,0xd6
	//    31cc4:	41c30333          	sub	t1,t1,t3
	//    31cc8:	6d83be03          	ld	t3,1752(t2) # 108398 <__TMC_END__>
	//    31ccc:	fd430313          	add	t1,t1,-44
	//    31cd0:	6d838293          	add	t0,t2,1752
	//    31cd4:	00135313          	srl	t1,t1,0x1
	//    31cd8:	0082b283          	ld	t0,8(t0)
	//    31cdc:	000e0067          	jr	t3

	// 0000000000031ce0 <faccessat@plt>:
	//    31ce0:	000d6e17          	auipc	t3,0xd6
	//    31ce4:	6c8e3e03          	ld	t3,1736(t3) # 1083a8 <faccessat@GLIBC_2.27>
	//    31ce8:	000e0367          	jalr	t1,t3
	//    31cec:	00000013          	nop

	unsigned long old_addr, new_addr, new_offset;
	unsigned old_auipc_insn, old_ld_insn, new_auipc_insn, new_ld_insn;
	elf_file_t *out_ef = &elf_link->out_ef;
	old_auipc_insn = elf_read_u32_va(ef, old_offset);
	old_addr = get_auipc_addr(old_auipc_insn, old_offset);
	if (is_first_entry) {
		// first entry has more instructions
		old_ld_insn = elf_read_u32_va(ef, old_offset + INST_LEN_BYTE * TWO_INST);
	} else {
		old_ld_insn = elf_read_u32_va(ef, old_offset + INST_LEN_BYTE);
	}
	old_addr += get_ld_addr(old_ld_insn);

	new_addr = get_new_addr_by_old_addr(elf_link, ef, old_addr);
	new_offset = get_new_addr_by_old_addr(elf_link, ef, old_offset);
	if (new_addr > MAX_PLT_ADDR) {
		SI_LOG_ERR("modify_plt_jump addr overflow: offset %lx->%lx value %lx->%lx\n",
			   old_offset, new_offset, old_addr, new_addr);
		return;
	}
	if (new_addr == NOT_FOUND || new_offset == NOT_FOUND) {
		si_panic("modify_plt_jump NOT_FOUND: offset %lx->%lx value %lx->%lx\n", old_offset, new_offset, old_addr, new_addr);
		return;
	}
	new_auipc_insn = gen_auipc_binary(new_addr, new_offset, old_auipc_insn);
	new_ld_insn = gen_ld_binary(new_addr, new_offset, old_ld_insn);
	elf_write_u32(out_ef, new_offset, new_auipc_insn);
	if (is_first_entry) {
		elf_write_u32(out_ef, new_offset + INST_LEN_BYTE * TWO_INST, new_ld_insn);
	} else {
		elf_write_u32(out_ef, new_offset + INST_LEN_BYTE, new_ld_insn);
	}

	SI_LOG_DEBUG("modify_plt_jump addr %lx->%lx at offset %lx\n", old_addr, new_addr, new_offset);
}

#define INST_EXTENT_FOUR_TIMES 4
#define INST_EXTENT_EIGHT_TIMES 8
static void modify_plt_section(elf_link_t *elf_link, elf_file_t *ef, unsigned long old_offset)
{
	Elf64_Shdr *old_rela_plt_sec = elf_find_section_by_name(ef, ".rela.plt");
	Elf64_Rela *old_rela_entry = (Elf64_Rela *)((char *)ef->hdr + old_rela_plt_sec->sh_offset);
	int count = old_rela_plt_sec->sh_size / old_rela_plt_sec->sh_entsize;

	// modify first .plt stub
	modify_plt_jump(elf_link, ef, old_offset, true);
	old_offset += INST_LEN_BYTE * INST_EXTENT_EIGHT_TIMES;
	// modify func@plt stubs
	for (int i = 0; i < count; ++i, ++old_rela_entry) {
		switch (ELF64_R_TYPE(old_rela_entry->r_info)) {
		case R_RISCV_JUMP_SLOT:
			modify_plt_jump(elf_link, ef, old_offset, false);
			old_offset += INST_LEN_BYTE * INST_EXTENT_FOUR_TIMES;
			break;
		default:
			si_panic("unsupported plt entry, %ld\n", ELF64_R_TYPE(old_rela_entry->r_info));
			break;
		}
	}
}

// 处理.rela.plt重定位 and .plt
void modify_rela_plt(elf_link_t *elf_link, si_array_t *arr)
{
	int len = arr->len;
	elf_obj_mapping_t *obj_rels = arr->data;

	SI_LOG_DEBUG("modify_rela_plt: \n");

	for (int i = 0; i < len; i++) {
		elf_obj_mapping_t *obj_rel = &obj_rels[i];
		Elf64_Rela *src_rela = obj_rel->src_obj;
		Elf64_Rela *dst_rela = obj_rel->dst_obj;
		int type = ELF64_R_TYPE(src_rela->r_info);
		int new_index = 0;

		if (is_share_mode(elf_link)) {
			unsigned old_index = ELF64_R_SYM(src_rela->r_info);
			new_index = get_new_sym_index(elf_link, obj_rel->src_ef, old_index);
		}
		if (new_index == NEED_CLEAR_RELA) {
			memset(dst_rela, 0, sizeof(Elf64_Rela));
			continue;
		}

		dst_rela->r_info = ELF64_R_INFO(new_index, type);
		dst_rela->r_offset = get_new_addr_by_old_addr(elf_link, obj_rel->src_ef, src_rela->r_offset);

		switch (type) {
		case R_RISCV_JUMP_SLOT:
			// 0000001083a8  000200000005 R_RISCV_JUMP_SLOT 0000000000000000 faccessat@GLIBC_2.27 + 0
			if (src_rela->r_addend != 0) {
				si_panic("R_RISCV_JUMP_SLOT addend is not zero: %ld\n", src_rela->r_addend);
			}
			break;
		default:
			si_panic("Unsupported RISCV plt relocation type: %d\n", type);
			break;
		}
	}

	SI_LOG_DEBUG("modify_plt: \n");
	Elf64_Shdr *old_plt;
	elf_file_t *in_ef;
	unsigned long old_offset;
	for (int i = 0; i < (int)elf_link->in_ef_nr; ++i) {
		in_ef = &elf_link->in_efs[i];
		old_plt = elf_find_section_by_name(in_ef, ".plt");
		old_offset = old_plt->sh_addr;
		modify_plt_section(elf_link, in_ef, old_offset);
	}
}

void modify_plt_got(elf_link_t *elf_link)
{
	// Note: In RISC-V, dynamic linking is implemented through .got and .plt,
	// while .plt.got section is generally not utilized.
	(void)elf_link;
}

void modify_rela_item(elf_link_t *elf_link, elf_file_t *src_ef, Elf64_Rela *src_rela, Elf64_Rela *dst_rela)
{
	// modify r_offset and index
	dst_rela->r_offset = get_new_addr_by_old_addr(elf_link, src_ef, src_rela->r_offset);
	unsigned int old_index = ELF64_R_SYM(src_rela->r_info);
	Elf64_Sym *old_syms = elf_get_symtab_array(src_ef);
	Elf64_Sym *old_sym = &old_syms[old_index];
	const char *name = elf_get_sym_name(src_ef, old_sym);
	// NOTE: Adaptation for .rela.text symbols with duplicate names is necessary, even though they are unused.
	unsigned int new_index = elf_find_symbol_index_by_name(&elf_link->out_ef, name);
	dst_rela->r_info = ELF64_R_INFO(new_index, ELF64_R_TYPE(src_rela->r_info));
	int type = ELF64_R_TYPE(src_rela->r_info);
	Elf64_Sym *new_syms = elf_get_symtab_array(&elf_link->out_ef);
	Elf64_Sym *new_sym = &new_syms[new_index];
	unsigned long old_addr, new_addr;

	switch (type) {
	// No relocation needed
	case R_RISCV_NONE:
		return;
	// S + A - P
	case R_RISCV_32_PCREL:
	case R_RISCV_JAL:
	case R_RISCV_PCREL_HI20:
	case R_RISCV_BRANCH:
	case R_RISCV_RVC_BRANCH:
	case R_RISCV_RVC_JUMP:
	// G + GOT + A - P
	case R_RISCV_GOT_HI20:
	// S - P
	case R_RISCV_PCREL_LO12_I:
	// -
	case R_RISCV_RELAX:
	// S + A
	case R_RISCV_64:
	// V - S - A
	case R_RISCV_SUB32:
	// V + S + A
	case R_RISCV_ADD32:
		// If addend is zero: The symbol does not point to a valid address but is used as an optimization anchor.
		// Don't attempt direct address resolution; handle as a special case.
		// If addend is non-zero: The symbol points to a valid address and can be resolved normally.
		if (elf_is_same_symbol_name("__global_pointer$", name) && src_rela->r_addend == 0) {
			SI_LOG_INFO("meet __global_pointer$ symbol, skip modify_rela_item\n");
			break;
		}

		old_addr = old_sym->st_value + src_rela->r_addend;
		new_addr = get_new_addr_by_old_addr(elf_link, src_ef, old_addr);
		if (new_addr == NOT_FOUND) {
			si_panic("modify_rela_item: addr is missing\n");
		}

		dst_rela->r_addend = new_addr - new_sym->st_value;
		SI_LOG_DEBUG("type %d change offset %lx->%lx content %lx->%lx addend %d -> %d\n", type, src_rela->r_offset,
			     dst_rela->r_offset, old_addr, new_addr, src_rela->r_addend, dst_rela->r_addend);
		return;

	default:
		si_panic("Unsupported RISCV relocation type in modify_rela_item: %d\n", type);
		break;
	}
}
