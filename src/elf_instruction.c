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

#define ELF_INSN_OP0_INDEX (0)
#define ELF_INSN_OP1_INDEX (1)
#define ELF_INSN_OP2_INDEX (2)
#define ELF_INSN_REG_SHIFT (3)
#define TLS_INSN_REG_MASK (0x38U)
#define TLS_INSN_OP_MASK (0xf8U)
#define TLS_INSN_GOT_REG_OP (0x05U)
#define TLS_INSN_REG_OP (0xc0U)

static inline unsigned char get_reg_from_insn(unsigned char *insn)
{
	// Byte[2]  00 reg 101    rax=000 rbx=011
	return (insn[ELF_INSN_OP2_INDEX] & TLS_INSN_REG_MASK) >> ELF_INSN_REG_SHIFT;
}

static inline void set_reg_to_insn(unsigned char *insn, unsigned char reg)
{
	// Byte[2]  11 000 reg    rax=000 rbx=011
	insn[ELF_INSN_OP2_INDEX] = reg | TLS_INSN_REG_OP;
}

// 48 8b 05 c8 97 15 00 	mov    0x1597c8(%rip),%rax
// 48 8b 1d f3 65 15 00 	mov    0x1565f3(%rip),%rbx
// 48 8b 2d e4 a4 1b 00 	mov    0x1ba4e4(%rip),%rbp   rbp=101
// 4c 8b 2d a7 e2 1a 00 	mov    0x1ae2a7(%rip),%r13   r13=101  op 4c reg r8-r15
bool elf_insn_is_reg_addr_mov(unsigned char *insn)
{
	if ((insn[ELF_INSN_OP0_INDEX] != 0x48U) && (insn[ELF_INSN_OP0_INDEX] != 0x4cU)) {
		return false;
	}
	if (insn[ELF_INSN_OP1_INDEX] != 0x8bU) {
		return false;
	}
	// Byte[2]  00 reg 101    rax=000 rbx=011
	unsigned char tmp = insn[ELF_INSN_OP2_INDEX];
	tmp = tmp & (~TLS_INSN_REG_MASK);
	if (tmp == TLS_INSN_GOT_REG_OP) {
		return true;
	}
	return false;
}

// 48 c7 c0 88 ff ff ff 	mov    $0xffffffffffffff88,%rax
// 48 c7 c3 88 ff ff ff 	mov    $0xffffffffffffff88,%rbx
// 49 c7 c5 88 ff ff ff 	mov    $0xffffffffffffff88,%r13  op 49 reg r8-r15
bool is_tls_insn_imm_offset(unsigned char *insn)
{
	if ((insn[ELF_INSN_OP0_INDEX] != 0x48U) && (insn[ELF_INSN_OP0_INDEX] != 0x49U)) {
		return false;
	}
	if (insn[ELF_INSN_OP1_INDEX] != 0xc7U) {
		return false;
	}
	// Byte[2]  11 000 reg    rax=000 rbx=011
	unsigned char tmp = insn[ELF_INSN_OP2_INDEX];
	tmp = tmp & TLS_INSN_OP_MASK;
	if (tmp == TLS_INSN_REG_OP) {
		return true;
	}

	return false;
}

void elf_insn_change_got_to_imm(unsigned char *insn)
{
	if (insn[ELF_INSN_OP0_INDEX] == 0x48U) {
		// rax rbx OP0 is 0x48U
	} else {
		// reg r8-r15
		insn[ELF_INSN_OP0_INDEX] = 0x49U;
	}
	insn[ELF_INSN_OP1_INDEX] = 0xc7U;
	unsigned char reg = get_reg_from_insn(insn);
	set_reg_to_insn(insn, reg);
}

// 48 8b 3d ce 67 0e 00         mov    0xe67ce(%rip),%rdi
// 48 8d 3d ce 67 0e 00         lea    0xe67ce(%rip),%rdi    rdi=111
int elf_insn_change_mov_to_lea(unsigned char *insn)
{
	if (elf_insn_is_reg_addr_mov(insn) == false) {
		return -1;
	}
	// OP[1] 8d is lea
	insn[ELF_INSN_OP1_INDEX] = 0x8dU;

	return 0;
}

unsigned char *elf_insn_offset_to_addr(elf_file_t *ef, unsigned long insn_begin)
{
	return (unsigned char *)((void *)ef->hdr + insn_begin);
}
