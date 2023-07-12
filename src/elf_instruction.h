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

#ifndef _ELF_INSTRUCTION_H
#define _ELF_INSTRUCTION_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <si_array.h>
#include <si_common.h>
#include <si_debug.h>

#include "elf_read_elf.h"

// op op op imm(4Byte)
#define ELF_INSN_OP_LEN (3)

bool elf_insn_is_reg_addr_mov(unsigned char *insn);
bool is_tls_insn_imm_offset(unsigned char *insn);

unsigned char *elf_insn_offset_to_addr(elf_file_t *ef, unsigned long insn_begin);
void elf_insn_change_got_to_imm(unsigned char *insn);
int elf_insn_change_mov_to_lea(unsigned char *insn);

#endif /* _ELF_INSTRUCTION_H */
