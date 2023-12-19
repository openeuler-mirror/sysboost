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

#ifndef _ELF_RELOCATION_H
#define _ELF_RELOCATION_H

#include "elf_link_common.h"

int init_insn_table(void);

void modify_rela_dyn(elf_link_t *elf_link);
void modify_got(elf_link_t *elf_link);
void modify_local_call(elf_link_t *elf_link);

int modify_local_call_rela(elf_link_t *elf_link, elf_file_t *ef, Elf64_Rela *rela);
void modify_rela_plt(elf_link_t *elf_link, si_array_t *arr);
void modify_plt_got(elf_link_t *elf_link);
void correct_stop_libc_atexit(elf_link_t *elf_link);

#endif /* _ELF_RELOCATION_H */
