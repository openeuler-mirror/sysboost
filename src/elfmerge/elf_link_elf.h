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

#ifndef _LINK_ELF_H
#define _LINK_ELF_H

#include "elf_link_common.h"
#include "elf_read_elf.h"
#include <si_array.h>
#include <si_common.h>

elf_link_t *elf_link_new(void);
char *elf_link_mode_str(unsigned int mode);
int elf_link_set_mode(elf_link_t *elf_link, unsigned int mode);
elf_file_t *elf_link_add_infile(elf_link_t *elf_link, char *path);
int elf_link_write(elf_link_t *elf_link);

#endif /* _LINK_ELF_H */
