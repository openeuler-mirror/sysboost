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


#ifndef _ELF_HUGEPAGE_H
#define _ELF_HUGEPAGE_H

#include "elf_link_common.h"

void elf_set_hugepage(elf_link_t *elf_link);
int elf_set_symbolic_link(char *path, bool state);
int elf_set_rto(char *path, bool state);

#endif /* _ELF_HUGEPAGE_H */
