// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
//
// sysMaster is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

#ifndef _ELF_CHECK_ELF_H
#define _ELF_CHECK_ELF_H

#include <stdbool.h>
#include <stdint.h>

#include "elf_link_common.h"
#include <si_common.h>

void elf_check_elf(elf_link_t *elf_link);

#endif /* _ELF_CHECK_ELF_H */
