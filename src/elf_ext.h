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

#ifndef _ELF_EXT_H
#define _ELF_EXT_H

#ifndef PAGE_SHIFT
#define PAGE_SHIFT              12
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE               (1UL << PAGE_SHIFT)
#endif

#ifndef PF_HUGEPAGE
#define PF_HUGEPAGE (0x01000000)
#endif

#ifndef EF_AARCH64_SYMBOLIC_LINK
#define EF_AARCH64_SYMBOLIC_LINK (0x00010000U)
#endif

#ifndef EF_AARCH64_HUGEPAGE
#define EF_AARCH64_HUGEPAGE (0x00020000U)
#endif

#ifndef EF_AARCH64_RTO
#define EF_AARCH64_RTO (0x00040000U)
#endif

#ifndef EF_X86_64_SYMBOLIC_LINK
#define EF_X86_64_SYMBOLIC_LINK    (0x00010000U)
#endif

#ifndef EF_X86_64_HUGEPAGE
#define EF_X86_64_HUGEPAGE         (0x00020000U)
#endif

#ifndef EF_X86_64_RTO
#define EF_X86_64_RTO              (0x00040000U)
#endif

#ifdef __aarch64__
#define OS_SPECIFIC_FLAG_SYMBOLIC_LINK EF_AARCH64_SYMBOLIC_LINK
#define OS_SPECIFIC_FLAG_HUGEPAGE EF_AARCH64_HUGEPAGE
#define OS_SPECIFIC_FLAG_RTO EF_AARCH64_RTO

#define ELF_VDSO_LEN (1 * PAGE_SIZE)
// VVAR_NR_PAGES * PAGE_SIZE
#define ELF_VVAR_LEN (2 * PAGE_SIZE)

#else
#define OS_SPECIFIC_FLAG_SYMBOLIC_LINK EF_X86_64_SYMBOLIC_LINK
#define OS_SPECIFIC_FLAG_HUGEPAGE EF_X86_64_HUGEPAGE
#define OS_SPECIFIC_FLAG_RTO EF_X86_64_RTO

#define ELF_VDSO_LEN (2 * PAGE_SIZE)
// -vvar_start
#define ELF_VVAR_LEN (4 * PAGE_SIZE)

#endif

#define OS_SPECIFIC_MASK (0xffffffffU ^ OS_SPECIFIC_FLAG_SYMBOLIC_LINK ^ OS_SPECIFIC_FLAG_HUGEPAGE ^ OS_SPECIFIC_FLAG_RTO)

#define ELF_VVAR_AND_VDSO_LEN (ELF_VVAR_LEN + ELF_VDSO_LEN)

// ELF not define max len, but sometime we need
#define ELF_MAX_SYMBOL_NAME_LEN (128)

#endif /* _ELF_EXT_H */
