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

#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <si_debug.h>
#include <si_log.h>

#include "elf_hugepage.h"
#include "elf_link_common.h"
#include "elf_ext.h"

int elf_set_symbolic_link(char *path, bool state)
{
	int fd_dev, fd_elf, ret = 0;
	unsigned int cmd, nr = 0;

	fd_dev = open("/dev/sysboost_loader", 0);
	if (fd_dev == -1) {
		SI_LOG_ERR("open sysboost_loader device fail\n");
		return -1;
	}
	fd_elf = open(path, 0);
	if (fd_elf == -1) {
		SI_LOG_ERR("open %s fail\n", path);
		ret = -1;
		goto error_elf;
	}

	if (state)
		nr |= RTO_LOAD_FLAG_LOAD | RTO_LOAD_FLAG_PRELOAD;

	cmd = _IO(0, nr);

	ret = ioctl(fd_dev, cmd, fd_elf);
	if (ret) {
		SI_LOG_ERR("ioctl error\n");
	}

	close(fd_elf);
error_elf:
	close(fd_dev);
	return ret;
}

static int _elf_write_read_flags(char *path, unsigned int *flags, bool set)
{
	bool is_readonly = !*flags;
	elf_file_t *ef = malloc(sizeof(elf_file_t));
	if (ef == NULL) {
		SI_LOG_ERR("malloc fail\n");
		return -12;
	}

	int ret = elf_read_file(path, ef, is_readonly);
	if (ret != 0) {
		return ret;
	}

	if (!is_readonly) {
		if (set)
			ef->hdr->e_flags |= *flags;
		else
			ef->hdr->e_flags &= (0xffffffffU ^ *flags);
	}
	*flags = ef->hdr->e_flags;

	elf_close_file(ef);
	free(ef);
	ef = NULL;
	return 0;
}

static int _elf_set_flags(char *path, unsigned int flags)
{
	if (!flags)
		return -22;
	return _elf_write_read_flags(path, &flags, true);
}

static int _elf_unset_flags(char *path, unsigned int flags)
{
	if (!flags)
		return -22;
	return _elf_write_read_flags(path, &flags, false);
}

/*
 * return 1 means flags are set, 0 means flags are *not all* set;
 *          negative means error.
*/
static int _elf_test_flags(char *path, unsigned int flags)
{
	unsigned int all_flags = 0;
	int ret;
	ret = _elf_write_read_flags(path, &all_flags, 0);
	if (ret)
		return ret;

	return ((all_flags & flags) == flags);
}

int elf_set_rto(char *path, bool state)
{
	if (state) {
		return _elf_set_flags(path, OS_SPECIFIC_FLAG_RTO);
	}
	return _elf_unset_flags(path, OS_SPECIFIC_FLAG_RTO);
}

int elf_get_rto(char *path)
{
	int ret = _elf_test_flags(path, OS_SPECIFIC_FLAG_RTO);
	if (ret < 0)
		return ret;
	
	if (ret)
		SI_LOG_INFO("%s FLAG RTO is set\n", path);
	else
		SI_LOG_INFO("%s FLAG RTO is not set\n", path);
	return 0;
}

void elf_set_hugepage(elf_link_t *elf_link)
{
	int i, exec_only = 1;
	elf_file_t *ef = get_out_ef(elf_link);
	int count = ef->hdr->e_phnum;
	Elf64_Phdr *phdr = (Elf64_Phdr *)ef->hdr_Phdr;

	for (i = 0; i < count; i++) {
		if (phdr[i].p_type != PT_LOAD) {
			continue;
		}
		if (exec_only && !(phdr[i].p_flags & PF_X)) {
			continue;
		}
		phdr[i].p_flags |= PF_HUGEPAGE;
	}

	ef->hdr->e_flags |= OS_SPECIFIC_FLAG_HUGEPAGE;
	if (is_direct_vdso_optimize(elf_link)) {
		ef->hdr->e_flags |= OS_SPECIFIC_FLAG_RTO;
	}
}
