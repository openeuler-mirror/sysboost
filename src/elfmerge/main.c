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
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <si_debug.h>
#include <si_log.h>

#include "elf_hugepage.h"
#include "elf_link_common.h"
#include "elf_link_elf.h"
#include "elf_read_elf.h"
#include "elf_relocation.h"

int main(int argc, char *argv[])
{
	int ret = 0;
	char tmp[PATH_MAX];
	elf_link_t *elf_link = elf_link_new();
	char *str_ret;
	bool debug = false;
	enum RtoMode mode = ELF_LINK_SHARE;

	if (elf_link == NULL) {
		SI_LOG_ERR("no memory\n");
		return -1;
	}

	static struct option long_options[] = {
		{"output", 			required_argument, 	NULL, 	'o'},
		{"debug", 			no_argument, 		NULL, 	'd'},
		{"set", 			required_argument, 	NULL, 	's'},
		{"unset", 			required_argument, 	NULL, 	'u'},
		{"get", 			required_argument, 	NULL, 	'g'},
		{"set-rto", 			required_argument, 	NULL, 	'1'},
		{"unset-rto", 			required_argument, 	NULL, 	'0'},
		{"get-rto", 			required_argument, 	NULL, 	'2'},
		{"hook", 			no_argument, 		NULL, 	'h'},
		{ELF_LINK_STATIC_S, 		no_argument, 		NULL, 	'S'},
		{ELF_LINK_STATIC_NOLIBC_S, 	no_argument, 		NULL, 	'N'},
		{ELF_LINK_STATIC_NOLD_S, 	no_argument, 		NULL, 	'I'},
		{NULL, 				0, 			NULL, 	0}
	};

	int option_index = 0;
	int c;
	while ((c = getopt_long(argc, argv, "ds:u:hSNI", long_options, &option_index)) != -1) {
		switch (c) {
		case 'o':
			elf_link->out_ef.file_name = optarg;
			break;
		case 'd':
			debug = true;
			break;
		case 's':
			str_ret = realpath(optarg, tmp);
			if (!str_ret) {
				SI_LOG_ERR("get realpath fail: %s\n", optarg);
				return -1;
			}
			return elf_set_symbolic_link(tmp, true);
		case 'u':
			str_ret = realpath(optarg, tmp);
			if (!str_ret) {
				SI_LOG_ERR("get realpath fail: %s\n", optarg);
				return -1;
			}
			return elf_set_symbolic_link(tmp, false);
		case 'g':
			SI_LOG_ERR("not supported now, fix me\n");
			return -1;
		case '1':
			str_ret = realpath(optarg, tmp);
			if (!str_ret) {
				SI_LOG_ERR("get realpath fail: %s\n", optarg);
				return -1;
			}
			return elf_set_rto(tmp, true);
		case '0':
			str_ret = realpath(optarg, tmp);
			if (!str_ret) {
				SI_LOG_ERR("get realpath fail: %s\n", optarg);
				return -1;
			}
			return elf_set_rto(tmp, false);
		case '2':
			str_ret = realpath(optarg, tmp);
			if (!str_ret) {
				SI_LOG_ERR("get realpath fail: %s\n", optarg);
				return -1;
			}
			return elf_get_rto(tmp);
		case 'h':
			elf_link->hook_func = true;
			SI_LOG_INFO("hook func\n");
			break;
		case 'S':
			mode = ELF_LINK_STATIC;
			break;
		case 'N':
			mode = ELF_LINK_STATIC_NOLIBC;
			break;
		case 'I':
			mode = ELF_LINK_STATIC_NOLD;
			break;
		default:
			return -1;
		}
	}

	if (debug) {
		si_log_set_global_level(SI_LOG_LEVEL_DEBUG);
	} else {
		si_log_set_global_level(SI_LOG_LEVEL_INFO);
	}

	ret = init_insn_table();
	if (ret < 0) {
		return -1;
	}

	ret = elf_link_set_mode(elf_link, mode);
	if (ret < 0) {
		return -1;
	}
	SI_LOG_INFO("%s mode\n", elf_link_mode_str(mode));

	for (int i = optind; i < argc; i++) {
		if (*argv[i] == '0') {
			continue;
		}
		str_ret = realpath(argv[i], tmp);
		if (!str_ret) {
			SI_LOG_ERR("get realpath fail: %s\n", argv[i]);
			return -1;
		}
		elf_file_t *ef = elf_link_add_infile(elf_link, tmp);
		if (ef == NULL) {
			SI_LOG_ERR("add link file fail: %s\n", tmp);
			return -1;
		}
	}

	ret = elf_link_write(elf_link);
	if (ret < 0) {
		return -1;
	}
        free(elf_link);
	SI_LOG_INFO("OK\n");
	return 0;
}
