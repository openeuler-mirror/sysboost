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

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
	char buf[1024] = {0};

	printf("test_hugepage\n");
	pid_t pid = getpid();
	snprintf(buf, sizeof(buf), "cat /proc/%d/smaps", pid);
	system(buf);

	return 0;
}
