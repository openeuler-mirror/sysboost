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

extern void foo(void);
extern const char *exported_str;

const char *const message = "Test for local const variables.\n";

int test_local_function()
{
	printf("Test for local function.\n");
	return 0;
}

int main()
{
	foo();
	printf("Test for functions in unmerged .so file.\n");
	printf("%s", exported_str);
	printf("%s", message);
	test_local_function();
	return 0;
}