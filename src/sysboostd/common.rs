// Copyright (c) 2023 Huawei Technologies Co., Ltd.
// sysboost is licensed under the Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//     http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
// PURPOSE.
// See the Mulan PSL v2 for more details.
// Create: 2023-8-26

use crate::lib::process_ext::run_child;

pub const SYSBOOST_PATH: &str = "/usr/bin/elfmerge";

// echo always > /sys/kernel/mm/transparent_hugepage/enabled
pub fn set_thp() -> i32 {
	let args: Vec<String> = Vec::new();
	let ret = run_child("echo always > /sys/kernel/mm/transparent_hugepage/enabled", &args);
	return ret;
}

pub fn is_arch_x86_64() -> bool {
	if std::env::consts::ARCH == "x86_64" {
		return true;
	}
	return false;
}
