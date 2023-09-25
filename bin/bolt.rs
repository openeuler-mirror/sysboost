// Copyright (c) 2023 Huawei Technologies Co., Ltd.
// sysboost is licensed under the Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//     http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
// PURPOSE.
// See the Mulan PSL v2 for more details.
// Create: 2023-8-28

use crate::common::set_thp;
use crate::common::ARCH;
use crate::config::RtoConfig;
use crate::lib::process_ext::run_child;

use std::fs;
use std::path::Path;

// 因为sysboost限制最多只有10个APP可以做优化, 因此假设app名称不会冲突
// 为了避免不同架构profile误用, 因此名称中带arch信息
// 例子: mysqld的profile路径是 /usr/lib/sysboost.d/profile/mysqld.profile.aarch64
const SYSBOOST_BOLT_PROFILE: &str = "/usr/lib/sysboost.d/profile/";

fn get_profile_path(conf: &RtoConfig) -> String {
	if let Some(profile_path_str) = conf.profile_path.clone() {
		return profile_path_str;
	} else {
		match Path::new(&conf.elf_path).file_name() {
			Some(app_file_name) => {
				return format!("{}{}.profile.{}", SYSBOOST_BOLT_PROFILE, app_file_name.to_string_lossy(), ARCH);
			}
			None => {}
		}
	}
	return "".to_string();
}

// support profile
fn bolt_optimize_bin(conf: &RtoConfig) -> i32 {
	let mut args: Vec<String> = Vec::new();

	args.push("-reorder-blocks=ext-tsp".to_string());
	args.push("-reorder-functions=hfsort".to_string());
	args.push("-split-functions".to_string());
	args.push("-split-all-cold".to_string());
	args.push("-split-eh".to_string());
	args.push("-dyno-stats".to_string());

	let elf = conf.elf_path.clone();

	let elf_path = Path::new(&elf);
	let elf_path = match fs::canonicalize(elf_path) {
		Ok(p) => p,
		Err(e) => {
			log::error!("bolt_optimize_bin: get realpath failed: {}", e);
			return -1;
		}
	};
	let elf_bak_path = elf_path.with_extension("bak");
	match fs::copy(&elf_path, &elf_bak_path) {
		Ok(_) => {}
		Err(e) => {
			log::error!("Copy failed: {}", e);
			return -1;
		}
	}
	args.push(elf_bak_path.to_str().unwrap().to_string());
	args.push("-o".to_string());
	args.push(elf.split_whitespace().collect());

	let real_profile_path = get_profile_path(conf);
	if real_profile_path != "" {
		args.push(format!("-data={}", real_profile_path));
	}

	let ret = run_child("/usr/bin/llvm-bolt", &args);

	return ret;
}

fn bolt_optimize_so(conf: &RtoConfig) -> i32 {
	let mut args: Vec<String> = Vec::new();
	let mut ret = 1;
	// change layout of basic blocks in a function
	args.push("-reorder-blocks=ext-tsp".to_string());
	// Sorting functions by using hfsort+ a Hash-based function sorting algorithm
	args.push("-reorder-functions=hfsort+".to_string());
	args.push("-split-functions=true".to_string());
	args.push("-split-all-cold".to_string());
	args.push("-dyno-stats".to_string());
	args.push("-icf=1".to_string());

	for lib in conf.libs.iter() {
		let lib_path = Path::new(&lib);
		let lib_path = match fs::canonicalize(lib_path) {
			Ok(p) => p,
			Err(e) => {
				log::error!("bolt_optimize_so: get realpath failed: {}", e);
				return -1;
			}
		};
		let lib_bak_path = lib_path.with_extension("bak");
		match fs::copy(&lib_path, &lib_bak_path) {
			Ok(_) => {}
			Err(e) => {
				log::error!("Copy failed: {}", e);
				return -1;
			}
		}
		args.push(lib_bak_path.to_str().unwrap().to_string());
		args.push("-o".to_string());
		args.push(lib.split_whitespace().collect());
		ret = run_child("/usr/bin/llvm-bolt", &args);
	}
	return ret;
}

fn is_mysqld(conf: &RtoConfig) -> bool {
	match Path::new(&conf.elf_path).file_name() {
		Some(app_file_name) => {
			if app_file_name == "mysqld" {
				return true;
			}
		}
		None => {}
	}
	return false;
}

pub fn bolt_optimize(conf: &RtoConfig) -> i32 {
	if let Some(_p) = &conf.path.clone() {
		log::error!("Configuration file fail");
		return -1;
	} else {
		if conf.elf_path.is_empty() {
			let ret = bolt_optimize_so(&conf);
			return ret;
		} else {
			let ret = bolt_optimize_bin(&conf);
			// 如果优化程序是mysqld, 则开启透明大页
			if is_mysqld(conf) {
				set_thp();
			}
			return ret;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::common::ARCH;

	// cargo test -- tests::test_get_profile_path --nocapture
	// 测试profile路径是否正确
	#[test]
	fn test_get_profile_path() {
		let conf = RtoConfig {
			elf_path: "/usr/bin/mysqld".to_string(),
			mode: "static".to_string(),
			libs: Vec::new(),
			path: None,
			profile_path: None,
			watch_paths: Vec::new(),
		};
		let profile_str = get_profile_path(&conf);
		println!("---{}", profile_str);

		// /usr/lib/sysboost.d/profile/mysqld.profile.aarch64
		let expect = format!("/usr/lib/sysboost.d/profile/mysqld.profile.{}", ARCH);
		assert!(profile_str == expect, "result: {}  expect: {}", profile_str, expect);
	}
}
