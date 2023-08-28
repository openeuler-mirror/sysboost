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

use crate::lib::fs_ext;
use crate::lib::process_ext::run_child;
use crate::config::RtoConfig;

use std::fs;
use std::path::Path;

const SYSBOOST_BOLT_PROFILE: &str = "/usr/lib/sysboost.d/profile/";

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
	let profile_str = format!("{}{}", elf, ".profile");
	if let Some(profile_path_str) = conf.profile_path.clone() {
		args.push(format!("{}{}", "-data=".to_string(), profile_path_str));

	} else {
		if let Some(find_file_str) = fs_ext::find_file_in_dirs(&profile_str, &SYSBOOST_BOLT_PROFILE) {
			args.push(format!("{}{}", "-data=".to_string(), find_file_str));
		}
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
			return ret;
		}
	}
}
