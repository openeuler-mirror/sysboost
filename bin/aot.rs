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

use crate::common::SYSBOOST_PATH;
use crate::config::RtoConfig;
use crate::lib::fs_ext;
use crate::lib::process_ext::run_child;

use goblin::elf::Elf;
use std::{env, fs};

// Obtain the full path from real path, environment variable PATH, current dir
fn get_lib_full_path(lib: &str, confpaths: Vec<&str>, rpaths: Vec<&str>, paths: Vec<&str>) -> Option<String> {
	if !(confpaths.is_empty()) {
		for confpath in confpaths {
			let full_dir = fs_ext::find_file_in_dirs(&lib, &confpath);
			if let Some(ref _n) = full_dir {
				return full_dir;
			}
		}
	} else if !(rpaths.is_empty()) {
		for rpath in rpaths {
			let full_dir = fs_ext::find_file_in_dirs(&lib, &rpath);
			if let Some(ref _n) = full_dir {
				return full_dir;
			}
		}
	} else if !(paths.is_empty()) {
		for path in paths {
			let full_dir = fs_ext::find_file_in_dirs(&lib, &path);
			if let Some(ref _n) = full_dir {
				return full_dir;
			}
		}
	} else {
		let d = "./";
		let full_dir = fs_ext::find_file_in_dirs(&lib, &d);
		if let Some(ref _n) = full_dir {
			return full_dir;
		}
	}
	None
}

// read elf file as using readelf
pub fn parse_elf_file(elf_path: &str) -> Option<Elf> {
	let elf_bytes = match fs::read(&elf_path) {
		Ok(elf_bytes) => elf_bytes,
		Err(_e) => {
			log::info!("Error: read elf file fault, please check config.");
			return None;
		}
	};
	match Elf::parse(&elf_bytes) {
		Ok(elf) => Some(elf),
		Err(_e) => {
			log::info!("Error: parse elf file fault, please check the elf file");
			None
		}
	};
	None
}

pub fn find_libs(conf: &RtoConfig, elf: &Elf) -> Vec<String> {
	let mut libs = conf.libs.clone();

	let confpaths_temp = conf.path.as_ref().map_or_else(String::new, |v| v.clone());
	let confpaths: Vec<&str> = confpaths_temp.split(':').collect();
	let rpaths = elf.rpaths.clone();
	if let Some(paths_temp) = env::var_os("PATH") {
		let paths_str = paths_temp.to_string_lossy();
		let lib_paths: Vec<&str> = paths_str.split(':').collect();
		for lib in elf.libraries.iter() {
			let findlib = get_lib_full_path(lib, confpaths.clone(), rpaths.clone(), lib_paths.clone()).unwrap_or("".to_string());
			libs.push(findlib);
		}
		libs
	} else {
		log::info!("The environment variable PATH is empty. Please check.");
		libs
	}
}

pub fn set_app_link_flag(path: &String, is_set: bool) -> i32 {
	let mut args: Vec<String> = Vec::new();
	if is_set {
		args.push("--set".to_string());
	} else {
		args.push("--unset".to_string());
	}

	// 回滚场景, 路径是软链接要转换为真实路径
	let real_path = match fs::canonicalize(path) {
		Ok(p) => p,
		Err(e) => {
			log::error!("get realpath failed: {}", e);
			return -1;
		}
	};

	args.push(format!("{}", real_path.to_string_lossy()));
	let ret = run_child(SYSBOOST_PATH, &args);
	return ret;
}

// 生成rto文件
// rto文件先生成到临时文件, 然后mv到最终路径, 避免并发操作文件问题
// sysboost --output=/usr/bin/bash.tmp.rto -static /usr/bin/bash lib1 lib2
pub fn gen_app_rto(conf: &RtoConfig) -> i32 {
	if let Some(_p) = &conf.profile_path.clone() {
		log::error!("Configuration file fail");
		return -1;
	}

	let mut args: Vec<String> = Vec::new();
	args.push("--output".to_string());
	args.push(format!("{}.tmp.rto", conf.elf_path));
	args.push(format!("--{}", conf.mode));
	args.push(conf.elf_path.to_owned());
	for lib in conf.libs.iter() {
		args.push(lib.split_whitespace().collect());
	}
	let mut ret = run_child(SYSBOOST_PATH, &args);
	if ret != 0 {
		return ret;
	}
	ret = fs_ext::move_file(&format!("{}.tmp.rto", conf.elf_path), &format!("{}.rto", conf.elf_path));
	if ret != 0 {
		return ret;
	}
	let mut set: Vec<String> = Vec::new();
	set.push("--set-rto".to_string());
	set.push(format!("{}.rto", conf.elf_path));
	ret = run_child(SYSBOOST_PATH, &set);
	if ret != 0 {
		return ret;
	}
	let mut set_mod: Vec<String> = Vec::new();
	set_mod.push("755".to_string());
	set_mod.push(format!("{}.rto", conf.elf_path));
	ret = run_child("/usr/bin/chmod", &set_mod);
	if ret != 0 {
		return ret;
	}

	// 设置链接标志位
	ret = set_app_link_flag(&conf.elf_path, true);

	return ret;
}
