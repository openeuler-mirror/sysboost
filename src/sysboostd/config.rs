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

use crate::common::SYSBOOST_PATH;

use ini::Properties;
use serde::Deserialize;
use ini::Ini;
use lazy_static::lazy_static;
use std::sync::RwLock;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

pub const SYSBOOST_CONFIG_PATH: &str = "/etc/sysboost.d/sysboost.ini";
// only 10 program can use boost
const MAX_BOOST_PROGRAM: u32 = 10;

#[derive(Debug, Deserialize)]
pub struct RtoConfig {
	pub name: String,
	// 目标程序的全路径
	pub elf_path: String,
	// 优化模式
	pub mode: String,
	// 依赖的动态库路径
	pub libs: Vec<String>,  // TODO: 修改为字符串, 列表形式影响可读性
	// profile文件路径
	pub profile_path: Option<String>,
	// llvm-bolt命令文件夹路径
	pub bolt_dir: String,
	// 环境变量
	#[serde(rename = "PATH")]
	pub path: Option<String>,

	#[serde(skip)]
	pub watch_paths: Vec<String>,
}

pub struct GeneralSection {
	pub coredump_monitor_flag: bool,
}

// INI格式配置文件
// [general]
// coredump_monitor_flag = false
//
// [/usr/bin/bash]
// mode = static
// libs = /usr/lib64/libtinfo.so.6, xxxx
pub struct InitConfig {
	pub general: GeneralSection, // use inner value to get mutable access
	pub elfsections: Vec<RtoConfig>
}

// 考虑内部可变性和线程安全
// 可使用Mutex和RwLock
// 性能：sysboost只在全局配置文件解析写，其余都只读
lazy_static! {
    pub static ref INIT_CONF: RwLock<InitConfig> = RwLock::new(
			InitConfig {
				general: GeneralSection{coredump_monitor_flag: true},
				elfsections: Vec::new()
			}
		);
}

fn detect_so(path: &String, rtoconfig: &mut RtoConfig) {
	let args: &Vec<String> = &vec![path.to_string();1];
	let mut run_thread = match Command::new("/usr/bin/ldd").args(args).stdout(Stdio::piped()).spawn() {
		Ok(run_thread) => run_thread,
		Err(e) => {
			log::error!("Failed to execute command: {}", e);
			return;
		}
	};
	let stdout = match run_thread.stdout.take() {
		Some(stdout) => stdout,
		None => {
			log::error!("Failed to capture stdout");
			return;
		}
	};
	let reader = BufReader::new(stdout);
	for line in reader.lines() {
		let line = line.unwrap_or_else(|_| "<read error>".to_owned());
		let start = match line.find('/') {
			Some(s) => {s},
			None => continue
		};
		let end = match line.find('(') {
			Some(e) => {e},
			None => continue
		};
		let lib_path = line[start..end].trim();
		if lib_path == "/usr/lib64/libc.so.6" || lib_path == "/lib/ld-linux-aarch64.so.1" {
			continue;
		}
		rtoconfig.libs.push(lib_path.to_string());
	}
	log::debug!("Automatically detect {} dependent so files: {:?}",rtoconfig.name, &rtoconfig.libs);
}

pub fn parse_sysinit_config() {
	let conf_file = match Ini::load_from_file(SYSBOOST_CONFIG_PATH){
		Ok(c) => {c}
		Err(e) => {
			log::info!("load file {} failed",SYSBOOST_CONFIG_PATH);
			return;
		}
	};
	let mut i = 0;
	for (sec, prop) in &conf_file {
		if i >= MAX_BOOST_PROGRAM {
			log::error!("too many boost program");
			break;
		}
		match sec {
			Some("general") => {
				parse_general(prop);
			},
			Some(elf_section) => {
				parse_rto_config(elf_section.to_string(), prop);
				i += 1;
				log::info!("parse elf section config {}", i);
			},
			None => continue
		}
	}
}

fn parse_general(prop: &Properties) {
	match prop.get("coredump_monitor_flag") {
		Some("false") => {
			INIT_CONF.write().unwrap().general.coredump_monitor_flag = false;
		},
		_ => {}
	}
}

fn is_mode_invalid(mode: String) -> bool {
	if mode != "static" && mode != "static-nolibc" && mode != "share" && mode != "bolt" {
		true
	}
	else {
		false
	}
}

fn parse_rto_config(sec: String, prop: &Properties) {
	let sec_name:Vec<&str> = sec.as_str().split("/").collect();
	let mut rtoconf = RtoConfig {
		name: sec_name[sec_name.len()-1].to_string(),
		elf_path: sec.clone(),
		mode: prop.get("mode").unwrap().to_string(),
		// 需要处理配置文件中libs = ;和没有libs属性的情况
		libs: match prop.get("libs") {
			Some(p) => {
				if p.trim().is_empty() {
					Vec::new()
				}
				else {
					p.split(",").map(|s| s.to_string()).collect()
				}
			}
			None => {Vec::new()}
			},
	 	profile_path: prop.get("profile_path").map(|s| s.to_string()),
		path: prop.get("path").map(|s| s.to_string()),
		bolt_dir: match prop.get("bolt_dir") {
			Some(p) => {
				if p.trim().is_empty() {
					String::new()
				}
				else {
					p.to_string()
				}
			}
			None => {String::new()}
			},
		watch_paths: Vec::new(),
	};
	if rtoconf.elf_path == SYSBOOST_PATH || is_mode_invalid(rtoconf.mode.clone()){
		log::error!("invalid config in {}", &sec);
		return;
	}
	//如果用户没有配置libs, 则自动检测libs
	if prop.get("libs") == None {
		detect_so(&sec, &mut rtoconf);
	}
	// add elf file to watch list
	rtoconf.watch_paths.push(rtoconf.elf_path.clone());
	for lib in rtoconf.libs.iter() {
		rtoconf.watch_paths.push(lib.split_whitespace().collect());
	}
	INIT_CONF.write().unwrap().elfsections.push(rtoconf);
}