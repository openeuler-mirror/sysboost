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
use crate::common::SYSBOOST_CONFIG_PATH;

use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

// 选型toml格式作为配置文件格式, toml格式可读性最佳
#[derive(Debug, Deserialize)]
pub struct RtoConfig {
	// 目标程序的全路径
	pub elf_path: String,
	// 优化模式
	pub mode: String,
	// 依赖的动态库路径
	pub libs: Vec<String>,  // TODO: 修改为字符串, 列表形式影响可读性
	// profile文件路径
	pub profile_path: Option<String>,
	// 环境变量
	#[serde(rename = "PATH")]
	pub path: Option<String>,

	#[serde(skip)]
	pub watch_paths: Vec<String>,
}

impl FromStr for RtoConfig {
	type Err = toml::de::Error;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		toml::from_str(s)
	}
}

// elf_path = "/usr/bin/bash"
// mode = "static"
// libs = "/usr/lib64/libtinfo.so.6"
fn parse_config(contents: String) -> Option<RtoConfig> {
	let conf_e = contents.parse::<RtoConfig>();
	match conf_e {
		Ok(ref c) => log::info!("parse config: {:?}", c),
		Err(e) => {
			log::error!("parse config fail: {}", e);
			return None;
		}
	};

	let conf = conf_e.unwrap();
	if conf.mode != "static" && conf.mode != "static-nolibc" && conf.mode != "share" && conf.mode != "bolt" {
		return None;
	}
	if conf.elf_path == SYSBOOST_PATH {
		// the tool can not renew self code
		return None;
	}

	return Some(conf);
}

pub fn read_config(path: &PathBuf) -> Option<RtoConfig> {
	let ext = path.extension();
	if ext == None || ext.unwrap() != "toml" {
		return None;
	}

	let contents = match fs::read_to_string(path) {
		Ok(c) => c,
		Err(e) => {
			log::error!("reading file fail {}", e);
			return None;
		}
	};
	return parse_config(contents);
}

pub fn get_config(name: &str) -> Option<RtoConfig> {
	let conf_path = format!("{}/{}.toml", SYSBOOST_CONFIG_PATH, name);
	return read_config(&PathBuf::from(conf_path));
}
