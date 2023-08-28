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

use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, Deserialize)]
pub struct RtoConfig {
	pub elf_path: String,
	pub mode: String,
	pub libs: Vec<String>,
	// Absolute path of the profile
	pub profile_path: Option<String>,

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
