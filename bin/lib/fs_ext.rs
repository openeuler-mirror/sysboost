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

use log::{self};
use std::fs;
use std::path::PathBuf;

pub fn move_file(new_path: &String, old_path: &String) -> i32 {
	match fs::rename(&new_path, &old_path) {
		Ok(_) => {}
		Err(e) => {
			log::error!("move file failed: {}", e);
			return -1;
		}
	}

	return 0;
}

pub fn is_symlink(path: &PathBuf) -> bool {
	let file_type = match fs::symlink_metadata(path) {
		Ok(metadata) => metadata.file_type(),
		Err(_) => {
			log::error!("get file type fail: {:?}", path.file_name());
			return false;
		}
	};

	return file_type.is_symlink();
}

pub fn find_file_in_dirs(file_name: &str, dirs: &str) -> Option<String> {
	let dir_entries = fs::read_dir(dirs).ok()?;
	for entry in dir_entries {
		let entry = entry.ok()?;
		let path = entry.path();
		if path.is_file() && path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default() == file_name {
			return Some(path.to_string_lossy().into_owned());
		}
	}
	None
}
