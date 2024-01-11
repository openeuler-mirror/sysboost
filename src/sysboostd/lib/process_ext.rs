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

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

pub fn run_child(cmd: &str, args: &Vec<String>) -> i32 {
	log::info!("run child: {}, {}", cmd, args.join(" ").to_string());
	let mut child = match Command::new(cmd).args(args).stdout(Stdio::piped()).spawn() {
		Ok(child) => child,
		Err(e) => {
			log::error!("Failed to execute command: {}", e);
			return -1;
		}
	};
	let stdout = match child.stdout.take() {
		Some(stdout) => stdout,
		None => {
			log::error!("Failed to capture stdout");
			return -1;
		}
	};
	let reader = BufReader::new(stdout);

	for line in reader.lines() {
		let line = line.unwrap_or_else(|_| "<read error>".to_owned());
		log::info!("output: {}", line);
	}

	let status = match child.wait() {
		Ok(status) => status,
		Err(e) => {
			log::error!("Failed to wait on child: {}", e);
			return -1;
		}
	};

	let exit_code = match status.code() {
		Some(code) => code,
		None => {
			log::error!("Terminated by signal");
			return -1;
		}
	};

	if exit_code != 0 {
		log::debug!("Command exited with code: {}", exit_code);
	}

	exit_code
}
