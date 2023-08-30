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
use std::fs;

const KO_RTO_PARAM_PATH: &str = "/sys/module/sysboost_loader/parameters/use_rto";
const HPAGE_RTO_PARAM_PATH: &str = "/sys/module/sysboost_loader/parameters/use_hpage";
const KO_PATH: &str = "/lib/modules/sysboost/sysboost_loader.ko";

// echo 1 > /sys/module/sysboost_loader/parameters/use_rto
pub fn set_ko_rto_flag(is_set: bool) -> i32 {
	let mut args;
	if is_set {
		args = "1".to_string();
	} else {
		args= "0".to_string();
	}
	match fs::write(KO_RTO_PARAM_PATH.to_string(), args) {
		Ok(_) => {
			return 0;
		}
		Err(e) => {
			log::error!("Error writing use_rto");
			return -1;
		}
	}
	0
}

// echo 1 > /sys/module/sysboost_loader/parameters/use_hpage
pub fn set_hpage_rto_flag(is_set: bool) -> i32 {
	let mut args;
	if is_set {
		args = "1".to_string();
	} else {
		args= "0".to_string();
	}
	match fs::write(HPAGE_RTO_PARAM_PATH.to_string(), args) {
		Ok(_) => {
			return 0;
		}
		Err(e) => {
			log::error!("Error writing use_hpage");
			return -1;
		}
	}
	0
}

fn insmod_ko(path: &String) {
	let mut args: Vec<String> = Vec::new();
	args.push(path.to_string());
	run_child("/usr/sbin/insmod", &args);
}

pub fn insmod_sysboost_ko() {
	insmod_ko(&KO_PATH.to_string());
}

pub fn test_kmod() -> i32 {
	let mut args: Vec<String> = Vec::new();
	args.push("-c".to_string());
	args.push("lsmod | grep sysboost_loader".to_string());
	let ret = run_child("/usr/bin/bash", &args);
	if ret == 0 {
		log::info!("sysboost_loader.ko is ready");
	} else {
		log::info!("sysboost_loader.ko is not ready");
	}
	return ret;
}
