// Copyright (c) 2023 Huawei Technologies Co., Ltd.
// sysboost is licensed under the Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//     http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
// PURPOSE.
// See the Mulan PSL v2 for more details.
// Create: 2023-4-20

mod aot;
mod bolt;
mod common;
mod config;
mod coredump_monitor;
mod daemon;
mod kmod_util;
mod lib;
mod netlink_client;
mod interface;

use crate::config::parse_sysinit_config;
use crate::coredump_monitor::coredump_monitor_loop;
use crate::coredump_monitor::parse_crashed_log;
use crate::daemon::daemon_loop;
use crate::interface::delete_one_record;
use crate::interface::gen_bolt_optimize_bin;
use crate::interface::stop_one_elf;
use crate::interface::write_back_config;
use crate::kmod_util::test_kmod;
use crate::bolt::gen_profile;
use crate::config::INIT_CONF;

use basic::logger::{self};
use daemonize::Daemonize;
use log::{self};
use std::env;
use std::thread;

const APP_NAME: &str = "sysboostd";
const DEFAULT_TIMEOUT: u32 = 10;
const PROFILE_PATH_DEFAULT: &str = "/usr/lib/sysboost.d/profile/mysqld.profile";

fn parameter_wrong_exit() {
	println!("parameter is wrong");
	std::process::exit(-1);
}

fn main() {
	let args: Vec<String> = env::args().collect();
	let mut is_debug = false;
	let mut is_daemon = false;
	let mut is_gen_porfile = false;
	let mut timeout = DEFAULT_TIMEOUT;
	let mut name = "";

	let mut is_bolt = false;
	let mut bolt_option = "";
	let mut profile_path = "";
	let mut bolt_elf_name = "";

	let mut is_stop = false;
	let mut stop_elf_name = "";
	// arg0 is program name, parameter is from arg1
	for i in 1..args.len() {
		if args[i].contains("--gen-profile=") {
			if let Some(index) = args[i].find('=') {
				is_gen_porfile = true;
				name = &args[i][index + 1..];
			} else {
				parameter_wrong_exit();
			}
			continue;
		}
		if args[i].contains("--timeout=") {
			if let Some(index) = args[i].find('=') {
				let sub_str = &args[i][index + 1..];
				timeout = sub_str.parse().unwrap();
			}
			continue;
		}
		if args[i].contains("--gen-bolt=") {
			if let Some(index) = args[i].find('=') {
				is_bolt = true;
				bolt_elf_name = &args[i][index + 1..];
			}
			continue;
		}
		if args[i].contains("--bolt-option=") {
			if let Some(index) = args[i].find('=') {
				bolt_option = &args[i][index + 1..];
			}
			continue;
		}
		if args[i].contains("--profile-path=") {
			if let Some(index) = args[i].find('=') {
				profile_path = &args[i][index + 1..];
			}
			continue;
		}
		if args[i].contains("--stop=") {
			if let Some(index) = args[i].find('=') {
				is_stop = true;
				stop_elf_name = &args[i][index + 1..];
			}
			if stop_elf_name.is_empty() {
				parameter_wrong_exit();
			}
			continue;
		}
		match args[i].as_str() {
			"--debug" => {
				is_debug = true;
			}
			"--daemon" => {
				is_daemon = true;
			}
			"--test-kmod" => {
				std::process::exit(test_kmod());
			}
			_ => {
				parameter_wrong_exit();
			}
		}
	}
	
	if is_debug {
		logger::init_log_to_console(APP_NAME, log::LevelFilter::Debug);
	} else {
		logger::init_log(APP_NAME, log::LevelFilter::Info, "syslog", None);
	}

	// 配置文件解析
	parse_sysinit_config();
	parse_crashed_log();
	//sysboostd --gen-bolt="/path/to/mysqld" --bolt-option="xxx" --profile-path="/path/to/mysqld.profile"
	if is_bolt {
		if profile_path.is_empty() {
			profile_path = PROFILE_PATH_DEFAULT;
		}
		let ret = gen_bolt_optimize_bin(bolt_elf_name, bolt_option, profile_path);
		if ret < 0 {
			std::process::exit(-1);
		}
		std::process::exit(write_back_config(bolt_elf_name));
	}
	//sysboostd --stop=/path/to/mysqld
	if is_stop {
		logger::init_log_to_console(APP_NAME, log::LevelFilter::Debug);
		let ret = stop_one_elf(stop_elf_name);
		if ret < 0 {
			std::process::exit(-1);
		}
		std::process::exit(delete_one_record(stop_elf_name));
	}
	if is_gen_porfile {
		logger::init_log_to_console(APP_NAME, log::LevelFilter::Debug);
		std::process::exit(gen_profile(name, timeout));
	}

	log::info!("{} running", APP_NAME);

	if is_daemon {
		let daemonize = Daemonize::new();
		match daemonize.start() {
			Ok(_) => log::info!("On Daemon"),
			Err(e) => {
				log::error!("Error, {}", e);
				std::process::exit(-1);
			}
		}
	}

	// start up coredump monitor
	if INIT_CONF.read().unwrap().general.coredump_monitor_flag {
		let _coredump_monitor_handle = thread::spawn(||{
			coredump_monitor_loop();
		});
	}
	
	// daemon service gen rto ELF with config
	daemon_loop();
}
