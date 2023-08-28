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

mod lib;
mod common;
mod config;
mod kmod_util;
mod aot;
mod bolt;
mod daemon;
mod coredump_monitor;

use crate::kmod_util::test_kmod;
use crate::daemon::daemon_loop;
use crate::coredump_monitor::coredump_monitor_loop;

use basic::logger::{self};
use daemonize::Daemonize;
use log::{self};
use std::env;
use std::thread;

const APP_NAME: &str = "sysboostd";

fn main() {
	let args: Vec<String> = env::args().collect();
	let mut is_debug = false;
	let mut is_daemon = false;

	// arg0 is program name, parameter is from arg1
	for i in 1..args.len() {
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
				println!("parameter is wrong");
				std::process::exit(-1);
			}
		}
	}

	if is_debug {
		logger::init_log_to_console(APP_NAME, log::LevelFilter::Debug);
	} else {
		logger::init_log(APP_NAME, log::LevelFilter::Info, "syslog", None);
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
        let _coredump_monitor_handle = thread::spawn(||{
                coredump_monitor_loop();
        });

	// daemon service gen rto ELF with config
	daemon_loop();
}
