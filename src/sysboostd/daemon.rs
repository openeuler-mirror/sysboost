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

use crate::aot::gen_app_rto;
use crate::aot::set_app_link_flag;
use crate::bolt::bolt_optimize;
use crate::config::SYSBOOST_CONFIG_PATH;
use crate::config::INIT_CONF;
use crate::config::RtoConfig;
use crate::coredump_monitor::is_app_crashed;
use crate::kmod_util::insmod_sysboost_ko;
use crate::kmod_util::set_hpage_rto_flag;
use crate::kmod_util::set_ko_rto_flag;
use crate::kmod_util::test_kmod;
use crate::lib::fs_ext;

use inotify::{EventMask, Inotify, WatchMask};
use log::{self};
use std::fs;
use std::os::unix::fs as UnixFs;
use std::path::{Path};
use std::thread;
use std::time::Duration;

pub const SYSBOOST_DB_PATH: &str = "/var/lib/sysboost/";
//const LDSO: &str = "ld-";
//const LIBCSO: &str = "libc.so";

// sleep some time wait for next event
const MIN_SLEEP_TIME: u64 = 10000;

pub fn db_add_link(conf: &RtoConfig) -> i32 {
	// symlink app.link to app, different modes correspond to different directories
	let file_name = Path::new(&conf.elf_path).file_name().unwrap().to_str().unwrap();
	let link_path = format!("{}{}.link", SYSBOOST_DB_PATH, file_name);
	let ret_e = UnixFs::symlink(&conf.elf_path, &link_path);
	match ret_e {
		Ok(_) => log::info!("symlink sucess {}", link_path),
		Err(_) => {
			log::error!("symlink fail {}", link_path);
			return -1;
		}
	};
	0
}

pub fn db_remove_link(path: &String) {
	let ret = fs::remove_file(&path);
	match ret {
		Ok(_) => log::info!("remove link {} success", path),
		Err(e) => log::error!("remove link fail: {}", e),
	};
}

// TODO: use bolt to optimize dynamic library and then merge them
fn sysboost_core_process(conf: &RtoConfig) -> i32 {
	let mut ret= 0;
	match conf.mode.as_str() {
		"bolt" => {
			ret = bolt_optimize(&conf);
			if ret != 0 {
				log::error!("Error: bolt mode start fault.");
				return ret;
			}
		}
		"static" | "static-nolibc" | "share" => {
			ret = gen_app_rto(&conf);
			if ret != 0 {
				log::error!("Error: generate rto start fault.");
				return ret;
			}
			log::info!("generate {} rto success.",&conf.name);
		}
		_ => {
			log::info!("Warning: read elf file fault, please check config.");
			// handle other cases
		}
	}
	ret
}

fn clean_last_rto() {
	// all link, need unset flag
	let dir_e = fs::read_dir(&Path::new(SYSBOOST_DB_PATH));
	let dir = match dir_e {
		Ok(dir) => dir,
		Err(e) => {
			log::error!("{}", e);
			return;
		}
	};

	for entry in dir {
		let entry = entry.ok().unwrap();
		let path = entry.path();
		if path.is_dir() {
			continue;
		}
		if path.file_name() == None {
			continue;
		}
		if fs_ext::is_symlink(&path) == false {
			continue;
		}
		let file_name = path.file_name().unwrap();
		let p = format!("{}{}", SYSBOOST_DB_PATH, file_name.to_string_lossy());
		// 回滚场景, 路径是软链接要转换为真实路径
		let real_path = match fs::canonicalize(&p) {
			Ok(p) => p,
			Err(e) => {
				log::error!("get realpath failed: {}", e);
				continue;
			}
		};
		set_app_link_flag(&format!("{}",real_path.to_string_lossy()), false);
		db_remove_link(&p);
		match fs::remove_file(format!("{}.rto", real_path.to_string_lossy())) {
			Ok(_) => log::info!("remove {} success", format!("{}.rto", real_path.to_string_lossy())),
			Err(e) => log::info!("remove {} failed: {}", format!("{}.rto", real_path.to_string_lossy()), e),
		}
	}
}

fn watch_old_files_perapp(conf: &RtoConfig, inotify: &mut Inotify) {
	for entry in &conf.watch_paths {
		match inotify.add_watch(entry, WatchMask::MODIFY) {
			Ok(_) => {}
			Err(e) => {
				log::error!("add_watch fail {}", e);
			}
		};
	}
}

fn watch_old_files(rto_configs: &Vec<RtoConfig>) -> Inotify {
	// init fail exit program
	let mut inotify = Inotify::init().expect("Failed to init inotify.");
	for entry in rto_configs {
		watch_old_files_perapp(&entry, &mut inotify);
	}
	return inotify;
}

fn check_files_modify(inotify: &mut Inotify) -> bool {
	let mut buffer = [0u8; 4096];
	let events = match inotify.read_events(&mut buffer) {
		Ok(events) => events,
		Err(_) => return false,
	};

	for event in events {
		if event.mask.contains(EventMask::MODIFY) {
			log::info!("File modified: {:?}", event);
			// The name field is present only when watch dir
			// https://man7.org/linux/man-pages/man7/inotify.7.html
			return true;
		} else if event.mask.contains(EventMask::IGNORED) {
			println!("{:?}", event);
			return true;
		}
	}
	return false;
}

fn start_service() {
	let conf_reader = INIT_CONF.read().unwrap();

	set_ko_rto_flag(true);
	set_hpage_rto_flag(true);
	clean_last_rto();

	for conf in conf_reader.elfsections.iter() {
		log::info!("parse config: {:?}", conf);
		if is_app_crashed(conf.elf_path.clone()) {
			log::info!("{} has crashed, ingnore", &conf.elf_path);
			continue;
		}
		sysboost_core_process(conf);
	}
	log::info!("parse all config");
	let mut inotify = Inotify::init().unwrap();
	match inotify.add_watch(SYSBOOST_CONFIG_PATH, WatchMask::MODIFY) {
		Err(e) => {
			log::info!("watch init file failed {}", e);
		}
		_ => {}
	};
	let mut buffer = [0; 1024];
	let mut file_inotify = watch_old_files(&conf_reader.elfsections);

	loop {
		// wait some time
		thread::sleep(Duration::from_secs(MIN_SLEEP_TIME));
		// do not support config dynamic modify, need restart service
		let events = inotify.read_events(&mut buffer).unwrap();
		for event in events {
			if event.mask.contains(EventMask::IGNORED) {
				println!("{:?}", event);
				return;
			}
		}
		// check config file and ELF file modify,
		// if they have changed, we need to renew rto
		let is_elf_modify = check_files_modify(&mut file_inotify);
		if is_elf_modify == true {
			return;
		}
	}
}

pub fn daemon_loop() {
	if test_kmod() == 1 {
		insmod_sysboost_ko();
	}

	// When rebooting, you should clean up the backup environment
	loop {
		start_service();
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::lib::process_ext::run_child;
	use basic::logger::{self};
	use std::process::Command;

	#[test]
	fn test_check_elf_files_modify_1() {
		let mut elf_inotify = Inotify::init().expect("Failed to init inotify.");

		// create file, link to it
		Command::new("/usr/bin/touch").arg("xxx.log").spawn().expect("Fail to run cmd");

		// watch it
		let file_path = Path::new("xxx.log");
		elf_inotify.add_watch(file_path, WatchMask::MODIFY).expect("Failed to add watch.");

		// modity it, touch can not trigger evnet
		Command::new("bash").arg("-c").arg("echo 1 >> xxx.log").spawn().expect("Fail to run cmd");

		// wait modify happen
		thread::sleep(Duration::from_secs(1));

		let is_elf_modify = check_files_modify(&mut elf_inotify);
		assert_eq!(is_elf_modify, true);
	}

	#[test]
	fn test_check_elf_files_modify_2() {
		let mut elf_inotify = Inotify::init().expect("Failed to init inotify.");

		// create file, link to it
		Command::new("/usr/bin/touch").arg("xxx.log").spawn().expect("Fail to run cmd");
		std::mem::forget(UnixFs::symlink("xxx.log", "xxx.link"));

		// watch link file
		let file_path = Path::new("xxx.link");
		// let canonical_path = fs::canonicalize(file_path).expect("fail");
		// println!("{} -- {}", file_path.display(), canonical_path.to_str().unwrap());
		elf_inotify.add_watch(file_path, WatchMask::MODIFY).expect("Failed to add watch.");

		// modity it, touch can not trigger evnet
		Command::new("bash").arg("-c").arg("echo 1 >> xxx.log").spawn().expect("Fail to run cmd");

		// wait modify happen
		thread::sleep(Duration::from_secs(1));

		let is_elf_modify = check_files_modify(&mut elf_inotify);
		assert_eq!(is_elf_modify, true);
	}

	#[test]
	fn test_run_child() {
		logger::init_log("APP_NAME", log::LevelFilter::Info, "syslog", None);

		let cmd = "ls";
		let args = vec!["-l".to_owned(), ".".to_owned()];
		let exit_code = run_child(cmd, &args);

		assert_eq!(exit_code, 0);
	}

	#[test]
	#[cfg(target_arch = "aarch64")]
	fn test_process_config_arm() {
		// Create a temporary directory for testing
		let temp_dir = tempfile::tempdir().unwrap();

		// Create a temporary ELF file for testing
		let bash_path = "/usr/bin/bash";
		let elf_path = temp_dir.path().join("bash");
		std::fs::copy(&bash_path, &elf_path).unwrap();

		// Create a temporary config file for testing
		let config_path = temp_dir.path().join("test.toml");
		std::fs::write(&config_path, "elf_path = './bash' mode = 'static' PATH = '/usr/lib64:/usr/bin'").unwrap();

		let conf_e = read_config(&config_path.clone());
		let conf = match conf_e {
			Some(conf) => conf,
			None => return,
		};

		let elf = match parse_elf_file(&conf.elf_path) {
			Some(elf) => elf,
			None => return,
		};

		let libs = find_libs(&conf, &elf);
		let mut libs_nolibc = find_libs(&conf, &elf);
		libs_nolibc.retain(|s| !s.contains(LDSO));
		libs_nolibc.retain(|s| !s.contains(LIBCSO));

		let bash_libs = vec![
			String::from("/usr/lib64/libtinfo.so.6"),
			String::from("/usr/lib64/libc.so.6"),
			String::from("/lib/ld-linux-aarch64.so.1"),
		];

		let bash_libs_nolibc = vec![String::from("/usr/lib64/libtinfo.so.6")];

		assert_eq!(libs, bash_libs);
		assert_eq!(libs_nolibc, bash_libs_nolibc);
	}

	#[test]
	#[cfg(target_arch = "x86_64")]
	fn test_process_config_x86() {
		// Create a temporary directory for testing
		let temp_dir = tempfile::tempdir().unwrap();

		// Create a temporary ELF file for testing
		let bash_path = "/usr/bin/bash";
		let elf_path = temp_dir.path().join("bash");
		std::fs::copy(&bash_path, &elf_path).unwrap();

		// Create a temporary config file for testing
		let config_path = temp_dir.path().join("test.toml");
		std::fs::write(&config_path, "elf_path = './bash' mode = 'static' PATH = '/usr/lib64:/usr/bin'").unwrap();

		let conf_e = read_config(&config_path.clone());
		let conf = match conf_e {
			Some(conf) => conf,
			None => return,
		};

		let elf = match parse_elf_file(&conf.elf_path) {
			Some(elf) => elf,
			None => return,
		};

		let libs = find_libs(&conf, &elf);
		let mut libs_nolibc = find_libs(&conf, &elf);
		libs_nolibc.retain(|s| !s.contains(LDSO));
		libs_nolibc.retain(|s| !s.contains(LIBCSO));

		let bash_libs = vec![
			String::from("/usr/lib64/libtinfo.so.6"),
			String::from("/usr/lib64/libc.so.6"),
			String::from("/lib64/ld-linux-x86-64.so.2"),
		];

		let bash_libs_nolibc = vec![String::from("/usr/lib64/libtinfo.so.6")];

		assert_eq!(libs, bash_libs);
		assert_eq!(libs_nolibc, bash_libs_nolibc);
	}
}
