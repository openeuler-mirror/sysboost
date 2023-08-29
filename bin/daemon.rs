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

use crate::lib::fs_ext;
use crate::kmod_util::set_ko_rto_flag;
use crate::kmod_util::set_hpage_rto_flag;
use crate::kmod_util::insmod_sysboost_ko;
use crate::config::RtoConfig;
use crate::config::read_config;
use crate::aot::gen_app_rto;
use crate::aot::set_app_aot_flag;
use crate::aot::parse_elf_file;
use crate::aot::find_libs;
use crate::bolt::bolt_optimize;

use inotify::{EventMask, Inotify, WatchMask};
use log::{self};
use std::fs;
use std::os::unix::fs as UnixFs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

const SYSBOOST_DB_PATH: &str = "/var/lib/sysboost/";
const LDSO: &str = "ld-";
const LIBCSO: &str = "libc.so";

// sleep some time wait for next event
const MIN_SLEEP_TIME: u64 = 10;

// only 10 program can use boost
const MAX_BOOST_PROGRAM: u32 = 10;

fn db_add_link(conf: &RtoConfig) -> i32 {
	// symlink app.link to app, different modes correspond to different directories
	let file_name = Path::new(&conf.elf_path).file_name().unwrap().to_str().unwrap();
	let link_path = format!("{}{}.link", SYSBOOST_DB_PATH, file_name);
	let ret_e = UnixFs::symlink(&conf.elf_path, &link_path);
	match ret_e {
		Ok(_) => {}
		Err(_) => {
			log::error!("symlink fail {}", link_path);
			return -1;
		}
	};

	return 0;
}

pub fn db_remove_link(path: &String) {
	let ret = fs::remove_file(&path);
	match ret {
		Ok(_) => return,
		Err(e) => {
			log::error!("remove link fail: {}", e);
		}
	};
}

// TODO: use bolt to optimize dynamic library and then merge them
fn sysboost_core_process(conf: &RtoConfig) -> i32 {
	match conf.mode.as_str() {
		"bolt" => {
			let ret = bolt_optimize(&conf);
			if ret != 0 {
				log::error!("Error: bolt mode start fault.");
				return ret;
			}
		},
		"static" | "static-nolibc" | "share" => {
			let ret = gen_app_rto(&conf);
			if ret != 0 {
				log::error!("Error: generate rto start fault.");
				return ret;
			}
		},
		_ => {
			log::info!("Warning: read elf file fault, please check config.");
			// handle other cases
		}
	}

	let ret = db_add_link(&conf);
	if ret != 0 {
		log::error!("Error: db add link fault.");
		return ret;
	}

	let ret = set_app_aot_flag(&conf.elf_path, true);
	if ret != 0 {
		log::error!("Error: set app aot flag fault.");
		return ret;
	}
	return ret;
}

fn process_config(path: PathBuf) -> Option<RtoConfig> {
	let conf_e = read_config(&path);
	let mut conf = match conf_e {
		Some(conf) => conf,
		None => return None,
	};

	let elf = match parse_elf_file(&conf.elf_path) {
		Some(elf) => elf,
		None => return None,
	};

	// auto get lib path
	// In static-nolibc mode, ld and libc need to be deleted after detection.
	// In share mode, no detection is performed based on libs.
	if conf.mode == "static" {
		let libs = find_libs(&conf, &elf);
		conf.libs = libs;
	} else if conf.mode == "static-nolibc" {
		let mut libs = find_libs(&conf, &elf);
		libs.retain(|s| !s.contains(LDSO));
		libs.retain(|s| !s.contains(LIBCSO));
		conf.libs = libs;
	}

	// add elf file to watch list
	conf.watch_paths.push(conf.elf_path.clone());
	for lib in conf.libs.iter() {
		conf.watch_paths.push(lib.split_whitespace().collect());
	}

	// add config file to watch list
	let path_str = path.clone().into_os_string().into_string().unwrap();
	conf.watch_paths.push(path_str);

	let ret = sysboost_core_process(&conf);
	if ret != 0 {
		log::error!("Error: db add link fault.");
		return None;
	}

	return Some(conf);
}

fn refresh_all_config(rto_configs: &mut Vec<RtoConfig>) {
	// read configs /etc/sysboost.d, like bash.toml
	let dir_e = fs::read_dir(&Path::new("/etc/sysboost.d"));
	let dir = match dir_e {
		Ok(dir) => dir,
		Err(e) => {
			log::error!("{}", e);
			return;
		}
	};

	let mut i = 0;
	for entry in dir {
		let entry = entry.ok().unwrap();
		let path = entry.path();
		if path.is_dir() {
			continue;
		}
		if path.file_name() == None {
			continue;
		}

		if i == MAX_BOOST_PROGRAM {
			log::error!("too many boost program");
			break;
		}
		let ret = process_config(path);
		match ret {
			Some(conf) => rto_configs.push(conf),
			None => {}
		}
		log::error!("refresh all config {}", i);
		i += 1;
	}

	if rto_configs.len() > 0 {
		set_ko_rto_flag(true);
		set_hpage_rto_flag(true);
	}
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
		set_app_aot_flag(&p, false);
		db_remove_link(&p);
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
	set_ko_rto_flag(false);
	set_hpage_rto_flag(false);
	clean_last_rto();

	let mut rto_configs: Vec<RtoConfig> = Vec::new();
	refresh_all_config(&mut rto_configs);
	let mut inotify = Inotify::init().unwrap();
	let mut try_again = true;
	match inotify.add_watch("/etc/sysboost.d/bash.toml", WatchMask::MODIFY) {
		Ok(_) => {
			try_again = false;
		}
		Err(e) => {
			log::info!("init watch bash.toml failed {}", e);
		}
	};
	let mut buffer = [0; 1024];

	let mut file_inotify = watch_old_files(&rto_configs);

	loop {
		// wait some time
		thread::sleep(Duration::from_secs(MIN_SLEEP_TIME));
		if try_again {
			match inotify.add_watch("/etc/sysboost.d/bash.toml", WatchMask::MODIFY) {
				Ok(_) => {
					try_again = false;
					return;
				}
				Err(e) => {
					log::info!("init watch bash.toml failed {}", e);
				}
			};
		}
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
	insmod_sysboost_ko();

	// When rebooting, you should clean up the backup environment
	loop {
		start_service();
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use basic::logger::{self};
	use std::process::Command;
	use crate::lib::process_ext::run_child;

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

		let bash_libs_nolibc = vec![
			String::from("/usr/lib64/libtinfo.so.6"),
		];

		assert_eq!(libs, bash_libs);
		assert_eq!(libs_nolibc, bash_libs_nolibc);

	}

	#[test]
	#[cfg(target_arch = "x86")]
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

		let bash_libs_nolibc = vec![
			String::from("/usr/lib64/libtinfo.so.6"),
		];

		assert_eq!(libs, bash_libs);
		assert_eq!(libs_nolibc, bash_libs_nolibc);

	}

}
