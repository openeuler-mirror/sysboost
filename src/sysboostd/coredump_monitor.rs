// Copyright (c) 2023 Huawei Technologies Co., Ltd.
// sysboost is licensed under the Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//     http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
// PURPOSE.
// See the Mulan PSL v2 for more details.
// Create: 2023-7-13

use std::path::Path;
use log::{self};
use std::fs;
use lazy_static::lazy_static;
use std::sync::RwLock;
use std::fs::OpenOptions;
use std::io::{Write, Read};

use crate::netlink_client::{open_netlink, read_event};
use crate::aot::set_app_link_flag;
use crate::daemon;
use crate::daemon::SYSBOOST_DB_PATH;

pub const SYSBOOST_LOG_PATH: &str = "/etc/sysboost.d/log.ini";

lazy_static! {
        pub static ref CRASH_PATH: RwLock<Vec<String>> = RwLock::new(
                Vec::new()
        );
}

pub fn parse_crashed_log() {
        let file_name = Path::new(&SYSBOOST_LOG_PATH);
        let mut file = match std::fs::File::open(file_name) {
                Ok(f) => {f}
                Err(e) => {
                        log::error!("open log.ini failed {}", e);
                        return;
                }
        };
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let mut writer = CRASH_PATH.write().unwrap();
        *writer = contents.split("\n").map(|s| s.to_string()).collect();

}
pub fn is_app_crashed(path: String) -> bool {
        for cpath in CRASH_PATH.read().unwrap().iter() {
                if cpath.to_string() == path {
                        log::info!("{} has crashed, ingnore", path);
                        return true;
                }
        }
        false
}

fn record_crashed_path(path: String) {
        let exist = Path::new(&SYSBOOST_LOG_PATH).exists();
        if !exist {
                std::fs::File::create(SYSBOOST_LOG_PATH.to_string()).expect("log.ini create failed");  
        }
        let file_name = Path::new(&SYSBOOST_LOG_PATH);
        let mut file = match OpenOptions::new().append(true).open(file_name) {
                Ok(f) => {f}
                Err(e) => {
                        log::error!("open log.ini failed {}", e);
                        return;
                }
        };
        match file.write_all(path.as_bytes()) {
                Ok(_) => {}
                Err(e) => {
                        log::error!("write log.ini failed {}", e);
                        return;
                }   
        }
        match file.write_all("\n".as_bytes()) {
                Ok(_) => {}
                Err(e) => {
                        log::error!("write log.ini failed {}", e);
                        return;
                } 
        }
}

fn do_rollback(path: &String) -> i32 {
        let paths: Vec<&str> = path.split(".rto").collect();
        let names: Vec<&str> = paths[0].split("/").collect();
        let binary_name = names[names.len() - 1];
        let file_path = paths[0];
        let rto_path = format!("{}.rto", file_path);
        // unset flag
        let ret = set_app_link_flag(&file_path.to_string(), false);
	if ret != 0 {
		log::error!("Failed to unset link flag for bash!");
		return ret;
	}
        // remove link
        let link_path = format!("{}{}.link", SYSBOOST_DB_PATH, binary_name);
        let exist = Path::new(&link_path).exists();
        if exist {
                daemon::db_remove_link(&link_path);
        }
     
        // remove bash.rto
        let exist = Path::new(&rto_path).exists();
        if exist {
                match fs::remove_file(&rto_path) {
                        Ok(_) => {}
                        Err(e) => {
                                log::error!("remove file failed: {}", e);
                        }
                }
        }
        // 添加路径记录,防止再次优化
        record_crashed_path(file_path.to_string());     
        0      
}

pub fn coredump_monitor_loop() {
	let _sock = open_netlink();
        let sock = match  _sock {
                Ok(data) => {data},
                Err(e) => panic!("sock error: {}", e),
        };
        loop {
                let _path = read_event(sock);
                let path = match _path{
                    Ok(data) => {data},
                    Err(e) => panic!("get path error: {}", e),
                };
                do_rollback(&path);
        }
}