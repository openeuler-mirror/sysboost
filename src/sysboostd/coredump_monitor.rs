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

use crate::netlink_client::{open_netlink, read_event};
use crate::aot::set_app_link_flag;
use crate::daemon;

const SYSBOOST_DB_PATH: &str = "/var/lib/sysboost/";
const SYSBOOST_TOML_PATH: &str = "/etc/sysboost.d/";

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
        
        // rename .toml
        let toml_path = format!("{}{}.toml", SYSBOOST_TOML_PATH, binary_name);
        let exist = Path::new(&toml_path).exists(); 
        if exist {
                let toml = Path::new(&toml_path);
                let toml_err = toml.with_extension("toml.err");
                match fs::rename(&toml, &toml_err) {
                        Ok(_) => {}
                        Err(e) => {
                                log::error!("Mv toml failed: {}", e);
                        }
                }
        }       
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