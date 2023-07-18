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

use crate::daemon;

use log::{self};
use lazy_static::lazy_static;
use std::collections::HashMap;
use cnproc::PidMonitor;
use cnproc::PidEvent;
use std::sync::Mutex;
use std::fs;
use procfs::Process;
use std::path::Path;

const BASH_RTO_PATH: &str = "/usr/bin/bash.rto";
const BASH_PATH: &str = "/usr/bin/bash";
const BASH_TOML_PATH: &str = "/etc/sysboost.d/bash.toml";
const BASH_LINK_PATH: &str = "/var/lib/bash";

lazy_static! {
    static ref MERGE_FILES: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static ref PID_INFOS: Mutex<HashMap<i32, String>> = Mutex::new(HashMap::new());
}

fn init_merge_file_list() {
    MERGE_FILES.lock().unwrap().push(BASH_PATH.to_string());
}

fn process_exec_event(pid: i32) {
    // get execute file_path
    let process = match Process::new(pid) {
        Ok(process) => process,
        Err(e) => {
            log::error!("Failed to get execte process: {}", e);
            return;
        }
    };
    let file_path = match process.exe() {
        Ok(file_path) => file_path,
        Err(e) => {
            log::error!("Failed to get excute file path: {}", e);
            return;
        }
    };
    if MERGE_FILES.lock().unwrap().contains(&file_path.as_path().display().to_string()) == false {
        return;
    }
    PID_INFOS.lock().unwrap().insert(pid, String::from(file_path.to_str().unwrap()));
}

fn do_bash_rollback() -> i32 {
    // unset flag
    let ret = daemon::set_app_aot_flag(&BASH_PATH.to_string(), false);
    if ret != 0 {
        log::error!("Failed to unset flag for bash!");
        return ret;
    }
    // remove link
    daemon::db_remove_link(&BASH_LINK_PATH.to_string());
    // remove bash.rto
    let bash_rto = Path::new(BASH_RTO_PATH);
    match fs::remove_file(&bash_rto) {
        Ok(_) => {}
        Err(e) => {
            log::error!("remove file failed: {}", e);
            return -1;
        }
    }
    // rename bash.toml
    let bash_toml = Path::new(BASH_TOML_PATH);
    let bash_toml_err = bash_toml.with_extension("toml.err");
    match fs::rename(&bash_toml_err, &bash_toml) {
        Ok(_) => {}
        Err(e) => {
            log::error!("Mv failed: {}", e);
            return -1;
        }
    }
    return 0;
}

fn do_common_rollback(file_path: &String) -> i32 {
    let file_exist = Path::new(file_path).exists();
    if !file_exist {
        log::error!("{} is not exist!", file_path);
    }
     match fs::remove_file(&file_path) {
        Ok(_) => {}
        Err(e) => {
            log::error!("remove file failed: {}", e);
            return -1;
        }
    }
    return 0;
}

fn process_coredump_event(pid: i32) {
    // get file path by pid
    println!("process_coredump_event called ,pid is {}", pid);
    if PID_INFOS.lock().unwrap().contains_key(&pid) == false {
        log::info!("{} is not exist in PID_INFOS!", pid);
        return;
    }
    
    if let Some(file_path) = PID_INFOS.lock().unwrap().get(&pid) {
        log::info!("{} has create a coredump!", file_path);
        println!("{} has create a coredump!", file_path);
        if MERGE_FILES.lock().unwrap().contains(&file_path) == false {
            return;
        }
        
        if file_path == BASH_PATH {
            let ret = do_bash_rollback();
            if ret != 0 {
                log::error!("rollback bash failed!");
            }
        } else {
            let ret = do_common_rollback(file_path);
            if ret != 0 {
                log::error!("rollback {} failed!", file_path);
            }
        }
    }

    PID_INFOS.lock().unwrap().remove(&pid);
}

fn process_exit_event(pid: i32) {
    PID_INFOS.lock().unwrap().remove(&pid);
}

pub fn coredump_monitor_loop() {
    init_merge_file_list();
    let mut monitor = match PidMonitor::new() {
        Ok(p) => p,
        Err(e) => panic!("create PidMonitor failed: {}", e)
    };
    loop {
        match monitor.recv() {
            None => {}
            Some(event) => {
                match event {
                    PidEvent::Exec(pid) => process_exec_event(pid),
                    PidEvent::Coredump(pid) => process_coredump_event(pid),
                    PidEvent::Exit(pid) => process_exit_event(pid),
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::process::Command;

    const COREDUMP_TEST_PATH: &str = "tests/test_coredump/test.c";
    const EXCUTE_TEST_PATH: &str = "tests/test_coredump/test";

    fn add_merge_file(file_path: String) {
        MERGE_FILES.lock().unwrap().push(file_path);
    }

    #[test]
    fn test_coredump_monitor() {
        // create excute file
        let source_file = Path::new(COREDUMP_TEST_PATH);
        let source_file = match fs::canonicalize(source_file) {
            Ok(p) => p,
            Err(e) => {
                panic!("Failed to get realpath: {}", e);
            }
        };
        let source_file_exist = source_file.exists();
        assert!(source_file_exist == true, "coredump source file does not exist!");
        let excute_file = Path::new(EXCUTE_TEST_PATH);
        
        let output = Command::new("gcc").args(&["-o", &excute_file.to_str().unwrap(), &source_file.to_str().unwrap()])
                .output().expect("Faild to execute command!");
        if !output.status.success() {
            panic!("Failed to create excute file!");
        }
        let real_excute_file = match fs::canonicalize(excute_file) {
            Ok(p) => p,
            Err(e) => {
                panic!("Failed to get realpath: {}", e);
            }
        };
        
        let excute_file_exist = real_excute_file.exists();
        assert!(excute_file_exist == true, "excute file is not exist!");
        
        add_merge_file(real_excute_file.to_str().unwrap().to_string());
        println!("merge file list is {:?}", MERGE_FILES.lock().unwrap());
        // do coredump monitor
        let _coredump_monitor = thread::spawn(|| {
            coredump_monitor_loop();                
        });

        // excute a coredump action
        let excute_command = String::from("./") + excute_file.to_str().unwrap();
        let output = Command::new(&excute_command).output()
                .expect("Failed to excute command!");

        if output.status.success() {
            panic!("Coredump has not created!");
        }
        let excute_file_exist = excute_file.exists();
        assert!(excute_file_exist == false, "excute file is not deleted!");
    }
}
