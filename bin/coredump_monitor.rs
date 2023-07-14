use lazy_static::lazy_static;
use std::collections::HashMap;
use cnproc::PidMonitor;
use cnproc::PidEvent;
use std::sync::Mutex;
use std::fs;
use procfs::Process;

lazy_static! {
    static ref MERGE_FILES: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static ref PID_INFOS: Mutex<HashMap<i32, String>> = Mutex::new(HashMap::new());
}

// add merged file into vector, provide for testcase
fn add_merge_file(file_path: String) {
    MERGE_FILES.lock().unwrap().push(file_path);
}

fn init_merge_file_list() {
    MERGE_FILES.lock().unwrap().push(String::from("/usr/bin/bash.rto"));
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

fn process_coredump_event(pid: i32) {
    // get file path by pid
    if PID_INFOS.lock().unwrap().contains_key(&pid) == false {
        log::info!("{} is not exist in PID_INFOS!", pid);
        return;
    }
    
    if let Some(file_path) = PID_INFOS.lock().unwrap().get(&pid) {
        log::info!("{} has create a coredump!", file_path);
        if MERGE_FILES.lock().unwrap().contains(&file_path) {
            fs::remove_file(&file_path).expect("File delete failed!");
        }
    }

    PID_INFOS.lock().unwrap().remove(&pid);
}

fn process_exit_event(pid: i32) {
    PID_INFOS.lock().unwrap().remove(&pid);
}

pub fn coredump_monitor_loop() {
    init_merge_file_list();
    let mut monitor = PidMonitor::new().unwrap();
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

