use lazy_static::lazy_static;
use std::collections::HashMap;
use cnproc::PidMonitor;
use cnproc::PidEvent;

lazy_static! {
    static ref pid_maps: HashMap<u32, &'static str> = HashMap::new();
}

fn process_exec_event(pid: i32) {
    // pid_maps.insert(pid, pname);
}

fn process_coredump_event(pid: i32) {
    println!("lyt coredump pid: {}", pid);
}

fn process_exit_event(pid: i32) {
    // pid_maps.remove(pid)
}

fn main_loop() {
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
