use std::fs;
use std::path::Path;
use std::os::unix::fs as UnixFs;
use std::fs::OpenOptions;
use std::io::{Write, Read};
use std::io::BufRead;

use crate::aot::{set_rto_link_flag, set_app_link_flag};
use crate::coredump_monitor::set_mode;
use crate::lib::process_ext::run_child;
use crate::daemon::{SYSBOOST_DB_PATH, self};

pub const OPTIMIZED_ELF_LOG: &str = "/etc/sysboost.d/.optimized.log";

pub fn write_back_config(name: &str) -> i32 {
        let exist = Path::new(&OPTIMIZED_ELF_LOG).exists();
        if !exist {
            let _ = std::fs::File::create(OPTIMIZED_ELF_LOG.to_string());
            set_mode(OPTIMIZED_ELF_LOG);
        }
        let file_name = Path::new(&OPTIMIZED_ELF_LOG);
        let mut file = match OpenOptions::new().append(true).open(file_name) {
            Ok(f) => {f}
            Err(e) => {
                log::error!("open {} failed: {}", OPTIMIZED_ELF_LOG, e);
                return -1;
            }
        };
        let content = format!("{}\n", name);
        match file.write_all(content.as_bytes()) {
                Ok(_) => {return 0;}
                Err(e) => {
                    log::error!("write {} failed: {}", OPTIMIZED_ELF_LOG, e);
                    return -1;
                }   
        }
}
pub fn delete_one_record(name: &str) -> i32 {
    let exist = Path::new(&OPTIMIZED_ELF_LOG).exists();
    if !exist {
            return 0;
    }
    let file_name = Path::new(&OPTIMIZED_ELF_LOG);
    let rfile = match OpenOptions::new().read(true).open(file_name) {
        Ok(f) => {f}
        Err(e) => {
            log::error!("open {} failed: {}", OPTIMIZED_ELF_LOG, e);
            return -1;
        }
    };
    let mut buf = String::new();
    let reader = std::io::BufReader::new(&rfile);
    for line in reader.lines() {
        if line.as_ref().unwrap().contains(name){
            continue;
        }
        buf.push_str(line.as_ref().unwrap());
        buf.push_str("\n")
    }
    let mut wfile = match OpenOptions::new().truncate(true).write(true).open(file_name) {
        Ok(f) => {f}
        Err(e) => {
            log::error!("open {} failed: {}", OPTIMIZED_ELF_LOG, e);
            return -1;
        }
    };
    match wfile.write_all(buf.as_bytes()) {
        Ok(_) => {return 0;}
        Err(e) => {
            log::error!("write {} failed: {}", OPTIMIZED_ELF_LOG, e);
            return -1;
        }   
    }

}
pub fn bolt_add_link(file_name: &str) -> i32 {
	// symlink app.link to app, different modes correspond to different directories
	let names: Vec<&str> = file_name.split("/").collect();
	let binary_name = names[names.len() - 1];
	let link_path = format!("{}{}.link", SYSBOOST_DB_PATH, binary_name);
	let ret_e = UnixFs::symlink(&binary_name, &link_path);
	match ret_e {
		Ok(_) => log::info!("symlink sucess {}", link_path),
		Err(_) => {
			log::error!("symlink fail {}", link_path);
			return -1;
		}
	};
	0
}

pub fn gen_bolt_optimize_bin(name: &str, bolt_option: &str, profile_path: &str) -> i32 {
	let mut args: Vec<String> = Vec::new();
	if bolt_option.is_empty() {
		args.push("-reorder-blocks=ext-tsp".to_string());
		args.push("-reorder-functions=hfsort".to_string());
		args.push("-split-functions".to_string());
		args.push("-split-all-cold".to_string());
		args.push("-split-eh".to_string());
		args.push("-dyno-stats".to_string());
	} else {
		let options: Vec<&str> = bolt_option.split(" ").collect();
		for option in options{
			args.push(option.to_string());
		}
	}
	let elf_path = Path::new(name);
	let elf_path = match fs::canonicalize(elf_path) {
		Ok(p) => p,
		Err(e) => {
			log::error!("bolt_optimize_bin: get realpath failed: {}", e);
			return -1;
		}
	};
	let rto_path = elf_path.with_extension("rto");
	args.push(name.to_string());
	args.push("-o".to_string());
	args.push(rto_path.to_str().unwrap().to_string());
	args.push(format!("-data={}", profile_path));
	let mut ret = run_child("/usr/bin/llvm-bolt", &args);
	if ret != 0 {
		return ret;
	}
	ret = set_rto_link_flag(&rto_path.to_str().unwrap().to_string(), true);
	ret = set_app_link_flag(&name.to_string(), true);
	ret = bolt_add_link(name);
	return ret;

}

pub fn stop_one_elf(path: &str) -> i32 {
	let names: Vec<&str> = path.split("/").collect();
	let binary_name = names[names.len() - 1];
	let rto_path = format!("{}.rto", path);
	// unset flag
	let ret = set_app_link_flag(&path.to_string(), false);
	if ret != 0 {
		log::error!("Failed to unset link flag for {}", path);
		return ret;
	}
	// remove link
	let link_path = format!("{}{}.link", SYSBOOST_DB_PATH, binary_name);
	daemon::db_remove_link(&link_path);

	// remove xx.rto
	let exist = Path::new(&rto_path).exists();
	if exist {
		match fs::remove_file(&rto_path) {
			Ok(_) => {}
			Err(e) => {
				log::error!("remove file failed: {}", e);
			}
		}
	}  
	0      
}