// Copyright (c) 2023 Huawei Technologies Co., Ltd.
// sysboost is licensed under the Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//     http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
// PURPOSE.
// See the Mulan PSL v2 for more details.
// Create: 2023-5-17


// test all sysboostd modes and features
#[cfg(test)]
mod tests {
	use std::fs;
	use std::fs::File;
	use std::io::Read;
	use std::io::Write;
	use std::process::Command;
	use std::io::{BufRead, BufReader};
	use std::{thread, time};
	use std::thread::sleep;
	use std::time::Duration;

	// Normal Scenarios
	// 1. try to start sysboostd, if sysboostd
	fn is_sysboostd_running() -> bool {
		// Start sysboostd service if it's not running
		let output = Command::new("systemctl").args(&["is-active", "sysboost.service"]).output().expect("Failed to execute command");

		if !output.status.success() {
			let output = Command::new("systemctl").args(&["start", "sysboost.service"]).output().expect("Failed to execute command");
			if !output.status.success() {
				panic!("Failed to start sysboostd service: {}", String::from_utf8_lossy(&output.stderr));
			}
		}

		// Check if sysboostd is running
		let output = Command::new("systemctl").args(&["is-active", "sysboost.service"]).output().expect("Failed to execute command");

		if output.status.success() {
			let stdout = String::from_utf8_lossy(&output.stdout);
			let status = stdout.trim();
			assert!(status == "active", "sysboostd is not running");
		}

		return true;
	}

	#[test]
	fn test_sysboostd_is_running() {
		// Check if sysboostd is running
		let sysboostd_running = is_sysboostd_running();
		assert!(sysboostd_running, "sysboostd is not running");
	}

	#[test]
	fn test_bash_rto_can_running() {
		// Remove old bash.rto file if it exists
		let bash_rto_path = "/usr/bin/bash.rto";
		if std::path::Path::new(bash_rto_path).exists() {
			match std::fs::remove_file(bash_rto_path) {
				Ok(_) => {},
				Err(e) => {
					panic!("Failed to remove old bash.rto file: {}", e);
				}
			};
		}
		// Create config file
		let config_file_path = "/etc/sysboost.d/bash.toml";
		let mut config_file = match File::create(config_file_path) {
			Ok(file) => file,
			Err(e) => {
				panic!("Failed to create config file: {}", e);
			}
		};
		writeln!(config_file, "elf_path = \"/usr/bin/bash\"").unwrap();
		writeln!(config_file, "mode = \"static\"").unwrap();
		writeln!(config_file, "libs = \"/usr/lib64/libtinfo.so.6\"").unwrap();

		// Restart sysboostd service
		let output = Command::new("systemctl").args(&["restart", "sysboost.service"]).output().expect("Failed to execute command");
		assert!(output.status.success(), "Failed to restart sysboostd service: {}", String::from_utf8_lossy(&output.stderr));

		// Check if bash.rto is generated
		let bash_rto_path = "/usr/bin/bash.rto";
		let bash_rto_exists = std::path::Path::new(bash_rto_path).exists();
		assert!(bash_rto_exists, "bash.rto is not generated");
	}

	#[test]
	fn test_delete_conf_app_unset() {
		let config_file_path = "/etc/sysboost.d/bash.toml";
		let bash_path = "/usr/bin/bash";
		match fs::remove_file(config_file_path) {
			Ok(_) => {}
			Err(_) => assert!(false, "fail to delete bash.toml"),
		}

		// Restart sysboostd service
		let output = Command::new("systemctl").args(&["restart", "sysboost.service"]).output().expect("Failed to execute command");
		assert!(output.status.success(), "Failed to restart sysboostd service: {}", String::from_utf8_lossy(&output.stderr));

		// read eflags of bash
		let mut file = match File::open(bash_path) {
			Ok(file) => file,
			Err(e) => {
				assert!(false, "Error opening file: {}", e);
				return;
			}
		};
		let mut buffer = [0; 256];
		if let Err(e) = file.read_exact(&mut buffer) {
			assert!(false, "Error reading file: {}", e);
			return;
		}

		let eflags = buffer[48] as u32 | (buffer[49] as u32) << 8 | (buffer[50] as u32) << 16 | (buffer[51] as u32) << 24;
		assert!(eflags == 0, "ELF file eflags is {}\nbuffer is {:?}", eflags, buffer);
	}

	#[test]
	fn test_replace_bash_rto_with_python() {
		// Replace bash.rto with Python
		let output = Command::new("/bin/sh")
			.arg("-c")
			.arg("sudo mv /usr/bin/bash.rto /usr/bin/bash.rto.bak; sudo cp /usr/bin/python3 /usr/bin/bash.rto")
			.output()
			.expect("Failed to execute command");

		// Check the status code of the command
		assert!(
			output.status.success(),
			"Failed to replace bash.rto with Python: {}",
			String::from_utf8_lossy(&output.stderr)
		);

		// Restart Bash and check if it's running Python
		let output = Command::new("bash")
			.args(&["-c", "\"print('Python is running')\""])
			.output()
			.expect("Failed to execute command");

		// Check the output of the Python program
		let stdout = String::from_utf8_lossy(&output.stdout);
		let stderr = String::from_utf8_lossy(&output.stderr);
		assert!(
			stdout.trim() == "Python is running",
			"Bash is not running Python: {}",
			stderr.trim()
		);
	}

	fn is_contain_log_message(message : &str) -> bool {
		let file_name = "/var/log/messages";
		let file = File::open(file_name).unwrap();
		let lines = BufReader::new(file).lines();

		for line in lines{
			if let Ok(data) = line {
				if data.contains(message) {
					return true;
				}
			}
		}

		return false;
	}

	fn clear_log_message() {
		let cmd_string = "> /var/log/messages".to_string();
		let output =  Command::new("bash").arg("-c").arg(cmd_string).output().expect("Failed to execute command");
		if !output.status.success() {
			panic!("Failed to clear file");
		}
	}

	#[test]
	fn test_print_log_messages() {
		// clear /var/log/message
		clear_log_message();
		// stop sysboost
		let output = Command::new("systemctl").args(&["is-active", "sysboost.service"]).output().expect("Failed to execute command");
		if output.status.success() {
			let output = Command::new("systemctl").args(&["stop", "sysboost.service"]).output().expect("Failed to execute command");
			if !output.status.success() {
				panic!("Failed to stop sysboostd service: {}", String::from_utf8_lossy(&output.stderr));
			}
		}

		let output = Command::new("systemctl").args(&["is-active", "sysboost.service"]).output().expect("Failed to execute command");
		if output.status.success() {
			let stdout = String::from_utf8_lossy(&output.stdout);
			let status = stdout.trim();
			assert!(status == "inactive", "sysboostd is running");
		}

		// start sysboost
		let output = Command::new("systemctl").args(&["start", "sysboost.service"]).output().expect("Failed to execute command");
		if !output.status.success() {
			panic!("Failed to start sysboostd service: {}", String::from_utf8_lossy(&output.stderr));
		}

		let output = Command::new("systemctl").args(&["is-active", "sysboost.service"]).output().expect("Failed to execute command");

		if output.status.success() {
			let stdout = String::from_utf8_lossy(&output.stdout);
			let status = stdout.trim();
			assert!(status == "active", "sysboostd is running");
		}
		// check log message
		let sleep_millis = time::Duration::from_millis(1000);
		thread::sleep(sleep_millis);
		let has_message =  is_contain_log_message("Started Run sysboost for Kunpeng CPU");
		assert!(has_message, "log info is not print in message!");
                let has_daemon_message =  is_contain_log_message("On Daemon");
                assert!(has_daemon_message, "log info is not print in message!");
	}

	// Unnormal Scenarios
	// 1、When sysboostd break
	#[test]
	fn test_restore_sysboostd_env() {
		// Create libtinfo.toml file in /etc/sysboost.d directory
		let toml_path = "/etc/sysboost.d/libtinfo.toml";
		let toml_content = "elf_path = '/usr/lib64/libtinfo.so' mode = 'bolt'";
		fs::write(toml_path, toml_content).unwrap();

		// Sleep for 3 seconds
		sleep(Duration::from_secs(3));

		// Delete libtinfo.toml file
		fs::remove_file(toml_path).unwrap();

		// Restart sysboostd service using systemctl
		let output = Command::new("systemctl")
			.arg("restart")
			.arg("sysboostd")
			.output()
			.unwrap();
		assert!(output.status.success());

		// Check if /var/lib/sysboost directory exists and has files
		let sysboost_dir = "/var/lib/sysboost";
		assert!(fs::metadata(sysboost_dir).unwrap().is_dir());
		assert!(fs::read_dir(sysboost_dir).unwrap().next().is_some());

		// Check if /usr/lib64/libtinfo.so.bak file exists
		let bak_path = "/usr/lib64/libtinfo.so.bak";
		assert!(fs::metadata(bak_path).unwrap().is_file());
	}

	fn kill_pid(pid: u32) {
		match Command::new("kill").arg("-9").arg(pid.to_string()).output() {
			Ok(_) => return,
			Err(_) => return
		}
	}

	fn read_file(path: &str) -> String {
		match fs::read_to_string(path) {
			Ok(content) => content,
			Err(_) => String::new(),
		}
	}

	// cargo test --test test_sysboostd -- tests::test_symbolic_link --exact --nocapture
	// 测试命令是否正确设置链接flag
	// sysboost -s /usr/bin/bash
	// 设置后, 执行 bash &
	// 观察点: /proc/pid/maps 里面包含 bash.rto 文件路径
	#[test]
	fn test_symbolic_link() {
		let mut child = Command::new("sysboost").arg("-s").arg("/usr/bin/bash").spawn().expect("Failed to execute command");
		let ret = child.wait().expect("wait child fail").code().expect("get return value fail");
		assert!(ret == 0, "command fail, ret={}", ret);

		let child = Command::new("bash").arg("&").spawn().expect("Failed to execute command");
		let c_pid = child.id();

		let maps_path = format!("/proc/{}/maps", c_pid);
		let contents = read_file(maps_path.as_str());
		assert!(contents.contains("bash.rto"), "contains bash.rto, \n{}", contents);

		kill_pid(c_pid);
	}
}

