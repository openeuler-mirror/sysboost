#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

# Copyright (c) 2023 Huawei Technologies Co., Ltd.
# sysboost is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http:#license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# Create: 2023-9-25

import unittest
import subprocess
import os


'''
cmd 是字符串列表 ['xxx', 'xx']; cmd是命令行的时候, 需要带shell=True
subprocess.run(args, *, stdin=None, input=None, stdout=None, stderr=None, shell=False, timeout=None, check=False, encoding=None, errors=None, env=None, universal_newlines=None)
`stdin` 参数用于指定标准输入，`input` 参数用于指定输入内容，`stdout` 和 `stderr` 参数用于指定标准输出和标准错误输出，`shell` 参数用于指定是否使用 shell 执行命令，`timeout` 参数用于指定超时时间，`check` 参数用于指定是否检查返回值，`encoding` 和 `errors` 参数用于指定编码和错误处理方式，`env` 参数用于指定环境变量，`universal_newlines` 参数用于指定是否将输入输出转换为字符串。
`subprocess.run()` 的返回值是一个 `CompletedProcess` 对象，其中包含了执行结果的各种信息，例如返回值、标准输出、标准错误输出等。可以通过 `result.returncode` 获取返回值，通过 `result.stdout` 和 `result.stderr` 获取标准输出和标准错误输出。
'''
def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, check=False, capture_output=True, text=True)
    except Exception as e:
        print(e)
        return (-1, None)
    return (result.returncode, result.stdout)


def write_file(file_path, s):
    file = open(file_path, "w")
    file.write(s)
    file.close()


class TestSysboostd(unittest.TestCase):
    ''' 测试在线生成profile文件
        sysboostd --gen-profile=mysqld
        观察点: /usr/lib/sysboost.d/profile/mysqld.profile.now 是否正确生成
    '''
    def test_gen_profile(self):
        # 测试环境需要安装perf
        # yum install perf

        # 生成toml, 不是每个测试环境都有mysql, 用bash模拟测试
        run_cmd("mkdir -p /etc/sysboost.d")
        run_cmd("rm -f /etc/sysboost.d/mysqld.toml")
        s = '''elf_path = "/usr/bin/bash"
mode = "bolt"
'''
        write_file("/etc/sysboost.d/mysqld.toml", s)

        # 测试
        file_path = "/usr/lib/sysboost.d/profile/mysqld.profile.now"
        run_cmd("rm -f {}".format(file_path))
        ret,_ = run_cmd("sysboostd --gen-profile=mysqld")
        self.assertEqual(ret, 0)
        self.assertEqual(os.path.exists(file_path), True)

if __name__ == '__main__':
    unittest.main(verbosity=2)
