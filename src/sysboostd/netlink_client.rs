// Copyright (c) 2023 Huawei Technologies Co., Ltd.
// sysboost is licensed under the Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//     http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
// PURPOSE.
// See the Mulan PSL v2 for more details.
// Create: 2023-10-26

use libc;
use std::io::{Error, Result};

pub const GRP_NUMBER:  i32 = 21;
pub const PATH_MAX: usize = 4096;

#[inline]
fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

#[inline]
fn nlmsg_hdrlen() -> usize {
    nlmsg_align(std::mem::size_of::<libc::nlmsghdr>())
}

#[inline]
fn nlmsg_length(len: usize) -> usize {
    len + nlmsg_hdrlen()
}

#[repr(C)]
#[derive(Debug)]
pub struct crash_info {
    pub len: libc::c_int,
    pub path: [libc::c_char; PATH_MAX]
}

pub fn open_netlink() -> Result<i32> {
    let group = GRP_NUMBER;
    let sock: i32 = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW,
            // for some reason bindgen doesn't make this
            // a libc::c_int
            libc::NETLINK_USERSOCK as i32,
        )
    };
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = std::process::id();
    if unsafe {
        libc::bind(
            sock,
            &addr as *const libc::sockaddr_nl as _,
            std::mem::size_of_val(&addr) as _,
        )
    } < 0
    {
        return Err(Error::last_os_error());
    }
    if unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_NETLINK,
            libc::NETLINK_ADD_MEMBERSHIP as i32,
            &group as *const libc::c_int as _,
            std::mem::size_of_val(&group) as _,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    return Ok(sock);
}
pub fn read_event(sock: i32) -> Result<String> {
    let mut buffer: [libc::c_char;65536] = [0; 65536];
    let mut nladdr = unsafe { std::mem::zeroed() };
    let mut iov_vec = libc::iovec {
        iov_len: std::mem::size_of_val(&buffer) as _,
        iov_base: buffer.as_mut_ptr() as _,
    };
    let mut msg:libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut nladdr as *mut libc::sockaddr_nl as _;
    msg.msg_namelen = std::mem::size_of_val(&nladdr) as _;
    msg.msg_iov = &mut iov_vec as *mut libc::iovec as _;
    msg.msg_iovlen = 1;
    
    let len = unsafe {libc::recvmsg(sock, &mut msg as *mut libc::msghdr as _, 0)};
    if len < 0 {
        return Err(Error::last_os_error());
    }
    let header = buffer.as_ptr() as *const libc::nlmsghdr;
    let msg = (header as usize + nlmsg_length(0)) as *const crash_info;
    let slice = unsafe{core::slice::from_raw_parts((*msg).path.as_ptr(), (*msg).len as usize)};
    let data = core::str::from_utf8(slice).unwrap();
    return Ok(data.to_string());
}