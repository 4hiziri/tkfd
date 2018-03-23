use nix;
use nix::errno::Errno;
use nix::unistd::Pid;

use libc;
use libc::{c_void, user_regs_struct};

use byteorder::{NativeEndian, WriteBytesExt};

use std::{mem, ptr};


pub fn getregs(pid: Pid) -> nix::Result<user_regs_struct> {
    use nix::sys::ptrace::Request::PTRACE_GETREGS;

    // Creates an uninitialized pointer to store result in
    let data: user_regs_struct = unsafe { mem::uninitialized() };
    let res = unsafe {
        libc::ptrace(
            PTRACE_GETREGS as libc::c_uint,
            libc::pid_t::from(pid),
            ptr::null_mut::<user_regs_struct>(),
            &data as *const _ as *const c_void,
        )
    };

    Errno::result(res)?;
    Ok(data)
}

#[cfg(target_pointer_width = "64")]
pub fn peekdata(pid: Pid, addr: u64, size: usize) -> Vec<u8> {
    use nix::sys::ptrace::Request::PTRACE_PEEKDATA;

    let byte_len: usize = 8;
    let mut dst: Vec<u8> = Vec::with_capacity(size);
    let about_num = if size % byte_len == 0 {
        size / byte_len
    } else {
        size / byte_len + 1
    };

    for i in 0..about_num {
        unsafe {
            let i = i as u64;
            let data = libc::ptrace(
                PTRACE_PEEKDATA as libc::c_uint,
                pid,
                addr + i * byte_len as u64,
            );

            let mut buf: Vec<u8> = Vec::new();
            buf.write_u64::<NativeEndian>(data as u64).unwrap();
            dst.append(&mut buf);
        }
    }

    let over_len = (byte_len - size % byte_len) % byte_len;
    for _ in 0..over_len {
        dst.pop();
    }

    dst
}

#[cfg(target_pointer_width = "32")]
pub fn peekdata(pid: Pid, addr: u32, size: usize) -> Vec<u8> {
    use nix::sys::ptrace::Request::PTRACE_PEEKDATA;

    let byte_len: usize = 4;
    let mut dst: Vec<u8> = Vec::with_capacity(size);
    let about_num = if size % byte_len == 0 {
        size / byte_len
    } else {
        size / byte_len + 1
    };

    for i in 0..about_num {
        unsafe {
            // extract here?
            let i = i as u32;
            let data = libc::ptrace(
                PTRACE_PEEKDATA as libc::c_uint,
                pid,
                addr + i * byte_len as u32,
            );

            let mut buf: Vec<u8> = Vec::new();
            buf.write_u32::<NativeEndian>(data as u32).unwrap();
            dst.append(&mut buf);
        }
    }

    let over_len = (byte_len - size % byte_len) % byte_len;
    for _ in 0..over_len {
        dst.pop();
    }

    dst
}
