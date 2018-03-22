#[macro_use]
extern crate log;
extern crate env_logger;
extern crate nix;
extern crate libc;
extern crate byteorder;

use nix::sys::ptrace;
use nix::sys::wait;
use nix::unistd::Pid;
use nix::errno::Errno;
use nix::errno::Errno::ESRCH;
use nix::Error::Sys;
// use nix::sys::signal;

use libc::{c_void, user_regs_struct};

use byteorder::{NativeEndian, WriteBytesExt};

use std::env;
use std::str::FromStr;
use std::{mem, ptr};

// use std::thread::sleep;
// use std::time::Duration;

fn getregs(pid: Pid) -> nix::Result<user_regs_struct> {
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
fn peekdata(pid: Pid, addr: u64, size: usize) -> Vec<u8> {
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
fn peekdata(pid: Pid, addr: u32, size: usize) -> Vec<u8> {
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

fn main() {
    env_logger::init();

    let args = env::args().collect::<Vec<String>>();
    let pid = i32::from_str(&args[1]).unwrap();
    let pid = Pid::from_raw(pid);

    if ptrace::attach(pid).is_err() {
        debug!("Failed to attach: {}", pid);
        return;
    }
    debug!("Attached to {}", pid);

    if let Ok(status) = wait::waitpid(Some(pid), None) {
        use wait::WaitStatus::*;

        match status {
            Stopped(pid, _) => {
                let mut option = ptrace::Options::empty();
                option.set(ptrace::Options::PTRACE_O_TRACESYSGOOD, true);
                match ptrace::setoptions(pid, option) {
                    Ok(()) => {debug!("setoptions successed");}
                    Err(Sys(ESRCH)) => {
                        debug!("setoptions failed: ESRCH");
                        println!("Erorr exit");
                        return;
                    }
                    Err(sys) => {
                        debug!("setoptions failed: {:?}", sys);
                        println!("Erorr exit");
                        return;
                    }
                };
            }
            stat => {
                debug!("setoptions failed: {:?}", stat);
                println!("Error");
                return;
            }
        }
    } else {
        debug!("waitpid failed");
        println!("Error");
    }


    let mut is_enter_stopped = false;
    let mut prev_orig_rax: u64 = std::u64::MAX; // -1?

    ptrace::syscall(pid).unwrap();
    loop {
        if let Ok(status) = wait::waitpid(Some(pid), None) {
            use wait::WaitStatus::*;

            match status {
                Exited(_, _) => break,                
                PtraceSyscall(_) => {
                    let regs: user_regs_struct = getregs(pid).unwrap();

                    is_enter_stopped = if prev_orig_rax == regs.orig_rax {
                        !is_enter_stopped
                    } else {
                        true
                    };

                    prev_orig_rax = regs.orig_rax;

                    if is_enter_stopped && regs.orig_rax as i64 == libc::SYS_write {
                        debug!("============================");
                        debug!("orig_rax = 0x{:X}", regs.orig_rax);
                        debug!("rax = 0x{:X}", regs.rax);
                        debug!("rdi = 0x{:X}", regs.rdi);
                        debug!("rsi = 0x{:X}", regs.rsi);
                        debug!("rdx = 0x{:X}", regs.rdx);
                        debug!("============================");

                        let fd = regs.rdi;
                        let buf_addr = regs.rsi;
                        let size = regs.rdx;

                        if fd == 1 || fd == 2 {
                            let data = peekdata(pid, buf_addr as u64, size as usize);
                            // let data = u64vec_u8vec(data).unwrap();
                            // debug!("peekdata: {:?}", data);
                            unsafe {
                                let string = std::str::from_utf8_unchecked(&data);
                                // debug!("peekdata_string: {}", string);
                                if fd == 1 {
                                    print!("{}", string);
                                } else if fd == 2 {
                                    eprint!("{}", string);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        ptrace::syscall(pid).unwrap();
    }

    if ptrace::detach(pid).is_err() {
        debug!("Failed to detach: {}", pid);
        return;
    }

    debug!("Detached from {}", pid);
}
