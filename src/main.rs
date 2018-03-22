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

#[cfg(target_pointer_width = "64")]
fn regularize_num(num: usize) -> usize {
    let dif = 0x8 - (num % 0x8);
    let ret = num + dif;

    assert_eq!(ret % 0x8, 0);

    ret
}

#[cfg(target_pointer_width = "32")]
fn regularize_num(num: usize) -> usize {
    let dif = 0x4 - (num % 0x4);
    let ret = num + dif;

    assert_eq!(ret % 0x4, 0);

    ret
}

fn u64vec_u8vec(u64vec: Vec<u64>) -> Result<Vec<u8>, std::io::Error> {
    let mut dst: Vec<u8> = Vec::new();

    for u64_val in u64vec {
        dst.write_u64::<NativeEndian>(u64_val)?;
    }

    Ok(dst)
}

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

fn peekdata(pid: Pid, addr: u64, size: usize) -> Vec<u64> {
    use nix::sys::ptrace::Request::PTRACE_PEEKDATA;

    let mut dst: Vec<u64> = Vec::with_capacity(size);

    unsafe {
        // FIXME: increment error
        for i in 0..(regularize_num(size)) {
            let data = libc::ptrace(PTRACE_PEEKDATA as libc::c_uint, pid, addr + i as u64);
            dst.push(data as u64);
        }
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
                        println!("============================");
                        println!("orig_rax = 0x{:X}", regs.orig_rax);
                        println!("rax = 0x{:X}", regs.rax);
                        println!("rdi = 0x{:X}", regs.rdi);
                        println!("rsi = 0x{:X}", regs.rsi);
                        println!("rdx = 0x{:X}", regs.rdx);
                        println!("============================");

                        let fd = regs.rdi;
                        let buf_addr = regs.rsi;
                        let size = regs.rdx;

                        if fd == 1 || fd == 2 {
                            let data = peekdata(pid, buf_addr as u64, size as usize);
                            let data = u64vec_u8vec(data).unwrap();
                            // debug!("peekdata: {:?}", data);
                            unsafe {
                                let string = std::str::from_utf8_unchecked(&data);
                                debug!("peekdata_string: {}", string);
                            }
                            break;
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
