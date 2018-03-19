#[macro_use]
extern crate log;
extern crate env_logger;
extern crate nix;
extern crate libc;

use nix::sys::ptrace;
use nix::sys::wait;
use nix::unistd::Pid;
use nix::errno::Errno;
use nix::errno::Errno::ESRCH;
use nix::Error::Sys;
use nix::sys::signal;

use libc::{c_void, user_regs_struct};

use std::env;
use std::str::FromStr;
use std::{mem, ptr};

use std::thread::sleep;
use std::time::Duration;

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

fn peekdata(pid: Pid, addr: u64, size: u64) {
    // TODO: peekdata size
    for i in 0..size {
        println!("{}", i);
    }
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

    let mut option = ptrace::Options::empty();
    option.set(ptrace::Options::PTRACE_O_TRACESYSGOOD, true);
    match ptrace::setoptions(pid, option) {
        Ok(()) => (),
        Err(Sys(ESRCH)) => {
            ptrace::detach(pid).unwrap();
        }
        Err(_) => {
            ptrace::detach(pid).unwrap();
        }
    };

    let mut is_enter_stopped = false;
    let mut prev_orig_rax: u64 = std::u64::MAX; // -1?

    loop {
        if let Ok(status) = wait::waitpid(Some(pid), None) {
            use wait::WaitStatus::*;

            debug!("status: {:?}", status);

            match status {
                Exited(_, _) => break,                
                PtraceSyscall(_) => {
                    let regs: user_regs_struct = getregs(pid).unwrap();

                    is_enter_stopped = if prev_orig_rax == regs.orig_rax {
                        !is_enter_stopped
                    } else {
                        true
                    };

                    debug!("regs: {:?}", regs.orig_rax);

                    if is_enter_stopped && regs.orig_rax as i64 == libc::SYS_write {
                        println!("============================");
                        println!("orig_rax = 0x{:X}", regs.orig_rax);
                        println!("rax = 0x{:X}", regs.rax);
                        println!("rsi = 0x{:X}", regs.rsi);
                        println!("rdx = 0x{:X}", regs.rdx);
                        println!("rdi = 0x{:X}", regs.rdi);
                        println!("============================");

                        peekdata(pid, 0, 0);
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
