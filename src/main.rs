#[macro_use]
extern crate log;
extern crate env_logger;
extern crate nix;
extern crate libc;

use nix::sys::ptrace;
use nix::sys::wait;
use nix::unistd::Pid;

use libc::{c_void, user_regs_struct};

use nix::errno::Errno;

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
        libc::ptrace(PTRACE_GETREGS as libc::c_uint,
                     libc::pid_t::from(pid),
                     ptr::null_mut::<user_regs_struct>(),
                     &data as *const _ as *const c_void)
    };
    Errno::result(res)?;
    Ok(data)
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

    loop {
        if let Ok(status) = wait::waitpid(Some(pid), None) {
            use wait::WaitStatus::*;
            
            match status {
                Exited(_, _) => break,                
                Stopped(_, signal) => {
                    println!("stopped by signal {:?}", signal);
                    let regs: user_regs_struct = getregs(pid).unwrap();

                    let syscall = regs.orig_rax as i64;
                    
                    if syscall == libc::SYS_write {
                        
                    }
                    
                    println!("0x{:X} 0x{:X} 0x{:X} 0x{:X}", regs.orig_rax, regs.rsi, regs.rdx, regs.rdi);
                }
                _=> continue,
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
