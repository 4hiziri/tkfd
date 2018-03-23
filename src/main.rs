#[macro_use]
extern crate log;
extern crate env_logger;
extern crate nix;
extern crate libc;
extern crate byteorder;
extern crate tkfd;

use nix::sys::ptrace;
use nix::sys::wait;
use nix::sys::signal;
use nix::unistd::Pid;
use nix::errno::Errno::ESRCH;
use nix::Error::Sys;

use libc::user_regs_struct;

use std::env;
use std::str::FromStr;
use std::process;

use tkfd::my_ptrace::*;

static mut PID_FOR_SIG: Option<Pid> = None;

fn checked_setoptions(pid: Pid) {
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
                        process::exit(1);
                    }
                    Err(sys) => {
                        debug!("setoptions failed: {:?}", sys);
                        println!("Erorr exit");
                        process::exit(1);
                    }
                };
            }
            stat => {
                debug!("setoptions failed: {:?}", stat);
                println!("Error");
                process::exit(1);
            }
        }
    } else {
        debug!("waitpid failed");
        println!("Error");
        process::exit(1);
    }
}

fn debug_regs(regs: user_regs_struct) {
    debug!("============================");
    debug!("orig_rax = 0x{:X}", regs.orig_rax);
    debug!("rax = 0x{:X}", regs.rax);
    debug!("rdi = 0x{:X}", regs.rdi);
    debug!("rsi = 0x{:X}", regs.rsi);
    debug!("rdx = 0x{:X}", regs.rdx);
    debug!("============================");
}

fn dump_mem(pid: Pid, regs: user_regs_struct) {
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

fn dump_loop(pid: Pid) {
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
                        dump_mem(pid, regs);
                        debug_regs(regs);
                    }
                }
                _ => {}
            }
        }

        ptrace::syscall(pid).unwrap();
    }
}

extern "C" fn handler_sigint(_: i32) {
    debug!("handler_sigint");

    let pid = unsafe { PID_FOR_SIG.unwrap() };

    match ptrace::detach(pid) {
        Ok(_) => debug!("Detach successed."),
        Err(_) => debug!("Failed to detach: {}", pid),
    }

    process::exit(1);
}

fn signal_setup() {
    let handler = signal::SigHandler::Handler(handler_sigint);
    let sig_action =
        signal::SigAction::new(handler, signal::SaFlags::empty(), signal::SigSet::empty());

    unsafe {
        signal::sigaction(signal::SIGINT, &sig_action).unwrap();
    }

}

fn main() {
    env_logger::init();

    let args = env::args().collect::<Vec<String>>();
    let pid = i32::from_str(&args[1]).unwrap();
    let pid = Pid::from_raw(pid);

    unsafe {
        PID_FOR_SIG = Some(pid);
    }

    signal_setup();

    if ptrace::attach(pid).is_err() {
        debug!("Failed to attach: {}", pid);
        return;
    }

    debug!("Attached to {}", pid);

    checked_setoptions(pid);

    dump_loop(pid);

    match ptrace::detach(pid) {
        Ok(_) => debug!("Detach successed."),
        Err(_) => debug!("Failed to detach: {}", pid),
    }
}
