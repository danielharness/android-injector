use procfs::process::{MMapPath, MMPermissions};

use common::child_factory::fork_sleeper;
use injector::{Error, ptrace};
use injector::process_trace::{RemoteAddress, Stopped, TracedProcess};

mod common;

#[test]
fn attach() {
    let child = fork_sleeper();
    let traced_process = TracedProcess::attach(*child).unwrap();
    let child_procfs = procfs::process::Process::new(child.as_raw()).unwrap();
    assert!(
        child_procfs.status().unwrap().state.starts_with('t'),
        "Tracee is not in \"tracing stop\" state after attach",
    );
    traced_process.detach().unwrap();
}

#[test]
fn read_write_memory() {
    let mut array: [u8; 4] = [1, 2, 3, 4];

    let child = fork_sleeper();
    let mut traced_process = TracedProcess::attach(*child).unwrap();
    let address_in_child = RemoteAddress(array.as_mut_ptr() as u64);
    let child_array = traced_process
        .read_memory(address_in_child, array.len())
        .unwrap();
    assert_eq!(child_array, [1, 2, 3, 4]);
    traced_process
        .write_memory(address_in_child, &[5, 6, 7, 8])
        .unwrap();
    let child_array = traced_process
        .read_memory(address_in_child, array.len())
        .unwrap();
    assert_eq!(child_array, [5, 6, 7, 8]);
    assert_eq!(array, [1, 2, 3, 4]);
    traced_process.detach().unwrap();
}

#[test]
fn get_registers() {
    let child = fork_sleeper();
    let traced_process = TracedProcess::attach(*child).unwrap();
    let (sp, pc) = match traced_process.get_regs().unwrap() {
        ptrace::UserRegs::Arm32(regs) => (regs.sp as u64, regs.pc as u64),
        ptrace::UserRegs::Arm64(regs) => (regs.sp, regs.pc),
    };

    let mut is_sp_valid = false;
    let mut is_pc_valid = false;
    let child_procfs = procfs::process::Process::new(child.as_raw()).unwrap();
    for map in child_procfs.maps().unwrap() {
        match map.pathname {
            MMapPath::Path(_) => {
                if (map.address.0 <= pc && pc <= map.address.1)
                    && map.perms.contains(MMPermissions::EXECUTE)
                {
                    is_pc_valid = true;
                }
            }
            MMapPath::Stack | MMapPath::TStack(_) => {
                if (map.address.0 <= sp) && (sp <= map.address.1) {
                    is_sp_valid = true;
                }
            }
            _ => (),
        }
    }

    assert!(
        is_sp_valid,
        "Tracee's sp register doesn't point to a stack region"
    );
    assert!(
        is_pc_valid,
        "Tracee's pc register doesn't point to executable memory"
    );

    traced_process.detach().unwrap();
}

#[test]
fn set_registers() {
    let child = fork_sleeper();
    let mut traced_process = TracedProcess::attach(*child).unwrap();
    match traced_process.get_regs().unwrap() {
        ptrace::UserRegs::Arm32(mut regs) => {
            regs.regs = [1234; 13];
            traced_process
                .set_regs(&ptrace::UserRegs::Arm32(regs))
                .unwrap();
            match traced_process.get_regs().unwrap() {
                ptrace::UserRegs::Arm32(new_regs) => assert_eq!(new_regs.regs, regs.regs),
                _ => panic!("Tracee changed architecture"),
            }
        }
        ptrace::UserRegs::Arm64(mut regs) => {
            regs.regs = [1234; 31];
            traced_process
                .set_regs(&ptrace::UserRegs::Arm64(regs))
                .unwrap();
            match traced_process.get_regs().unwrap() {
                ptrace::UserRegs::Arm64(new_regs) => assert_eq!(new_regs.regs, regs.regs),
                _ => panic!("Tracee changed architecture"),
            }
        }
    }

    traced_process.detach().unwrap();
}

#[test]
fn trace_signal() {
    let child = fork_sleeper();
    let traced_process = TracedProcess::attach(*child).unwrap().cont(None).unwrap();
    // SAFETY: There are no preconditions for the safety of this call.
    unsafe { libc::kill(child.as_raw(), libc::SIGUSR1) };
    let (traced_process, signal) = traced_process.wait_signal_stop().unwrap();
    assert_eq!(signal as i32, libc::SIGUSR1);
    traced_process.detach().unwrap();
}

#[test]
fn trace_syscall() {
    let get_syscall =
        |traced_process: &TracedProcess<Stopped>| match traced_process.get_regs().unwrap() {
            ptrace::UserRegs::Arm32(regs) => regs.regs[7] as libc::c_long,
            ptrace::UserRegs::Arm64(regs) => regs.regs[8] as libc::c_long,
        };

    let child = fork_sleeper();
    let traced_process = TracedProcess::attach(*child)
        .unwrap()
        .cont_syscall(None)
        .unwrap()
        .wait_syscall_stop()
        .unwrap();
    let enter_syscall = get_syscall(&traced_process);
    assert!(enter_syscall == libc::SYS_nanosleep || enter_syscall == libc::SYS_restart_syscall);

    let traced_process = traced_process
        .cont_syscall(None)
        .unwrap()
        .wait_syscall_stop()
        .unwrap();
    let exit_syscall = get_syscall(&traced_process);
    assert_eq!(exit_syscall, enter_syscall);

    traced_process.detach().unwrap();
}

#[test]
fn wait_on_exited_tracee() {
    let child = fork_sleeper();
    let traced_process = TracedProcess::attach(*child).unwrap().cont(None).unwrap();
    // SAFETY: There are no preconditions for the safety of this call.
    unsafe { libc::kill(child.as_raw(), libc::SIGKILL) };
    let wait_res = traced_process.wait_signal_stop();
    match wait_res {
        Err(Error::TraceeExited(..)) => (),
        _ => panic!("`wait` did not error properly after tracee exited"),
    }
}
