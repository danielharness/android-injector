use nix::sys::signal;
use nix::sys::signal::Signal;

use crate::{Error, Result};
use crate::process_trace::{Stopped, TracedProcess};

/// Interrupts the current system call a traced process is executing.
pub fn interrupt_syscall(
    mut traced_process: TracedProcess<Stopped>,
) -> Result<TracedProcess<Stopped>> {
    let running = traced_process.cont_syscall(None)?;
    // Use `SIGCHLD` to interrupt the system call as it is a harmless signal
    signal::kill(running.pid, Some(Signal::SIGCHLD))
        .map_err(|err| Error::Waitpid(err.into(), running.pid))?;
    // Wait for system call to finish (two events - syscall enter and syscall exit)
    traced_process = running
        .wait_syscall_stop()?
        .cont_syscall(None)?
        .wait_syscall_stop()?;
    Ok(traced_process)
}

/// Waits for a traced process to hit a breakpoint (i.e. receive `SIGTRAP`).
pub fn wait_for_breakpoint(
    mut traced_process: TracedProcess<Stopped>,
) -> Result<TracedProcess<Stopped>> {
    let mut previous_stop_signal: Option<Signal> = None;
    loop {
        let current_stop_signal;
        (traced_process, current_stop_signal) = traced_process
            .cont(previous_stop_signal)?
            .wait_signal_stop()?;
        if current_stop_signal == Signal::SIGTRAP {
            break;
        }
        previous_stop_signal = Some(current_stop_signal);
    }
    Ok(traced_process)
}
