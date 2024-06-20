//! Safety-enforcing wrapper for `ptrace`.

use std::marker::PhantomData;

use errno::errno;

use crate::InjectorError;

/// States of a process traced with `ptrace`.
pub trait TracedProcessState {}

/// Traced process is stopped.
pub struct Stopped;

impl TracedProcessState for Stopped {}

/// Traced process is running.
pub struct Running;

impl TracedProcessState for Running {}

pub struct TracedProcess<State: TracedProcessState> {
    pid: libc::pid_t,
    state: PhantomData<State>,
}

impl TracedProcess<Stopped> {}

impl TracedProcess<Running> {
    /// Starts tracing process with given pid.
    /// Attaches to the process, and waits for it to stop before returning.
    pub fn attach(pid: libc::pid_t) -> Result<TracedProcess<Stopped>, InjectorError> {
        // SAFETY: Call to a safe C function.
        let res = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid) };
        if res == -1 {
            return Err(InjectorError::Ptrace(std::io::Error::last_os_error(), pid));
        }

        let traced_process = TracedProcess::<Running> {
            pid,
            state: Default::default(),
        };
        Ok(traced_process.wait()?)
    }

    /// Blocks until tracee is stopped (or exits, in which case an error is returned).
    fn wait(self) -> Result<TracedProcess<Stopped>, InjectorError> {
        let mut status: libc::c_int = 0;
        loop {
            // SAFETY: The only mutable reference to `status` is passed to `waitpid`.
            // The next access to `status` is only after `waitpid` returns.
            let res = unsafe { libc::waitpid(self.pid, &mut status as *mut _, 0) };
            if res != -1 {
                break;
            }
            if errno().0 == libc::EINTR {
                continue;
            }
            return Err(InjectorError::Waitpid(std::io::Error::last_os_error()));
        }

        // Ensure tracee stopped and not exited
        // TODO: `ExitReason` enum, with `ExitStatus(i32)` and `TermSignal(i32)`
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Err(InjectorError::TraceeExited(self.pid));
        }

        Ok(TracedProcess::<Stopped> {
            pid: self.pid,
            state: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use scopeguard::defer;

    use super::*;

    #[test]
    fn attach() {
        let mut child = Command::new("cat").arg("/dev/random").spawn().unwrap();
        let child_pid = child.id() as libc::pid_t;
        defer! {
            child.kill().unwrap();
            child.wait().unwrap();
        }

        let traced_process = TracedProcess::attach(child_pid).unwrap();
        let child_procfs = procfs::process::Process::new(child_pid).unwrap();
        assert!(
            child_procfs.status().unwrap().state.starts_with('t'),
            "tracee pid {} is not in `tracing stop` state after attach", traced_process.pid
        );
    }
}
