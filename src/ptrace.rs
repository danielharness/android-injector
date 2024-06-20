//! Safety-enforcing wrapper for `ptrace`.

use std::marker::PhantomData;
use std::ptr;

use errno::{errno, Errno, set_errno};

use crate::InjectorError;

/// States of a process traced with `ptrace`.
pub trait TracedProcessState {}

/// Traced process is stopped.
pub struct Stopped;

impl TracedProcessState for Stopped {}

/// Traced process is running.
pub struct Running;

impl TracedProcessState for Running {}

/// Represents an address in a remote process.
#[derive(Copy, Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct RemoteAddress(pub u64);

impl From<RemoteAddress> for *mut libc::c_void {
    fn from(remote_address: RemoteAddress) -> Self {
        remote_address.0 as *mut libc::c_void
    }
}

pub struct TracedProcess<State: TracedProcessState> {
    pid: libc::pid_t,
    state: PhantomData<State>,
}

/// Wrapper for `ptrace` that handles wraps errors nicely.
unsafe fn ptrace_wrapper(
    request: libc::c_int, // TODO: `PtraceRequest` enum that derives `Debug`
    pid: libc::pid_t,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> Result<libc::c_long, InjectorError> {
    let is_peek = (request == libc::PTRACE_PEEKTEXT)
        || (request == libc::PTRACE_PEEKDATA)
        || (request == libc::PTRACE_PEEKUSER);
    if is_peek {
        // As per ptrace(2) - since `-1` is a valid return value for PTRACE_PEEK* operations,
        // clear `errno` before the operation and use it to check for errors.
        set_errno(Errno(0));
    }
    let res = unsafe { libc::ptrace(request, pid, addr, data) };
    if (is_peek && errno().0 != 0) || (!is_peek && res == -1) {
        return Err(InjectorError::Ptrace(std::io::Error::last_os_error(), pid));
    }
    Ok(res)
}

impl TracedProcess<Stopped> {
    /// Reads `len` bytes from given address in tracee.
    // pub fn read_memory(&self, address: RemoteAddress, len: usize) -> Result<Vec<u8>, InjectorError> {}

    /// Writes `data` to given address in tracee.
    // pub fn write_memory(&self, address: RemoteAddress, data: &[u8]) -> Result<(), InjectorError> {}

    /// Reads a long from given address in tracee.
    fn read_long(&self, address: RemoteAddress) -> Result<libc::c_long, InjectorError> {
        // SAFETY: Call to a safe C function.
        Ok(unsafe {
            ptrace_wrapper(
                libc::PTRACE_PEEKDATA,
                self.pid,
                address.into(),
                ptr::null_mut(),
            )
        }?)
    }

    /// Writes a long to given address in tracee.
    fn write_long(
        &mut self,
        address: RemoteAddress,
        data: libc::c_long,
    ) -> Result<(), InjectorError> {
        // SAFETY: This call affects the memory of the tracee.
        // For this process, it is a call to a safe C function.
        unsafe {
            ptrace_wrapper(
                libc::PTRACE_POKEDATA,
                self.pid,
                address.into(),
                data as *mut libc::c_void,
            )
        }?;
        Ok(())
    }
}

impl TracedProcess<Running> {
    /// Starts tracing process with given pid.
    /// Attaches to the process, and waits for it to stop before returning.
    pub fn attach(pid: libc::pid_t) -> Result<TracedProcess<Stopped>, InjectorError> {
        // SAFETY: Call to a safe C function.
        unsafe { ptrace_wrapper(libc::PTRACE_ATTACH, pid, ptr::null_mut(), ptr::null_mut()) }?;

        let traced_process = TracedProcess::<Running> {
            pid,
            state: Default::default(),
        };
        Ok(traced_process.wait()?)
    }

    /// Blocks until tracee is stopped (or exits, in which case an error is returned).
    pub fn wait(self) -> Result<TracedProcess<Stopped>, InjectorError> {
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
            "tracee pid {} is not in `tracing stop` state after attach",
            traced_process.pid
        );
    }
}
