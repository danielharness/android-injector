//! Safety-enforcing wrapper for `ptrace`.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;

use errno::errno;
use scopeguard::{guard, ScopeGuard};

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
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RemoteAddress(pub u64);

/// Represents a process traced using `ptrace`.
/// The traced process is referred to as the "tracee", and the tracing process as the "tracer".
///
/// The tracee is automatically detached when [`TracedProcess`] goes out of scope. Errors detected
/// on detach are ignored. It is recommended to call [`TracedProcess<Stopped>::detach`] manually to
/// be able to handle errors cleanly.
///
/// # States
/// [`TracedProcess`] can be in one of two states: [`Stopped`] or [`Running`].
/// A stopped tracee is currently in "tracing stop". This means the tracer can safely interact with
/// it, as it is not currently executing code.
/// A running tracee is currently not in "tracing stop". This doesn't necessarily mean it is in the
/// "running" state as far the OS is concerned - it just means that it is not in "tracing stop",
/// so the tracer cannot safely interact with it.
pub struct TracedProcess<State: TracedProcessState> {
    pid: libc::pid_t,
    detach_guard: ScopeGuard<libc::pid_t, fn(libc::pid_t)>,
    state: PhantomData<State>,
}

impl TracedProcess<Running> {
    /// Starts tracing process with given pid.
    /// Attaches to the process, and waits for it to stop before returning.
    pub fn attach(pid: libc::pid_t) -> Result<TracedProcess<Stopped>, InjectorError> {
        // TODO: Maybe try to cancel the running syscall when attaching, using `PTRACE_SYSCALL`
        // and changing registers

        // SAFETY: There are no preconditions for the safety of this call.
        unsafe {
            ptrace_wrapper(
                libc::PTRACE_ATTACH,
                pid,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }?;

        let traced_process = TracedProcess::<Running> {
            pid,
            detach_guard: guard(pid, |pid| ptrace_detach(pid).unwrap_or(())),
            state: Default::default(),
        };
        traced_process.wait()
    }

    /// Blocks until tracee is stopped (or exits, in which case an error is returned).
    pub fn wait(self) -> Result<TracedProcess<Stopped>, InjectorError> {
        let (_, status) = waitpid_wrapper(self.pid, 0)?;

        // Ensure tracee stopped and not exited
        // TODO: `ExitReason` enum, with `ExitStatus(i32)` and `TermSignal(i32)`
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            // Cancel detach guard since tracee already exited
            ScopeGuard::into_inner(self.detach_guard);
            return Err(InjectorError::TraceeExited(self.pid));
        }

        Ok(TracedProcess::<Stopped> {
            pid: self.pid,
            detach_guard: self.detach_guard,
            state: Default::default(),
        })
    }
}

impl TracedProcess<Stopped> {
    /// Detaches from tracee. It will continue execution normally.
    pub fn detach(self) -> Result<(), InjectorError> {
        let res = ptrace_detach(self.pid);
        // Cancel detach guard
        ScopeGuard::into_inner(self.detach_guard);
        res
    }

    /// Reads `len` bytes from given address in tracee.
    pub fn read_memory(
        &self,
        address: RemoteAddress,
        len: usize,
    ) -> Result<Vec<u8>, InjectorError> {
        let mut mem_file = self.open_memory_file(OpenOptions::new().read(true))?;
        mem_file
            .seek(SeekFrom::Start(address.0))
            .map_err(|err| InjectorError::TraceeMemory(err, self.pid))?;
        let mut output = vec![0; len];
        mem_file
            .read(&mut output)
            .map_err(|err| InjectorError::TraceeMemory(err, self.pid))?;
        Ok(output)
    }

    /// Writes `data` to given address in tracee.
    pub fn write_memory(
        &mut self,
        address: RemoteAddress,
        data: &[u8],
    ) -> Result<(), InjectorError> {
        let mut mem_file = self.open_memory_file(OpenOptions::new().write(true))?;
        mem_file
            .seek(SeekFrom::Start(address.0))
            .map_err(|err| InjectorError::TraceeMemory(err, self.pid))?;
        mem_file
            .write(&data)
            .map_err(|err| InjectorError::TraceeMemory(err, self.pid))?;
        Ok(())
    }

    /// Opens `/proc/<tracee_pid>/mem` and returns a handle to it.
    fn open_memory_file(&self, open_options: &OpenOptions) -> Result<File, InjectorError> {
        let proc_mem_path = format!("/proc/{}/mem", self.pid);
        open_options
            .open(proc_mem_path)
            .map_err(|err| InjectorError::TraceeMemory(err, self.pid))
    }
}

/// Wrapper for `ptrace` that converts errors.
unsafe fn ptrace_wrapper(
    request: libc::c_int, // TODO: `PtraceRequest` enum that derives `Debug`
    pid: libc::pid_t,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> Result<libc::c_long, InjectorError> {
    let res = unsafe { libc::ptrace(request, pid, addr, data) };
    if res == -1 {
        return Err(InjectorError::Ptrace(std::io::Error::last_os_error(), pid));
    }
    Ok(res)
}

/// Detaches from tracee with given pid. It will continue execution normally.
fn ptrace_detach(pid: libc::pid_t) -> Result<(), InjectorError> {
    // SAFETY: There are no preconditions for the safety of this call.
    unsafe {
        ptrace_wrapper(
            libc::PTRACE_DETACH,
            pid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    }?;
    Ok(())
}

/// Wrapper for `waitpid` that converts errors and handles `EINTR`.
/// On success, returns a tuple of `waitpid` return value and wait status (see waitpid(2)).
fn waitpid_wrapper(
    pid: libc::pid_t,
    options: libc::c_int,
) -> Result<(libc::pid_t, libc::c_int), InjectorError> {
    let mut res;
    let mut status: libc::c_int = 0;

    // Loop to handle `EINTR`.
    loop {
        // SAFETY: The only mutable reference to `status` is passed to `waitpid`.
        // The next access to `status` is only after `waitpid` returns.
        res = unsafe { libc::waitpid(pid, &mut status as *mut _, options) };
        if res != -1 {
            break;
        }
        if errno().0 == libc::EINTR {
            continue;
        }
        return Err(InjectorError::Waitpid(std::io::Error::last_os_error(), pid));
    }

    Ok((res, status))
}

#[cfg(test)]
mod tests {
    // TODO: Child factory that returns a scope-guarded pid_t.

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
            "tracee pid {child_pid} is not in `tracing stop` state after attach",
        );
        traced_process.detach().unwrap();
    }

    #[test]
    fn memory_read_write() {
        const INITIAL_ARRAY_VALUE: [u8; 4] = [1, 2, 3, 4];
        let mut array: [u8; 4] = INITIAL_ARRAY_VALUE;

        // SAFETY: Child process and parent process call `_exit` and `waitpid`, respectively,
        // at end of scope.
        let res = unsafe { libc::fork() };
        match res {
            -1 => {
                let error = std::io::Error::last_os_error();
                panic!("Error in `fork` call: {}", error);
            }
            0 => {
                // Child
                // SAFETY: Only called in child process.
                defer! { unsafe { libc::_exit(0) }; }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            child_pid => {
                // Parent
                defer! { waitpid_wrapper(child_pid, 0).unwrap(); }
                let mut traced_process = TracedProcess::attach(child_pid).unwrap();
                let address_in_child = RemoteAddress(array.as_mut_ptr() as u64);
                let child_array = traced_process
                    .read_memory(address_in_child, array.len())
                    .unwrap();
                assert_eq!(child_array, INITIAL_ARRAY_VALUE);
                traced_process
                    .write_memory(address_in_child, &[0u8; 4])
                    .unwrap();
                let child_array = traced_process
                    .read_memory(address_in_child, array.len())
                    .unwrap();
                assert_eq!(child_array, [0u8; 4]);
                assert_eq!(array, INITIAL_ARRAY_VALUE);
                traced_process.detach().unwrap();
            }
        }
    }
}
