//! Safety-enforcing wrapper for `ptrace`.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::mem::{MaybeUninit, size_of, size_of_val};

use errno::errno;
use scopeguard::{guard, ScopeGuard};

use crate::InjectorError;

/// States of a process traced with `ptrace`.
pub trait TracedProcessState {}

/// Traced process is in "tracing stop".
pub struct Stopped;

impl TracedProcessState for Stopped {}

/// Traced process is not in "tracing stop".
pub struct Running;

impl TracedProcessState for Running {}

/// Represents an address in a remote process.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RemoteAddress(pub u64);

/// User registers as provided by `ptrace` for arm32 processes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Arm32UserRegs {
    pub regs: [u32; 13],
    pub sp: u32,
    pub lr: u32,
    pub pc: u32,
    pub cpsr: u32,
    pub orig_r0: u32,
}

/// User registers as provided by `ptrace` for arm64 processes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Arm64UserRegs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// Possible sets of user registers a process might have.
pub enum UserRegs {
    Arm32(Arm32UserRegs),
    Arm64(Arm64UserRegs),
}

/// Union of possible sets of user registers used as input to `PTRACE_*REGSET` requests.
#[repr(C)]
union PtraceRegSetUserRegs {
    arm32: Arm32UserRegs,
    arm64: Arm64UserRegs,
}

/// This constant makes `PTRACE_*REGSET` requests refer to general-purpose registers. It is not
/// defined in android, but still supported.
const NT_PRSTATUS: libc::c_int = 1;

// TODO: Examples
/// Represents a process traced using `ptrace`.
/// The traced process is referred to as the "tracee", and the tracing process as the "tracer".
///
/// The tracee is automatically detached when [`TracedProcess`] goes out of scope. Errors detected
/// on detach are ignored. It is recommended to call [`TracedProcess<Stopped>::detach`] manually to
/// be able to handle errors cleanly.
///
/// # States
///
/// [`TracedProcess`] can be in one of two states: [`Stopped`] or [`Running`].
/// A stopped tracee is currently in "tracing stop". This means the tracer can safely interact with
/// it, as it is not currently executing code.
/// A running tracee is currently not in "tracing stop". This doesn't necessarily mean it is in the
/// "running" state as far the OS is concerned - it just means that it is not in "tracing stop",
/// so the tracer cannot safely interact with it.
///
/// # Safety
///
/// The provided APIs are safe to use for the tracer. However, as they allow direct manipulation of
/// many aspects of the traced process, they are very much unsafe for the tracee. Much care is
/// required to not cause unintended or undefined behaviour in the tracee.
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
        // to block before the syscall restart and changing syscall register to something invalid.

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

    /// Gets the general-purpose registers of tracee.
    pub fn get_regs(&self) -> Result<UserRegs, InjectorError> {
        let mut regs = MaybeUninit::<PtraceRegSetUserRegs>::uninit();
        let mut iovec = libc::iovec {
            iov_base: regs.as_mut_ptr() as *mut libc::c_void,
            iov_len: size_of_val(&regs),
        };
        // SAFETY: At most `iovec.iov_len` bytes will be written to the address of `regs`.
        // Since `iovec.iov_len` is set to the size of `regs`, the write is guaranteed to not
        // overflow.
        unsafe {
            ptrace_wrapper(
                libc::PTRACE_GETREGSET,
                self.pid,
                NT_PRSTATUS as *mut libc::c_void,
                (&mut iovec as *mut _) as *mut libc::c_void,
            )
        }?;

        const ARM32_USER_REGS_SIZE: usize = size_of::<Arm32UserRegs>();
        const ARM64_USER_REGS_SIZE: usize = size_of::<Arm64UserRegs>();
        match iovec.iov_len {
            // SAFETY: The `PTRACE_GETREGSET` request returned successfully, and based on the size
            // it placed in `iovec.iov_len`, it populated `regs` as if it were `Arm32UserRegs`.
            // Thus the union (1) is initialised and (2) refers to the field `arm32`.
            ARM32_USER_REGS_SIZE => Ok(UserRegs::Arm32(unsafe { regs.assume_init().arm32 })),
            // SAFETY: The `PTRACE_GETREGSET` request returned successfully, and based on the size
            // it placed in `iovec.iov_len`, it populated `regs` as if it were `Arm64UserRegs`.
            // Thus the union (1) is initialised and (2) refers to the field `arm64`.
            ARM64_USER_REGS_SIZE => Ok(UserRegs::Arm64(unsafe { regs.assume_init().arm64 })),
            _ => Err(InjectorError::UnsupportedTraceeArchitecture(self.pid)),
        }
    }

    /// Sets the general-purpose registers of tracee.
    /// Providing a wrong register set for tracee's architecture will cause this function to return
    /// an error.
    pub fn set_regs(&mut self, user_regs: &UserRegs) -> Result<(), InjectorError> {
        let (mut regs, regs_size) = match user_regs {
            UserRegs::Arm32(regs) => (PtraceRegSetUserRegs { arm32: *regs }, size_of_val(regs)),
            UserRegs::Arm64(regs) => (PtraceRegSetUserRegs { arm64: *regs }, size_of_val(regs)),
        };
        let mut iovec = libc::iovec {
            iov_base: (&mut regs as *mut _) as *mut libc::c_void,
            iov_len: regs_size,
        };
        // SAFETY: At most `iovec.iov_len` bytes will be read from the address of `regs`.
        // Since `iovec.iov_len` is set to the size of the initialized field in the union `regs`,
        // only valid data will be read.
        unsafe {
            ptrace_wrapper(
                libc::PTRACE_SETREGSET,
                self.pid,
                NT_PRSTATUS as *mut libc::c_void,
                (&mut iovec as *mut _) as *mut libc::c_void,
            )
        }?;
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

    use procfs::process::{MMapPath, MMPermissions};
    use scopeguard::defer;

    use super::*;

    /// Forks a child that sleeps in a loop. Returns a scope guard that kills the child and then
    /// waits on it.
    fn fork_sleeper() -> ScopeGuard<libc::pid_t, fn(libc::pid_t)> {
        // SAFETY: Child process calls `_exit` at end of scope. Parent process gets a scope guard
        // that kills the child and then waits on it.
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
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
            child_pid => {
                // Parent
                guard(child_pid, |child_pid| {
                    // SAFETY: There are no preconditions for the safety of this call.
                    unsafe { libc::kill(child_pid, libc::SIGKILL) };
                    waitpid_wrapper(child_pid, 0).unwrap();
                })
            }
        }
    }

    #[test]
    fn attach() {
        let child = fork_sleeper();
        let traced_process = TracedProcess::attach(*child).unwrap();
        let child_procfs = procfs::process::Process::new(*child).unwrap();
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
            UserRegs::Arm32(regs) => (regs.sp as u64, regs.pc as u64),
            UserRegs::Arm64(regs) => (regs.sp, regs.pc),
        };

        let mut is_sp_valid = false;
        let mut is_pc_valid = false;
        let child_procfs = procfs::process::Process::new(*child).unwrap();
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
            UserRegs::Arm32(mut regs) => {
                regs.regs = [1234; 13];
                traced_process.set_regs(&UserRegs::Arm32(regs)).unwrap();
                match traced_process.get_regs().unwrap() {
                    UserRegs::Arm32(new_regs) => assert_eq!(new_regs.regs, regs.regs),
                    _ => panic!("Tracee changed architecture"),
                }
            }
            UserRegs::Arm64(mut regs) => {
                regs.regs = [1234; 31];
                traced_process.set_regs(&UserRegs::Arm64(regs)).unwrap();
                match traced_process.get_regs().unwrap() {
                    UserRegs::Arm64(new_regs) => assert_eq!(new_regs.regs, regs.regs),
                    _ => panic!("Tracee changed architecture"),
                }
            }
        }

        traced_process.detach().unwrap();
    }
}
