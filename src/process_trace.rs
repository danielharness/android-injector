//! Safety-enforcing wrapper for `ptrace`.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;

use nix::errno::Errno;
use nix::sys::wait;
use nix::unistd::Pid;
use scopeguard::{guard, ScopeGuard};

use crate::{Error, ptrace, Result};

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
    pid: Pid,
    detach_guard: ScopeGuard<Pid, fn(Pid)>,
    state: PhantomData<State>,
}

impl TracedProcess<Running> {
    /// Starts tracing process with given pid.
    /// Attaches to the process, and waits for it to stop before returning.
    pub fn attach(pid: Pid) -> Result<TracedProcess<Stopped>> {
        ptrace::attach(pid)?;

        let traced_process = TracedProcess::<Running> {
            pid,
            detach_guard: guard(pid, |pid| ptrace::detach(pid).unwrap_or(())),
            state: Default::default(),
        }
            .wait()?
            .0;

        ptrace::set_options(pid, libc::PTRACE_O_TRACESYSGOOD)?;

        Ok(traced_process)
    }

    /// Blocks until tracee is stopped, and returns the reason for stopping.
    /// If tracee exits, or if the wait fails, an error is returned.
    fn wait(self) -> Result<(TracedProcess<Stopped>, wait::WaitStatus)> {
        // Loop to handle `EINTR`.
        let res = loop {
            match wait::waitpid(Some(self.pid), None) {
                Err(err) if err == Errno::EINTR => continue,
                res => break res,
            }
        };

        match res {
            Ok(status @ wait::WaitStatus::Exited(..))
            | Ok(status @ wait::WaitStatus::Signaled(..)) => {
                // Cancel detach guard since tracee already exited
                ScopeGuard::into_inner(self.detach_guard);
                Err(Error::TraceeExited(self.pid, status))
            }

            Ok(status) => Ok((
                TracedProcess::<Stopped> {
                    pid: self.pid,
                    detach_guard: self.detach_guard,
                    state: Default::default(),
                },
                status,
            )),

            Err(err) => Err(Error::Waitpid(err.into(), self.pid)),
        }
    }
}

impl TracedProcess<Stopped> {
    /// Detaches from tracee. It will continue execution normally.
    pub fn detach(self) -> Result<()> {
        let res = ptrace::detach(self.pid);
        // Cancel detach guard
        ScopeGuard::into_inner(self.detach_guard);
        res
    }

    /// Reads `len` bytes from given address in tracee.
    pub fn read_memory(&self, address: RemoteAddress, len: usize) -> Result<Vec<u8>> {
        let mut mem_file = self.open_memory_file(OpenOptions::new().read(true))?;
        mem_file
            .seek(SeekFrom::Start(address.0))
            .map_err(|err| Error::TraceeMemory(err, self.pid))?;
        let mut output = vec![0; len];
        mem_file
            .read(&mut output)
            .map_err(|err| Error::TraceeMemory(err, self.pid))?;
        Ok(output)
    }

    /// Writes `data` to given address in tracee.
    pub fn write_memory(&mut self, address: RemoteAddress, data: &[u8]) -> Result<()> {
        let mut mem_file = self.open_memory_file(OpenOptions::new().write(true))?;
        mem_file
            .seek(SeekFrom::Start(address.0))
            .map_err(|err| Error::TraceeMemory(err, self.pid))?;
        mem_file
            .write(&data)
            .map_err(|err| Error::TraceeMemory(err, self.pid))?;
        Ok(())
    }

    /// Gets the general-purpose registers of tracee.
    pub fn get_regs(&self) -> Result<ptrace::UserRegs> {
        ptrace::get_gp_register_set(self.pid)
    }

    /// Sets the general-purpose registers of tracee.
    /// Providing a wrong register set for tracee's architecture will cause this function to return
    /// an error.
    pub fn set_regs(&mut self, user_regs: &ptrace::UserRegs) -> Result<()> {
        ptrace::set_gp_register_set(self.pid, user_regs)
    }

    /// Opens `/proc/<tracee_pid>/mem` and returns a handle to it.
    fn open_memory_file(&self, open_options: &OpenOptions) -> Result<File> {
        let proc_mem_path = format!("/proc/{}/mem", self.pid);
        open_options
            .open(proc_mem_path)
            .map_err(|err| Error::TraceeMemory(err, self.pid))
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use procfs::process::{MMapPath, MMPermissions};
    use scopeguard::defer;

    use super::*;

    /// Forks a child that sleeps in a loop. Returns a scope guard that kills the child and then
    /// waits on it.
    fn fork_sleeper() -> ScopeGuard<Pid, fn(Pid)> {
        // SAFETY: Child process calls `_exit` at end of scope. Parent process gets a scope guard
        // that kills the child and then waits on it.
        let res = unsafe { libc::fork() };
        match res {
            -1 => {
                let error = io::Error::last_os_error();
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
                let child_pid = Pid::from_raw(child_pid);
                guard(child_pid, |child_pid| {
                    // SAFETY: There are no preconditions for the safety of this call.
                    unsafe { libc::kill(child_pid.into(), libc::SIGKILL) };
                    wait::waitpid(child_pid, None).unwrap();
                })
            }
        }
    }

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
}
