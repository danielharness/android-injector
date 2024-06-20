//! Safety-enforcing wrapper for `ptrace`.

use std::fmt::{Debug, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;

use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
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

impl Debug for RemoteAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RemoteAddress")
            .field(&format_args!("0x{:x}", self.0))
            .finish()
    }
}

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
    pub pid: Pid,
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

    /// Blocks until tracee is stopped by a signal.
    /// If tracee exits, or if the wait fails, an error is returned.
    pub fn wait_signal_stop(self) -> Result<(TracedProcess<Stopped>, Signal)> {
        let (mut traced_process, mut wait_status) = self.wait()?;
        loop {
            (traced_process, wait_status) = match wait_status {
                WaitStatus::Stopped(_, signal) => break Ok((traced_process, signal)),
                _ => traced_process.cont(None)?.wait()?,
            }
        }
    }

    /// Blocks until tracee is stopped at entry or exit from a system call.
    /// If tracee exits, or if the wait fails, an error is returned.
    pub fn wait_syscall_stop(self) -> Result<TracedProcess<Stopped>> {
        let (mut traced_process, mut wait_status) = self.wait()?;
        loop {
            (traced_process, wait_status) = match wait_status {
                WaitStatus::Stopped(_, signal) => {
                    traced_process.cont_syscall(Some(signal))?.wait()?
                }
                WaitStatus::PtraceSyscall(..) => break Ok(traced_process),
                _ => traced_process.cont_syscall(None)?.wait()?,
            }
        }
    }

    /// Blocks until tracee is stopped, and returns the reason for stopping.
    /// If tracee exits, or if the wait fails, an error is returned.
    pub fn wait(self) -> Result<(TracedProcess<Stopped>, WaitStatus)> {
        // Loop to handle `EINTR`.
        let res = loop {
            match waitpid(Some(self.pid), None) {
                Err(err) if err == Errno::EINTR => continue,
                res => break res,
            }
        };

        match res {
            Ok(status @ WaitStatus::Exited(..)) | Ok(status @ WaitStatus::Signaled(..)) => {
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

    /// Restarts tracee, letting it continue execution normally.
    /// Optionally delivers given signal to tracee. If the tracee is not currently stopped due to a
    /// signal, no signal will be delivered.
    pub fn cont(self, signal: Option<Signal>) -> Result<TracedProcess<Running>> {
        ptrace::cont(self.pid, signal)?;
        Ok(TracedProcess::<Running> {
            pid: self.pid,
            detach_guard: self.detach_guard,
            state: Default::default(),
        })
    }

    /// Restarts tracee, letting it continue execution normally.
    /// It will automatically be stopped at the next entry to or exit from a system call.
    /// Optionally delivers given signal to tracee. If the tracee is not currently stopped due to a
    /// signal, no signal will be delivered.
    pub fn cont_syscall(self, signal: Option<Signal>) -> Result<TracedProcess<Running>> {
        ptrace::syscall(self.pid, signal)?;
        Ok(TracedProcess::<Running> {
            pid: self.pid,
            detach_guard: self.detach_guard,
            state: Default::default(),
        })
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
