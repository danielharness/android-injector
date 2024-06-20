//! A shellcode injector for android that supports arm32 and arm46.

#![cfg(all(
    target_os = "android",
    any(target_arch = "arm", target_arch = "aarch64")
))]

use std::path::PathBuf;

use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;

pub use injector::*;

pub mod injector;
pub mod process_trace;
pub mod ptrace;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error in `ptrace({2:?})` call for tracee pid {1}: `{0}`")]
    Ptrace(#[source] std::io::Error, Pid, ptrace::Request),
    #[error("Error in `waitpid` call for tracee pid {1}: `{0}`")]
    Waitpid(#[source] std::io::Error, Pid),
    #[error("Error while reading or writing memory for tracee pid {1}: `{0}`")]
    TraceeMemory(#[source] std::io::Error, Pid),
    #[error("Tracee pid {0} exited during tracing with reason: `{1:?}`")]
    TraceeExited(Pid, WaitStatus),
    #[error("Tracee pid {0} failed to execute syscall {1}")]
    TraceeSyscallFailed(Pid, i64),
    #[error("Tracee pid {0} has unsupported architecture")]
    UnsupportedTraceeArchitecture(Pid),
    #[error("Parallelizer shellcode for tracee pid {0} returned unsuccessfully with code: {1}")]
    ParallelizerShellcodeFailed(Pid, u32),
    #[error("Error while interacting with file \"{1}\": `{0}`")]
    Filesystem(#[source] std::io::Error, PathBuf),
    #[error("Error while parsing elf \"{1}\": `{0}`")]
    ElfParse(#[source] elf::ParseError, PathBuf),
    #[error("Elf \"{0}\" is missing symbol \"{1}\"")]
    ElfMissingSymbol(PathBuf, String),
    #[error("Error while parsing procfs of tracee pid {1}: `{0}`")]
    ProcfsParse(#[source] procfs::ProcError, Pid),
    #[error("Failed to find linker of tracee pid {0}")]
    LinkerNotFound(Pid),
}
