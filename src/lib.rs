#![cfg(all(
    target_os = "android",
    any(target_arch = "arm", target_arch = "aarch64")
))]

pub mod ptrace;

#[derive(thiserror::Error, Debug)]
pub enum InjectorError {
    #[error("Error in `ptrace` call for tracee pid {1}: `{0}`")] // TODO: Include `PtraceRequest`
    Ptrace(#[source] std::io::Error, libc::pid_t),
    #[error("Error in `waitpid` call for tracee pid {1}: `{0}`")]
    Waitpid(#[source] std::io::Error, libc::pid_t),
    #[error("Error while reading or writing memory for tracee pid {1}: `{0}`")]
    TraceeMemory(#[source] std::io::Error, libc::pid_t),
    #[error("Tracee pid {0} exited during `ptrace`")] // TODO: Include `ExitReason`
    TraceeExited(libc::pid_t),
    #[error("Unknown error")]
    Unknown,
}
