use nix::unistd::Pid;
use tracing::{info, info_span};

use crate::process_trace::TracedProcess;
use crate::ptrace;
use crate::Result;

mod arm32;
mod arm64;
mod cross_arch;

/// Injects a payload shellcode to a process with given pid.
/// The shellcode will be written to a new `r-x` mapping created in the process.
/// If an argument is provided, it will also be written to the same mapping.
/// The shellcode will be executed in the same thread, blocking its normal execution.
/// After the shellcode is done executing, the original execution state is restored.
/// The shellcode is *not* unmapped.
///
/// # Interface
///
/// The shellcode should conform to the following interface:
/// `extern "C" fn shellcode(arg_addr: *const u8, arg_len: usize) -> u32`, where:
/// - `arg_addr` is a pointer to the provided argument.
/// - `arg_len` is the size of the provided argument.
/// - The return value is what will be returned from this function.
///
/// # Implementation
///
/// - Attach to the process with `ptrace`.
/// - If the process is currently executing a system call, interrupt it.
/// - Coerce process to execute `mmap` to map a location for the shellcode.
/// - Copy shellcode to the new mapping using `/proc/<pid>/mem`.
/// - Coerce process to execute the shellcode.
/// - Restore original execution and detach.
pub fn inject_shellcode_blocking(
    pid: Pid,
    payload_shellcode: &[u8],
    payload_argument: Option<&[u8]>,
) -> Result<u32> {
    let _log_guard = info_span!("inject", pid = pid.as_raw()).entered();
    let traced_process = TracedProcess::attach(pid)?;
    info!(pid = pid.as_raw(), "attached to process for tracing");

    let inject_function = match traced_process.get_regs()? {
        ptrace::UserRegs::Arm32(_) => {
            info!(arch = "arm32", "detected tracee's architecture");
            arm32::inject_shellcode_blocking
        }
        ptrace::UserRegs::Arm64(_) => {
            info!(arch = "arm64", "detected tracee's architecture");
            arm64::inject_shellcode_blocking
        }
    };

    inject_function(
        traced_process,
        payload_shellcode,
        payload_argument.unwrap_or(&[]),
    )
}
