use nix::unistd::Pid;
use tracing::{info, info_span};

use crate::injector::cross_arch::build_parallelizer_argument;
use crate::process_trace::TracedProcess;
use crate::Result;
use crate::{ptrace, Error};

mod arm32;
mod arm64;
mod cross_arch;
#[path = "../../shellcode/src/api.rs"]
mod parallelizer_shellcode_api;

/// Injects a payload shellcode to a process with given pid.
/// The shellcode will be written to a new `r-x` mapping created in the process.
/// If an argument is provided, it will also be written to the same mapping.
/// The shellcode will be executed in the same thread, blocking its normal execution.
/// After the shellcode is done executing, the original execution state is restored.
/// The shellcode is *not* unmapped.
///
/// # Deadlocks
///
/// If, for example, the process is currently holding a lock, and the payload attempts to lock it,
/// a deadlock will result. For this reason, the payload should be as context-safe as possible to
/// avoid deadlocks. See [`inject_shellcode_parallel`] for injecting non-context-safe payloads.
///
/// # Interface
///
/// The payload shellcode should conform to the following interface:
/// `extern "C" fn(arg_addr: *const u8, arg_len: usize) -> u32`, where:
/// - `arg_addr` is a pointer to the provided argument.
/// - `arg_len` is the size of the provided argument.
/// - The return value is what will be returned from this function.
///
/// # Implementation
///
/// - Attach to the process with `ptrace`.
/// - If the process is currently executing a system call, interrupt it.
/// - Coerce process to execute `mmap` to map a location for the payload.
/// - Copy payload to the new mapping using `/proc/<pid>/mem`.
/// - Coerce process to execute the payload shellcode.
/// - Restore original execution and detach.
pub fn inject_shellcode_blocking(
    pid: Pid,
    payload_shellcode: &[u8],
    payload_argument: Option<&[u8]>,
) -> Result<u32> {
    inject_shellcode_impl(pid, payload_shellcode, payload_argument, false)
}

/// Same as [`inject_shellcode_blocking`], except the payload shellcode will be run in a new thread,
/// not blocking original execution. This function succeeding does not necessarily guarantee the
/// payload started running - it just means all the blocking steps of parallelization have
/// succeeded. The payload may still fail to start running if any of the non-blocking steps of
/// parallelization fail.
pub fn inject_shellcode_parallel(
    pid: Pid,
    payload_shellcode: &[u8],
    payload_argument: Option<&[u8]>,
) -> Result<()> {
    inject_shellcode_impl(pid, payload_shellcode, payload_argument, true).map(|_| ())
}

fn inject_shellcode_impl(
    pid: Pid,
    payload_shellcode: &[u8],
    payload_argument: Option<&[u8]>,
    parallel: bool,
) -> Result<u32> {
    let payload_argument = payload_argument.unwrap_or(&[]);

    let _log_guard = info_span!("inject", pid = pid.as_raw(), parallel).entered();
    let traced_process = TracedProcess::attach(pid)?;
    info!(pid = pid.as_raw(), "attached to process for tracing");

    let (inject_function, parallelizer_shellcode): (fn(_, _, _) -> _, _) =
        match traced_process.get_regs()? {
            ptrace::UserRegs::Arm32(_) => {
                info!(arch = "arm32", "detected tracee's architecture");
                (
                    arm32::inject_shellcode_blocking,
                    arm32::PARALLELIZER_SHELLCODE,
                )
            }
            ptrace::UserRegs::Arm64(_) => {
                info!(arch = "arm64", "detected tracee's architecture");
                (
                    arm64::inject_shellcode_blocking,
                    arm64::PARALLELIZER_SHELLCODE,
                )
            }
        };

    match parallel {
        false => inject_function(traced_process, payload_shellcode, payload_argument),
        true => {
            info!("building argument for parallelizer shellcode");
            let parallelizer_arg =
                build_parallelizer_argument(pid, payload_shellcode, payload_argument)?;
            info!("injecting parallelizer shellcode");
            let parallelizer_ret =
                inject_function(traced_process, parallelizer_shellcode, &parallelizer_arg)?;
            info!(ret = parallelizer_ret, "parallelizer shellcode finished");

            if parallelizer_ret != (parallelizer_shellcode_api::ReturnCode::Success as u32) {
                Err(Error::ParallelizerShellcodeFailed(pid, parallelizer_ret))
            } else {
                Ok(0)
            }
        }
    }
}
