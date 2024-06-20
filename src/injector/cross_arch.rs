use std::fs::File;
use std::mem::size_of_val;
use std::num::NonZeroUsize;
use std::path::Path;
use std::slice::from_raw_parts;

use elf::ElfStream;
use elf::endian::NativeEndian;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use procfs::process::MMPermissions;

use crate::{Error, Result};
use crate::injector::parallelizer_shellcode_api;
use crate::process_trace::{Stopped, TracedProcess};

/// Interrupts the current system call a traced process is executing.
pub fn interrupt_syscall(
    mut traced_process: TracedProcess<Stopped>,
) -> Result<TracedProcess<Stopped>> {
    let running = traced_process.cont_syscall(None)?;
    // Use `SIGCHLD` to interrupt the system call as it is a harmless signal
    signal::kill(running.pid, Some(Signal::SIGCHLD))
        .map_err(|err| Error::Waitpid(err.into(), running.pid))?;
    // Wait for system call to finish (two events - syscall enter and syscall exit)
    traced_process = running
        .wait_syscall_stop()?
        .cont_syscall(None)?
        .wait_syscall_stop()?;
    Ok(traced_process)
}

/// Waits for a traced process to hit a breakpoint (i.e. receive `SIGTRAP`).
pub fn wait_for_breakpoint(
    mut traced_process: TracedProcess<Stopped>,
) -> Result<TracedProcess<Stopped>> {
    let mut previous_stop_signal: Option<Signal> = None;
    loop {
        let current_stop_signal;
        (traced_process, current_stop_signal) = traced_process
            .cont(previous_stop_signal)?
            .wait_signal_stop()?;
        if current_stop_signal == Signal::SIGTRAP {
            break;
        }
        previous_stop_signal = Some(current_stop_signal);
    }
    Ok(traced_process)
}

/// Rounds a number up to a multiple.
pub fn round_up(n: usize, multiple: NonZeroUsize) -> usize {
    let multiple = multiple.get();
    return ((n + (multiple - 1)) / multiple) * multiple;
}

/// Gets the value of a symbol with given name from a given elf file.
fn get_symbol_value(elf_path: &Path, symbol: &str) -> Result<u64> {
    let file = File::open(elf_path).map_err(|err| Error::Filesystem(err, elf_path.into()))?;
    let mut elf = ElfStream::<NativeEndian, _>::open_stream(file)
        .map_err(|err| Error::ElfParse(err, elf_path.into()))?;
    let (symbol_table, string_table) = elf
        .symbol_table()
        .map_err(|err| Error::ElfParse(err, elf_path.into()))?
        .ok_or_else(|| Error::ElfMissingSymbol(elf_path.into(), symbol.into()))?;

    for current_symbol in symbol_table {
        let current_symbol_name = string_table
            .get(current_symbol.st_name as usize)
            .map_err(|err| Error::ElfParse(err, elf_path.into()))?;
        if current_symbol_name == symbol {
            return Ok(current_symbol.st_value);
        }
    }

    Err(Error::ElfMissingSymbol(elf_path.into(), symbol.into()))
}

/// Gets the address of `dlsym` in process with given pid.
fn get_dlsym(pid: Pid) -> Result<u64> {
    let procfs =
        procfs::process::Process::new(pid.as_raw()).map_err(|err| Error::ProcfsParse(err, pid))?;
    for map in procfs.maps().map_err(|err| Error::ProcfsParse(err, pid))? {
        if !map.perms.contains(MMPermissions::EXECUTE) {
            continue;
        }
        if let procfs::process::MMapPath::Path(path) = map.pathname {
            let file_name = path
                .file_name()
                .unwrap_or("".as_ref())
                .to_str()
                .unwrap_or("");
            if file_name.starts_with("linker") {
                let dlsym_symbol_value = get_symbol_value(&path, "__dl_dlsym")?;
                return Ok(map.address.0 + dlsym_symbol_value);
            }
        }
    }

    Err(Error::LinkerNotFound(pid))
}

/// Builds the argument for the parallelizer shellcode for a process with given pid.
pub fn build_parallelizer_argument(
    pid: Pid,
    payload_shellcode: &[u8],
    payload_argument: &[u8],
) -> Result<Vec<u8>> {
    let dlsym = get_dlsym(pid)?;
    let parallelizer_argument_metadata = parallelizer_shellcode_api::ArgumentMetadata {
        payload_shellcode_len: payload_shellcode.len() as u64,
        payload_argument_len: payload_argument.len() as u64,
        dlsym,
    };
    // SAFETY: Safe serialization of a struct to a byte slice with same size as the struct.
    let seriazlied_parallelizer_argument_metadata = unsafe {
        from_raw_parts(
            (&parallelizer_argument_metadata as *const _) as *const u8,
            size_of_val(&parallelizer_argument_metadata),
        )
    };

    let mut parallelizer_argument = vec![];
    parallelizer_argument.extend_from_slice(seriazlied_parallelizer_argument_metadata);
    parallelizer_argument.extend_from_slice(payload_shellcode);
    parallelizer_argument.extend_from_slice(payload_argument);
    Ok(parallelizer_argument)
}

#[cfg(test)]
mod tests {
    use nix::unistd::Pid;

    #[test]
    fn get_dlsym() {
        let dlsym = super::get_dlsym(Pid::this()).unwrap();
        assert_eq!(libc::dlsym as *const (), dlsym as *const ());
    }
}
