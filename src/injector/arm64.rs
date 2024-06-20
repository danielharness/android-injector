use std::num::NonZeroUsize;

use tracing::info;

use crate::{Error, Result};
use crate::injector::cross_arch::{interrupt_syscall, round_up, wait_for_breakpoint};
use crate::process_trace::{RemoteAddress, Stopped, TracedProcess};
use crate::ptrace::{Arm64UserRegs, UserRegs};

pub const PARALLELIZER_SHELLCODE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/shellcode_arm64.bin"));

const ALIGNMENT: NonZeroUsize = match NonZeroUsize::new(16) {
    Some(n) => n,
    None => [][0],
};
const BREAKPOINT_INSTRUCTION: [u8; 4] = 0xd4200000u32.to_le_bytes();
const SYSCALL_INSTRUCTION: [u8; 4] = 0xd4000001u32.to_le_bytes();

const SYS_MMAP: i64 = 222;

/// Architecture-specific implementation. See documentation of
/// [`crate::injector::inject_shellcode_blocking`].
pub fn inject_shellcode_blocking(
    mut traced_process: TracedProcess<Stopped>,
    payload_shellcode: &[u8],
    payload_argument: &[u8],
) -> Result<u32> {
    // Save original state
    let original_regs = get_regs(&traced_process)?;

    // Check if tracee is currently in a system call
    let current_instruction =
        traced_process.read_memory(RemoteAddress(original_regs.pc), SYSCALL_INSTRUCTION.len())?;
    if current_instruction == SYSCALL_INSTRUCTION {
        info!("tracee is currently in system call, interrupting it");
        traced_process = interrupt_syscall(traced_process)?;
    }

    // Round up lengths so that injected code is properly aligned
    let payload_shellcode_aligned_len = round_up(payload_shellcode.len(), ALIGNMENT);
    let breakpoint_instruction_aligned_len = round_up(BREAKPOINT_INSTRUCTION.len(), ALIGNMENT);
    let payload_argument_aligned_len = round_up(payload_argument.len(), ALIGNMENT);

    // Call `mmap`
    let map_len = payload_shellcode_aligned_len
        + breakpoint_instruction_aligned_len
        + payload_argument_aligned_len;
    info!(
        len = map_len,
        prot = "PROT_READ | PROT_EXEC",
        flags = "MAP_ANONYMOUS | MAP_PRIVATE",
        "coercing tracee to call `mmap`"
    );
    let (mut traced_process, mmap_ret) = call_syscall(
        traced_process,
        SYS_MMAP,
        0,                                                // addr
        map_len as u64,                                   // len
        (libc::PROT_READ | libc::PROT_EXEC) as u64,       // prot
        (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE) as u64, // flags
        (-1i64) as u64,                                   // fd
        0,                                                // offset
    )?;
    info!(ret = mmap_ret, "tracee returned from `mmap` successfully");
    let payload_shellcode_address = RemoteAddress(mmap_ret as u64);
    let breakpoint_instruction_address =
        RemoteAddress(payload_shellcode_address.0 + (payload_shellcode_aligned_len as u64));
    let payload_argument_address = RemoteAddress(
        breakpoint_instruction_address.0 + (breakpoint_instruction_aligned_len as u64),
    );

    // Copy shellcode and metadata to mapped address
    info!(
        ?payload_shellcode_address,
        payload_shellcode_len = payload_shellcode_aligned_len,
        ?breakpoint_instruction_address,
        breakpoint_instruction_len = breakpoint_instruction_aligned_len,
        ?payload_argument_address,
        payload_argument_len = payload_argument_aligned_len,
        "copying payload to tracee"
    );
    traced_process.write_memory(payload_shellcode_address, payload_shellcode)?;
    traced_process.write_memory(breakpoint_instruction_address, &BREAKPOINT_INSTRUCTION)?;
    traced_process.write_memory(payload_argument_address, payload_argument)?;

    // Call shellcode
    info!("coercing tracee to call payload");
    let mut call_regs = original_regs.clone();
    call_regs.pc = payload_shellcode_address.0;
    call_regs.regs[30] = breakpoint_instruction_address.0;
    call_regs.regs[0] = payload_argument_address.0;
    call_regs.regs[1] = payload_argument.len() as u64;
    traced_process.set_regs(&UserRegs::Arm64(call_regs))?;
    traced_process = wait_for_breakpoint(traced_process)?;
    let payload_ret = get_regs(&traced_process)?.regs[0];
    info!(ret = payload_ret, "tracee returned from payload shellcode");

    // Restore original state
    info!("restoring original state for tracee");
    traced_process.set_regs(&UserRegs::Arm64(original_regs))?;
    traced_process.detach()?;

    Ok(payload_ret as u32)
}

/// Gets the general-purpose registers of a traced process.
fn get_regs(traced_process: &TracedProcess<Stopped>) -> Result<Arm64UserRegs> {
    match traced_process.get_regs()? {
        UserRegs::Arm64(regs) => Ok(regs),
        _ => Err(Error::UnsupportedTraceeArchitecture(traced_process.pid)),
    }
}

/// Coerces a traced process to call a system call, then restores its state.
fn call_syscall(
    mut traced_process: TracedProcess<Stopped>,
    syscall_number: i64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> Result<(TracedProcess<Stopped>, i64)> {
    // Save original state
    let original_regs = get_regs(&traced_process)?;
    let original_instruction =
        traced_process.read_memory(RemoteAddress(original_regs.pc), SYSCALL_INSTRUCTION.len())?;

    // Change current instruction to the system call instruction
    traced_process.write_memory(RemoteAddress(original_regs.pc), &SYSCALL_INSTRUCTION)?;

    // Populate registers for the system call
    let mut syscall_regs = original_regs.clone();
    syscall_regs.regs[8] = syscall_number as u64;
    syscall_regs.regs[0] = arg0;
    syscall_regs.regs[1] = arg1;
    syscall_regs.regs[2] = arg2;
    syscall_regs.regs[3] = arg3;
    syscall_regs.regs[4] = arg4;
    syscall_regs.regs[5] = arg5;
    traced_process.set_regs(&UserRegs::Arm64(syscall_regs))?;

    // Wait for system call to finish (two events - syscall enter and syscall exit)
    let mut traced_process = traced_process
        .cont_syscall(None)?
        .wait_syscall_stop()?
        .cont_syscall(None)?
        .wait_syscall_stop()?;
    let syscall_ret = get_regs(&traced_process)?.regs[0];

    // Restore original state
    traced_process.write_memory(RemoteAddress(original_regs.pc), &original_instruction)?;
    traced_process.set_regs(&UserRegs::Arm64(original_regs))?;

    // Check return value
    match syscall_ret as i64 {
        -1 => Err(Error::TraceeSyscallFailed(
            traced_process.pid,
            syscall_number,
        )),
        ret => Ok((traced_process, ret)),
    }
}
