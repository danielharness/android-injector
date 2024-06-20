//! Wrapper for `ptrace`.
//! The `nix` crate provides a cleaner and more robust `ptrace` API, but unfortunately it has very
//! lackluster support for android, and doesn't support cross-architecture (e.g. arm32 -> arm64)
//! tracing.

use std::mem::{MaybeUninit, size_of, size_of_val};
use std::ptr;

use nix::unistd::Pid;

use crate::{Error, Result};

/// Supported `ptrace` requests.
#[repr(i32)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Request {
    Attach = libc::PTRACE_ATTACH,
    Detach = libc::PTRACE_DETACH,
    SetOptions = libc::PTRACE_SETOPTIONS,
    Cont = libc::PTRACE_CONT,
    Syscall = libc::PTRACE_SYSCALL,
    GetRegSet = libc::PTRACE_GETREGSET,
    SetRegSet = libc::PTRACE_SETREGSET,
}

/// General-purpose user registers as provided by `ptrace` for arm32 processes.
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

/// General-purpose user registers as provided by `ptrace` for arm64 processes.
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

/// Union of possible sets of general-purpose user registers used in `PTRACE_*REGSET` requests.
#[repr(C)]
union GpRegSetUserRegs {
    pub arm32: Arm32UserRegs,
    pub arm64: Arm64UserRegs,
}

/// This constant makes `PTRACE_*REGSET` requests refer to general-purpose registers. It is not
/// defined in android, but still supported.
const NT_PRSTATUS: libc::c_int = 1;

/// Wrapper for `ptrace` that converts errors.
/// See ptrace(2) for documentation on the various `ptrace` requests.
///
/// # Safety
///
/// Some `ptrace` requests read or write data to pointers in `addr` or `data`. It is the caller's
/// responsibility to ensure the pointers provided to these requests are valid.
unsafe fn ptrace_other(
    request: Request,
    pid: Pid,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> Result<libc::c_long> {
    let res = unsafe { libc::ptrace(request as libc::c_int, pid.as_raw(), addr, data) };
    match res {
        -1 => Err(Error::Ptrace(std::io::Error::last_os_error(), pid, request)),
        _ => Ok(res),
    }
}

/// Attaches to a process.
pub fn attach(pid: Pid) -> Result<()> {
    // SAFETY: There are no preconditions for the safety of this call.
    unsafe { ptrace_other(Request::Attach, pid, ptr::null_mut(), ptr::null_mut()) }?;
    Ok(())
}

/// Detaches from a tracee.
pub fn detach(pid: Pid) -> Result<()> {
    // SAFETY: There are no preconditions for the safety of this call.
    unsafe { ptrace_other(Request::Detach, pid, ptr::null_mut(), ptr::null_mut()) }?;
    Ok(())
}

/// Sets options for a tracee.
pub fn set_options(pid: Pid, options: i32) -> Result<()> {
    // SAFETY: There are no preconditions for the safety of this call.
    unsafe { ptrace_other(Request::SetOptions, pid, ptr::null_mut(), options as *mut _) }?;
    Ok(())
}

/// Restarts a tracee.
pub fn cont(pid: Pid, signal: i32) -> Result<()> {
    // SAFETY: There are no preconditions for the safety of this call.
    unsafe { ptrace_other(Request::Cont, pid, ptr::null_mut(), signal as *mut _) }?;
    Ok(())
}

/// Restarts a tracee
/// It will automatically be stopped at the next entry to or exit from a system call.
/// Restarts a tracee.
pub fn syscall(pid: Pid, signal: i32) -> Result<()> {
    // SAFETY: There are no preconditions for the safety of this call.
    unsafe { ptrace_other(Request::Syscall, pid, ptr::null_mut(), signal as *mut _) }?;
    Ok(())
}

/// Gets the general-purpose register set of a tracee.
pub fn get_gp_register_set(pid: Pid) -> Result<UserRegs> {
    let mut regs = MaybeUninit::<GpRegSetUserRegs>::uninit();
    let mut iovec = libc::iovec {
        iov_base: regs.as_mut_ptr().cast(),
        iov_len: size_of_val(&regs) as libc::size_t,
    };
    // SAFETY: At most `iovec.iov_len` bytes will be written to the address of `regs`.
    // Since `iovec.iov_len` is set to the size of `regs`, the write is guaranteed to not
    // overflow.
    unsafe {
        ptrace_other(
            Request::GetRegSet,
            pid,
            NT_PRSTATUS as *mut _,
            (&mut iovec as *mut _) as *mut _,
        )
    }?;

    const ARM32_USER_REGS_SIZE: usize = size_of::<Arm32UserRegs>();
    const ARM64_USER_REGS_SIZE: usize = size_of::<Arm64UserRegs>();
    match iovec.iov_len {
        ARM32_USER_REGS_SIZE => {
            // SAFETY: The `PTRACE_GETREGSET` request returned successfully, and based on the size
            // it placed in `iovec.iov_len`, it populated `regs` as if it were `Arm32UserRegs`.
            // Thus the union (1) is initialised and (2) refers to the field `arm32`.
            Ok(UserRegs::Arm32(unsafe { regs.assume_init().arm32 }))
        }
        ARM64_USER_REGS_SIZE => {
            // SAFETY: The `PTRACE_GETREGSET` request returned successfully, and based on the size
            // it placed in `iovec.iov_len`, it populated `regs` as if it were `Arm64UserRegs`.
            // Thus the union (1) is initialised and (2) refers to the field `arm64`.
            Ok(UserRegs::Arm64(unsafe { regs.assume_init().arm64 }))
        }
        _ => Err(Error::UnsupportedTraceeArchitecture(pid)),
    }
}

/// Sets the general-purpose register set of a tracee.
/// Providing a wrong register set for the tracee's architecture will cause this function to return
/// an error.
pub fn set_gp_register_set(pid: Pid, user_regs: &UserRegs) -> Result<()> {
    let (mut regs, regs_size) = match user_regs {
        UserRegs::Arm32(regs) => (GpRegSetUserRegs { arm32: *regs }, size_of_val(regs)),
        UserRegs::Arm64(regs) => (GpRegSetUserRegs { arm64: *regs }, size_of_val(regs)),
    };
    let mut iovec = libc::iovec {
        iov_base: (&mut regs as *mut _) as *mut _,
        iov_len: regs_size as libc::size_t,
    };
    // SAFETY: At most `iovec.iov_len` bytes will be read from the address of `regs`.
    // Since `iovec.iov_len` is set to the size of the initialized field in the union `regs`,
    // only valid data will be read.
    unsafe {
        ptrace_other(
            Request::SetRegSet,
            pid,
            NT_PRSTATUS as *mut _,
            (&mut iovec as *mut _) as *mut _,
        )
    }?;
    Ok(())
}
