use core::arch::asm;
use core::ffi::c_void;

use crate::defines::*;

/// Wrapper for the `mmap` (or `mmap2`, on 32-bit) syscall.
#[inline(always)]
pub fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: isize,
) -> Result<*mut c_void, ()> {
    let ret: *mut c_void;

    #[cfg(target_arch = "arm")]
    // SAFETY: There are no preconditions for the safety of this assembly.
    unsafe {
        asm!(
        "svc #0",
        in("r7") SYS_mmap2,
        in("r0") addr,
        in("r1") len,
        in("r2") prot,
        in("r3") flags,
        in("r4") fd,
        in("r5") offset / 4096,
        lateout("r0") ret,
        );
    }

    #[cfg(target_arch = "aarch64")]
    // SAFETY: There are no preconditions for the safety of this assembly.
    unsafe {
        asm!(
        "svc #0",
        in("x8") SYS_mmap,
        in("x0") addr,
        in("x1") len,
        in("x2") prot,
        in("x3") flags,
        in("x4") fd,
        in("x5") offset,
        lateout("x0") ret,
        );
    }

    match ret as *const c_void {
        MAP_FAILED => Err(()),
        _ => Ok(ret),
    }
}

/// Wrapper for the `munmap` syscall.
///
/// Safety:
///
/// Since this call deletes memory mappings, it is only safe if the caller can ensure no code will
/// access the unmapped memory.
#[inline(always)]
pub unsafe fn munmap(addr: *mut c_void, len: usize) -> Result<(), ()> {
    let ret: i32;

    #[cfg(target_arch = "arm")]
    unsafe {
        asm!(
        "svc #0",
        in("r7") SYS_munmap,
        in("r0") addr,
        in("r1") len,
        lateout("r0") ret,
        );
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!(
        "svc #0",
        in("x8") SYS_munmap,
        in("x0") addr,
        in("x1") len,
        lateout("x0") ret,
        );
    }

    match ret {
        -1 => Err(()),
        _ => Ok(()),
    }
}

/// Wrapper for the `mprotect` syscall.
///
/// Safety:
///
/// Since this call modifies the access protections of a memory region, it is only safe if the
/// caller can ensure no code will access the affected memory region incorrectly.
#[inline(always)]
pub unsafe fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> Result<(), ()> {
    let ret: i32;

    #[cfg(target_arch = "arm")]
    unsafe {
        asm!(
        "svc #0",
        in("r7") SYS_mprotect,
        in("r0") addr,
        in("r1") len,
        in("r2") prot,
        lateout("r0") ret,
        );
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!(
        "svc #0",
        in("x8") SYS_mprotect,
        in("x0") addr,
        in("x1") len,
        in("x2") prot,
        lateout("x0") ret,
        );
    }

    match ret {
        -1 => Err(()),
        _ => Ok(()),
    }
}
