//! Defines from `libc`.

#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_void};

pub const PROT_READ: c_int = 1;
pub const PROT_WRITE: c_int = 2;
pub const PROT_EXEC: c_int = 4;
pub const MAP_PRIVATE: c_int = 0x2;
pub const MAP_ANONYMOUS: c_int = 0x0020;
pub const MAP_FAILED: *const c_void = -1isize as *const c_void;

#[cfg(target_arch = "arm")]
pub const SYS_munmap: c_long = 91;
#[cfg(target_arch = "arm")]
pub const SYS_mprotect: c_long = 125;
#[cfg(target_arch = "arm")]
pub const SYS_mmap2: c_long = 192;

#[cfg(target_arch = "aarch64")]
pub const SYS_munmap: c_long = 215;
#[cfg(target_arch = "aarch64")]
pub const SYS_mmap: c_long = 222;
#[cfg(target_arch = "aarch64")]
pub const SYS_mprotect: c_long = 226;
