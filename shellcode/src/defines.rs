//! Definitions from `libc`.

pub mod function_types {
    use core::ffi::{c_char, c_int, c_long, c_void};

    pub type Dlsym =
        unsafe extern "C" fn(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    pub type Mmap = unsafe extern "C" fn(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: isize,
    ) -> *mut c_void;
    pub type Munmap = unsafe extern "C" fn(addr: *mut c_void, len: usize) -> c_int;
    pub type Clone = unsafe extern "C" fn(
        cb: extern "C" fn(*mut c_void) -> c_int,
        child_stack: *mut c_void,
        flags: c_int,
        arg: *mut c_void,
        ...
    ) -> c_int;
    pub type PthreadCreate = unsafe extern "C" fn(
        native: *mut c_long,
        attr: *const c_void,
        f: extern "C" fn(*mut c_void) -> *mut c_void,
        value: *mut c_void,
    ) -> c_int;
}

pub mod constants {
    use core::ffi::{c_int, c_void};

    pub const PROT_READ: c_int = 1;
    pub const PROT_WRITE: c_int = 2;
    pub const MAP_PRIVATE: c_int = 0x2;
    pub const MAP_ANONYMOUS: c_int = 0x0020;
    pub const MAP_FAILED: *mut c_void = -1isize as *mut c_void;
    pub const CLONE_VM: c_int = 0x100;
    pub const CLONE_FS: c_int = 0x200;
    pub const CLONE_FILES: c_int = 0x400;
    pub const CLONE_SIGHAND: c_int = 0x800;
    pub const CLONE_THREAD: c_int = 0x10000;
    pub const CLONE_SYSVSEM: c_int = 0x40000;

    #[cfg(target_arch = "arm")]
    pub const RTLD_DEFAULT: *mut c_void = -1isize as *mut c_void;
    #[cfg(target_arch = "aarch64")]
    pub const RTLD_DEFAULT: *mut c_void = 0i64 as *mut c_void;
}
