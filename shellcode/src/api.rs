//! API for the parallelizer shellcode.

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ArgumentMetadata {
    /// Length of payload shellcode.
    pub payload_shellcode_len: u64,
    /// Length of payload argument.
    pub payload_argument_len: u64,
    /// Pointer to the `dlsym` function.
    pub dlsym: u64,
}

#[repr(C)]
#[non_exhaustive]
#[allow(dead_code)]
pub enum ReturnCode {
    Success = 0,
    InvalidArgument = 1,
    DlsymFailed = 2,
    MmapFailed = 3,
    CloneFailed = 4,
}
