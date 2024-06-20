//! Minimal stage-one shellcode, that may be inserted anywhere to set up for a payload of any size.

#![cfg(any(target_arch = "arm", target_arch = "aarch64"))]
#![deny(warnings)]
#![no_std]
#![no_main]

use core::ffi::c_void;
use core::ptr::{copy_nonoverlapping, null_mut};

use crate::defines::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::syscalls::{mmap, mprotect, munmap};

mod defines;
mod syscalls;

const ERROR_RETURN: *const c_void = -1isize as *const c_void;

/// Maps given payload into a `r-x` area and returns the mapped address.
#[no_mangle]
pub extern "C" fn _start(payload_addr: *const u8, payload_len: usize) -> *const c_void {
    let Ok(map_addr) = mmap(
        null_mut(),
        payload_len,
        PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    ) else {
        return ERROR_RETURN;
    };

    // SAFETY: `map_addr` was just mapped for writing with a length of `payload_len`.
    unsafe { copy_nonoverlapping(payload_addr, map_addr as *mut u8, payload_len) }

    // SAFETY: `map_addr` is a mapping only known to this code. To ensure this code will no longer
    // access it for writing, it is downgraded to point to `const` after this call succeeds.
    if let Err(_) = unsafe { mprotect(map_addr, payload_len, PROT_READ | PROT_EXEC) } {
        // Best-effort unmap on failure.
        // SAFETY: `map_addr` is a mapping only known to this code. To ensure this code will no
        // longer access it, it is hidden after this call.
        unsafe { munmap(map_addr, payload_len) }.ok();
        #[allow(unused)]
            let map_addr = ();

        return ERROR_RETURN;
    }
    let map_addr = map_addr as *const c_void;

    map_addr
}

/// A panic handler that does nothing just so the compiler is satisfied.
/// It will never be used as panics are set to abort.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
