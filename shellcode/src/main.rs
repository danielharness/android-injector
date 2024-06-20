#![cfg(any(target_arch = "arm", target_arch = "aarch64"))]
#![no_std]
#![no_main]

use syscalls::write;

mod syscalls;

#[no_mangle]
pub extern "C" fn _start() {
    let message: &str = "Hello, Shellcode!\n";
    unsafe {
        let _ = write(2, message.as_ptr(), message.len());
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
