//! Parallelizer shellcode that creates a new thread in a context-safe manner and uses it to run a
//! payload.

#![cfg(any(target_arch = "arm", target_arch = "aarch64"))]
#![deny(warnings)]
#![deny(unsafe_op_in_unsafe_fn)]
#![no_std]
#![no_main]

use core::ffi::{c_int, c_long, c_void, CStr};
use core::mem::{size_of, transmute};
use core::ptr::{null, null_mut};
use core::slice::from_raw_parts;

use crate::api::{ArgumentMetadata, ReturnCode};
use crate::defines::constants::{
    CLONE_FILES, CLONE_FS, CLONE_SIGHAND, CLONE_SYSVSEM, CLONE_THREAD, CLONE_VM, MAP_ANONYMOUS,
    MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE, RTLD_DEFAULT,
};
use crate::defines::function_types;

mod api;
mod defines;

const STACK_LEN: usize = 1 * 1024 * 1024;

#[repr(C)]
struct ParsedArgument<'a> {
    payload_shellcode: unsafe extern "C" fn(arg_addr: *const u8, arg_len: usize) -> u32,
    payload_argument: &'a [u8],
    dlsym: function_types::Dlsym,
}

/// Creates a new thread in a context-safe manner and uses it to run provided payload.
///
/// # Interface
///
/// The argument for this shellcode should be an [`ArgumentMetadata`] serialized to raw bytes,
/// followed by the payload shellcode, followed by the payload argument.
/// Example:
/// - `arg_addr`: Pointer to `<24 bytes ArgumentMetadata> + <84 bytes shellcode> +
/// <16 bytes argument>`
/// - `arg_len`: `24 + 84 + 16 = 124`
/// Possible return values can be found at [`ReturnCode`].
///
/// # Safety
///
/// This shellcode is only safe to call if:
/// 1. The argument matches the format described above.
/// 2. The argument is mapped to a `r-x` memory region.
/// 3. The argument is aligned correctly.
#[no_mangle]
#[link_section = ".entry"]
pub unsafe extern "C" fn start(arg_addr: *const u8, arg_len: usize) -> ReturnCode {
    // SAFETY: By contract, argument forms a valid slice.
    let argument = unsafe { from_raw_parts(arg_addr, arg_len) };
    // SAFETY: `parse_raw_argument` is safe to call for with arguments that adhere to the contract
    // of this function.
    let argument = match unsafe { parse_raw_argument(argument) } {
        Ok(arg) => arg,
        Err(_) => return ReturnCode::InvalidArgument,
    };

    // Get needed `libc` functions
    let mmap: function_types::Mmap = match get_symbol(argument.dlsym, c"mmap") {
        // SAFETY: Address refers to a function with this signature.
        Ok(addr) => unsafe { transmute(addr) },
        Err(_) => return ReturnCode::DlsymFailed,
    };
    let munmap: function_types::Munmap = match get_symbol(argument.dlsym, c"munmap") {
        // SAFETY: Address refers to a function with this signature.
        Ok(addr) => unsafe { transmute(addr) },
        Err(_) => return ReturnCode::DlsymFailed,
    };
    let clone: function_types::Clone = match get_symbol(argument.dlsym, c"clone") {
        // SAFETY: Address refers to a function with this signature.
        Ok(addr) => unsafe { transmute(addr) },
        Err(_) => return ReturnCode::DlsymFailed,
    };

    // Since `pthread_create` acquires a lock while creating a thread, calling `pthread_create`
    // directly may deadlock if this thread is currently calling that function. To avoid a possible
    // deadlock, first create a low-level thread using the `clone` system call, and then have it
    // call `pthread_create` to create an actual pthread.
    // SAFETY: There are no preconditions for the safety of this call.
    let child_stack = match unsafe {
        mmap(
            null_mut(),
            STACK_LEN,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    } {
        MAP_FAILED => return ReturnCode::MmapFailed,
        addr => addr,
    };
    // SAFETY: The pointer is one byte past the bounds of the mapping.
    let child_stack_top = unsafe { child_stack.add(STACK_LEN) };

    // Since `argument` is currently saved on this thread's stack, as soon as this function returns
    // it will be invalidated. The new thread needs to access the argument, so save it at the bottom
    // of its stack.
    // SAFETY: The pointer is valid for writing and is properly aligned.
    unsafe { (child_stack as *mut ParsedArgument).write(argument) };

    // SAFETY: The created thread has a newly mapped stack. It shares the TLS of this thread, but
    // won't use it as it only calls `pthread_create` and then directly exits.
    let clone_res = unsafe {
        clone(
            transmute(clone_thread_entry as *const ()),
            child_stack_top,
            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM,
            child_stack,
        )
    };
    match clone_res {
        -1 => {
            // SAFETY: Since `clone` failed, the mapped stack won't be accessed anywhere and can be
            // safely unmapped.
            unsafe { munmap(child_stack, STACK_LEN) };
            ReturnCode::CloneFailed
        }
        _ => ReturnCode::Success,
    }
}

/// A panic handler that does nothing just so the compiler is satisfied.
/// It will never be used as panics are set to abort.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Parses shellcode argument.
///
/// # Safety
///
/// This function is safe to call with an argument that adheres to the safety contract of [`start`].
unsafe fn parse_raw_argument(raw_argument: &[u8]) -> Result<ParsedArgument, ()> {
    // SAFETY: By contract, argument starts with a `PayloadArgument` serialized to raw bytes and is
    // aligned correctly.
    let metadata = &unsafe { raw_argument.align_to::<ArgumentMetadata>() }.1[0];
    if (size_of::<ArgumentMetadata>()
        + (metadata.payload_shellcode_len as usize)
        + (metadata.payload_argument_len as usize))
        != raw_argument.len()
    {
        return Err(());
    }

    let payload_shellcode_addr = raw_argument[size_of::<ArgumentMetadata>()..].as_ptr();
    // SAFETY: By contract, after the serialized `PayloadArgument` there are
    // `PayloadArgument::payload_shellcode_len` bytes of the payload shellcode.
    let payload_shellcode = unsafe { transmute(payload_shellcode_addr) };

    let payload_argument = &raw_argument
        [(size_of::<ArgumentMetadata>() + (metadata.payload_shellcode_len as usize))..];

    // SAFETY: By contract, `PayloadArgument::pthread_create` should be a pointer to the `libc`
    // function.
    let dlsym = unsafe { transmute(metadata.dlsym as *const ()) };

    Ok(ParsedArgument {
        payload_shellcode,
        payload_argument,
        dlsym,
    })
}

/// Gets the address of a symbol with given name.
fn get_symbol(dlsym: function_types::Dlsym, symbol: &CStr) -> Result<*const (), ()> {
    const NULL: *mut c_void = null_mut();
    // SAFETY: The symbol is passed as a valid and readable C string.
    match unsafe { dlsym(RTLD_DEFAULT, symbol.as_ptr()) } {
        NULL => Err(()),
        addr => Ok(addr as *mut ()),
    }
}

/// Entry function for the thread created using `clone`. Creates a pthread that runs the payload
/// shellcode.
///
/// # Safety
///
/// `argument` must point to a valid [`ParsedArgument`].
unsafe extern "C" fn clone_thread_entry(argument: *mut c_void) -> c_int {
    // SAFETY: BY contract, `argument` is a pointer to a `ParsedArgument`.
    let parsed_argument = unsafe { (argument as *const ParsedArgument).read() };

    let pthread_create: function_types::PthreadCreate =
        match get_symbol(parsed_argument.dlsym, c"pthread_create") {
            // SAFETY: Address refers to a function with this signature.
            Ok(addr) => unsafe { transmute(addr) },
            Err(_) => return 1,
        };

    let mut pthread_id: c_long = 0;
    // SAFETY: Mutable references to `pthread_id` and `argument` are passed to `pthread_create` as
    // pointers. These variables are not accessed until the function returns.
    let pthread_create_res = unsafe {
        pthread_create(
            &mut pthread_id as *mut _,
            null(),
            transmute(payload_pthread_entry as *const ()),
            argument,
        )
    };
    match pthread_create_res {
        0 => 0,
        _ => 1,
    }
}

/// Entry function for the pthread that runs the payload shellcode.
///
/// # Safety
///
/// `argument` must point to a valid [`ParsedArgument`].
unsafe extern "C" fn payload_pthread_entry(argument: *mut c_void) -> *mut c_void {
    // SAFETY: BY contract, `argument` is a pointer to a `ParsedArgument`.
    let argument = unsafe { (argument as *const ParsedArgument).read() };

    // SAFETY: User of this shellcode should provide a safe payload.
    unsafe {
        (argument.payload_shellcode)(
            argument.payload_argument.as_ptr(),
            argument.payload_argument.len(),
        ) as *mut c_void
    }
}
