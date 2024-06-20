use android_injector::injector::inject_shellcode_blocking;

use crate::common::child_factory::fork_sleeper;

mod common;

#[cfg(target_arch = "arm")]
const SHELLCODE_RETURNS_1234: [u8; 8] = [210, 4, 0, 227, 30, 255, 47, 225];
#[cfg(target_arch = "arm")]
const SHELLCODE_RETURNS_ARGUMENT_PLUS_1234: [u8; 16] = [
    0, 0, 144, 229, 210, 20, 0, 227, 1, 0, 128, 224, 30, 255, 47, 225,
];

#[cfg(target_arch = "aarch64")]
const SHELLCODE_RETURNS_1234: [u8; 8] = [64, 154, 128, 82, 192, 3, 95, 214];
#[cfg(target_arch = "aarch64")]
const SHELLCODE_RETURNS_ARGUMENT_PLUS_1234: [u8; 12] =
    [8, 0, 64, 185, 0, 73, 19, 17, 192, 3, 95, 214];

#[test]
fn inject_shellcode_blocking_without_argument() {
    let child = fork_sleeper();
    let ret = inject_shellcode_blocking(*child, &SHELLCODE_RETURNS_1234, None).unwrap();
    assert_eq!(ret, 1234);
}

#[test]
fn inject_shellcode_blocking_with_argument() {
    let child = fork_sleeper();
    let arg = 4567u32;
    let ret = inject_shellcode_blocking(
        *child,
        &SHELLCODE_RETURNS_ARGUMENT_PLUS_1234,
        Some(&arg.to_le_bytes()),
    )
        .unwrap();
    assert_eq!(ret, 1234 + arg);
}
