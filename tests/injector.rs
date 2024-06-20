use std::thread;
use std::time::Duration;

use test_log::test;

use android_injector::injector::{inject_shellcode_blocking, inject_shellcode_parallel};

use crate::common::child_factory::fork_sleeper;

mod common;

/// Shellcodes for testing.
mod shellcode {
    #[cfg(target_arch = "arm")]
    pub const RETURN_1234: [u8; 8] = [210, 4, 0, 227, 30, 255, 47, 225];
    #[cfg(target_arch = "arm")]
    pub const RETURN_ARG_PLUS_1234: [u8; 16] = [
        0, 0, 144, 229, 210, 20, 0, 227, 1, 0, 128, 224, 30, 255, 47, 225,
    ];
    #[cfg(target_arch = "arm")]
    pub const SLEEP_IN_LOOP: [u8; 40] = [
        8, 208, 77, 226, 0, 192, 160, 227, 100, 48, 160, 227, 13, 32, 160, 225, 162, 112, 160, 227,
        0, 16, 160, 227, 8, 16, 141, 232, 2, 0, 160, 225, 0, 0, 0, 239, 251, 255, 255, 234,
    ];
    #[cfg(target_arch = "arm")]
    pub const CHDIR_TO_ARG_THEN_SLEEP_IN_LOOP: [u8; 48] = [
        8, 208, 77, 226, 12, 112, 160, 227, 0, 0, 0, 239, 0, 192, 160, 227, 100, 48, 160, 227, 13,
        32, 160, 225, 162, 112, 160, 227, 0, 16, 160, 227, 8, 16, 141, 232, 2, 0, 160, 225, 0, 0,
        0, 239, 251, 255, 255, 234,
    ];

    #[cfg(target_arch = "aarch64")]
    pub const RETURN_1234: [u8; 8] = [64, 154, 128, 82, 192, 3, 95, 214];
    #[cfg(target_arch = "aarch64")]
    pub const RETURN_ARG_PLUS_1234: [u8; 12] = [8, 0, 64, 185, 0, 73, 19, 17, 192, 3, 95, 214];
    #[cfg(target_arch = "aarch64")]
    pub const SLEEP_IN_LOOP: [u8; 32] = [
        255, 67, 0, 209, 137, 12, 128, 82, 225, 3, 31, 170, 233, 127, 0, 169, 224, 3, 0, 145, 168,
        12, 128, 82, 1, 0, 0, 212, 252, 255, 255, 23,
    ];
    #[cfg(target_arch = "aarch64")]
    pub const CHDIR_TO_ARG_THEN_SLEEP_IN_LOOP: [u8; 40] = [
        255, 67, 0, 209, 40, 6, 128, 82, 1, 0, 0, 212, 137, 12, 128, 82, 225, 3, 31, 170, 233, 127,
        0, 169, 224, 3, 0, 145, 168, 12, 128, 82, 1, 0, 0, 212, 252, 255, 255, 23,
    ];
}

#[test]
fn inject_shellcode_blocking_without_argument() {
    let child = fork_sleeper();
    let ret = inject_shellcode_blocking(*child, &shellcode::RETURN_1234, None).unwrap();
    assert_eq!(ret, 1234);
}

#[test]
fn inject_shellcode_blocking_with_argument() {
    let child = fork_sleeper();
    let arg = 4567u32;
    let ret = inject_shellcode_blocking(
        *child,
        &shellcode::RETURN_ARG_PLUS_1234,
        Some(&arg.to_le_bytes()),
    )
        .unwrap();
    assert_eq!(ret, 1234 + arg);
}

fn find_non_main_thread(procfs: &procfs::process::Process) -> Option<procfs::process::Task> {
    procfs.tasks().unwrap().find_map(|task| {
        let task = task.unwrap();
        if task.tid != procfs.pid {
            Some(task)
        } else {
            None
        }
    })
}

#[test]
fn inject_shellcode_parallel_without_argument() {
    let child = fork_sleeper();
    inject_shellcode_parallel(*child, &shellcode::SLEEP_IN_LOOP, None).unwrap();
    // Wait for injection to finish
    thread::sleep(Duration::from_millis(200));

    let child_procfs = procfs::process::Process::new(child.as_raw()).unwrap();
    let child_thread_procfs = find_non_main_thread(&child_procfs)
        .expect("Child does not have a new thread after parallel injecting sleep shellcode");
    assert!(
        child_thread_procfs.status().unwrap().state.starts_with('S'),
        "Child's thread is not sleeping after parallel injecting sleep shellcode",
    );
}

#[test]
fn inject_shellcode_parallel_with_argument() {
    let child = fork_sleeper();
    let arg = "/".as_bytes();
    inject_shellcode_parallel(
        *child,
        &shellcode::CHDIR_TO_ARG_THEN_SLEEP_IN_LOOP,
        Some(arg),
    )
        .unwrap();
    // Wait for injection to finish
    thread::sleep(Duration::from_millis(200));

    let child_procfs = procfs::process::Process::new(child.as_raw()).unwrap();
    let child_thread_procfs = find_non_main_thread(&child_procfs)
        .expect("Child does not have a new thread after parallel injecting sleep shellcode");
    assert!(
        child_thread_procfs.status().unwrap().state.starts_with('S'),
        "Child's thread is not sleeping after parallel injecting sleep shellcode",
    );
    assert_eq!(
        child_procfs.cwd().unwrap().as_os_str().as_encoded_bytes(),
        arg
    )
}

#[test]
fn inject_shellcode_parallel_immediate_return() {
    let child = fork_sleeper();
    inject_shellcode_parallel(*child, &shellcode::RETURN_1234, None).unwrap();
    // Wait for injection to finish
    thread::sleep(Duration::from_millis(200));

    let child_procfs = procfs::process::Process::new(child.as_raw()).unwrap();
    assert!(
        find_non_main_thread(&child_procfs).is_none(),
        "Child has a thread running even though it should have exited"
    );
}
