use std::io;

use nix::sys::wait;
use nix::unistd::Pid;
use scopeguard::{defer, guard, ScopeGuard};

/// Forks a child that sleeps in a loop. Returns a scope guard that kills the child and then
/// waits on it.
pub fn fork_sleeper() -> ScopeGuard<Pid, fn(Pid)> {
    // SAFETY: Child process calls `_exit` at end of scope. Parent process gets a scope guard
    // that kills the child and then waits on it.
    let res = unsafe { libc::fork() };
    match res {
        -1 => {
            let error = io::Error::last_os_error();
            panic!("Error in `fork` call: {}", error);
        }
        0 => {
            // Child
            // SAFETY: Only called in child process.
            defer! { unsafe { libc::_exit(0) }; }
            loop {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        child_pid => {
            // Parent
            let child_pid = Pid::from_raw(child_pid);
            guard(child_pid, |child_pid| {
                // SAFETY: There are no preconditions for the safety of this call.
                unsafe { libc::kill(child_pid.into(), libc::SIGKILL) };
                wait::waitpid(child_pid, None).ok();
            })
        }
    }
}
