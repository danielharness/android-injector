use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::unistd::{fork, ForkResult, Pid};
use scopeguard::{defer, guard, ScopeGuard};

/// Forks a child that sleeps in a loop. Returns a scope guard that kills the child and then
/// waits on it.
pub fn fork_sleeper() -> ScopeGuard<Pid, fn(Pid)> {
    // SAFETY: Child process calls `_exit` at end of scope. Parent process gets a scope guard
    // that kills the child and then waits on it.
    let res = unsafe { fork() }.unwrap();
    match res {
        ForkResult::Child => {
            // SAFETY: Only called in child process.
            defer! { unsafe { libc::_exit(0) }; }
            loop {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        ForkResult::Parent { child } => guard(child, |child| {
            signal::kill(child, Signal::SIGKILL).ok();
            waitpid(child, Some(WaitPidFlag::WEXITED)).ok();
        }),
    }
}
