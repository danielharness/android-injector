use std::fs;
use std::path::PathBuf;

use clap::Parser;
use nix::unistd::Pid;

use android_injector::{inject_shellcode_blocking, inject_shellcode_parallel};

#[derive(Parser, Debug)]
struct Args {
    /// Pid to inject into
    pid: i32,

    /// Path of shellcode to read and inject
    shellcode: PathBuf,

    /// Use parallel instead of blocking inject
    #[arg(short, long, default_value_t = false)]
    parallel: bool,

    /// Path of argument file to read and pass to the injected shellcode
    #[arg(short, long)]
    shellcode_argument: Option<PathBuf>,
}

fn main() {
    tracing_subscriber::fmt().init();

    let args = Args::parse();
    let pid = Pid::from_raw(args.pid);
    let shellcode = fs::read(args.shellcode).unwrap();
    let shellcode_argument = args.shellcode_argument.map(|p| fs::read(p).unwrap());

    if args.parallel {
        inject_shellcode_parallel(pid, &shellcode, shellcode_argument.as_deref()).unwrap();
    } else {
        inject_shellcode_blocking(pid, &shellcode, shellcode_argument.as_deref()).unwrap();
    }
}
