## Android Injector

A shellcode injector for android, written in rust.  
Supports arm32 and arm64.

## Usage

```rust
use std::fs;
use nix::unistd::Pid;

fn main() {
    let pid = Pid::from_raw(1234);
    let shellcode = fs::read("shellcode.bin").unwrap();

    // Blocks the injectee while the shellcode runs
    android_injector::inject_shellcode_blocking(pid, &shellcode, None).unwrap();

    // Doesn't block the injectee while the shellcode runs
    android_injector::inject_shellcode_parallel(pid, &shellcode, None).unwrap();
}
```

See complete examples in `/examples`.
