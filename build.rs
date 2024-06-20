use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo::rerun-if-changed=shellcode/src/");
    std::env::set_current_dir("shellcode").unwrap();
    let shellcode_arm32 = build_shellcode("armv7a-none-eabi");
    let shellcode_arm64 = build_shellcode("aarch64-unknown-none");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::copy(shellcode_arm32, out_dir.join("shellcode_arm32.bin")).unwrap();
    std::fs::copy(shellcode_arm64, out_dir.join("shellcode_arm64.bin")).unwrap();
}

fn build_shellcode(target: &str) -> PathBuf {
    assert!(Command::new("cargo")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .arg("build")
        .arg("--release")
        .arg("--target")
        .arg(target)
        .status()
        .unwrap()
        .success());

    let target_dir = PathBuf::from(format!("target/{target}/release/"));
    let shellcode_binary = target_dir.join("shellcode");
    let shellcode_stripped = target_dir.join("shellcode.stripped");
    let shellcode_raw = target_dir.join("shellcode.bin");
    assert!(Command::new("strip")
        .arg("-s")
        .arg("--strip-unneeded")
        .arg("-x")
        .arg("-X")
        .arg("-o")
        .arg(&shellcode_stripped)
        .arg(&shellcode_binary)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("objcopy")
        .arg("-O")
        .arg("binary")
        .arg(&shellcode_stripped)
        .arg(&shellcode_raw)
        .status()
        .unwrap()
        .success());
    shellcode_raw
}
