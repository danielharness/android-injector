use std::process;
use std::thread::sleep;
use std::time::Duration;

fn main() {
    let pid = process::id();

    loop {
        println!("pid = {pid}");
        sleep(Duration::from_secs(1));
    }
}
