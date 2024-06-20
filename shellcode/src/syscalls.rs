use core::arch::asm;

#[cfg(target_arch = "arm")]
pub unsafe fn write(fd: i32, msg: *const u8, len: usize) -> Result<usize, ()> {
    let sys_nr: usize = 4;
    let ret: isize;
    asm!(
    "svc #0",
    in("r7") sys_nr,
    in("r0") fd,
    in("r1") msg,
    in("r2") len,
    lateout("r0") ret,
    );
    match ret {
        -1 => Err(()),
        _ => Ok(ret as usize),
    }
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn write(fd: i32, msg: *const u8, len: usize) -> Result<usize, ()> {
    let sys_nr: usize = 64;
    let ret: isize;
    asm!(
    "svc #0",
    in("x8") sys_nr,
    in("x0") fd,
    in("x1") msg,
    in("x2") len,
    lateout("x0") ret,
    );
    match ret {
        -1 => Err(()),
        _ => Ok(ret as usize),
    }
}
