//! Small C API written in Rust with four seeded boundary bugs (`buggy_*`) and
//! their fixed counterparts (`fixed_*`). Used by ffi-review's lab to check that
//! the generated NULL-argument tests make miri / ASan flag the buggy exports
//! and pass on the fixed ones.
use std::ffi::{c_char, c_int, CStr};

/// Sums `len` bytes. Bug: no NULL check before building the slice.
#[no_mangle]
pub extern "C" fn buggy_sum(data: *const u8, len: usize) -> u64 {
    let s = unsafe { std::slice::from_raw_parts(data, len) };
    s.iter().map(|&b| b as u64).sum()
}

#[no_mangle]
pub extern "C" fn fixed_sum(data: *const u8, len: usize) -> u64 {
    if data.is_null() {
        return 0;
    }
    let s = unsafe { std::slice::from_raw_parts(data, len) };
    s.iter().map(|&b| b as u64).sum()
}

/// Length of a C string. Bug: CStr::from_ptr on NULL.
#[no_mangle]
pub extern "C" fn buggy_strlen(s: *const c_char) -> usize {
    unsafe { CStr::from_ptr(s) }.to_bytes().len()
}

#[no_mangle]
pub extern "C" fn fixed_strlen(s: *const c_char) -> usize {
    if s.is_null() {
        return 0;
    }
    unsafe { CStr::from_ptr(s) }.to_bytes().len()
}

/// Writes `n` into `*out`. Bug: writes through a NULL out-pointer.
#[no_mangle]
pub extern "C" fn buggy_store(out: *mut c_int, n: c_int) -> c_int {
    unsafe { *out = n };
    0
}

#[no_mangle]
pub extern "C" fn fixed_store(out: *mut c_int, n: c_int) -> c_int {
    if out.is_null() {
        return -1;
    }
    unsafe { *out = n };
    0
}

/// Copies `len` bytes from `src` to `dst`. Bug: no NULL check (with len 0
/// current Rust accepts NULL, so only the len 16 call is UB).
#[no_mangle]
pub extern "C" fn buggy_copy(dst: *mut u8, src: *const u8, len: usize) -> c_int {
    unsafe { std::ptr::copy_nonoverlapping(src, dst, len) };
    0
}

#[no_mangle]
pub extern "C" fn fixed_copy(dst: *mut u8, src: *const u8, len: usize) -> c_int {
    if dst.is_null() || src.is_null() {
        return -1;
    }
    unsafe { std::ptr::copy_nonoverlapping(src, dst, len) };
    0
}
