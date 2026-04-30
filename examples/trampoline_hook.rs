use koyhook::Hooker;
use std::ffi::c_void;
use std::ptr::NonNull;

fn print_name_hk(name: &str) -> i32 {
    println!("Hooked! input value was = {name}");
    67
}

fn print_name(name: &str) -> i32 {
    println!("{name}");
    0
}

fn main() {
    let hooker = Hooker::new();

    hooker.trampoline_hook(
        NonNull::new(print_name as *mut u8).unwrap(),
        NonNull::new(print_name_hk as *mut u8).unwrap(),
    );

    let val = print_name("Koy");
    println!("{val}");
}
