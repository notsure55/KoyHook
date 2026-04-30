use koyhook::KoyHook;
use std::ffi::c_void;
use std::ptr::NonNull;

fn print_name_hk(name: &str) -> i32 {
    println!("Hooked! input value was = {name}");

    print_name("Hai from inside print_name we hooked it up yu'erd");
    67
}

fn print_name(name: &str) -> i32 {
    println!("{name}");
    0
}

fn main() {
    let hooker = KoyHook::new();

    hooker.overwrite_hook(
        NonNull::new(print_name as *mut u8).unwrap(),
        NonNull::new(print_name_hk as *mut u8).unwrap(),
    );

    let val = print_name("koy");
    println!("{val}");
}
