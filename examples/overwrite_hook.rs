use anyhow::Result;
use koyhook::KoyHook;
use simple_logger::SimpleLogger;
use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::OnceLock;

type PrintNameT = fn(&str, i32) -> i32;

static ORIGINAL_PRINT_NAME: OnceLock<PrintNameT> = OnceLock::new();

fn print_name_hk(name: &str, value: i32) -> i32 {
    println!("Hooked! input value was = {name}");

    let value = ORIGINAL_PRINT_NAME.get().unwrap()(name, value);

    value + 1
}

fn print_name(name: &str, value: i32) -> i32 {
    println!("{name}");
    value
}

fn main() -> Result<()> {
    SimpleLogger::new().with_colors(true).init().unwrap();

    let hooker = KoyHook::new();

    let original_print_name: PrintNameT = unsafe {
        std::mem::transmute(hooker.overwrite_hook(
            NonNull::new(print_name as *mut u8).unwrap(),
            NonNull::new(print_name_hk as *mut u8).unwrap(),
        )?)
    };

    ORIGINAL_PRINT_NAME.set(original_print_name);

    //loop {}
    for i in 0..10 {
        let val = print_name("koy", i);
        println!("{val}");
    }

    Ok(())
}
