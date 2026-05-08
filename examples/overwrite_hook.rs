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

    let value = if let Some(print_name) = ORIGINAL_PRINT_NAME.get() {
        print_name(name, value)
    } else {
        0
    };

    value + 1
}

fn print_name(name: &str, value: i32) -> i32 {
    println!("My name is = {name}");
    value
}

fn main() -> Result<()> {
    SimpleLogger::new().with_colors(true).init().unwrap();

    let mut hooker = KoyHook::new();

    let original_print_name: PrintNameT = unsafe {
        std::mem::transmute(hooker.hook(
            NonNull::new(print_name as *mut u8).unwrap(),
            NonNull::new(print_name_hk as *mut u8).unwrap(),
        )?)
    };

    ORIGINAL_PRINT_NAME.set(original_print_name);

    for i in 0..10 {
        let val = print_name("koy", i);
        println!("{val}");
    }

    hooker.detach_all();

    for i in 0..10 {
        let _ = print_name("tiny", i);
    }

    Ok(())
}
