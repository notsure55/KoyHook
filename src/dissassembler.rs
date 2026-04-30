use dynasmrt::{dynasm, DynasmApi, ExecutableBuffer};
use iced_x86::{self, Decoder, DecoderOptions, OpKind};
use std::ptr::NonNull;

pub const MAX_INSTRUCTION_LEN: usize = 15;
pub const JMP_LEN: usize = 12;
const MAX_FUNCTION_SIZE: usize = 4096;

pub fn calculate_function_size(func: NonNull<u8>) -> (usize, usize) {
    // Length plus max instruction length so we dont chop off any instructions when overwriting bytes
    let data = std::ptr::slice_from_raw_parts::<u8>(func.as_ptr(), MAX_FUNCTION_SIZE);

    let mut function_size = 0;
    let mut function_extra_size = 0;

    unsafe {
        for i in 0..(&*data).len() {
            if (&*data)[i] == 0xCC && function_size == 0 {
                function_size = i;
            }

            if function_size != 0 {
                function_extra_size += 1;
                if (&*data)[i] != 0xCC {
                    function_extra_size -= 1;
                    break;
                }
            }
        }
    }

    (function_size, function_extra_size)
}

pub fn create_jmp(func: *const u8) -> ExecutableBuffer {
    let mut ops = dynasmrt::x64::Assembler::new().unwrap();

    dynasm!(ops
            ; .arch x64
            ; mov rax, QWORD func as _
            ; jmp rax
    );

    ops.finalize().unwrap()
}
pub fn create_call(func: *const u8) -> ExecutableBuffer {
    let mut ops = dynasmrt::x64::Assembler::new().unwrap();

    dynasm!(ops
            ; .arch x64
            ; mov rax, QWORD func as _
            ; call rax
    );

    ops.finalize().unwrap()
}
pub fn calculate_size_rel_to_ins(func: NonNull<u8>, len: usize) -> Option<usize> {
    // Length plus max instruction length so we dont chop off any instructions when overwriting bytes
    let data = std::ptr::slice_from_raw_parts::<u8>(func.as_ptr(), len + MAX_INSTRUCTION_LEN);

    let decoder = Decoder::new(64, unsafe { &*data }, DecoderOptions::NONE).into_iter();

    let mut current_size = 0;
    for ins in decoder {
        current_size += ins.len();
        if current_size >= len {
            break;
        }
    }

    // SAFETY if we break from the loop without having a size higher than len we
    // will return None because there is not enough space to overwrite bytes
    if current_size < len {
        None
    } else {
        Some(current_size)
    }
}
pub fn push_registers() -> ExecutableBuffer {
    let mut ops = dynasmrt::x64::Assembler::new().unwrap();

    dynasm!(ops
            ; .arch x64
            ; push rax
            ; push rcx
            ; push rdx
            ; push rbx
            ; push rsi
            ; push rdi
            ; push r8
            ; push r9
            ; push r10
            ; push r11
            ; push r12
            ; push r13
            ; push r14
            ; push r15
    );

    ops.finalize().unwrap()
}
pub fn pop_registers() -> ExecutableBuffer {
    let mut ops = dynasmrt::x64::Assembler::new().unwrap();

    dynasm!(ops
            ; .arch x64
            ; pop r15
            ; pop r14
            ; pop r13
            ; pop r12
            ; pop r11
            ; pop r10
            ; pop r9
            ; pop r8
            ; pop rdi
            ; pop rsi
            ; pop rbx
            ; pop rdx
            ; pop rcx
            ; pop rax
    );

    ops.finalize().unwrap()
}

// 70
pub fn update_relative_offset<T: num_traits::PrimInt>(
    bytes: *mut u8,
    reloc_diff: T,
    offset: usize,
) {
    unsafe {
        let ptr = bytes.add(offset).cast::<T>();

        let value = ptr.read_unaligned();

        ptr.write_unaligned(value + reloc_diff);
    }
}

pub fn read_relative_offset<T: num_traits::PrimInt>(
    bytes: *mut u8,
    reloc_diff: T,
    offset: usize,
) -> T {
    unsafe {
        let ptr = bytes.add(offset).cast::<T>();

        ptr.read_unaligned()
    }
}

pub fn fixup_func_relatives(
    bytes: &mut Vec<u8>,
    addr: usize,
    original_addr: usize,
    new_target_addr: Option<usize>,
) {
    let bytes_clone = bytes.clone();

    let mut decoder =
        Decoder::with_ip(64, &bytes_clone, original_addr as u64, DecoderOptions::NONE);

    let relocation_difference = (original_addr as i64 - addr as i64) as i32;

    for ins in decoder.iter() {
        let ip = ins.ip();

        if ins.is_ip_rel_memory_operand() == true {
            println!("Found relative instruction patching!");

            update_relative_offset::<i32>(
                bytes.as_mut_ptr(),
                relocation_difference as i32,
                ip as usize - original_addr + ins.len() - 4,
            );
        }

        let op = ins.op0_kind();

        match op {
            OpKind::NearBranch16 => println!("Found rip relative nearbranch16 = {ins}"),
            OpKind::NearBranch32 => println!("Found rip relative nearbranch32 = {ins}"),
            OpKind::NearBranch64 => {
                println!("Found rip relative nearbranch64 = {ins}");
                let offset = read_relative_offset::<i32>(
                    bytes.as_mut_ptr(),
                    relocation_difference,
                    ip as usize - original_addr + ins.len() - 4,
                );

                // this means offset calls new address
                if (ip as i64 + offset as i64 + ins.len() as i64) as usize == addr {
                    println!("Relative call to old address Patching!");
                    if let Some(new_target_addr) = new_target_addr {
                        update_relative_offset::<i32>(
                            bytes.as_mut_ptr(),
                            (original_addr as i64 - new_target_addr as i64) as i32,
                            ip as usize - original_addr + ins.len() - 4,
                        );
                    }
                } else {
                    update_relative_offset::<i32>(
                        bytes.as_mut_ptr(),
                        relocation_difference,
                        ip as usize - original_addr + ins.len() - 4,
                    );
                }
            }
            OpKind::FarBranch16 | OpKind::FarBranch32 => {}
            _ => (),
        };
    }
}
