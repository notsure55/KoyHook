use anyhow::Result;
use dynasmrt::{dynasm, DynasmApi, ExecutableBuffer};
use iced_x86::{
    self, Code, Decoder, DecoderOptions, Encoder, Instruction, MemoryOperand, OpKind, Register,
};
use std::ptr::NonNull;

pub const MAX_INSTRUCTION_LEN: usize = 15;
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
pub fn calculate_size_rel_to_ins(func: &NonNull<u8>, len: usize) -> Option<usize> {
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
// TODO Fix this dogshizzle
fn update_relative_offset<T: num_traits::PrimInt>(bytes: *mut u8, reloc_diff: T, offset: usize) {
    unsafe {
        let ptr = bytes.add(offset).cast::<T>();

        let value = ptr.read_unaligned();

        ptr.write_unaligned(value + reloc_diff);
    }
}

fn read_relative_offset<T: num_traits::PrimInt>(bytes: *mut u8, offset: usize) -> T {
    unsafe {
        let ptr = bytes.add(offset).cast::<T>();

        ptr.read_unaligned()
    }
}

pub fn create_jmp1(addr: usize) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new(64);

    let new_ins1 = Instruction::with2(Code::Mov_r64_imm64, Register::RAX, addr as u64)?;

    let new_ins2 = Instruction::with1(Code::Jmp_rm64, Register::RAX)?;

    encoder.encode(&new_ins1, addr as u64)?;
    encoder.encode(&new_ins2, (addr + new_ins1.len()) as u64)?;

    Ok(encoder.take_buffer())
}

pub fn create_mov_64_from_relative_lea(ins: Instruction) -> Result<Instruction> {
    let op0 = ins.op0_register();

    log::info!("Old Instruction = {ins}");

    let new_ins = Instruction::with2(Code::Mov_r64_imm64, op0, ins.memory_displacement64())?;

    log::info!("New Instruction = {new_ins}");

    Ok(new_ins)
}

pub fn create_farbranch_from_nearbranch64(
    ins: Instruction,
    original_function_call: Option<usize>,
    target_new_location: Option<usize>,
) -> Result<[Instruction; 2]> {
    log::info!("Old Instruction = {ins}");

    let displacement = ins.memory_displacement64();

    let mut new_ins1 = Instruction::with2(Code::Mov_r64_imm64, Register::RAX, displacement)?;

    if let Some(original) = original_function_call {
        log::info!("{displacement:X}, {original:X}");
        if displacement == original as u64 {
            log::info!("Found call to original function patching!");
            new_ins1 = Instruction::with2(
                Code::Mov_r64_imm64,
                Register::RAX,
                target_new_location.unwrap() as u64,
            )?;
        }
    }

    let new_ins2 = Instruction::with1(Code::Call_rm64, Register::RAX)?;

    log::info!("New Instructions = {new_ins1} {new_ins2}");

    Ok([new_ins1, new_ins2])
}

pub fn process_ins(
    ins: Instruction,
    original_function_call: Option<usize>,
    target_new_location: Option<usize>,
) -> Result<Vec<Instruction>> {
    let mut new_instructions = vec![];

    if ins.is_ip_rel_memory_operand() == true {
        log::info!("Found relative instruction patching!");
        new_instructions.push(create_mov_64_from_relative_lea(ins)?);
    }

    let op = ins.op0_kind();

    match op {
        OpKind::NearBranch16 => println!("Found rip relative nearbranch16 = {ins}"),
        OpKind::NearBranch32 => println!("Found rip relative nearbranch32 = {ins}"),
        OpKind::NearBranch64 => {
            if ins.is_jmp_short() || ins.is_jcc_short() {
                log::info!("Found rip relative jmpshort! {ins}");
            } else {
                log::info!("Found rip relative nearbranch64");
                new_instructions.extend_from_slice(&create_farbranch_from_nearbranch64(
                    ins,
                    original_function_call,
                    target_new_location,
                )?);
            }
        }
        OpKind::FarBranch16 | OpKind::FarBranch32 => {}
        _ => (),
    }

    if new_instructions.is_empty() {
        new_instructions.push(ins);
    }

    Ok(new_instructions)
}

pub fn fixup_func_relatives(
    bytes: &mut Vec<u8>,
    addr: usize,
    original_addr: usize,
    target_function_call: Option<usize>,
    target_new_location: Option<usize>,
) -> Result<()> {
    let bytes_clone = bytes.clone();

    let mut encoder = Encoder::new(64);

    let mut decoder =
        Decoder::with_ip(64, &bytes_clone, original_addr as u64, DecoderOptions::NONE);

    for ins in decoder.iter() {
        let ip = ins.ip();

        let new_ins = process_ins(ins, target_function_call, target_new_location)?;

        for ins in new_ins.iter() {
            encoder.encode(ins, ip)?;
        }
    }

    *bytes = encoder.take_buffer();

    Ok(())
}
