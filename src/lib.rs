use anyhow::Result;
use dynasmrt::{dynasm, DynasmApi, ExecutableBuffer};
use iced_x86::{Decoder, DecoderOptions};
use std::ffi::c_void;
use std::ptr::NonNull;
use windows::Win32::System::Memory::*;

const MAX_INSTRUCTION_LEN: usize = 15;

pub struct Hooker {}

impl Hooker {
    pub fn new() -> Self {
        Self {}
    }
    fn create_jmp(func: *const u8) -> ExecutableBuffer {
        let mut ops = dynasmrt::x64::Assembler::new().unwrap();

        dynasm!(ops
                ; .arch x64
                ; mov rax, QWORD func as _
                ; jmp rax
        );

        ops.finalize().unwrap()
    }
    fn create_call(func: *const u8) -> ExecutableBuffer {
        let mut ops = dynasmrt::x64::Assembler::new().unwrap();

        dynasm!(ops
                ; .arch x64
                ; mov rax, QWORD func as _
                ; call rax
        );

        ops.finalize().unwrap()
    }
    fn calculate_overwrite_size(func: NonNull<u8>, len: usize) -> Option<usize> {
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
    fn copy_bytes(ptr: NonNull<u8>, size: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; size];
        unsafe { ptr.as_ptr().copy_to(bytes.as_mut_ptr(), size) };

        bytes
    }
    fn push_registers() -> ExecutableBuffer {
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
    fn pop_registers() -> ExecutableBuffer {
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
    pub fn trampoline_hook(&self, target: NonNull<u8>, detour: NonNull<u8>) -> Result<()> {
        let detour_call = Self::create_call(detour.as_ptr());

        // hard coded as 12 for now because jmp byte count is always 12
        let size = Self::calculate_overwrite_size(target, 12)
            .expect("Failed to get corrent length for function instructions");

        let target_jmp = Self::create_jmp(unsafe { target.byte_add(size) }.as_ptr());

        let overwrite_bytes = Self::copy_bytes(target, size);

        let push_registers = Self::push_registers();
        let pop_registers = Self::pop_registers();

        let trampoline_total_size = target_jmp.len()
            + detour_call.len()
            + size
            + push_registers.len()
            + pop_registers.len();

        // allocate memory for trampoline function
        let original_address = unsafe {
            VirtualAlloc(
                None,
                trampoline_total_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        let trampoline_jmp = Self::create_jmp(original_address.cast::<u8>());

        println!("Trampoline address = {original_address:p}");

        let trampoline_address = NonNull::new(original_address).unwrap().cast::<u8>();

        // First write push registers so we can save the registers for calling the original func
        let trampoline_address = copy_bytes_to_memory(
            trampoline_address,
            push_registers.ptr(dynasmrt::AssemblyOffset(0)),
            push_registers.len(),
        );

        // Then we call our detour func
        let trampoline_address = copy_bytes_to_memory(
            trampoline_address,
            detour_call.ptr(dynasmrt::AssemblyOffset(0)),
            detour_call.len(),
        );

        // pop all registers after detour func
        let trampoline_address = copy_bytes_to_memory(
            trampoline_address,
            pop_registers.ptr(dynasmrt::AssemblyOffset(0)),
            pop_registers.len(),
        );

        // write back overwritten bytes
        let trampoline_address = copy_bytes_to_memory(
            trampoline_address,
            overwrite_bytes.as_ptr(),
            overwrite_bytes.len(),
        );

        let _ = copy_bytes_to_memory(
            trampoline_address,
            target_jmp.ptr(dynasmrt::AssemblyOffset(0)),
            target_jmp.len(),
        );

        copy_bytes_to_readable_memory(
            target,
            trampoline_jmp.ptr(dynasmrt::AssemblyOffset(0)),
            trampoline_jmp.len(),
        )?;

        unsafe {
            overwrite_memory_protections(
                original_address,
                trampoline_total_size,
                PAGE_EXECUTE_READ,
            )?;
        }

        Ok(())
    }

    pub fn inline_hook(&self, target: NonNull<u8>, detour: NonNull<u8>) -> Result<()> {
        let detour_jmp = Self::create_jmp(detour.as_ptr());

        copy_bytes_to_readable_memory(
            target,
            detour_jmp.ptr(dynasmrt::AssemblyOffset(0)),
            detour_jmp.len(),
        )?;

        Ok(())
    }
}

pub unsafe fn overwrite_memory_protections(
    ptr: *mut c_void,
    size: usize,
    flags: PAGE_PROTECTION_FLAGS,
) -> Result<PAGE_PROTECTION_FLAGS> {
    unsafe {
        let mut old_protect: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
        VirtualProtect(ptr, size, flags, &mut old_protect)?;
        Ok(old_protect)
    }
}

pub fn copy_bytes_to_memory(dst: NonNull<u8>, src: *const u8, size: usize) -> NonNull<u8> {
    unsafe {
        dst.as_ptr().copy_from(src, size);
        dst.add(size)
    }
}

pub fn copy_bytes_to_readable_memory(dst: NonNull<u8>, src: *const u8, size: usize) -> Result<()> {
    // SAFETY: This write is safe because pointers are know to be nonnull so we can overwrite memory without an access violation
    unsafe {
        let old_protect =
            overwrite_memory_protections(dst.as_ptr() as _, size, PAGE_EXECUTE_READWRITE)?;

        dst.as_ptr().copy_from(src, size);

        overwrite_memory_protections(dst.as_ptr() as _, size, old_protect)?;
    }

    Ok(())
}
