use anyhow::Result;
use std::ptr::NonNull;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;

mod dissassembler;
mod memory;

pub struct KoyHook {}

impl KoyHook {
    pub fn new() -> Self {
        Self {}
    }
    pub fn trampoline_hook(&self, target: NonNull<u8>, detour: NonNull<u8>) -> Result<()> {
        let detour_call = dissassembler::create_call(detour.as_ptr());

        // hard coded as 12 for now because jmp byte count is always 12
        let size = dissassembler::calculate_size_rel_to_ins(target, 12)
            .expect("Failed to get corrent length for function instructions");

        let target_jmp = dissassembler::create_jmp(unsafe { target.byte_add(size) }.as_ptr());

        let overwrite_bytes = memory::copy_bytes(target, size);

        let push_registers = dissassembler::push_registers();
        let pop_registers = dissassembler::pop_registers();

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

        let trampoline_jmp = dissassembler::create_jmp(original_address.cast::<u8>());

        println!("Trampoline address = {original_address:p}");

        let trampoline_address = NonNull::new(original_address).unwrap().cast::<u8>();

        // First write push registers so we can save the registers for calling the original func
        let trampoline_address = memory::copy_bytes_to_memory(
            trampoline_address,
            push_registers.ptr(dynasmrt::AssemblyOffset(0)),
            push_registers.len(),
        );

        // Then we call our detour func
        let trampoline_address = memory::copy_bytes_to_memory(
            trampoline_address,
            detour_call.ptr(dynasmrt::AssemblyOffset(0)),
            detour_call.len(),
        );

        // pop all registers after detour func
        let trampoline_address = memory::copy_bytes_to_memory(
            trampoline_address,
            pop_registers.ptr(dynasmrt::AssemblyOffset(0)),
            pop_registers.len(),
        );

        // write back overwritten bytes
        let trampoline_address = memory::copy_bytes_to_memory(
            trampoline_address,
            overwrite_bytes.as_ptr(),
            overwrite_bytes.len(),
        );

        let _ = memory::copy_bytes_to_memory(
            trampoline_address,
            target_jmp.ptr(dynasmrt::AssemblyOffset(0)),
            target_jmp.len(),
        );

        unsafe {
            memory::overwrite_memory_protections(
                original_address,
                trampoline_total_size,
                PAGE_EXECUTE_READ,
            )?;
        }

        memory::copy_bytes_to_readable_memory(
            target,
            trampoline_jmp.ptr(dynasmrt::AssemblyOffset(0)),
            trampoline_jmp.len(),
        )?;

        Ok(())
    }
    pub fn inline_hook(&self, target: NonNull<u8>, detour: NonNull<u8>) -> Result<()> {
        let detour_jmp = dissassembler::create_jmp(detour.as_ptr());

        memory::copy_bytes_to_readable_memory(
            target,
            detour_jmp.ptr(dynasmrt::AssemblyOffset(0)),
            detour_jmp.len(),
        )?;

        Ok(())
    }

    pub fn overwrite_hook(&self, target: NonNull<u8>, detour: NonNull<u8>) -> Result<NonNull<u8>> {
        let (target_size, target_extra_size) = dissassembler::calculate_function_size(target);
        let (detour_size, _) = dissassembler::calculate_function_size(detour);

        let mut target_bytes = memory::copy_bytes(target, target_size);
        let mut detour_bytes = memory::copy_bytes(detour, detour_size);

        let new_target = NonNull::new(unsafe {
            VirtualAlloc(None, target_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as *mut u8
        })
        .unwrap();

        dissassembler::fixup_func_relatives(
            &mut target_bytes,
            new_target.addr().into(),
            target.addr().into(),
            None,
        );

        memory::copy_bytes_to_memory(new_target, target_bytes.as_ptr(), target_size);

        unsafe {
            memory::overwrite_memory_protections(
                new_target.as_ptr() as _,
                target_size,
                PAGE_EXECUTE_READ,
            )?;
        }

        //dissassembler::fixup(target_bytes);
        dissassembler::fixup_func_relatives(
            &mut detour_bytes,
            target.addr().into(),
            detour.addr().into(),
            Some(new_target.addr().into()),
        );

        let difference = detour_size as i64 - target_size as i64;

        // Then we can overwrite bytes from target with detour
        if difference <= target_extra_size as i64 {
            println!("Difference is less than extra bytes overwriting target! {target:?}");
            memory::copy_bytes_to_readable_memory(target, detour_bytes.as_ptr(), detour_size);

            // TODO find out if flushing cache actually matters
            unsafe {
                let handle = GetCurrentProcess();
                FlushInstructionCache(handle, Some(target.as_ptr() as _), detour_size)
            };
        } else {
            let new_size = (detour_size as i64
                - difference
                - dissassembler::JMP_LEN as i64
                - dissassembler::MAX_INSTRUCTION_LEN as i64) as usize;

            let detour_new_size =
                dissassembler::calculate_size_rel_to_ins(detour, new_size).unwrap();

            let left_over = detour_size - detour_new_size;

            memory::copy_bytes_to_readable_memory(target, detour_bytes.as_ptr(), detour_new_size);

            let detour_branch = NonNull::new(unsafe {
                VirtualAlloc(None, left_over, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as *mut u8
            })
            .unwrap();

            let jmp_bytes = dissassembler::create_jmp(detour_branch.as_ptr());

            let mut detour_branch_bytes = vec![];
            detour_branch_bytes.extend_from_slice(&detour_bytes[detour_new_size..]);

            dissassembler::fixup_func_relatives(
                &mut detour_branch_bytes,
                detour_branch.addr().into(),
                detour.addr().into(),
                Some(new_target.addr().into()),
            );
        }

        Ok(target)
    }
}
