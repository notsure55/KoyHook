use anyhow::Result;
use std::ptr::NonNull;
use windows::Win32::System::Memory::*;

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
        let size = dissassembler::calculate_size_rel_to_ins(&target, 12)
            .expect("Failed to get corrent length for function instructions");

        let target_jmp = dissassembler::create_jmp(unsafe { target.byte_add(size) }.as_ptr());

        let overwrite_bytes = memory::copy_bytes(&target, size);

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

    pub fn relocate_target(target: &NonNull<u8>, size: usize) -> Result<NonNull<u8>> {
        let new_target = memory::allocate(size);

        log::info!(
            "Relocating target function! {:p} Current size = {size:X}",
            new_target
        );

        let mut target_bytes = memory::copy_bytes(target, size);

        dissassembler::fixup_func_relatives(
            &mut target_bytes,
            new_target.addr().into(),
            target.addr().into(),
            None,
            None,
        )?;

        log::info!("New size of target = {:X}", target_bytes.len());

        let _ = memory::copy_bytes_to_memory(new_target, target_bytes.as_ptr(), target_bytes.len());

        Ok(new_target)
    }

    pub fn relocate_detour(
        detour: &NonNull<u8>,
        size: usize,
        target_old_location: &NonNull<u8>,
        target_new_location: &NonNull<u8>,
        size_diff: i32,
    ) -> Result<NonNull<u8>> {
        let mut detour_bytes = memory::copy_bytes(detour, size);

        let detour_leftovers = if size_diff > 0 {
            log::info!("Detour larger than Target allocating extraspace for detour!");
            let difference =
                dissassembler::calculate_size_rel_to_ins(detour, size - size_diff as usize - 12)
                    .unwrap();

            // NEED 12 extra bytes for jmp at end
            let mut leftover_bytes: Vec<u8> = detour_bytes.drain(difference..).collect();

            let leftover_addr = memory::allocate(leftover_bytes.len());

            dissassembler::fixup_func_relatives(
                &mut leftover_bytes,
                leftover_addr.addr().into(),
                usize::from(detour.addr()) + difference,
                Some(target_old_location.addr().into()),
                Some(target_new_location.addr().into()),
            )?;

            memory::copy_bytes_to_memory(
                leftover_addr,
                leftover_bytes.as_ptr(),
                leftover_bytes.len(),
            );

            log::info!("Done setting up extraspace for detour! {leftover_addr:p}");

            let leftovers_jmp = dissassembler::create_jmp1(leftover_addr.addr().into())?;

            Some(leftovers_jmp)
        } else {
            None
        };

        dissassembler::fixup_func_relatives(
            &mut detour_bytes,
            target_old_location.addr().into(),
            detour.addr().into(),
            Some(target_old_location.addr().into()),
            Some(target_new_location.addr().into()),
        )?;

        if let Some(leftovers_jmp) = detour_leftovers {
            detour_bytes.extend(leftovers_jmp);
        }

        memory::copy_bytes_to_readable_memory(
            *target_old_location,
            detour_bytes.as_ptr(),
            detour_bytes.len(),
        );

        Ok(*detour)
    }

    pub fn overwrite_hook(&self, target: NonNull<u8>, detour: NonNull<u8>) -> Result<()> {
        let (target_size, target_extra_size) = dissassembler::calculate_function_size(target);
        let (detour_size, _) = dissassembler::calculate_function_size(detour);

        let new_target = Self::relocate_target(&target, target_size)?;

        let size_diff = i32::try_from(detour_size)?
            - (i32::try_from(target_size)? + i32::try_from(target_extra_size)?);

        let _ = Self::relocate_detour(&detour, detour_size, &target, &new_target, size_diff)?;

        Ok(())
    }
}
