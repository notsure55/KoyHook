use anyhow::Result;
use std::ptr::NonNull;
use windows::Win32::System::Memory::*;

mod dissassembler;
mod memory;

use lifter::Dissassembler;

pub struct KoyHook {}

impl KoyHook {
    pub fn new() -> Self {
        Self {}
    }
    /*pub fn trampoline_hook(&self, target: NonNull<u8>, detour: NonNull<u8>) -> Result<()> {
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
    }*/

    pub fn relocate_target(
        target: &NonNull<u8>,
        size: usize,
        dissassembler: &Dissassembler,
    ) -> Result<NonNull<u8>> {
        let new_target = memory::allocate(size);

        let bytes = memory::copy_bytes(&target, size);

        let mut function =
            dissassembler.dissassemble_function(&bytes, usize::from(target.addr()) as u64);

        log::info!("Original target = {function}");

        let relocated_function = function.fix_relocations(usize::from(new_target.addr()) as u64)?;

        log::info!("Relocated target = {relocated_function}");

        let bytes = relocated_function.to_bytes()?;

        let _ = memory::copy_bytes_to_memory(new_target, bytes.as_ptr(), bytes.len());

        Ok(new_target)
    }

    pub fn relocate_detour(
        detour: &NonNull<u8>,
        size: usize,
        target_old_location: &NonNull<u8>,
        size_diff: i32,
        dissassembler: &Dissassembler,
    ) -> Result<NonNull<u8>> {
        let bytes = memory::copy_bytes(&detour, size);

        let mut function =
            dissassembler.dissassemble_function(&bytes, usize::from(detour.addr()) as u64);

        log::info!("Original detour = {function}");

        let relocated_function =
            function.fix_relocations(usize::from(target_old_location.addr()) as u64)?;

        log::info!("Relocated detour = {relocated_function}");

        let mut bytes = relocated_function.to_bytes()?;

        let detour_leftovers = if size_diff > 0 {
            log::info!("Detour larger than Target allocating extraspace for detour!");
            let difference = dissassembler::calculate_size_rel_to_ins(
                &bytes,
                bytes.len() - size_diff as usize - 12,
            )
            .unwrap();

            // NEED 12 extra bytes for jmp at end
            let mut leftover_bytes: Vec<u8> = bytes.drain(difference..).collect();

            let leftover_addr = memory::allocate(leftover_bytes.len());

            memory::copy_bytes_to_memory(
                leftover_addr,
                leftover_bytes.as_ptr(),
                leftover_bytes.len(),
            );

            log::info!("Done setting up extraspace for detour! {leftover_addr:p}");

            let leftovers_jmp = lifter::create_jmp1(usize::from(leftover_addr.addr()) as u64)?;

            Some(leftovers_jmp)
        } else {
            None
        };

        if let Some(leftovers_jmp) = detour_leftovers {
            bytes.extend(leftovers_jmp);
        }

        memory::copy_bytes_to_readable_memory(*target_old_location, bytes.as_ptr(), bytes.len());

        Ok(*target_old_location)
    }

    pub fn overwrite_hook(&self, target: NonNull<u8>, detour: NonNull<u8>) -> Result<NonNull<u8>> {
        let (target_size, target_extra_size) = dissassembler::calculate_function_size(target);

        let dissassembler = lifter::Dissassembler::new();

        let new_target = Self::relocate_target(&target, target_size, &dissassembler)?;

        let jmp_bytes = lifter::create_jmp1(usize::from(detour.addr()) as u64)?;

        memory::copy_bytes_to_readable_memory(target, jmp_bytes.as_ptr(), jmp_bytes.len());

        log::info!("{new_target:p}");

        Ok(new_target)
    }
}
