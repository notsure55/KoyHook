use anyhow::Result;
use std::collections::HashMap;
use std::ptr::NonNull;

mod memory;

use lifter::Dissassembler;

struct CachedHook {
    original_bytes: Vec<u8>,
    original_address: NonNull<u8>,
}

pub struct KoyHook {
    hooks: HashMap<u64, CachedHook>,
}

impl KoyHook {
    pub fn new() -> Self {
        Self {
            hooks: HashMap::new(),
        }
    }

    pub fn relocate_target(
        target: &NonNull<u8>,
        size: usize,
        dissassembler: &Dissassembler,
    ) -> Result<(NonNull<u8>, Vec<u8>)> {
        let new_target = memory::allocate(size);

        let original_bytes = memory::copy_bytes(&target, size);

        let mut function =
            dissassembler.dissassemble_function(&original_bytes, usize::from(target.addr()) as u64);

        log::info!("Original target = {function}");

        let relocated_function = function.fix_relocations()?;

        log::info!("Relocated target = {relocated_function}");

        let bytes = relocated_function.to_bytes()?;

        let _ = memory::copy_bytes_to_memory(new_target, bytes.as_ptr(), bytes.len());

        Ok((new_target, original_bytes))
    }

    pub fn hook(&mut self, target: NonNull<u8>, detour: NonNull<u8>) -> Result<NonNull<u8>> {
        let target_size = lifter::helper::MAX_FUNCTION_SIZE;

        let dissassembler = lifter::Dissassembler::new();

        let (new_target, target_original_bytes) =
            Self::relocate_target(&target, target_size, &dissassembler)?;

        let jmp_bytes = lifter::create_jmp1(usize::from(detour.addr()) as u64)?;

        memory::copy_bytes_to_readable_memory(target, jmp_bytes.as_ptr(), jmp_bytes.len())?;

        log::info!("{new_target:p}");

        self.hooks.insert(
            usize::from(new_target.addr()) as u64,
            CachedHook {
                original_bytes: target_original_bytes,
                original_address: target,
            },
        );

        Ok(new_target)
    }

    /// Pass in new address returned from hook
    pub fn detach(&self, address: u64) -> Result<()> {
        log::info!("Detaching hook {address:X}!");
        if let Some(cached_hook) = self.hooks.get(&address) {
            memory::copy_bytes_to_readable_memory(
                cached_hook.original_address,
                cached_hook.original_bytes.as_ptr(),
                cached_hook.original_bytes.len(),
            )?;
        }

        Ok(())
    }

    pub fn detach_all(&self) -> Result<()> {
        log::info!("Detaching all hooks!");
        for (_, cached_hook) in self.hooks.iter() {
            memory::copy_bytes_to_readable_memory(
                cached_hook.original_address,
                cached_hook.original_bytes.as_ptr(),
                cached_hook.original_bytes.len(),
            )?;
        }

        Ok(())
    }
}
