use anyhow::Result;
use std::ffi::c_void;
use std::ptr::NonNull;
use windows::Win32::System::Memory::*;

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

pub fn copy_bytes(ptr: NonNull<u8>, size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    unsafe { ptr.as_ptr().copy_to(bytes.as_mut_ptr(), size) };

    bytes
}
