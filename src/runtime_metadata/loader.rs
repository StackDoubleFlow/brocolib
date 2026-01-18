use std::{io, str};

use bad64::DecodeError;
use object::{Object, ObjectSection};
use thiserror::Error;

#[cfg(feature = "elf")]
pub mod elf;
#[cfg(feature = "pe")]
pub mod pe;

#[derive(Error, Debug)]
pub enum Il2CppBinaryError {
    #[error("error disassembling code")]
    Disassemble(DecodeError),

    #[error("failed to convert virtual address {0:#016x}")]
    VAddrConv(u64),

    #[error("could not find il2cpp_init symbol in elf")]
    MissingIl2CppInit,

    #[error("could not find registration function")]
    MissingRegistration,

    #[error("invalid Il2CppType with type {0}")]
    InvalidType(u8),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    BinaryDeserialize(#[from] binread::Error),

    #[error(transparent)]
    Utf8(#[from] str::Utf8Error),

    #[error(transparent)]
    Object(#[from] object::Error),
}

pub type Result<T> = std::result::Result<T, Il2CppBinaryError>;

#[derive(Error, Debug, Clone, Copy)]
#[error("error disassembling code")]
pub struct DisassembleError;

pub fn strlen(data: &[u8], offset: usize) -> usize {
    let mut len = 0;
    while data[offset + len] != 0 {
        len += 1;
    }
    len
}

pub fn get_str(data: &[u8], offset: usize) -> Result<&str> {
    let len = strlen(data, offset);
    let str = str::from_utf8(&data[offset..offset + len])?;
    Ok(str)
}

/// Convert a virtual address to a file offset
pub fn vaddr_conv<'a>(pe: &impl Object<'a>, vaddr: u64) -> Result<u64> {
    for section in pe.sections() {
        let addr = section.address();
        let size = section.size();
        if addr <= vaddr && vaddr - addr < size {
            if let Some((file_off, _)) = section.file_range() {
                let offset = file_off + (vaddr - addr);
                return Ok(offset);
            }
        }
    }
    Err(Il2CppBinaryError::VAddrConv(vaddr))
}
