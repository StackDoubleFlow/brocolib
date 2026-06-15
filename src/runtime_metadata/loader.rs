use std::{
    backtrace::Backtrace,
    io::{self, Cursor},
    str,
};

use bad64::DecodeError;
use binde::LittleEndian;
use byteorder::WriteBytesExt;
use object::{Architecture, Object, ObjectSection, RelocationEncoding, RelocationTarget};
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

    #[error("bad address {0:#016x}")]
    BadAddress(u64),

    #[error("could not find il2cpp_init symbol in elf")]
    MissingIl2CppInit,

    #[error("could not find registration function")]
    MissingRegistration,

    #[error("bad instruction encountered during disassembly {0} at {1:#016x}")]
    BadInstruction(String, u64),

    #[error("Architecture {0:?} is not supported")]
    UnsupportedArchitecture(Architecture),

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

pub fn read_u64<'a>(file: &impl Object<'a>, vaddr: u64, image: &[u8]) -> Result<u64> {
    let offset = vaddr_conv(file, vaddr)? as usize;
    let bytes = image
        .get(offset..offset + 8)
        .ok_or(Il2CppBinaryError::BadAddress(vaddr))?;

    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(arr))
}

/// Convert a virtual address to a file offset
pub fn vaddr_conv<'a>(obj: &impl Object<'a>, vaddr: u64) -> Result<u64> {
    // TODO: is this correct for vaddr 0?
    if vaddr == 0 {
        return Ok(0);
    }

    for section in obj.sections() {
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

fn process_relocations<'a>(obj: &impl Object<'a>, obj_data: Vec<u8>) -> Result<Vec<u8>> {
    let mut obj_data = obj_data;

    if let Some(relocations) = obj.dynamic_relocations() {
        for (addr, rel) in relocations {
            if rel.encoding() != RelocationEncoding::Generic
                || rel.target() != RelocationTarget::Absolute
            {
                // TODO: handle more relocation types
                continue;
            }

            let target = rel.addend() as u64;

            let mut cur = Cursor::new(&mut obj_data);
            cur.set_position(vaddr_conv(obj, addr)?);
            cur.write_u64::<LittleEndian>(target)?;
        }
    }

    Ok(obj_data)
}
