use std::{io, str};

#[cfg(feature = "aarch64")]
use bad64::DecodeError;
#[cfg(feature = "il2cpp_v39")]
use byteorder::{LittleEndian, ReadBytesExt};
use object::Architecture;
use thiserror::Error;

use crate::runtime_metadata::{loader::object_reader::ObjectReader, RuntimeMetadata};
use crate::{
    global_metadata::GlobalMetadata,
    runtime_metadata::{Il2CppCodeRegistration, Il2CppMetadataRegistration},
};

pub mod arch;
pub mod object_reader;
pub mod structs;

#[derive(Error, Debug)]
pub enum Il2CppBinaryError {
    #[cfg(feature = "aarch64")]
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

/// Reads just `Il2CppMetadataRegistration::typesCount` from the game binary,
/// without needing the global metadata to already be parsed.
///
/// v39's global metadata encodes `TypeIndex` fields at a width chosen based
/// on how many entries are in the runtime's `types` array, so this count has
/// to be known *before* global metadata can be parsed at all. See
/// `global_metadata::IndexSizes`.
#[cfg(feature = "il2cpp_v39")]
pub fn peek_types_count(obj_data: &[u8]) -> Result<u32> {
    let obj = ObjectReader::new(obj_data)?;
    let (_, mr_addr) = arch::find_registration(&obj)?;
    let mut cur = obj.make_cur(mr_addr)?;

    // Il2CppMetadataRegistration starts with (count: u32, pad: u32, ptr: u64)
    // triples for genericClasses, genericInsts, genericMethodTable, then
    // types - skip the first three to get to the types count.
    for _ in 0..3 {
        cur.read_u32::<LittleEndian>()?;
        cur.read_u32::<LittleEndian>()?;
        cur.read_u64::<LittleEndian>()?;
    }
    Ok(cur.read_u32::<LittleEndian>()?)
}

impl<'data> RuntimeMetadata<'data> {
    pub fn read_obj(obj_data: &'data [u8], global_metadata: &GlobalMetadata) -> Result<Self> {
        let obj = ObjectReader::new(obj_data)?;

        let (cr_addr, mr_addr) = arch::find_registration(&obj)?;

        let code_registration = Il2CppCodeRegistration::read(&obj, cr_addr)?;
        let metadata_registration =
            Il2CppMetadataRegistration::read(&obj, mr_addr, global_metadata)?;
        Ok(RuntimeMetadata {
            code_registration,
            metadata_registration,
        })
    }
}
