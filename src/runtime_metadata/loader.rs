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

/// Reads just the row count of `Il2CppMetadataRegistration::types` from the
/// game binary, without needing (or being able to build) a [`GlobalMetadata`]
/// yet. v39 global metadata needs this count up front to size its
/// variable-width `TypeIndex` fields (see
/// [`crate::variable_length_integer::IndexSizes`]), which creates a
/// dependency cycle with the normal [`RuntimeMetadata::read_obj`] path (that
/// needs an already-parsed `GlobalMetadata`) - so this peeks at just the
/// `type_addrs` length-prefixed array header field, four fields into
/// `Il2CppMetadataRegistration`, and stops there.
#[cfg(feature = "il2cpp_v39")]
pub fn peek_types_count(obj_data: &[u8]) -> Result<u32> {
    let obj = ObjectReader::new(obj_data)?;
    let (_cr_addr, mr_addr) = arch::find_registration(&obj)?;
    let mut cur = obj.make_cur(mr_addr)?;

    // Skip generic_class_addrs, generic_inst_addrs, and generic_method_table
    // (each a `count: u32, padding: u32, ptr: u64` length-prefixed array -
    // see `ObjectReader::read_len_arr`) to reach `type_addrs`.
    for _ in 0..3 {
        cur.read_u32::<LittleEndian>()?;
        cur.read_u32::<LittleEndian>()?;
        cur.read_u64::<LittleEndian>()?;
    }
    Ok(cur.read_u32::<LittleEndian>()?)
}
