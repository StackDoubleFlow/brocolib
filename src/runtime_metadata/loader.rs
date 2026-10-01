use std::{io, str};

#[cfg(feature = "aarch64")]
use bad64::DecodeError;
use object::Architecture;
use thiserror::Error;

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
    MetadataDeserialize(#[from] binread::Error),

    #[error(transparent)]
    Utf8(#[from] str::Utf8Error),

    #[error(transparent)]
    Object(#[from] object::Error),
}

pub type Result<T> = std::result::Result<T, Il2CppBinaryError>;

#[derive(Error, Debug, Clone, Copy)]
#[error("error disassembling code")]
pub struct DisassembleError;
