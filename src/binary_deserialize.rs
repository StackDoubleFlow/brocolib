use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Read;

pub use brocolib_proc_macros::BinaryDeserialize;

pub trait BinaryDeserialize: Sized {
    fn read<R>(reader: R) -> Result<Self>
    where
        R: Read;
}

impl BinaryDeserialize for u16 {
    fn read<R>(mut reader: R) -> Result<Self>
    where
        R: Read,
    {
        Ok(reader.read_u16::<LittleEndian>()?)
    }
}

impl BinaryDeserialize for u32 {
    fn read<R>(mut reader: R) -> Result<Self>
    where
        R: Read,
    {
        Ok(reader.read_u32::<LittleEndian>()?)
    }
}

impl BinaryDeserialize for i32 {
    fn read<R>(mut reader: R) -> Result<Self>
    where
        R: Read,
    {
        Ok(reader.read_i32::<LittleEndian>()?)
    }
}
