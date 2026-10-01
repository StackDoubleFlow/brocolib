use byteorder::ReadBytesExt;
use std::io::{Read, Result};

use super::SerializedIndexSizes;
pub use brocolib_proc_macros::MetadataDeserialize;
pub use byteorder::{BigEndian, ByteOrder, LittleEndian};

pub fn deserialize<E, T, R>(reader: R, index_sizes: &SerializedIndexSizes) -> Result<T>
where
    E: ByteOrder,
    T: MetadataDeserialize,
    R: Read,
{
    T::deserialize::<E, R>(reader, index_sizes)
}

pub trait MetadataDeserialize: Sized {
    fn deserialize<E, R>(reader: R, index_sizes: &SerializedIndexSizes) -> Result<Self>
    where
        E: ByteOrder,
        R: Read;
}

/// Create deserialize implementation ignoring endianness
macro_rules! impl_byte_deserialize {
    ($ty:ty, $size:literal, $read_fn:ident) => {
        impl MetadataDeserialize for $ty {
            fn deserialize<E, R>(mut reader: R, _index_sizes: &SerializedIndexSizes) -> Result<Self>
            where
                E: ByteOrder,
                R: Read,
            {
                reader.$read_fn()
            }
        }
    };
}

macro_rules! impl_primitive_deserialize {
    ($ty:ty, $size:literal, $read_fn:ident) => {
        impl MetadataDeserialize for $ty {
            fn deserialize<E, R>(mut reader: R, _index_sizes: &SerializedIndexSizes) -> Result<Self>
            where
                E: ByteOrder,
                R: Read,
            {
                reader.$read_fn::<E>()
            }
        }
    };
}

impl_byte_deserialize!(u8, 1, read_u8);
impl_byte_deserialize!(i8, 1, read_i8);
impl_primitive_deserialize!(u16, 2, read_u16);
impl_primitive_deserialize!(i16, 2, read_i16);
impl_primitive_deserialize!(u32, 4, read_u32);
impl_primitive_deserialize!(i32, 4, read_i32);
impl_primitive_deserialize!(u64, 8, read_u64);
impl_primitive_deserialize!(i64, 8, read_i64);
impl_primitive_deserialize!(u128, 16, read_u128);
impl_primitive_deserialize!(i128, 16, read_i128);

impl<T, const S: usize> MetadataDeserialize for [T; S]
where
    T: MetadataDeserialize,
{
    fn deserialize<E, R>(mut reader: R, index_sizes: &SerializedIndexSizes) -> Result<Self>
    where
        E: ByteOrder,
        R: Read,
    {
        Ok((0..S)
            .map(|_| T::deserialize::<E, &mut R>(&mut reader, index_sizes))
            .collect::<Result<Vec<T>>>()?
            .try_into()
            .map_err(|_| ())
            .unwrap())
    }
}
