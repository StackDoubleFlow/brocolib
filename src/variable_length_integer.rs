//! IL2CPP V39 uses variable length indexing for some of its metadata tables.
//! This module contains the logic for reading and writing these variable length indices.

use std::io::Cursor;

use binde::LittleEndian;
use byteorder::ReadBytesExt;

/// The width (in bytes) that each variable-width index kind is serialized at
/// in this file. Introduced in v39: see the comment on [`Il2CppSectionMetadata::count`].
#[derive(Debug, Clone, Copy)]
pub struct IndexSizes {
    /// Width (in bytes) of `TypeIndex` fields, sized against the *runtime*
    /// metadata's `types` array (not anything in this file), since that's
    /// the table `TypeIndex` actually indexes into.
    pub(crate) type_index: usize,
    pub(crate) type_definition_index: usize,
    pub(crate) generic_container_index: usize,
    pub(crate) parameter_index: usize,
}

impl IndexSizes {
    /// Computes each index kind's width from the row count of the table it
    /// indexes into: `types_count` comes from the *runtime* metadata (see
    /// the field docs above), while the other three come from this file's
    /// own section row counts (see [`crate::global_metadata::Il2CppSectionMetadata::count`]).
    pub fn new(
        types_count: u32,
        type_definitions_count: u32,
        generic_containers_count: u32,
        parameters_count: u32,
    ) -> Self {
        Self {
            type_index: index_size(types_count),
            type_definition_index: index_size(type_definitions_count),
            generic_container_index: index_size(generic_containers_count),
            parameter_index: index_size(parameters_count),
        }
    }
}

pub fn index_size(num_elements: u32) -> usize {
    if num_elements <= u8::MAX as u32 {
        1
    } else if num_elements <= u16::MAX as u32 {
        2
    } else {
        4
    }
}

/// Reads a variable-width index: an unsigned integer of `width` bytes whose
/// max value (the "no value" sentinel) is normalized to `u32::MAX`, matching
/// the fixed-width indices elsewhere in this file (see `IndexType::is_valid`).
pub fn read_var_index<T>(cursor: &mut Cursor<T>, width: usize) -> std::io::Result<u32>
where
    Cursor<T>: std::io::Read,
{
    Ok(match width {
        1 => {
            let v = cursor.read_u8()?;
            if v == u8::MAX { u32::MAX } else { v as u32 }
        }
        2 => {
            let v = cursor.read_u16::<LittleEndian>()?;
            if v == u16::MAX { u32::MAX } else { v as u32 }
        }
        _ => cursor.read_u32::<LittleEndian>()?,
    })
}

pub trait VariableWidthCursor {
    fn read_var_index(&mut self, width: usize) -> std::io::Result<u32>;
}

impl<T> VariableWidthCursor for Cursor<T>
where
    Cursor<T>: std::io::Read,
{
    fn read_var_index(&mut self, width: usize) -> std::io::Result<u32> {
        read_var_index(self, width)
    }
}
