//! IL2CPP v39 uses variable-width indices for some fields (see
//! [`IndexSizes`]): `TypeIndex`, `TypeDefinitionIndex`, `GenericContainerIndex`,
//! and `ParameterIndex` are each serialized at 1, 2, or 4 bytes depending on
//! how many rows the table they index into has. Since that width isn't known
//! until the section header has been read, any struct containing one of
//! these fields can't be parsed with the ordinary derive-based
//! [`BinaryDeserialize`] (which has no way to receive that context) and
//! needs a manual, [`IndexSizes`]-aware read instead - nor does it have a
//! compile-time-constant size, so tables of such structs need their row
//! count computed from a runtime element size instead of `BinaryDeserialize::SIZE`.
//! This module holds all of that v39-specific logic, kept separate from the
//! version-agnostic struct definitions in [`super`]. Structs containing one
//! of the four variable-width index kinds derive [`VarRead`] (see the
//! `#[cfg_attr(feature = "il2cpp_v39", derive(VarRead))]` on their
//! definitions in `super`) rather than listing their fields here by hand.

use super::*;
use crate::variable_length_integer::{IndexSizes, VariableWidthCursor};

impl VarRead for TypeIndex {
    fn var_read(cursor: &mut Cursor<&[u8]>, sizes: &IndexSizes) -> std::io::Result<Self> {
        Ok(Self(cursor.read_var_index(sizes.type_index)?))
    }
}
impl VarSize for TypeIndex {
    fn var_size(sizes: &IndexSizes) -> usize {
        sizes.type_index
    }
}

impl VarRead for TypeDefinitionIndex {
    fn var_read(cursor: &mut Cursor<&[u8]>, sizes: &IndexSizes) -> std::io::Result<Self> {
        Ok(Self::new(cursor.read_var_index(sizes.type_definition_index)?))
    }
}
impl VarSize for TypeDefinitionIndex {
    fn var_size(sizes: &IndexSizes) -> usize {
        sizes.type_definition_index
    }
}

impl VarRead for GenericContainerIndex {
    fn var_read(cursor: &mut Cursor<&[u8]>, sizes: &IndexSizes) -> std::io::Result<Self> {
        Ok(Self::new(cursor.read_var_index(sizes.generic_container_index)?))
    }
}
impl VarSize for GenericContainerIndex {
    fn var_size(sizes: &IndexSizes) -> usize {
        sizes.generic_container_index
    }
}

impl VarRead for ParameterIndex {
    fn var_read(cursor: &mut Cursor<&[u8]>, sizes: &IndexSizes) -> std::io::Result<Self> {
        Ok(Self::new(cursor.read_var_index(sizes.parameter_index)?))
    }
}
impl VarSize for ParameterIndex {
    fn var_size(sizes: &IndexSizes) -> usize {
        sizes.parameter_index
    }
}

/// Deserializes a value with [`IndexSizes`] available to resolve
/// variable-width index fields. Any type implementing [`BinaryDeserialize`]
/// gets this for free (see the blanket impl below, which just ignores
/// `sizes`); [`TypeIndex`] and the other three variable-width index kinds
/// implement it by hand above instead, since their width isn't known until
/// runtime. Structs containing one of those four (or nested structs that
/// do) get it via `#[derive(VarRead)]` (see `brocolib_macros`) instead of a
/// hand-written impl.
pub(super) trait VarRead: Sized {
    fn var_read(cursor: &mut Cursor<&[u8]>, sizes: &IndexSizes) -> std::io::Result<Self>;
}

impl<T: BinaryDeserialize> VarRead for T {
    fn var_read(cursor: &mut Cursor<&[u8]>, _sizes: &IndexSizes) -> std::io::Result<Self> {
        <T as BinaryDeserialize>::deserialize::<LittleEndian, _>(&mut *cursor)
    }
}

/// The on-disk byte size of a value once [`IndexSizes`] is known. Plays the
/// same role [`BinaryDeserialize::SIZE`] plays for fixed-width types, but as
/// a runtime value rather than an associated constant, since it depends on
/// how wide this file's variable-width indices turned out to be. Tables use
/// this to turn a section's raw byte length into a row count (see
/// [`super::Il2CppSectionMetadata::count`], which - contrary to what its name
/// suggests - is *not* a reliable row count for most tables).
pub(super) trait VarSize {
    fn var_size(sizes: &IndexSizes) -> usize;
}

impl<T: BinaryDeserialize> VarSize for T {
    fn var_size(_sizes: &IndexSizes) -> usize {
        T::SIZE
    }
}
