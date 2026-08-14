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
//! version-agnostic struct definitions in [`super`].

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
/// runtime.
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

/// Generates [`VarRead`] and [`VarSize`] impls for a struct whose fields are
/// all read in declaration order. Every field type implements both traits
/// already (either via the blanket impls above, for fixed-width types, or
/// by hand above, for the four variable-width index kinds) - fields are
/// listed in on-disk order, excluding any that don't exist in the v39
/// layout (e.g. `Il2CppTypeDefinition::element_type_index`, which is
/// v31-only).
macro_rules! var_read_struct {
    ($name:ident { $($field:ident: $fty:ty),* $(,)? }) => {
        impl VarRead for $name {
            fn var_read(cursor: &mut Cursor<&[u8]>, sizes: &IndexSizes) -> std::io::Result<Self> {
                Ok(Self {
                    $(
                        $field: VarRead::var_read(cursor, sizes)?,
                    )*
                })
            }
        }

        impl VarSize for $name {
            fn var_size(sizes: &IndexSizes) -> usize {
                0 $( + <$fty as VarSize>::var_size(sizes) )*
            }
        }
    };
}

var_read_struct!(Il2CppEventDefinition {
    name_index: StringIndex,
    type_index: TypeIndex,
    add: MethodIndex,
    remove: MethodIndex,
    raise: MethodIndex,
    token: Token,
});

var_read_struct!(Il2CppMethodDefinition {
    name_index: StringIndex,
    declaring_type: TypeDefinitionIndex,
    return_type: TypeIndex,
    return_parameter_token: Token,
    parameter_start: ParameterIndex,
    generic_container_index: GenericContainerIndex,
    token: Token,
    flags: u16,
    iflags: u16,
    slot: u16,
    parameter_count: u16,
});

var_read_struct!(Il2CppParameterDefinition {
    name_index: StringIndex,
    token: Token,
    type_index: TypeIndex,
});

var_read_struct!(Il2CppTypeDefinition {
    name_index: StringIndex,
    namespace_index: StringIndex,
    byval_type_index: TypeIndex,
    declaring_type_index: TypeIndex,
    parent_index: TypeIndex,
    generic_container_index: GenericContainerIndex,
    flags: u32,
    field_start: FieldIndex,
    method_start: MethodIndex,
    event_start: EventIndex,
    property_start: PropertyIndex,
    nested_types_start: NestedTypeIndex,
    interfaces_start: InterfaceIndex,
    vtable_start: VTableMethodIndex,
    interface_offsets_start: InterfaceOffsetIndex,
    method_count: u16,
    property_count: u16,
    field_count: u16,
    event_count: u16,
    nested_type_count: u16,
    vtable_count: u16,
    interfaces_count: u16,
    interface_offsets_count: u16,
    bitfield: u32,
    token: Token,
});

var_read_struct!(Il2CppImageDefinition {
    name_index: StringIndex,
    assembly_index: AssemblyIndex,
    type_start: TypeDefinitionIndex,
    type_count: u32,
    exported_type_start: TypeDefinitionIndex,
    exported_type_count: u32,
    entry_point_index: MethodIndex,
    token: Token,
    custom_attribute_start: AttributeDataRangeIndex,
    custom_attribute_count: u32,
});

var_read_struct!(Il2CppFieldDefinition {
    name_index: StringIndex,
    type_index: TypeIndex,
    token: Token,
});

var_read_struct!(Il2CppParameterDefaultValue {
    parameter_index: ParameterIndex,
    type_index: TypeIndex,
    data_index: FieldAndParameterDefaultValueIndex,
});

var_read_struct!(Il2CppFieldDefaultValue {
    field_index: FieldIndex,
    type_index: TypeIndex,
    data_index: FieldAndParameterDefaultValueIndex,
});

var_read_struct!(Il2CppFieldMarshaledSize {
    field_index: FieldIndex,
    type_index: TypeIndex,
    size: u32,
});

var_read_struct!(Il2CppGenericParameter {
    owner_index: GenericContainerIndex,
    name_index: StringIndex,
    constraints_start: GenericParameterConstraintIndex,
    constraints_count: u16,
    num: u16,
    flags: u16,
});

var_read_struct!(Il2CppInterfaceOffsetPair {
    interface_type_index: TypeIndex,
    offset: u32,
});

var_read_struct!(Il2CppWindowsRuntimeTypeNamePair {
    name_index: StringIndex,
    type_index: TypeIndex,
});

var_read_struct!(Il2CppFieldRef {
    type_index: TypeIndex,
    field_index: u32,
});
