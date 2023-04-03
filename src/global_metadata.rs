//! Global metadata types.

use crate::Metadata;
use std::io::Cursor;
use std::ops::Index;
use std::str;
use binread::BinRead;
use binde::{BinaryDeserialize, LittleEndian};
use thiserror::Error;

const SANITY: u32 = 0xFAB11BAF;
const VERSION: u32 = 29;

// TODO
type TypeIndex = u32;
type EncodedMethodIndex = u32;

/// A C# string literal.
/// 
/// These are stored as UTF-8 in the metadata file and expanded to UTF-16 at
/// runtime.
/// 
/// Defined at `vm/GlobalMetadataFileInternals.h:187`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppStringLiteral {
    pub length: u32,
    pub data_index: StringLiteralIndex,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:168`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppEventDefinition {
    pub name_index: StringIndex,
    pub type_index: TypeIndex,
    pub add: MethodIndex,
    pub remove: MethodIndex,
    pub raise: MethodIndex,
    pub token: u32,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:154`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppMethodDefinition {
    pub name_index: StringIndex,
    pub declaring_type: TypeDefinitionIndex,
    pub return_type: TypeIndex,
    pub parameter_start: ParameterIndex,
    pub generic_container_index: GenericContainerIndex,
    pub token: u32,

    /// Method attributes. See `il2cpp-tabledefs.h`.
    pub flags: u16,

    /// Method implementation attributes. See `il2cpp-tabledefs.h`.
    pub iflags: u16,
    pub slot: u16,
    pub parameter_count: u16,
}

impl Il2CppMethodDefinition {
    pub fn full_name(&self, metadata: &Metadata) -> String {
        let mr = &metadata.runtime_metadata.metadata_registration;
        let gm = &metadata.global_metadata;
        let mut full_name = String::new();
        full_name.push_str(&mr.types[self.return_type as usize].full_name(metadata));
        full_name.push(' ');
        full_name.push_str(&gm.type_definitions[self.declaring_type].full_name(metadata));
        full_name.push_str("::");
        full_name.push_str(&gm.string[self.name_index]);
        if self.generic_container_index.is_valid() {
            full_name.push('<');
            let gc = &gm.generic_containers[self.generic_container_index];
            for (i, param) in gm.generic_parameters[gc.generic_parameter_start.make_range(gc.type_argc)].iter().enumerate() {
                if i > 0 {
                    full_name.push_str(", ");
                }
                full_name.push_str(&gm.string[param.name_index]);
            }
            full_name.push('>');
        }
        full_name.push('(');
        for (i, param) in gm.parameters[self.parameter_start.make_range(self.parameter_count as u32)].iter().enumerate() {
            if i > 0 {
                full_name.push_str(", ");
            }
            full_name.push_str(&mr.types[param.type_index as usize].full_name(metadata));
            full_name.push(' ');
            full_name.push_str(&gm.string[param.name_index]);
        }
        full_name.push(')');
        full_name
    }
}

/// Defined at `vm/GlobalMetadataFileInternals.h:140`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppParameterDefinition {
    pub name_index: StringIndex,
    pub token: u32,
    pub type_index: TypeIndex,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:66`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppTypeDefinition {
    pub name_index: StringIndex,
    pub namespace_index: StringIndex,
    pub byval_type_index: TypeIndex,

    pub declaring_type_index: TypeIndex,
    pub parent_index: TypeIndex,

    /// Only used for enums
    pub element_type_index: TypeIndex,

    pub generic_container_index: GenericContainerIndex,

    pub flags: u32,

    pub field_start: FieldIndex,
    pub method_start: MethodIndex,
    pub event_start: EventIndex,
    pub property_start: PropertyIndex,
    pub nested_types_start: NestedTypeIndex,
    pub interfaces_start: InterfaceIndex,
    pub vtable_start: VTableMethodIndex,
    pub interface_offsets_start: InterfaceOffsetIndex,

    pub method_count: u16,
    pub property_count: u16,
    pub field_count: u16,
    pub event_count: u16,
    pub nested_type_count: u16,
    pub vtable_count: u16,
    pub interfaces_count: u16,
    pub interface_offsets_count: u16,

    /// bitfield to portably encode boolean values as single bits
    /// * 01 - valuetype;
    /// * 02 - enumtype;
    /// * 03 - has_finalize;
    /// * 04 - has_cctor;
    /// * 05 - is_blittable;
    /// * 06 - is_import_or_windows_runtime;
    /// * 07-10 - One of nine possible PackingSize values (0, 1, 2, 4, 8, 16,
    ///           32, 64, or 128)
    /// * 11 - PackingSize is default
    /// * 12 - ClassSize is default
    /// * 13-16 - One of nine possible PackingSize values (0, 1, 2, 4, 8, 16,
    ///           32, 64, or 128) - the specified packing size (even for
    ///           explicit layouts)
    pub bitfield: u32,
    pub token: u32,
}

impl Il2CppTypeDefinition {
    pub fn full_name(&self, metadata: &Metadata) -> String {
        let namespace = &metadata.global_metadata.string[self.namespace_index];
        let name = &metadata.global_metadata.string[self.name_index];

        if self.declaring_type_index != u32::MAX {
            return metadata.runtime_metadata.metadata_registration.types[self.declaring_type_index as usize].full_name(metadata) + "::" + name;
        }

        if namespace.is_empty() {
            return name.to_string();
        }

        let mut full_name = String::new();
        full_name.push_str(namespace);
        full_name.push('.');
        full_name.push_str(name);
        full_name
    }
}

/// Defined at `vm/GlobalMetadataFileInternals.h:208`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppImageDefinition {
    pub name_index: StringIndex,
    pub assembly_index: AssemblyIndex,

    pub type_start: TypeDefinitionIndex,
    pub type_count: u32,

    pub exported_type_start: TypeDefinitionIndex,
    pub exported_type_count: u32,

    pub entry_point_index: MethodIndex,
    pub token: u32,

    pub custom_attribute_start: AttributeDataRangeIndex,
    pub custom_attribute_count: u32,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:113`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppFieldDefinition {
    pub name_index: StringIndex,
    pub type_index: TypeIndex,
    pub token: u32,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:178`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppPropertyDefinition {
    pub name_index: StringIndex,
    pub get: MethodIndex,
    pub set: MethodIndex,
    /// See `il2cpp-tabledef.h`
    pub attrs: u32,
    pub token: u32,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:147`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppParameterDefaultValue {
    pub parameter_index: ParameterIndex,
    pub type_index: TypeIndex,
    pub data_index: FieldAndParameterDefaultValueIndex,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:120`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppFieldDefaultValue {
    pub field_index: FieldIndex,
    pub type_index: TypeIndex,
    pub data_index: FieldAndParameterDefaultValueIndex,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:127`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppFieldMarshaledSize {
    pub field_index: FieldIndex,
    pub type_index: TypeIndex,
    pub size: u32,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:258`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppGenericParameter {
    /// Type or method this parameter was defined in.
    pub owner_index: GenericContainerIndex, 
    /// The name of the generic parameter.
    pub name_index: StringIndex,
    /// An optional list of constraints for the generic parameter
    pub constraints_start: GenericParameterConstraintIndex,
    pub constraints_count: u16,
    /// The position in the generic parameter list.
    pub num: u16,
    pub flags: u16,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:247`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppGenericContainer {
    /// The index of the generic type definition or the generic method definition 
    /// corresponding to this container. Either index into Il2CppClass metadata
    /// array or Il2CppMethodDefinition array.
    pub owner_index: u32,
    /// The number of generic parameters this type or method has.
    pub type_argc: u32,
    /// If true, we're a generic method, otherwise a generic type definition.
    pub is_method: u32,
    /// Our type parameters.
    pub generic_parameter_start: GenericParameterIndex,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:60`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppInterfaceOffsetPair {
    pub interface_type_index: TypeIndex,
    pub offset: u32,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:193`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppAssemblyNameDefinition {
    /// The name of the assembly.
    /// 
    /// Assembly names do not end with `.dll`
    pub name_index: StringIndex,
    pub culture_index: StringIndex,
    pub public_key_index: StringIndex,
    pub hash_alg: u32,
    pub hash_len: u32,
    pub flags: u32,
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub revision: u32,
    pub public_key_token: [u8; 8],
}

/// Defined at `vm/GlobalMetadataFileInternals.h:226`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppAssemblyDefinition {
    pub image_index: ImageIndex,
    pub token: u32,
    pub referenced_assembly_start: u32,
    pub referenced_assembly_count: u32,
    pub aname: Il2CppAssemblyNameDefinition,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:235`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppCustomAttributeDataRange {
    pub token: u32,
    pub start_offset: u32,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:241`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppMetadataRange {
    pub start: u32,
    pub length: u32,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:269`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppWindowsRuntimeTypeNamePair {
    pub name_index: StringIndex,
    pub type_index: TypeIndex,
}

/// Defined at `vm/GlobalMetadataFileInternals.h:134`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppFieldRef {
    pub type_index: TypeIndex,
    /// local offset into type fields
    pub field_index: FieldIndex,
}

#[derive(Debug, BinaryDeserialize)]
struct OffsetLen {
    offset: u32,
    len: u32,
}

trait ReadMetadataTable<'a>
where
    Self: std::marker::Sized,
{
    fn read(cursor: &mut Cursor<&'a [u8]>, size: usize) -> std::io::Result<Self>;
}

macro_rules! metadata {
    ($($name:ident: $ty:ty,)*) => {
        #[derive(Debug, BinaryDeserialize)]
        struct Il2CppGlobalMetadataHeader {
            sanity: u32,
            version: u32,
            $(
                $name: OffsetLen,
            )*
        }

        #[derive(Debug)]
        pub struct GlobalMetadata<'a> {
            $(
                pub $name: $ty,
            )*
        }

        impl<'a> GlobalMetadata<'a> {
            fn deserialize(
                data: &'a [u8],
                header: Il2CppGlobalMetadataHeader,
            ) -> Result<GlobalMetadata, MetadataDeserializeError> {
                let mut cursor = Cursor::new(data);
                Ok(GlobalMetadata {
                    $(
                        $name: {
                            let size = header.$name.len as usize;
                            if size > 0 {
                                cursor.set_position(header.$name.offset as u64);
                                ReadMetadataTable::read(&mut cursor, size)?
                            } else {
                                Default::default()
                            }
                        },
                    )*
                })
            }
        }
    };
}


macro_rules! index_type {
    ($name:ident, $ty:ty) => {
        #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, BinRead)]
        pub struct $name($ty);

        impl $name {
            pub fn index(self) -> $ty {
                self.0
            }

            pub fn new(index: $ty) -> Self {
                Self(index)
            }

            pub fn make_range(self, count: $ty) -> std::ops::Range<$name> {
                if count > 0 {
                    self..Self::new(self.0 + count)
                } else {
                    Self(0)..Self(0)
                }
            }

            pub fn is_valid(self) -> bool {
                self.0 != <$ty>::MAX
            }
        }
        
        impl BinaryDeserialize for $name {
            const SIZE: usize = <$ty>::SIZE;
            fn deserialize<E, R>(reader: R) -> std::io::Result<Self>
                where
                    E: binde::ByteOrder,
                    R: std::io::Read {
                Ok(Self(binde::deserialize::<E, _, _>(reader)?))
            }
        }
    };
}

macro_rules! basic_table {
    ($name:ident: $ty:ty, $idx_name:ident: $idx_ty:ty) => {
        #[derive(Debug, Default)]
        pub struct $name {
            table: Vec<$ty>,
        }

        impl $name {
            pub fn as_vec(&self) -> &Vec<$ty> {
                &self.table
            }
        }

        impl ReadMetadataTable<'_> for $name {
            fn read(cursor: &mut Cursor<&[u8]>, size: usize) -> std::io::Result<Self> {
                let count = size / <$ty>::SIZE;
                let mut vec = Vec::new();
                for _ in 0..count {
                    vec.push(<$ty>::deserialize::<LittleEndian, _>(&mut *cursor)?);
                }
                Ok($name { table: vec })
            }
        }

        index_type!($idx_name, $idx_ty);

        impl Index<$idx_name> for $name {
            type Output = $ty;

            fn index(&self, index: $idx_name) -> &Self::Output {
                &self.table[index.0 as usize]
            }
        }

        impl<R> Index<R> for $name 
            where R: std::ops::RangeBounds<$idx_name>
        {
            type Output = [$ty];

            fn index(&self, range: R) -> &Self::Output {
                use std::ops::Bound;
                let start = match range.start_bound() {
                    Bound::Unbounded => Bound::Unbounded,
                    Bound::Included(idx) => Bound::Included(idx.0 as usize),
                    Bound::Excluded(idx) => Bound::Excluded(idx.0 as usize),
                };
                let end = match range.end_bound() {
                    Bound::Unbounded => Bound::Unbounded,
                    Bound::Included(idx) => Bound::Included(idx.0 as usize),
                    Bound::Excluded(idx) => Bound::Excluded(idx.0 as usize),
                };
                &self.table[(start, end)]
            }
        }
    };
    ($name:ident: $ty:ty, $idx_name:ident) => {
        basic_table!($name: $ty, $idx_name: u32);
    }
}

macro_rules! string_data_table {
    ($name:ident, $idx_name:ident) => {
        #[derive(Debug, Default)]
        pub struct $name<'data> {
            data: &'data [u8]
        }

        impl<'data> $name<'data> {
            pub fn data(&self) -> &'data [u8] {
                self.data
            }
        }

        index_type!($idx_name, u32);

        impl<'data> Index<$idx_name> for $name<'data> {
            type Output = str;

            fn index(&self, index: $idx_name) -> &Self::Output {
                let idx = index.0 as usize;
                let mut len = 0;
                while self.data[idx + len] != 0 {
                    len += 1;
                }

                // FIXME: maybe not panic here?
                str::from_utf8(&self.data[idx..idx + len]).unwrap()
            }
        }

        impl<'data> ReadMetadataTable<'data> for $name<'data> {
                fn read(cursor: &mut Cursor<&'data [u8]>, size: usize) -> std::io::Result<Self> {
                    let start = cursor.position() as usize;
                    Ok($name {
                        data: &cursor.get_ref()[start..start + size],
                    })
                }
            }
        };
}

basic_table!(StringLiteralTable: Il2CppStringLiteral, StringLiteralIndex);
string_data_table!(StringLiteralData, StringLiteralDataIndex);
string_data_table!(StringData, StringIndex);
basic_table!(EventTable: Il2CppEventDefinition, EventIndex);
basic_table!(PropertyTable: Il2CppPropertyDefinition, PropertyIndex);
basic_table!(MethodTable: Il2CppMethodDefinition, MethodIndex);
basic_table!(ParameterDefaultValueTable: Il2CppParameterDefaultValue, ParameterDefaultValueIndex);
basic_table!(FieldDefaultValueTable: Il2CppFieldDefaultValue, FieldDefaultValueIndex);
// TODO: data?
basic_table!(FieldAndParameterDefaultValueTable: u8, FieldAndParameterDefaultValueIndex);
basic_table!(FieldMarshaledSizeTable: Il2CppFieldMarshaledSize, FieldMarshaledSizeIndex);
basic_table!(ParameterTable: Il2CppParameterDefinition, ParameterIndex);
basic_table!(FieldTable: Il2CppFieldDefinition, FieldIndex);
basic_table!(GenericParameterTable: Il2CppGenericParameter, GenericParameterIndex);
basic_table!(GenericParameterConstraintTable: TypeIndex, GenericParameterConstraintIndex: u16);
basic_table!(GenericContainerTable: Il2CppGenericContainer, GenericContainerIndex);
basic_table!(NestedTypeTable: TypeDefinitionIndex, NestedTypeIndex);
basic_table!(InterfaceTable: TypeIndex, InterfaceIndex);
basic_table!(VTableMethodTable: EncodedMethodIndex, VTableMethodIndex);
basic_table!(InterfaceOffsetTable: Il2CppInterfaceOffsetPair, InterfaceOffsetIndex);
basic_table!(TypeDefinitionTable: Il2CppTypeDefinition, TypeDefinitionIndex);
basic_table!(ImageTable: Il2CppImageDefinition, ImageIndex);
basic_table!(AssemblyTable: Il2CppAssemblyDefinition, AssemblyIndex);
basic_table!(FieldRefTable: Il2CppFieldRef, FieldRefIndex);
// TODO: reference assemblies?
basic_table!(ReferencedAssemblyTable: u32, ReferenceAssemblyIndex);
basic_table!(AttributeDataRangeTable: Il2CppCustomAttributeDataRange, AttributeDataRangeIndex);
// TODO: data?
basic_table!(AttributeDataTable: u8, AttributeDataIndex);
basic_table!(AttributeInfoTable: Il2CppCustomAttributeDataRange, AttributeInfoIndex);
basic_table!(AttributeTypeTable: TypeIndex, AttributeTypeIndex);
basic_table!(UnresolvedVirtualCallParameterTypeTable: TypeIndex, UnresolvedVirtualCallParameterTypeIndex);
basic_table!(UnresolvedVirtualCallParameterRangeTable: Il2CppMetadataRange, UnresolvedVirtualCallParameterRangeIndex);
basic_table!(WindowsRuntimeTypeNameTable: Il2CppWindowsRuntimeTypeNamePair, WindowsRuntimeTypeNameIndex);
string_data_table!(WindowsRuntimeStringData, WindowsRuntimeStringDataIndex);
basic_table!(ExportedTypeDefinitionTable: TypeDefinitionIndex, ExportedTypeDefinitionIndex);

metadata! {
    string_literal: StringLiteralTable,
    string_literal_data: StringLiteralData<'a>,
    string: StringData<'a>,
    events: EventTable,
    properties: PropertyTable,
    methods: MethodTable,
    parameter_default_values: ParameterDefaultValueTable,
    field_default_values: FieldDefaultValueTable,
    field_and_parameter_default_value_data: FieldAndParameterDefaultValueTable,
    field_marshaled_sizes: FieldMarshaledSizeTable,
    parameters: ParameterTable,
    fields: FieldTable,
    generic_parameters: GenericParameterTable,
    generic_parameter_constraints: GenericParameterConstraintTable,
    generic_containers: GenericContainerTable,
    nested_types: NestedTypeTable,
    interfaces: InterfaceTable,
    vtable_methods: VTableMethodTable,
    interface_offsets: InterfaceOffsetTable,
    type_definitions: TypeDefinitionTable,
    images: ImageTable,
    assemblies: AssemblyTable,
    field_refs: FieldRefTable,
    referenced_assemblies: ReferencedAssemblyTable,
    attribute_data: AttributeDataTable,
    attribute_data_range: AttributeDataRangeTable,
    unresolved_virtual_call_parameter_types: UnresolvedVirtualCallParameterTypeTable,
    unresolved_virtual_call_parameter_ranges: UnresolvedVirtualCallParameterRangeTable,
    windows_runtime_type_names: WindowsRuntimeTypeNameTable,
    windows_runtime_strings: WindowsRuntimeStringData<'a>,
    exported_type_definitions: ExportedTypeDefinitionTable,
}

#[derive(Error, Debug)]
pub enum MetadataDeserializeError {
    #[error("binary deserialization error")]
    Bin(#[from] std::io::Error),

    #[error("il2cpp metadata header sanity check failed")]
    SanityCheck,

    #[error("il2cpp metadata header version check failed, found {0}")]
    VersionCheck(u32),
}

pub fn deserialize(data: &[u8]) -> Result<GlobalMetadata, MetadataDeserializeError> {
    let header = Il2CppGlobalMetadataHeader::deserialize::<LittleEndian, _>(Cursor::new(data))?;

    if header.sanity != SANITY {
        return Err(MetadataDeserializeError::SanityCheck);
    }

    if header.version != VERSION {
        return Err(MetadataDeserializeError::VersionCheck(header.version));
    }

    GlobalMetadata::deserialize(data, header)
}
