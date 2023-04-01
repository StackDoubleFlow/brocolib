use std::io::Cursor;
use std::marker::PhantomData;
use std::ops::Index;
use std::str;

use binde::{BinaryDeserialize, LittleEndian};
use deku::bitvec::BitVec;
use deku::ctx::Endian;
use deku::prelude::*;
use thiserror::Error;

const SANITY: u32 = 0xFAB11BAF;
const VERSION: u32 = 29;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MetadataIndex<T, I = u32> {
    idx: I,
    _phantom: PhantomData<*mut T>, // invariant
}

impl<T, I> BinaryDeserialize for MetadataIndex<T, I>
    where I: BinaryDeserialize
{
    const SIZE: usize = I::SIZE;

    fn deserialize<E, R>(reader: R) -> std::io::Result<Self>
        where
            E: binde::ByteOrder,
            R: std::io::Read {
        Ok(Self {
            idx: binde::deserialize::<E, _, _>(reader)?,
            _phantom: PhantomData,
        })
    }
}

impl<T, I> DekuWrite for MetadataIndex<T, I>
    where I: DekuWrite
{
    fn write(
            &self,
            output: &mut deku::bitvec::BitVec<u8, deku::bitvec::Msb0>,
            ctx: (),
        ) -> Result<(), DekuError> {
        self.idx.write(output, ctx)
    }
}

impl<T> MetadataIndex<T> {
    pub fn new(idx: u32) -> Self {
        Self {
            idx,
            _phantom: PhantomData
        }
    }
}

#[derive(Debug, Default)]
pub struct MetadataTable<T> {
    table: T,
}

impl<T: DekuWrite> DekuWrite for MetadataTable<T> {
    fn write(
            &self,
            output: &mut deku::bitvec::BitVec<u8, deku::bitvec::Msb0>,
            ctx: (),
        ) -> Result<(), DekuError> {
        self.table.write(output, ctx)
    }
}

// Regular indexing for u32
impl<T> Index<MetadataIndex<T>> for MetadataTable<Vec<T>> {
    type Output = T;

    fn index(&self, index: MetadataIndex<T>) -> &Self::Output {
        &self.table[index.idx as usize]
    }
}

// Regular indexing for u16
impl<T> Index<MetadataIndex<T, u16>> for MetadataTable<Vec<T>> {
    type Output = T;

    fn index(&self, index: MetadataIndex<T, u16>) -> &Self::Output {
        &self.table[index.idx as usize]
    }
}

impl<T> IntoIterator for MetadataTable<T> 
    where T: IntoIterator
{
    type Item = T::Item;
    type IntoIter = T::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.table.into_iter()
    }
}

impl<T> MetadataTable<Vec<T>> {
    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.table.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.table.iter_mut()
    }
}

macro_rules! string_data {
    ($ty:tt) => {
        #[derive(Debug, Default)]
        struct $ty<'data>(&'data [u8]);

        impl<'data> Index<MetadataIndex<$ty<'data>>> for MetadataTable<$ty<'data>> {
            type Output = str;

            fn index(&self, index: MetadataIndex<$ty>) -> &Self::Output {
                let idx = index.idx as usize;
                let mut len = 0;
                while self.table.0[idx + len] != 0 {
                    len += 1;
                }

                // FIXME: maybe not panic here?
                str::from_utf8(&self.table.0[idx..idx + len]).unwrap()
            }
        }

        impl<'data> ReadMetadataTable<'data> for MetadataTable<$ty<'data>> {
            fn read(cursor: &mut Cursor<&'data [u8]>, size: usize) -> std::io::Result<Self> {
                let start = cursor.position() as usize;
                Ok(MetadataTable {
                    table: $ty(&cursor.get_ref()[start..start + size])
                })
            }
        }

        impl<'data> DekuWrite for MetadataTable<$ty<'data>> {
            fn write(
                    &self,
                    output: &mut deku::bitvec::BitVec<u8, deku::bitvec::Msb0>,
                    ctx: (),
                ) -> Result<(), DekuError> {
                self.table.0.write(output, ctx)
            }
        }
    };
}

string_data!(StringLiteralData);
string_data!(StringData);
string_data!(WindowsRuntimeStringData);

pub type TypeIndex = u32;
pub type TypeDefinitionIndex = u32;
pub type FieldIndex = u32;
pub type DefaultValueIndex = u32;
pub type DefaultValueDataIndex = u32;
pub type CustomAttributeIndex = u32;
pub type ParameterIndex = u32;
pub type MethodIndex = u32;
pub type GenericMethodIndex = u32;
pub type PropertyIndex = u32;
pub type EventIndex = u32;
pub type GenericContainerIndex = u32;
pub type GenericParameterIndex = u32;
pub type GenericParameterConstraintIndex = u16;
pub type NestedTypeIndex = u32;
pub type InterfacesIndex = u32;
pub type VTableIndex = u32;
pub type InterfaceOffsetIndex = u32;
pub type RGCTXIndex = u32;
pub type StringIndex = u32;
pub type StringLiteralIndex = u32;
pub type GenericInstIndex = u32;
pub type ImageIndex = u32;
pub type AssemblyIndex = u32;
pub type InteropDataIndex = u32;

type EncodedMethodIndex = u32;

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppStringLiteral {
    pub length: u32,
    pub data_index: StringLiteralIndex,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppEventDefinition {
    pub name_index: StringIndex,
    pub type_index: TypeIndex,
    pub add: MethodIndex,
    pub remove: MethodIndex,
    pub raise: MethodIndex,
    pub token: u32,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppMethodDefinition {
    pub name_index: StringIndex,
    pub declaring_type: TypeDefinitionIndex,
    pub return_type: TypeIndex,
    pub parameter_start: ParameterIndex,
    pub generic_container_index: GenericContainerIndex,
    pub token: u32,
    pub flags: u16,
    pub iflags: u16,
    pub slot: u16,
    pub parameter_count: u16,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppParameterDefinition {
    pub name_index: i32,
    pub token: u32,
    pub type_index: i32,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppTypeDefinition {
    pub name_index: StringIndex,
    pub namespace_index: StringIndex,
    pub byval_type_index: TypeIndex,

    pub declaring_type_index: TypeIndex,
    pub parent_index: TypeIndex,
    pub element_type_index: TypeIndex,

    pub generic_container_index: GenericContainerIndex,

    pub flags: u32,

    pub field_start: FieldIndex,
    pub method_start: MethodIndex,
    pub event_start: EventIndex,
    pub property_start: PropertyIndex,
    pub nested_types_start: NestedTypeIndex,
    pub interfaces_start: InterfacesIndex,
    pub vtable_start: VTableIndex,
    pub interface_offsets_start: InterfacesIndex,

    pub method_count: u16,
    pub property_count: u16,
    pub field_count: u16,
    pub event_count: u16,
    pub nested_type_count: u16,
    pub vtable_count: u16,
    pub interfaces_count: u16,
    pub interface_offsets_count: u16,

    pub bitfield: u32,
    pub token: u32,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppImageDefinition {
    pub name_index: StringIndex,
    pub assembly_index: AssemblyIndex,

    pub type_start: TypeDefinitionIndex,
    pub type_count: u32,

    pub exported_type_start: TypeDefinitionIndex,
    pub exported_type_count: u32,

    pub entry_point_index: MethodIndex,
    pub token: u32,

    pub custom_attribute_start: CustomAttributeIndex,
    pub custom_attribute_count: u32,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppFieldDefinition {
    pub name_index: StringIndex,
    pub type_index: TypeIndex,
    pub token: u32,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppPropertyDefinition {
    pub name_index: StringIndex,
    pub get: MethodIndex,
    pub set: MethodIndex,
    pub attrs: u32,
    pub token: u32,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppParameterDefaultValue {
    pub parameter_index: ParameterIndex,
    pub type_index: TypeIndex,
    pub data_index: DefaultValueDataIndex,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppFieldDefaultValue {
    pub field_index: FieldIndex,
    pub type_index: TypeIndex,
    pub data_index: DefaultValueDataIndex,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppFieldMarshaledSize {
    pub field_index: FieldIndex,
    pub type_index: TypeIndex,
    pub size: u32,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppGenericParameter {
    pub owner_index: GenericContainerIndex, /* Type or method this parameter was defined in. */
    pub name_index: StringIndex,
    pub constraints_start: GenericParameterConstraintIndex,
    pub constraints_count: u16,
    pub num: u16,
    pub flags: u16,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppGenericContainer {
    /// index of the generic type definition or the generic method definition corresponding to this container \
    /// either index into Il2CppClass metadata array or Il2CppMethodDefinition array
    pub owner_index: u32,
    pub type_argc: u32,
    /// If true, we're a generic method, otherwise a generic type definition.
    pub is_method: u32,
    /// Our type parameters.
    pub generic_parameter_start: GenericParameterIndex,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppInterfaceOffsetPair {
    pub interface_type_index: TypeIndex,
    pub offset: u32,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: deku::ctx::Endian")]
pub struct Il2CppAssemblyNameDefinition {
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

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppAssemblyDefinition {
    pub image_index: ImageIndex,
    pub token: u32,
    pub referenced_assembly_start: u32,
    pub referenced_assembly_count: u32,
    pub aname: Il2CppAssemblyNameDefinition,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppMetadataUsageList {
    pub start: u32,
    pub count: u32,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppMetadataUsagePair {
    pub destination_index: u32,
    pub encoded_source_index: u32,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppCustomAttributeDataRange {
    pub token: u32,
    pub start_offset: u32,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppMetadataRange {
    pub start: u32,
    pub length: u32,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppWindowsRuntimeTypeNamePair {
    pub name_index: StringIndex,
    pub type_index: TypeIndex,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppFieldRef {
    pub type_index: TypeIndex,
    /// local offset into type fields
    pub field_index: FieldIndex,
}

#[derive(Debug, BinaryDeserialize, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct OffsetLen {
    offset: u32,
    len: u32,
}

trait ReadMetadataTable<'a>
where
    Self: std::marker::Sized,
{
    fn read(cursor: &mut Cursor<&'a [u8]>, size: usize) -> std::io::Result<Self>;
}

impl<T: BinaryDeserialize> ReadMetadataTable<'_> for MetadataTable<Vec<T>> {
    fn read(cursor: &mut Cursor<&[u8]>, size: usize) -> std::io::Result<Self> {
        let count = size / T::SIZE;
        let mut vec = Vec::new();
        for _ in 0..count {
            vec.push(T::deserialize::<LittleEndian, _>(&mut *cursor)?);
        }
        Ok(MetadataTable {
            table: vec
        })
    }
}


macro_rules! metadata {
    ($($name:ident: $ty:ty,)*) => {
        #[derive(Debug, BinaryDeserialize, DekuWrite)]
        #[deku(endian = "little")]
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
                pub $name: MetadataTable<$ty>,
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

            fn serialize(metadata: &GlobalMetadata) -> Result<Vec<u8>, DekuError> {
                // TODO: optimize and reduce allocations
                let mut header_size = 8;
                $(
                    let _ = metadata.$name;
                    header_size += 8;
                )*

                let mut bv = BitVec::new();
                $(
                    let offset = bv.len() as u32 / 8;
                    metadata.$name.write(&mut bv, Endian::Little)?;
                    let len = (bv.len() as u32 / 8) - offset;
                    let $name = OffsetLen { offset: offset + header_size, len };
                )*

                let header = Il2CppGlobalMetadataHeader {
                    sanity: SANITY,
                    version: VERSION,
                    $(
                        $name,
                    )*
                };

                let mut data = header.to_bytes()?;
                data.append(&mut bv.into_vec());
                Ok(data)
            }
        }
    };
}

metadata! {
    string_literal: Vec<Il2CppStringLiteral>,
    string_literal_data: StringLiteralData<'a>,
    string: StringData<'a>,
    events: Vec<Il2CppEventDefinition>,
    properties: Vec<Il2CppPropertyDefinition>,
    methods: Vec<Il2CppMethodDefinition>,
    parameter_default_values: Vec<Il2CppParameterDefaultValue>,
    field_default_values: Vec<Il2CppFieldDefaultValue>,
    field_and_parameter_default_value_data: Vec<u8>,
    field_marshaled_sizes: Vec<Il2CppFieldMarshaledSize>,
    parameters: Vec<Il2CppParameterDefinition>,
    fields: Vec<Il2CppFieldDefinition>,
    generic_parameters: Vec<Il2CppGenericParameter>,
    generic_parameter_constraints: Vec<TypeIndex>,
    generic_containers: Vec<Il2CppGenericContainer>,
    nested_types: Vec<TypeDefinitionIndex>,
    interfaces: Vec<TypeIndex>,
    vtable_methods: Vec<EncodedMethodIndex>,
    interface_offsets: Vec<Il2CppInterfaceOffsetPair>,
    type_definitions: Vec<Il2CppTypeDefinition>,
    images: Vec<Il2CppImageDefinition>,
    assemblies: Vec<Il2CppAssemblyDefinition>,
    field_refs: Vec<Il2CppFieldRef>,
    referenced_assemblies: Vec<u32>,
    attribute_data: Vec<u8>,
    attribute_data_range: Vec<Il2CppCustomAttributeDataRange>,
    attributes_info: Vec<Il2CppCustomAttributeDataRange>,
    attribute_types: Vec<TypeIndex>,
    unresolved_virtual_call_parameter_types: Vec<TypeIndex>,
    unresolved_virtual_call_parameter_ranges: Vec<Il2CppMetadataRange>,
    windows_runtime_type_names: Vec<Il2CppWindowsRuntimeTypeNamePair>,
    windows_runtime_strings: WindowsRuntimeStringData<'a>,
    exported_type_definitions: Vec<TypeDefinitionIndex>,
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

pub fn serialize(metadata: &GlobalMetadata) -> Result<Vec<u8>, DekuError> {
    GlobalMetadata::serialize(metadata)
}
