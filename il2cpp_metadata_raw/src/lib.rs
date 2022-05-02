use deku::bitvec::{BitVec, BitView};
use deku::ctx::{Endian, Size};
use deku::prelude::*;
use thiserror::Error;

const SANITY: u32 = 0xFAB11BAF;
const VERSION: u32 = 24;

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

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppStringLiteral {
    pub length: u32,
    pub data_index: StringLiteralIndex,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppEventDefinition {
    pub name_index: StringIndex,
    pub type_index: TypeIndex,
    pub add: MethodIndex,
    pub remove: MethodIndex,
    pub raise: MethodIndex,
    pub token: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
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

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppParameterDefinition {
    pub name_index: i32,
    pub token: u32,
    pub type_index: i32,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppTypeDefinition {
    pub name_index: StringIndex,
    pub namespace_index: StringIndex,
    pub byval_type_index: TypeIndex,
    pub byref_type_index: TypeIndex,

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

#[derive(Debug, DekuRead, DekuWrite)]
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

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppFieldDefinition {
    pub name_index: i32,
    pub type_index: i32,
    pub token: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppPropertyDefinition {
    pub name_index: StringIndex,
    pub get: MethodIndex,
    pub set: MethodIndex,
    pub attrs: u32,
    pub token: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppParameterDefaultValue {
    pub parameter_index: ParameterIndex,
    pub type_index: TypeIndex,
    pub data_index: DefaultValueDataIndex,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppFieldDefaultValue {
    pub field_index: FieldIndex,
    pub type_index: TypeIndex,
    pub data_index: DefaultValueDataIndex,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppFieldMarshaledSize {
    pub field_index: FieldIndex,
    pub type_index: TypeIndex,
    pub size: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppGenericParameter {
    pub owner_index: GenericContainerIndex, /* Type or method this parameter was defined in. */
    pub name_index: StringIndex,
    pub constraints_start: GenericParameterConstraintIndex,
    pub constraints_count: u16,
    pub num: u16,
    pub flags: u16,
}

#[derive(Debug, DekuRead, DekuWrite)]
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

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppInterfaceOffsetPair {
    pub interface_type_index: TypeIndex,
    pub offset: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
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

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppAssemblyDefinition {
    pub image_index: ImageIndex,
    pub token: u32,
    pub referenced_assembly_start: u32,
    pub referenced_assembly_count: u32,
    pub aname: Il2CppAssemblyNameDefinition,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppMetadataUsageList {
    pub start: u32,
    pub count: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppMetadataUsagePair {
    pub destination_index: u32,
    pub encoded_source_index: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppCustomAttributeTypeRange {
    pub token: u32,
    pub start: u32,
    pub count: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppRange {
    pub start: u32,
    pub length: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppWindowsRuntimeTypeNamePair {
    pub name_index: StringIndex,
    pub type_index: TypeIndex,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct Il2CppFieldRef {
    pub type_index: TypeIndex,
    /// local offset into type fields
    pub field_index: FieldIndex,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little", ctx = "_: Endian")]
pub struct OffsetLen {
    offset: u32,
    len: u32,
}

macro_rules! metadata {
    ($($name:ident: $ty:ty,)*) => {
        #[derive(Debug, DekuRead, DekuWrite)]
        #[deku(endian = "little")]
        struct Il2CppGlobalMetadataHeader {
            sanity: u32,
            version: u32,
            $(
                $name: OffsetLen,
            )*
        }

        #[derive(Debug)]
        pub struct Metadata<'a> {
            $(
                pub $name: $ty,
            )*
        }

        impl<'a> Metadata<'a> {
            fn deserialize(
                data: &'a [u8],
                header: Il2CppGlobalMetadataHeader,
            ) -> Result<Metadata, MetadataDeserializeError> {
                Ok(Metadata {
                    $(
                        $name: {
                            let size = header.$name.len as usize;
                            if size > 0 {
                                let offset = header.$name.offset as usize;
                                let ctx = (Size::Bytes(size).into(), Endian::Little);
                                let bitvec = data[offset..offset + size].view_bits();
                                <$ty>::read(bitvec, ctx)?.1
                            } else {
                                Default::default()
                            }
                        },
                    )*
                })
            }

            fn serialize(metadata: &Metadata) -> Result<Vec<u8>, DekuError> {
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
    string_literal_data: &'a [u8],
    string: &'a [u8],
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
    metadata_usage_lists: Vec<Il2CppMetadataUsageList>,
    metadata_usage_pairs: Vec<Il2CppMetadataUsagePair>,
    field_refs: Vec<Il2CppFieldRef>,
    referenced_assemblies: Vec<u32>,
    attributes_info: Vec<Il2CppCustomAttributeTypeRange>,
    attribute_types: Vec<TypeIndex>,
    unresolved_virtual_call_parameter_types: Vec<TypeIndex>,
    unresolved_virtual_call_parameter_ranges: Vec<Il2CppRange>,
    windows_runtime_type_names: Vec<Il2CppWindowsRuntimeTypeNamePair>,
    exported_type_definitions: Vec<TypeDefinitionIndex>,
}

#[derive(Error, Debug)]
pub enum MetadataDeserializeError {
    #[error("binary deserialization error")]
    Bin(#[from] DekuError),
    #[error("il2cpp metadata header sanity check failed")]
    SanityCheck,
    #[error("il2cpp metadata header version check failed")]
    VersionCheck,
}

pub fn deserialize(data: &[u8]) -> Result<Metadata, MetadataDeserializeError> {
    let header = Il2CppGlobalMetadataHeader::from_bytes((data, 0))?.1;

    if header.sanity != SANITY {
        return Err(MetadataDeserializeError::SanityCheck);
    }

    if header.version != VERSION {
        return Err(MetadataDeserializeError::VersionCheck);
    }

    Metadata::deserialize(data, header)
}

pub fn serialize(metadata: &Metadata) -> Result<Vec<u8>, DekuError> {
    Metadata::serialize(metadata)
}
