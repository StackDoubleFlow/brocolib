//! Global metadata types.

use crate::Metadata;
use crate::runtime_metadata::TypeData;
use std::io::Cursor;
use std::ops::Index;
use std::{str, concat, stringify};
use binread::BinRead;
use binde::{BinaryDeserialize, LittleEndian};
use thiserror::Error;

const SANITY: u32 = 0xFAB11BAF;
const VERSION: u32 = 31;

// TODO
pub type TypeIndex = u32;

macro_rules! range_helper {
    ($name:ident, $table:ident, $start:ident, $count:ident, $ty:ty) => {
        pub fn $name<'md>(&self, metadata: &'md Metadata) -> &'md [$ty] {
            let range = self.$start.make_range(self.$count as _);
            &metadata.global_metadata.$table[range]
        }
    };
    ($table:ident, $start:ident, $count:ident, $ty:ty) => {
        range_helper!($table, $table, $start, $count, $ty);
    };
}

macro_rules! field_helper {
    ($name:ident, $table:ident, $field:ident, $ty:ty) => {
        pub fn $name<'md>(&self, metadata: &'md Metadata) -> &'md $ty {
            &metadata.global_metadata.$table[self.$field]
        }
    };
}

macro_rules! field_helper_optional {
    ($name:ident, $table:ident, $field:ident, $ty:ty) => {
        pub fn $name<'md>(&self, metadata: &'md Metadata) -> Option<&'md $ty> {
            match self.$field.is_valid() {
                false => None,
                true => Some(&metadata.global_metadata.$table[self.$field])
            }
        }
    };
}

#[derive(Debug)]
pub enum InvalidMethodIndex {
    NoData,
    AmbiguousMethod
}

#[derive(Debug)]
pub enum DecodedMethodIndex {
    Invalid(InvalidMethodIndex),
    TypeInfo(TypeIndex),
    Il2CppType(TypeIndex),
    MethodDef(MethodIndex),
    FieldInfo(FieldRefIndex),
    StringLiteral(StringLiteralIndex),
    // TODO: Generic method index
    MethodRef(u32),
    FieldRva(FieldRefIndex),
}

#[derive(Debug, Copy, Clone)]
pub struct EncodedMethodIndex(pub u32);

impl EncodedMethodIndex {
    pub fn decode(self) -> DecodedMethodIndex {
        let ty = (self.0 & 0xE0000000) >> 29;
        let idx = (self.0 & 0x1FFFFFFE) >> 1;
        let invalid = self.0 & 0x00000001;

        match ty {
            0 => DecodedMethodIndex::Invalid(match invalid {
                0 => InvalidMethodIndex::NoData,
                1 => InvalidMethodIndex::AmbiguousMethod,
                _ => panic!("Unknown invalid method index type: {}", invalid),
            }),
            1 => DecodedMethodIndex::TypeInfo(idx),
            2 => DecodedMethodIndex::Il2CppType(idx),
            3 => DecodedMethodIndex::MethodDef(MethodIndex::new(idx)),
            4 => DecodedMethodIndex::FieldInfo(FieldRefIndex::new(idx)),
            5 => DecodedMethodIndex::StringLiteral(StringLiteralIndex::new(idx)),
            6 => DecodedMethodIndex::MethodRef(idx),
            7 => DecodedMethodIndex::FieldRva(FieldRefIndex::new(idx)),
            _ => panic!("Unknown encoded method index type: {}", ty),
        }

    }
}


impl BinaryDeserialize for EncodedMethodIndex {
    const SIZE: usize = u32::SIZE;
    fn deserialize<E, R>(reader: R) -> std::io::Result<Self>
        where
            E: binde::ByteOrder,
            R: std::io::Read {
        Ok(Self(binde::deserialize::<E, _, _>(reader)?))
    }
}

#[derive(Debug, Copy, Clone, Hash, BinRead)]
pub struct Token(pub u32);

impl Token {
    pub fn ty(self) -> u32 {
        // TODO: TokenType enum
        self.0 & 0xFF000000
    }

    pub fn rid(self) -> u32 {
        self.0 & 0x00FFFFFF
    }
}

impl BinaryDeserialize for Token {
    const SIZE: usize = u32::SIZE;
    fn deserialize<E, R>(reader: R) -> std::io::Result<Self>
        where
            E: binde::ByteOrder,
            R: std::io::Read {
        Ok(Self(binde::deserialize::<E, _, _>(reader)?))
    }
}

/// A C# string literal.
/// 
/// These are stored as UTF-8 in the metadata file and expanded to UTF-16 at
/// runtime.
/// 
/// Defined at `vm/GlobalMetadataFileInternals.h:187`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppStringLiteral {
    pub length: u32,
    pub data_index: StringLiteralDataIndex,
}

impl Il2CppStringLiteral {
    field_helper!(data, string_literal_data, data_index, str);
}

/// Defined at `vm/GlobalMetadataFileInternals.h:168`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppEventDefinition {
    pub name_index: StringIndex,
    pub type_index: TypeIndex,
    pub add: MethodIndex,
    pub remove: MethodIndex,
    pub raise: MethodIndex,
    pub token: Token,
}

impl Il2CppEventDefinition {
    field_helper!(name, string, name_index, str);
    field_helper!(add_method, methods, add, Il2CppMethodDefinition);
    field_helper!(remove_method, methods, remove, Il2CppMethodDefinition);
    field_helper!(raise_method, methods, raise, Il2CppMethodDefinition);
}

/// Defined at `vm/GlobalMetadataFileInternals.h:154`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppMethodDefinition {
    pub name_index: StringIndex,
    pub declaring_type: TypeDefinitionIndex,
    pub return_type: TypeIndex,
    pub return_parameter_token: Token,
    pub parameter_start: ParameterIndex,
    /// Optional. Holds information about generic parameters.
    pub generic_container_index: GenericContainerIndex,
    pub token: Token,

    /// Method attributes. See `il2cpp-tabledefs.h`.
    pub flags: u16,

    /// Method implementation attributes. See `il2cpp-tabledefs.h`.
    pub iflags: u16,
    pub slot: u16,
    pub parameter_count: u16,
}

impl Il2CppMethodDefinition {
    field_helper!(name, string, name_index, str);
    field_helper!(declaring_type, type_definitions, declaring_type, Il2CppTypeDefinition);
    range_helper!(parameters, parameter_start, parameter_count, Il2CppParameterDefinition);
    field_helper_optional!(generic_container, generic_containers, generic_container_index, Il2CppGenericContainer);

    pub fn full_name(&self, metadata: &Metadata) -> String {
        let mr = &metadata.runtime_metadata.metadata_registration;
        let mut full_name = String::new();
        full_name.push_str(&mr.types[self.return_type as usize].full_name(metadata));
        full_name.push(' ');
        full_name.push_str(&self.declaring_type(metadata).full_name(metadata, true));
        full_name.push_str("::");
        full_name.push_str(self.name(metadata));
        if let Some(gc) = self.generic_container(metadata) {
            full_name.push_str(&gc.to_string(metadata));
        }
        full_name.push('(');
        for (i, param) in self.parameters(metadata).iter().enumerate() {
            if i > 0 {
                full_name.push_str(", ");
            }
            full_name.push_str(&mr.types[param.type_index as usize].full_name(metadata));
            full_name.push(' ');
            full_name.push_str(param.name(metadata));
        }
        full_name.push(')');
        full_name
    }
}

/// Defined at `vm/GlobalMetadataFileInternals.h:140`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppParameterDefinition {
    pub name_index: StringIndex,
    pub token: Token,
    pub type_index: TypeIndex,
}

impl Il2CppParameterDefinition {
    field_helper!(name, string, name_index, str);
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
    pub token: Token,
}

impl Il2CppTypeDefinition {
    field_helper!(name, string, name_index, str);
    field_helper!(namespace, string, namespace_index, str);
    field_helper!(generic_container, generic_containers, generic_container_index, Il2CppGenericContainer);
    range_helper!(methods, method_start, method_count, Il2CppMethodDefinition);
    range_helper!(fields, field_start, field_count, Il2CppFieldDefinition);
    range_helper!(events, event_start, event_count, Il2CppEventDefinition);
    range_helper!(properties, property_start, property_count, Il2CppPropertyDefinition);
    range_helper!(nested_types, nested_types_start, nested_type_count, TypeDefinitionIndex);
    range_helper!(interfaces, interfaces_start, interfaces_count, TypeIndex);
    range_helper!(vtable_methods, vtable_start, vtable_count, EncodedMethodIndex);
    range_helper!(interface_offsets, interface_offsets_start, interface_offsets_count, Il2CppInterfaceOffsetPair);

    pub fn full_name(&self, metadata: &Metadata, with_generics: bool) -> String {
        let namespace = self.namespace(metadata);
        let name = self.name(metadata);


        let mut full_name = String::new();
        if !namespace.is_empty() {
            full_name.push_str(namespace);
            full_name.push('.');
        }

        if self.declaring_type_index != u32::MAX {
            let s = metadata.runtime_metadata.metadata_registration.types
                [self.declaring_type_index as usize]
                .full_name(metadata)
                + "::";
            full_name.push_str(s.as_str());
        }

        full_name.push_str(name);
        if self.generic_container_index.is_valid() && with_generics {
            let gc = self.generic_container(metadata);
            full_name.push_str(&gc.to_string(metadata));
        }
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
    pub token: Token,

    pub custom_attribute_start: AttributeDataRangeIndex,
    pub custom_attribute_count: u32,
}

impl Il2CppImageDefinition {
    field_helper!(name, string, name_index, str);
    field_helper!(assembly, assemblies, assembly_index, Il2CppAssemblyDefinition);
    range_helper!(types, type_definitions, type_start, type_count, Il2CppTypeDefinition);
    range_helper!(exported_types, type_definitions, exported_type_start, exported_type_count, Il2CppTypeDefinition);
    field_helper!(entry_point, methods, entry_point_index, Il2CppMethodDefinition);
    range_helper!(custom_attributes, attribute_data_range, custom_attribute_start, custom_attribute_count, Il2CppCustomAttributeDataRange);
}

/// Defined at `vm/GlobalMetadataFileInternals.h:113`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppFieldDefinition {
    pub name_index: StringIndex,
    pub type_index: TypeIndex,
    pub token: Token,
}

impl Il2CppFieldDefinition {
    field_helper!(name, string, name_index, str);
}

/// Defined at `vm/GlobalMetadataFileInternals.h:178`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppPropertyDefinition {
    pub name_index: StringIndex,
    /// Index into declaring type's method list
    pub get: u32,
    /// Index into declaring type's method list
    pub set: u32,
    /// See `il2cpp-tabledef.h`
    pub attrs: u32,
    pub token: Token,
}

impl Il2CppPropertyDefinition {
    field_helper!(name, string, name_index, str);

    pub fn get_method_index(&self, decl_type: &Il2CppTypeDefinition) -> MethodIndex {
        MethodIndex::new(decl_type.method_start.index() + self.get)
    }

    pub fn get_method<'md>(&self, decl_type: &Il2CppTypeDefinition, metadata: &'md Metadata) -> &'md Il2CppMethodDefinition {
        let idx = self.get_method_index(decl_type);
        &metadata.global_metadata.methods[idx]
    }

    pub fn set_method_index(&self, decl_type: &Il2CppTypeDefinition) -> MethodIndex {
        MethodIndex::new(decl_type.method_start.index() + self.set)
    }

    pub fn set_method<'md>(&self, decl_type: &Il2CppTypeDefinition, metadata: &'md Metadata) -> &'md Il2CppMethodDefinition {
        let idx = self.set_method_index(decl_type);
        &metadata.global_metadata.methods[idx]
    }
}

/// Defined at `vm/GlobalMetadataFileInternals.h:147`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppParameterDefaultValue {
    pub parameter_index: ParameterIndex,
    pub type_index: TypeIndex,
    pub data_index: FieldAndParameterDefaultValueIndex,
}

impl Il2CppParameterDefaultValue {
    field_helper!(parameter, parameters, parameter_index, Il2CppParameterDefinition);
    // TODO: data type
    field_helper!(data, field_and_parameter_default_value_data, data_index, u8);
}

/// Defined at `vm/GlobalMetadataFileInternals.h:120`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppFieldDefaultValue {
    pub field_index: FieldIndex,
    pub type_index: TypeIndex,
    pub data_index: FieldAndParameterDefaultValueIndex,
}

impl Il2CppFieldDefaultValue {
    field_helper!(field, fields, field_index, Il2CppFieldDefinition);
    // TODO: data type
    field_helper!(data, field_and_parameter_default_value_data, data_index, u8);
}

/// Defined at `vm/GlobalMetadataFileInternals.h:127`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppFieldMarshaledSize {
    pub field_index: FieldIndex,
    pub type_index: TypeIndex,
    pub size: u32,
}

impl Il2CppFieldMarshaledSize {
    field_helper!(field, fields, field_index, Il2CppFieldDefinition);
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

impl Il2CppGenericParameter {
    field_helper!(owner, generic_containers, owner_index, Il2CppGenericContainer);
    field_helper!(name, string, name_index, str);
    range_helper!(constraints, generic_parameter_constraints, constraints_start, constraints_count, TypeIndex);
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

impl Il2CppGenericContainer {
    range_helper!(generic_parameters, generic_parameter_start, type_argc, Il2CppGenericParameter);

    pub fn to_string(&self, metadata: &Metadata) -> String {
        let mut full_name = String::new();
        full_name.push('<');
        for (i, param) in self.generic_parameters(metadata).iter().enumerate() {
            if i > 0 {
                full_name.push_str(", ");
            }
            full_name.push_str(param.name(metadata));
        }
        full_name.push('>');
        full_name
    }
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


impl Il2CppAssemblyNameDefinition {
    field_helper!(name, string, name_index, str);
    // TODO: are culture and public_key valid utf-8?
}
/// Defined at `vm/GlobalMetadataFileInternals.h:226`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppAssemblyDefinition {
    pub image_index: ImageIndex,
    pub token: Token,
    pub referenced_assembly_start: ReferencedAssemblyIndex,
    pub referenced_assembly_count: u32,
    pub aname: Il2CppAssemblyNameDefinition,
}

impl Il2CppAssemblyDefinition {
    field_helper!(image, images, image_index, Il2CppImageDefinition);
    range_helper!(referenced_assemblies, referenced_assembly_start, referenced_assembly_count, u32);
}

/// Defined at `vm/GlobalMetadataFileInternals.h:235`
#[derive(Debug, BinaryDeserialize)]
pub struct Il2CppCustomAttributeDataRange {
    pub token: Token,
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
    pub field_index: u32,
}

impl Il2CppFieldRef {
    pub fn resolve_field(&self, metadata: &Metadata) -> FieldIndex {
        let ty_data = &metadata.runtime_metadata.metadata_registration.types[self.type_index as usize].data;
        let TypeData::TypeDefinitionIndex(ty_def_idx) = ty_data else {
            panic!("Bad Il2CppFieldRef type data type: {:?}", ty_data);
        };
        let ty_def = &metadata.global_metadata.type_definitions[*ty_def_idx];
        FieldIndex::new(ty_def.field_start.0 + self.field_index)
    }
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
    ($($(#[$($attrss:tt)*])* $name:ident: $ty:ty,)*) => {
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
                $(#[$($attrss)*])*
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
    ($name:ident, $ty:ty, $for:ident) => {
        #[doc = concat!(
            "Index type for [`",
            stringify!($for),
            "`]."
        )]
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
        #[doc =
            concat!(
                "A metadata table of [`",
                stringify!($ty),
                "`]s.\n\nUse a [`",
                stringify!($idx_name),
                "`] to index into it."
            )
        ]
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

        index_type!($idx_name, $idx_ty, $name);

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
        #[doc =
            concat!(
                "A metadata table for string data.\n\nIndexing into it with a [`",
                stringify!($idx_name),
                "`] will yield string slices."
            )
        ]
        #[derive(Debug, Default)]
        pub struct $name<'data> {
            data: &'data [u8]
        }

        impl<'data> $name<'data> {
            pub fn data(&self) -> &'data [u8] {
                self.data
            }
        }

        index_type!($idx_name, u32, $name);

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
basic_table!(ReferencedAssemblyTable: u32, ReferencedAssemblyIndex);
basic_table!(AttributeDataRangeTable: Il2CppCustomAttributeDataRange, AttributeDataRangeIndex);
// TODO: data?
basic_table!(AttributeDataTable: u8, AttributeDataIndex);
basic_table!(AttributeInfoTable: Il2CppCustomAttributeDataRange, AttributeInfoIndex);
basic_table!(AttributeTypeTable: TypeIndex, AttributeTypeIndex);
basic_table!(UnresolvedIndirectCallParameterTypeTable: TypeIndex, UnresolvedIndirectCallParameterTypeIndex);
basic_table!(UnresolvedIndirectCallParameterRangeTable: Il2CppMetadataRange, UnresolvedIndirectCallParameterRangeIndex);
basic_table!(WindowsRuntimeTypeNameTable: Il2CppWindowsRuntimeTypeNamePair, WindowsRuntimeTypeNameIndex);
string_data_table!(WindowsRuntimeStringData, WindowsRuntimeStringDataIndex);
basic_table!(ExportedTypeDefinitionTable: TypeDefinitionIndex, ExportedTypeDefinitionIndex);

metadata! {
    string_literal: StringLiteralTable,
    string_literal_data: StringLiteralData<'a>,
    /// String data for the metadata itself.
    ///
    /// For C# string literal data, see [`GlobalMetadata::string_literal_data`].
    string: StringData<'a>,
    events: EventTable,
    properties: PropertyTable,
    methods: MethodTable,
    parameter_default_values: ParameterDefaultValueTable,
    field_default_values: FieldDefaultValueTable,
    field_and_parameter_default_value_data: FieldAndParameterDefaultValueTable,
    field_marshaled_sizes: FieldMarshaledSizeTable,
    /// C# method parameters.
    /// 
    /// This is normally indexed by a range returned from [`Il2CppMethodDefinition::parameters()`].
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
    unresolved_indirect_call_parameter_types: UnresolvedIndirectCallParameterTypeTable,
    unresolved_indirect_call_parameter_ranges: UnresolvedIndirectCallParameterRangeTable,
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
