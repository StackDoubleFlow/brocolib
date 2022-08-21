mod binary;

use crate::metadata::binary::{CodeRegistration, MetadataRegistration};
use crate::{utils, Elf};
use anyhow::{Context, Result};
use binary::find_registration;
use binde::BinaryDeserialize;
use byteorder::{ReadBytesExt, LE};
use il2cpp_metadata_raw::Metadata as RawMetadata;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy)]
pub struct TypeIndex(usize);
#[derive(Debug, Clone, Copy)]
pub struct TypeDefinitionIndex(usize);

#[derive(Debug)]
pub struct Type {
    pub data: u64,
    pub ty: u8,
    pub by_ref: bool,
}

#[derive(Debug)]
pub struct Parameter<'a> {
    pub name: &'a str,
    pub ty: TypeIndex,
}

#[derive(Debug)]
pub struct Method<'a> {
    pub name: &'a str,
    pub class: TypeDefinitionIndex,
    pub return_type: TypeIndex,
    pub params: Vec<Parameter<'a>>,
    pub flags: u16,
    pub token: u32,

    pub offset: u64,
}

#[derive(Debug)]
pub struct Field<'a> {
    pub name: &'a str,
    pub ty: TypeIndex,
    pub token: u32,
    pub offset: i32,
}

pub struct TypeDefinition<'a> {
    pub name: &'a str,
    pub namespace: &'a str,
    pub byval_ty: TypeIndex,

    pub methods: Vec<Method<'a>>,
    pub fields: Vec<Field<'a>>,

    pub token: u32,
}

pub struct Metadata<'a> {
    pub types: Vec<Type>,
    pub type_definitions: Vec<TypeDefinition<'a>>,

    pub type_map: HashMap<(&'a str, &'a str), TypeDefinitionIndex>,
}

impl<'a> std::ops::Index<TypeIndex> for Metadata<'a> {
    type Output = Type;

    fn index(&self, index: TypeIndex) -> &Self::Output {
        &self.types[index.0]
    }
}

impl<'a> std::ops::Index<TypeDefinitionIndex> for Metadata<'a> {
    type Output = TypeDefinition<'a>;

    fn index(&self, index: TypeDefinitionIndex) -> &Self::Output {
        &self.type_definitions[index.0]
    }
}

pub fn read<'a>(data: &'a [u8], elf: &'a Elf) -> Result<Metadata<'a>> {
    let (code_registration, metadata_registration) = find_registration(elf)?;
    let code_registration = CodeRegistration::read(elf, code_registration)?;
    let metadata_registration = MetadataRegistration::read(elf, metadata_registration)?;

    let raw_metadata = il2cpp_metadata_raw::deserialize(data)?;

    let mut type_definitions = Vec::with_capacity(raw_metadata.type_definitions.len());
    for (type_idx, raw) in raw_metadata.type_definitions.iter().enumerate() {
        let name = utils::get_str(&raw_metadata.string, raw.name_index as usize)?;
        let namespace = utils::get_str(&raw_metadata.string, raw.namespace_index as usize)?;
        let mut methods = Vec::with_capacity(raw.method_count as usize);
        let method_start = if raw.method_count > 0 {
            raw.method_start
        } else {
            0
        };
        for raw_method in &raw_metadata.methods
            [method_start as usize..method_start as usize + raw.method_count as usize]
        {
            let name = utils::get_str(&raw_metadata.string, raw_method.name_index as usize)?;
            let mut params = Vec::with_capacity(raw_method.parameter_count as usize);
            let param_start = if raw_method.parameter_count > 0 {
                raw_method.parameter_start
            } else {
                0
            };
            for raw_param in &raw_metadata.parameters
                [param_start as usize..param_start as usize + raw_method.parameter_count as usize]
            {
                params.push(Parameter {
                    name: utils::get_str(&raw_metadata.string, raw_param.name_index as usize)?,
                    ty: TypeIndex(raw_param.type_index as usize),
                })
            }
            methods.push(Method {
                name,
                class: TypeDefinitionIndex(type_idx),
                return_type: TypeIndex(raw_method.return_type as usize),
                params,
                flags: raw_method.flags,
                token: raw_method.token,
                offset: 0,
            })
        }
        let mut fields = Vec::with_capacity(raw.field_count as usize);
        let field_start = if raw.field_count > 0 {
            raw.field_start
        } else {
            0
        } as usize;
        let field_slice = &raw_metadata.fields[field_start..field_start + raw.field_count as usize];
        for (field_idx, raw_field) in field_slice.iter().enumerate() {
            let name = utils::get_str(&raw_metadata.string, raw_field.name_index as usize)?;
            let field_offset_addr = metadata_registration.field_offset_addrs[type_idx];
            let mut field_offset_data =
                &elf.data()[field_offset_addr as usize + field_idx as usize * 4..];
            fields.push(Field {
                name,
                ty: TypeIndex(raw_field.type_index as usize),
                token: raw_field.token,
                offset: field_offset_data.read_i32::<LE>()?,
            });
        }

        type_definitions.push(TypeDefinition {
            name,
            namespace,
            byval_ty: TypeIndex(raw.byval_type_index as usize),
            methods,
            fields,
            token: raw.token,
        })
    }

    for raw in &raw_metadata.images {
        let name = utils::get_str(&raw_metadata.string, raw.name_index as usize)?;
        let module = code_registration.modules.iter().find(|m| m.name == name);
        let module = module
            .with_context(|| format!("count not find code registration module '{}'", name))?;
        for type_def in &mut type_definitions
            [raw.type_start as usize..raw.type_start as usize + raw.type_count as usize]
        {
            for method in &mut type_def.methods {
                let rid = method.token & 0x00FFFFFF;
                method.offset = module.method_pointers[rid as usize - 1];
            }
        }
    }

    let type_map = type_definitions
        .iter()
        .enumerate()
        .map(|(i, def)| ((def.namespace, def.name), TypeDefinitionIndex(i)))
        .collect();

    Ok(Metadata {
        type_definitions,
        types: metadata_registration.types,

        type_map,
    })
}
