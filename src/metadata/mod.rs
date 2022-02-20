mod binary;
mod raw;

use crate::binary_deserialize::BinaryDeserialize;
use crate::metadata::binary::{CodeRegistration, MetadataRegistration};
use crate::{utils, Elf};
use anyhow::{Context, Result};
use binary::find_registration;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;

#[derive(Debug, Clone, Copy)]
pub struct TypeIndex(usize);
#[derive(Debug)]
pub struct TypeDefinitionIndex(usize);

pub struct Image<'a> {
    name: &'a str,
}

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
pub struct Field {}

pub struct TypeDefinition<'a> {
    pub name: &'a str,
    pub namespace: &'a str,

    pub methods: Vec<Method<'a>>,

    pub token: u32,
}

pub struct Metadata<'a> {
    pub types: Vec<Type>,
    pub type_definitions: Vec<TypeDefinition<'a>>,
}

impl<'a> std::ops::Index<TypeIndex> for Metadata<'a> {
    type Output = Type;

    fn index(&self, index: TypeIndex) -> &Self::Output {
        &self.types[index.0]
    }
}

pub fn read<'a>(data: &'a [u8], elf: &'a Elf) -> Result<Metadata<'a>> {
    let (code_registration, metadata_registration) = find_registration(elf)?;
    let code_registration = CodeRegistration::read(elf, code_registration)?;
    let metadata_registration = MetadataRegistration::read(elf, metadata_registration)?;

    let mut cur = Cursor::new(data);
    let mut header = [0; 66];
    for h in &mut header {
        *h = cur.read_u32::<LittleEndian>()?;
    }
    assert!(header[0] == 0xFAB11BAF, "metadata sanity check failed");
    assert!(header[1] == 24, "only il2cpp version 24 is supported");

    let str_offset = header[6] as usize;
    let methods_offset = header[12];
    let parameters_offset = header[22] as usize;
    let type_defs_offset = header[40];
    let type_defs_len = header[41] as usize / 92;
    let images_offset = header[42];
    let images_len = header[43] as usize / 40;

    let mut type_definitions = Vec::with_capacity(type_defs_len);
    cur.set_position(type_defs_offset as u64);
    for type_idx in 0..type_defs_len {
        let raw = raw::Il2CppTypeDefinition::read(&mut cur)?;
        let name = utils::get_str(data, str_offset + raw.name_index as usize)?;
        let namespace = utils::get_str(data, str_offset + raw.namespace_index as usize)?;
        let mut methods = Vec::with_capacity(raw.method_count as usize);
        let mut methods_cur = Cursor::new(data);
        if raw.method_count > 0 {
            methods_cur.set_position(methods_offset as u64 + raw.method_start as u64 * 32);
        }
        for _ in 0..raw.method_count {
            let raw_method = raw::Il2CppMethodDefinition::read(&mut methods_cur)?;
            let name = utils::get_str(data, str_offset + raw_method.name_index as usize)?;
            let mut params = Vec::with_capacity(raw_method.parameter_count as usize);
            let mut params_cur = Cursor::new(data);
            if raw_method.parameter_count > 0 {
                params_cur.set_position(
                    parameters_offset as u64 + raw_method.parameter_start as u64 * 12,
                );
            }
            for _ in 0..raw_method.parameter_count {
                let raw_param = raw::Il2CppParameterDefinition::read(&mut params_cur)?;
                params.push(Parameter {
                    name: utils::get_str(data, str_offset + raw_param.name_index as usize)?,
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
        type_definitions.push(TypeDefinition {
            name,
            namespace,
            methods,
            token: raw.token,
        })
    }

    cur.set_position(images_offset as u64);
    for _ in 0..images_len {
        let raw = raw::Il2CppImageDefinition::read(&mut cur)?;
        let name = utils::get_str(data, str_offset + raw.name_index as usize)?;
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

    Ok(Metadata {
        type_definitions,
        types: metadata_registration.types,
    })
}
