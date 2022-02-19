mod binary;
mod raw;

use crate::binary_deserialize::BinaryDeserialize;
use crate::metadata::binary::{CodeRegistration, MetadataRegistration};
use crate::{utils, Elf};
use anyhow::{bail, Context, Result};
use binary::find_registration;
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::Cursor;

#[derive(Debug)]
pub struct MethodIndex(usize);
#[derive(Debug)]
pub struct TypeIndex(usize);
#[derive(Debug)]
pub struct ParamIndex(usize);

pub struct Type {
    data: u64,
    ty: u8,
    by_ref: bool,
}

#[derive(Debug)]
pub struct Method<'a> {
    name: &'a str,
    return_type: TypeIndex,
    param_len: usize,
    param_start: ParamIndex,
    flags: u16,
    token: u32,

    offset: u8,
}

pub struct Field {}

pub struct TypeDefinition {
    pub name: String,
    pub namespace: String,

    pub token: u32,
}

pub struct Metadata<'a> {
    types: Vec<Type>,
    methods: Vec<Method<'a>>,
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
    let methods_len = header[13] as usize / 32;
    let mut methods = Vec::with_capacity(methods_len);
    cur.set_position(methods_offset as u64);
    for _ in 0..methods_len {
        let raw = raw::Il2CppMethodDefinition::read(&mut cur)?;
        let name = utils::get_str(data, str_offset + raw.name_index as usize)?;
        methods.push(Method {
            name,
            return_type: TypeIndex(raw.return_type as usize),
            param_len: raw.parameter_count as usize,
            param_start: ParamIndex(raw.parameter_start as usize),
            flags: raw.flags,
            token: raw.token,
            offset: 0,
        })
    }

    Ok(Metadata {
        methods,
        types: metadata_registration.types,
    })
}
