mod binary;

use byteorder::{LittleEndian, BigEndian, ReadBytesExt};
use std::{io::Cursor, collections::HashMap};
use anyhow::{Result, Context, bail};
use crate::{Elf, metadata::binary::{CodeRegistration, MetadataRegistration}, utils};
use binary::find_registration;

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
    name: Option<&'a str>,
    return_type: TypeIndex,
    param_len: usize,
    param_start: ParamIndex,
    flags: u16,
    token: u32,
    
    offset: u8,
}


pub struct Field {

}

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
    dbg!(&header);
    let str_offset = header[6] as usize;

    let methods_offset = header[12];
    let methods_len = header[13] as usize;
    let mut methods = Vec::with_capacity(methods_len);
    dbg!(methods_offset, methods_len);
    cur.set_position(methods_offset as u64);
    for i in 0..methods_len {
        let mut long_fields = [0; 6];
        for field in &mut long_fields {
            *field = cur.read_u32::<LittleEndian>()?;
        }
        let mut short_fields = [0; 4];
        for field in &mut short_fields {
            *field = cur.read_u16::<LittleEndian>()?;
        }
        dbg!(utils::get_str(data, str_offset + long_fields[0] as usize)?);
        println!("{}: {:8x}", i, long_fields[5] as u32);
        let name = if long_fields[0] as i32 > 0 {
            Some(utils::get_str(data, str_offset + long_fields[0] as usize)?)
        } else {
            None
        };
        methods.push(Method {
            name,
            return_type: TypeIndex(long_fields[2] as usize),
            param_len: short_fields[3] as usize,
            param_start: ParamIndex(long_fields[3] as usize),
            flags: short_fields[0] as u16,
            token: long_fields[5] as u32,
            offset: 0
        })
    }
    dbg!(&methods);

    Ok(Metadata {
        methods,
        types: metadata_registration.types,
    })
}