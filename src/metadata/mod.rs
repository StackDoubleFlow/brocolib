mod binary;

use byteorder::{LittleEndian, BigEndian, ReadBytesExt};
use std::{io::Cursor, collections::HashMap};
use anyhow::{Result, Context, bail};
use crate::Elf;
use binary::find_registration;

pub struct MethodIndex(usize);
pub struct TypeIndex(usize);

pub struct Type {
    data: u64,
    by_ref: bool,
}

pub struct Method {

}


pub struct Field {

}

pub struct TypeDefinition {
    pub name: String,
    pub namespace: String,

    pub token: u32,
}



pub struct Metadata {

}



pub fn read(data: &[u8], elf: Elf) -> Result<Metadata> {
    let (code_registration, metadata_registration) = find_registration(elf)?;

    let mut cur = Cursor::new(data);
    let mut header = [0; 66];
    for h in &mut header {
        *h = cur.read_u32::<LittleEndian>()?;
    }
    assert!(header[0] == 0xFAB11BAF, "metadata sanity check failed");
    assert!(header[1] == 24, "only il2cpp version 24 is supported");


    Ok(Metadata {

    })
}