mod cil;
mod decompiler;
mod metadata;
mod split_before;
mod utils;

use anyhow::{Context, Result};
use decompiler::decompile_fn;
use metadata::Method;
use object::endian::Endianness;
use object::read::elf::ElfFile64;
use object::{Object, ObjectSection};
use std::collections::HashMap;

#[derive(Debug)]
pub struct MethodInfo<'a> {
    metadata: &'a Method<'a>,
    size: u64,
}

type Elf<'a> = ElfFile64<'a, Endianness>;

fn main() -> Result<()> {
    let metadata = std::fs::read("./global-metadata.dat")?;
    let data = std::fs::read("libil2cpp.so").context("Failed to open libil2cpp.so")?;
    let elf = ElfFile64::<Endianness>::parse(data.as_slice())?;

    let metadata = metadata::read(&metadata, &elf)?;

    let mut method_infos = Vec::new();
    let mut offsets = Vec::new();
    for ty in &metadata.type_definitions {
        for method in &ty.methods {
            // println!("{}.{}::{} -> {:016x}", ty.namespace, ty.name, method.name, method.offset);
            if method.offset == 0 {
                continue;
            }
            method_infos.push(MethodInfo {
                metadata: method,
                size: 0,
            });
            offsets.push(method.offset);
        }
    }
    method_infos.sort_by_key(|mi| mi.metadata.offset);
    offsets.sort_unstable();

    let data = std::fs::read("libil2cpp.so").context("Failed to open libil2cpp.so")?;
    let elf = ElfFile64::<Endianness>::parse(data.as_slice())?;
    let section = elf.section_by_name("il2cpp").unwrap();
    let section_start = section.address();
    let section_size = section.size();
    let section_end = section_start + section_size;

    let mut sizes = Vec::new();
    let mut offsets_iter = offsets.iter();
    let mut a = *offsets_iter.next().unwrap();
    loop {
        let b = *offsets_iter.next().unwrap_or(&section_end);
        sizes.push(b - a);
        if b == section_end {
            break;
        }
        a = b;
    }
    for (size, info) in sizes.iter().zip(method_infos.iter_mut()) {
        info.size = *size;
    }

    let methods_map: HashMap<u64, &Method> = offsets
        .iter()
        .cloned()
        .zip(method_infos.iter().map(|mi| mi.metadata))
        .collect();

    // BombCutSoundEffect.Init
    let offset = 18356880;
    let mi = method_infos
        .into_iter()
        .find(|mi| mi.metadata.offset == offset)
        .unwrap();
    let size = mi.size;
    decompile_fn(
        &metadata,
        methods_map,
        mi,
        section.data_range(offset, size)?.unwrap(),
    );

    Ok(())
}
