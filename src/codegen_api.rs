use anyhow::{bail, Result};
use bad64::{decode, Imm, Op, Operand};
use byteorder::{ReadBytesExt, LE};
use std::collections::HashMap;

use crate::metadata::Metadata;
use crate::{DisassembleError, Elf, MethodInfo};

fn find_raise_nri(
    elf: &Elf,
    metadata: &Metadata,
    methods: &HashMap<u64, &MethodInfo>,
) -> Result<u64> {
    let string = metadata.type_map[&("System", "String")];
    let string_eq = metadata[string]
        .methods
        .iter()
        .find(|method| method.name == "Equals")
        .expect("System.String.Equals not found");
    let size = methods[&string_eq.offset].size;

    let end = string_eq.offset + size;
    let mut ins_data = &elf.data()[end as usize - 4..end as usize];
    let ins = decode(ins_data.read_u32::<LE>()?, end - 4).map_err(|_| DisassembleError)?;
    match (ins.op(), ins.operands()[0]) {
        (Op::BL, Operand::Label(Imm::Unsigned(imm))) => Ok(imm),
        _ => bail!("Unexpected instruction when searching for find_raise_nri"),
    }
}

pub struct CodegenAddrs {
    pub raise_nri: u64,
}

impl CodegenAddrs {
    pub fn find(
        elf: &Elf,
        metadata: &Metadata,
        methods: &HashMap<u64, &MethodInfo>,
    ) -> Result<Self> {
        Ok(Self {
            raise_nri: find_raise_nri(elf, metadata, methods)?,
        })
    }
}
