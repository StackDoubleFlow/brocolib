use std::collections::HashMap;
use std::io::Cursor;
use anyhow::{Result, ensure, bail, Context};
use bad64::{Operand, Instruction, DecodeError, Imm, Op, disasm, Reg};
use byteorder::{LittleEndian, ReadBytesExt};
use object::{Object, ObjectSection};
use thiserror::Error;
use crate::Elf;


#[derive(Error, Debug, Clone, Copy)]
#[error("error disassembling code")]
struct DisassembleError;

fn analyze_reg_rel(instructions: &[Result<Instruction, DecodeError>]) -> Result<HashMap<Reg, u64>> {
    let mut map = HashMap::new();
    for ins in instructions {
        let ins = ins.as_ref().map_err(|_| DisassembleError)?;
        match (ins.op(), ins.operands()) {
            (Op::ADRP, [Operand::Reg { reg, .. }, Operand::Label(Imm::Unsigned(imm))]) => {
                map.insert(*reg, *imm);
            }
            (Op::ADD, [Operand::Reg { reg: a, .. }, Operand::Reg { reg: b, .. }, Operand::Imm64 { imm: Imm::Unsigned(imm), .. }]) => {
                ensure!(a == b);
                map.entry(*a).and_modify(|v| *v += imm);
            }
            _ => {}
        }

    }
    Ok(map)
}

/// Returns address to (g_CodeRegistration, g_MetadataRegistration)
pub fn find_registration(elf: Elf) -> Result<(u64, u64)> {
    let init_array = elf.section_by_name(".init_array").context("could not find .init_array section in elf")?;
    let mut init_array_cur = Cursor::new(init_array.data()?);
    for _ in 0..init_array.size() / 8 {
        let init_addr = init_array_cur.read_u64::<LittleEndian>()?;
        let init_code = &elf.data()[init_addr as usize..init_addr as usize + 7 * 4];
        let instructions: Vec<_> = disasm(init_code, init_addr).collect();

        let last_ins = instructions[6].as_ref().map_err(|_| DisassembleError)?;
        if last_ins.op() != Op::B {
            continue;
        }
        if let Ok(regs) = analyze_reg_rel(instructions.as_slice()) {
            let fn_addr = regs[&Reg::X1];
            let code = &elf.data()[fn_addr as usize..fn_addr as usize + 7 * 4];
            let instructions: Vec<_> = disasm(code, fn_addr).collect();
            let regs = analyze_reg_rel(instructions.as_slice())?;
            return Ok((regs[&Reg::X0], regs[&Reg::X1]))
        }
    }
    bail!("codegen registration not found");
}
