use std::collections::HashMap;
use std::io::Cursor;
use anyhow::{Result, ensure, bail, Context};
use bad64::{Operand, Instruction, DecodeError, Imm, Op, disasm, Reg};
use byteorder::{LittleEndian, ReadBytesExt};
use object::{Object, ObjectSection};
use thiserror::Error;
use std::str;
use crate::{utils, Elf};

use super::Type;


#[derive(Error, Debug, Clone, Copy)]
#[error("error disassembling code")]
struct DisassembleError;

fn analyze_reg_rel(elf: &Elf, instructions: &[Result<Instruction, DecodeError>]) -> Result<HashMap<Reg, u64>> {
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
            (Op::LDR, [Operand::Reg { reg: a, .. }, Operand::MemOffset { reg: b, offset: Imm::Signed(imm), .. }]) => {
                ensure!(a == b);
                map.entry(*a).and_modify(|v| {
                    let ptr = utils::vaddr_conv(elf, (*v as i64 + imm) as u64);
                    // TODO: propogate error
                    *v = (&elf.data()[ptr as usize..ptr as usize + 8]).read_u64::<LittleEndian>().unwrap(); 
                });
            }
            _ => {}
        }

    }
    Ok(map)
}

/// Returns address to (g_CodeRegistration, g_MetadataRegistration)
pub fn find_registration(elf: &Elf) -> Result<(u64, u64)> {
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
        if let Ok(regs) = analyze_reg_rel(elf, instructions.as_slice()) {
            let fn_addr = regs[&Reg::X1];
            let code = &elf.data()[fn_addr as usize..fn_addr as usize + 7 * 4];
            let instructions: Vec<_> = disasm(code, fn_addr).collect();
            let regs = analyze_reg_rel(elf, instructions.as_slice())?;
            return Ok((regs[&Reg::X0], regs[&Reg::X1]))
        }
    }
    bail!("codegen registration not found");
}

struct CodeGenModule<'a> {
    name: &'a str,
    method_pointers: Vec<u64>,
}

pub struct CodeRegistration<'a> {
    modules: Vec<CodeGenModule<'a>>,
}

impl<'a> CodeRegistration<'a> {
    pub fn read(elf: &'a Elf, addr: u64) -> Result<Self> {
        let mut cur = Cursor::new(elf.data());
        let addr = utils::vaddr_conv(elf, addr);
        cur.set_position(addr + 8 * 15);
        let modules_len = cur.read_u64::<LittleEndian>()?;
        let modules_addr = cur.read_u64::<LittleEndian>()?;

        cur.set_position(utils::vaddr_conv(elf, modules_addr));
        let module_addrs: Vec<_> = (0..modules_len).map(|_| cur.read_u64::<LittleEndian>()).collect();
        let mut modules = Vec::with_capacity(modules_len as usize);
        for module_addr in module_addrs {
            cur.set_position(utils::vaddr_conv(elf, module_addr?));
            let name_ptr = utils::vaddr_conv(elf, cur.read_u64::<LittleEndian>()?);
            let name = utils::get_str(elf.data(), name_ptr as usize)?;

            let method_ptrs_len = cur.read_u64::<LittleEndian>()?;
            let method_ptrs_ptr = utils::vaddr_conv(elf, cur.read_u64::<LittleEndian>()?);
            let mut method_pointers = Vec::with_capacity(method_ptrs_len as usize);
            cur.set_position(method_ptrs_ptr);
            for _ in 0..method_ptrs_len {
                method_pointers.push(utils::vaddr_conv(elf, cur.read_u64::<LittleEndian>()?));
            }

            modules.push(CodeGenModule {
                name,
                method_pointers
            });
        }

        Ok(Self {
            modules
        })
    }
}

pub struct MetadataRegistration {
    pub types: Vec<Type>,
}

impl MetadataRegistration {
    pub fn read(elf: &Elf, addr: u64) -> Result<Self> {
        let mut cur = Cursor::new(elf.data());
        let addr = utils::vaddr_conv(elf, addr);
        cur.set_position(addr + 8 * 6);
        let types_len = cur.read_u64::<LittleEndian>()?;
        let types_addr = cur.read_u64::<LittleEndian>()?;

        cur.set_position(utils::vaddr_conv(elf, types_addr));
        let type_addrs: Vec<_> = (0..types_len).map(|_| cur.read_u64::<LittleEndian>()).collect();
        let mut types = Vec::with_capacity(types_len as usize);
        for type_addr in type_addrs {
            cur.set_position(utils::vaddr_conv(elf, type_addr?));
            let data = cur.read_u64::<LittleEndian>()?;
            let _attrs = cur.read_u16::<LittleEndian>()?;
            let ty = cur.read_u8()?;
            let bitfield = cur.read_u8()?;
            let by_ref = (bitfield >> 7) != 0;
            types.push(Type { data, ty, by_ref })
        }

        Ok(Self {
            types,
        })
    }
}
