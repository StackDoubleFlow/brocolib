use anyhow::{bail, ensure, Context, Result};
use bad64::{disasm, DecodeError, Imm, Instruction, Op, Operand, Reg};
use byteorder::{LittleEndian, ReadBytesExt};
use object::read::elf::ElfFile64;
use object::{Endianness, Object, ObjectSection, ObjectSegment};
use std::collections::HashMap;
use std::io::Cursor;
use std::str;
use thiserror::Error;

type Elf<'a> = ElfFile64<'a, Endianness>;

#[derive(Error, Debug, Clone, Copy)]
#[error("error disassembling code")]
pub struct DisassembleError;

#[derive(Debug)]
pub struct Type {
    pub data: u64,
    pub ty: u8,
    pub by_ref: bool,
}

pub fn strlen(data: &[u8], offset: usize) -> usize {
    let mut len = 0;
    while data[offset + len] != 0 {
        len += 1;
    }
    len
}

pub fn get_str(data: &[u8], offset: usize) -> Result<&str> {
    let len = strlen(data, offset);
    let str = str::from_utf8(&data[offset..offset + len])?;
    Ok(str)
}

pub fn vaddr_conv(elf: &Elf, vaddr: u64) -> Result<u64> {
    for segment in elf.segments() {
        if segment.address() <= vaddr {
            let offset = vaddr - segment.address();
            if offset < segment.size() {
                // println!("{:08x} -> {:08x}", vaddr, segment.file_range().0 + offset);
                return Ok(segment.file_range().0 + offset);
            }
        }
    }
    bail!("Failed to convert virtual address {:016x}", vaddr);
}

fn analyze_reg_rel(
    elf: &Elf,
    instructions: &[Result<Instruction, DecodeError>],
) -> Result<HashMap<Reg, u64>> {
    let mut map = HashMap::new();
    for ins in instructions {
        let ins = ins.as_ref().map_err(|_| DisassembleError)?;
        match (ins.op(), ins.operands()) {
            (Op::ADRP, [Operand::Reg { reg, .. }, Operand::Label(Imm::Unsigned(imm))]) => {
                map.insert(*reg, *imm);
            }
            (
                Op::ADD,
                [Operand::Reg { reg: a, .. }, Operand::Reg { reg: b, .. }, Operand::Imm64 {
                    imm: Imm::Unsigned(imm),
                    ..
                }],
            ) => {
                ensure!(a == b);
                map.entry(*a).and_modify(|v| *v += imm);
            }
            (
                Op::LDR,
                [Operand::Reg { reg: a, .. }, Operand::MemOffset {
                    reg: b,
                    offset: Imm::Signed(imm),
                    ..
                }],
            ) => {
                ensure!(a == b);
                map.entry(*a).and_modify(|v| {
                    // TODO: propogate error
                    let ptr = vaddr_conv(elf, (*v as i64 + imm) as u64).unwrap();
                    *v = (&elf.data()[ptr as usize..ptr as usize + 8])
                        .read_u64::<LittleEndian>()
                        .unwrap();
                });
            }
            _ => {}
        }
    }
    Ok(map)
}

/// Returns address to (g_CodeRegistration, g_MetadataRegistration)
pub fn find_registration(elf: &Elf) -> Result<(u64, u64)> {
    let init_array = elf
        .section_by_name(".init_array")
        .context("could not find .init_array section in elf")?;
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
            return Ok((regs[&Reg::X0], regs[&Reg::X1]));
        }
    }
    bail!("codegen registration not found");
}

pub struct CodeGenModule<'a> {
    pub name: &'a str,
    pub method_pointers: Vec<u64>,
}

pub struct CodeRegistration<'a> {
    pub modules: Vec<CodeGenModule<'a>>,
}

impl<'a> CodeRegistration<'a> {
    pub fn read(elf: &'a Elf, addr: u64) -> Result<Self> {
        let mut cur = Cursor::new(elf.data());
        let addr = vaddr_conv(elf, addr)?;
        cur.set_position(addr + 8 * 15);
        let modules_len = cur.read_u64::<LittleEndian>()?;
        let modules_addr = cur.read_u64::<LittleEndian>()?;

        cur.set_position(vaddr_conv(elf, modules_addr)?);
        let module_addrs: Vec<_> = (0..modules_len)
            .map(|_| cur.read_u64::<LittleEndian>())
            .collect();
        let mut modules = Vec::with_capacity(modules_len as usize);
        for module_addr in module_addrs {
            cur.set_position(vaddr_conv(elf, module_addr?)?);
            let name_ptr = vaddr_conv(elf, cur.read_u64::<LittleEndian>()?)?;
            let name = get_str(elf.data(), name_ptr as usize)?;

            let method_ptrs_len = cur.read_u64::<LittleEndian>()?;
            let method_ptrs_ptr = vaddr_conv(elf, cur.read_u64::<LittleEndian>()?)?;
            let mut method_pointers = Vec::with_capacity(method_ptrs_len as usize);
            cur.set_position(method_ptrs_ptr);
            for _ in 0..method_ptrs_len {
                method_pointers.push(vaddr_conv(elf, cur.read_u64::<LittleEndian>()?)?);
            }

            modules.push(CodeGenModule {
                name,
                method_pointers,
            });
        }

        Ok(Self { modules })
    }
}

pub struct MetadataRegistration {
    pub types: Vec<Type>,
    pub field_offset_addrs: Vec<u64>,
}

impl MetadataRegistration {
    pub fn read(elf: &Elf, addr: u64) -> Result<Self> {
        let mut cur = Cursor::new(elf.data());
        let addr = vaddr_conv(elf, addr)?;
        cur.set_position(addr + 8 * 6);
        let types_len = cur.read_u64::<LittleEndian>()?;
        let types_addr = cur.read_u64::<LittleEndian>()?;

        cur.set_position(vaddr_conv(elf, types_addr)?);
        let type_addrs: Vec<_> = (0..types_len)
            .map(|_| cur.read_u64::<LittleEndian>())
            .collect();
        let mut types = Vec::with_capacity(types_len as usize);
        for type_addr in type_addrs {
            cur.set_position(vaddr_conv(elf, type_addr?)?);
            let data = cur.read_u64::<LittleEndian>()?;
            let _attrs = cur.read_u16::<LittleEndian>()?;
            let ty = cur.read_u8()?;
            let bitfield = cur.read_u8()?;
            let by_ref = (bitfield >> 7) != 0;
            types.push(Type { data, ty, by_ref })
        }

        cur.set_position(addr + 8 * 10);
        let offsets_len = cur.read_u64::<LittleEndian>()?;
        let offsets_addr = cur.read_u64::<LittleEndian>()?;
        cur.set_position(vaddr_conv(elf, offsets_addr)?);
        let field_offset_addrs = (0..offsets_len)
            .map(|_| cur.read_u64::<LittleEndian>())
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(Self {
            types,
            field_offset_addrs,
        })
    }
}
