use anyhow::{bail, ensure, Context, Result};
use bad64::{disasm, DecodeError, Imm, Instruction, Op, Operand, Reg};
use binread::{BinRead, BinReaderExt};
use byteorder::{LittleEndian, ReadBytesExt};
use object::read::elf::ElfFile64;
use object::{Endianness, Object, ObjectSection, ObjectSegment};
use std::collections::HashMap;
use std::io::Cursor;
use std::str;
use thiserror::Error;

pub type Elf<'a> = ElfFile64<'a, Endianness>;

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

pub fn addr_in_bss(elf: &Elf, vaddr: u64) -> bool {
    match elf.section_by_name(".bss") {
        Some(bss) => {
            bss.address() <= vaddr && vaddr - bss.address() < bss.size()
        }
        None => false,
    }
    
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

struct ElfReader<'a> {
    elf: &'a Elf<'a>,
}

impl<'a> ElfReader<'a> {
    fn new(elf: &'a Elf) -> Self {
        Self { elf }
    }

    fn make_cur(&self, vaddr: u64) -> Result<Cursor<&[u8]>> {
        let pos = vaddr_conv(self.elf, vaddr)?;
        let mut cur = Cursor::new(self.elf.data());
        cur.set_position(pos);
        Ok(cur)
    }

    fn get_str(&self, vaddr: u64) -> Result<&'a str> {
        let ptr = vaddr_conv(self.elf, vaddr)?;
        get_str(self.elf.data(), ptr as usize)
    }
}

#[derive(BinRead)]
pub struct TokenAdjustorThunkPair {
    pub token: u32,
    #[br(align_before = 8)]
    pub adjustor_thunk: u64,
}

#[derive(BinRead)]
pub struct Range {
    pub start: u32,
    pub length: u32,
}

#[derive(BinRead)]
pub struct TokenRangePair {
    pub token: u32,
    pub range: Range,
}

#[derive(BinRead)]
#[br(repr = u32)]
pub enum RGCTXDataType {
    Invalid,
    Type,
    Class,
    Method,
    Array
}

#[derive(BinRead)]
pub struct RGCTXDefinition {
    pub ty: RGCTXDataType,
    /// Can be either a method or type index
    pub data: u32
}

fn read_arr<T>(reader: &ElfReader, vaddr: u64, len: usize) -> Result<Vec<T>> where T: BinRead {
    let mut cur = reader.make_cur(vaddr)?;
    let mut vec = Vec::with_capacity(len as usize);
    for _ in 0..len {
        vec.push(cur.read_le()?);
    }
    Ok(vec)
}

fn read_len_arr<T>(reader: &ElfReader, cur: &mut Cursor<&[u8]>) -> Result<Vec<T>> where T: BinRead {
    let count = cur.read_u32::<LittleEndian>()? as usize;
    let _padding = cur.read_u32::<LittleEndian>()?;
    let addr = cur.read_u64::<LittleEndian>()?;
    read_arr(&reader, addr, count)
}

fn read_len_arr_nullable<T>(reader: &ElfReader, cur: &mut Cursor<&[u8]>) -> Result<Vec<T>> where T: BinRead + Default + Clone {
    let count = cur.read_u32::<LittleEndian>()? as usize;
    let _padding = cur.read_u32::<LittleEndian>()?;
    let addr = cur.read_u64::<LittleEndian>()?;
    if addr_in_bss(reader.elf, addr) {
        Ok(vec![Default::default(); count])
    } else {
        read_arr(&reader, addr, count)
    }
}

pub struct CodeGenModule<'a> {
    pub name: &'a str,
    pub method_pointers: Vec<u64>,
    pub adjustor_thunks: Vec<TokenAdjustorThunkPair>,
    pub invoker_indices: Vec<u32>,

    // TODO:
    // reverse_pinvoke_wrapper_indicies: Vec<TokenIndexMethodTuple>,

    pub rgctx_ranges: Vec<TokenRangePair>,
    pub rgctxs: Vec<RGCTXDefinition>,

    // TODO:
    // debugger_metadata: DebuggerMetadataRegistration
}

impl<'a> CodeGenModule<'a> {
    fn read(reader: &ElfReader<'a>, vaddr: u64) -> Result<Self> {
        let mut cur = reader.make_cur(vaddr)?;

        let name = reader.get_str(cur.read_u64::<LittleEndian>()?)?;

        let method_pointers = read_len_arr_nullable(reader, &mut cur)?;
        let adjustor_thunks = read_len_arr(reader, &mut cur)?;

        let addr = cur.read_u64::<LittleEndian>()?;
        let invoker_indices = read_arr(reader, addr, method_pointers.len())?;

        let _todo = cur.read_u128::<LittleEndian>()?;

        let rgctx_ranges = read_len_arr(reader, &mut cur)?;
        let rgctxs = read_len_arr(reader, &mut cur)?;
        Ok(Self {
            name,
            method_pointers,
            adjustor_thunks,
            invoker_indices,
            rgctx_ranges,
            rgctxs
        })
    }
}

pub struct CodeRegistration<'a> {
    pub reverse_pinvoke_wrappers: Vec<u64>,
    pub generic_method_pointers: Vec<u64>,
    pub generic_adjustor_thunks: Vec<u64>,
    pub invoker_pointers: Vec<u64>,
    pub custom_attribute_generators: Vec<u64>,
    pub unresolved_virtual_call_pointers: Vec<u64>,

    // TODO
    // pub interop_data: Vec<InteropData>,
    // pub windows_runtime_factory_table: Vec<WindowsRuntimeFactoryTableEntry>,

    pub code_gen_modules: Vec<CodeGenModule<'a>>,
}

impl<'a> CodeRegistration<'a> {
    pub fn read(elf: &'a Elf, addr: u64) -> Result<Self> {
        let reader = ElfReader::new(elf);
        let mut cur = reader.make_cur(addr)?;

        let reverse_pinvoke_wrappers = read_len_arr(&reader, &mut cur)?;

        let generic_method_pointers = read_len_arr(&reader, &mut cur)?;
        let addr = cur.read_u64::<LittleEndian>()?;
        let generic_adjustor_thunks = read_arr(&reader, addr, generic_method_pointers.len())?;

        let invoker_pointers = read_len_arr(&reader, &mut cur)?;
        let custom_attribute_generators = read_len_arr(&reader, &mut cur)?;
        let unresolved_virtual_call_pointers= read_len_arr(&reader, &mut cur)?;

        let _todo = cur.read_u128::<LittleEndian>()?;
        let _todo = cur.read_u128::<LittleEndian>()?;

        let module_addrs = read_len_arr(&reader, &mut cur)?;
        let mut code_gen_modules = Vec::with_capacity(module_addrs.len());
        for addr in module_addrs {
            code_gen_modules.push(CodeGenModule::read(&reader, addr)?);
        }

        Ok(Self {
            reverse_pinvoke_wrappers,
            generic_method_pointers,
            generic_adjustor_thunks,
            invoker_pointers,
            custom_attribute_generators,
            unresolved_virtual_call_pointers,
            code_gen_modules
        })
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
