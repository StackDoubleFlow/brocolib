//! ELF runtime metadata parsing.
//!
//! For IL2CPP Unity games that are built for linux or linux-based platforms,
//! you will find a shared object file named `libil2cpp.so`. This file contains
//! the libil2cpp library, code generated from C#, as well as certain metadata
//! information.
//!
//! To read metadata information from `libil2cpp.so`, see
//! [`RuntimeMetadata::read()`] and [`RuntimeMetadata::read_elf()`].

use super::*;
use crate::global_metadata::{GenericParameterIndex, GlobalMetadata, TypeDefinitionIndex};
use bad64::{disasm, DecodeError, Imm, Instruction, Op, Operand, Reg};
use binread::{BinRead, BinReaderExt};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use object::read::elf::ElfFile64;
use object::{Endianness, Object, ObjectSection, ObjectSegment, ObjectSymbol, RelocationKind, RelocationTarget};
use std::collections::HashMap;
use std::io::{self, Cursor};
use std::str;
use thiserror::Error;

pub type Elf<'data> = ElfFile64<'data, Endianness>;

#[derive(Error, Debug, Clone, Copy)]
#[error("error disassembling code")]
pub struct DisassembleError;

#[derive(Error, Debug)]
pub enum Il2CppBinaryError {
    #[error("error disassembling code")]
    Disassemble(DecodeError),

    #[error("failed to convert virtual address {0:#016x}")]
    VAddrConv(u64),

    #[error("could not find il2cpp_init symbol in elf")]
    MissingIl2CppInit,

    #[error("could not find indirect branch in Runtime::Init")]
    MissingBlr,

    #[error("could not find registration function")]
    MissingRegistration,

    #[error("invalid Il2CppType with type {0}")]
    InvalidType(u8),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    BinaryDeserialize(#[from] binread::Error),

    #[error(transparent)]
    Utf8(#[from] str::Utf8Error),

    #[error(transparent)]
    Elf(#[from] object::Error),
}

type Result<T> = std::result::Result<T, Il2CppBinaryError>;

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
        Some(bss) => bss.address() <= vaddr && vaddr - bss.address() < bss.size(),
        None => false,
    }
}

/// Converts a virtual address in the elf to a file offset
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
    Err(Il2CppBinaryError::VAddrConv(vaddr))
}

fn analyze_reg_rel(elf: &Elf, elf_rel: &[u8], instructions: &[Instruction]) -> HashMap<Reg, u64> {
    let mut map = HashMap::new();
    for ins in instructions {
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
                if a != b {
                    continue;
                }
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
                if a != b {
                    continue;
                }
                map.entry(*a).and_modify(|v| {
                    // TODO: propogate error
                    let offset = vaddr_conv(elf, (*v as i64 + imm) as u64).unwrap();
                    *v = (&elf_rel[offset as usize..offset as usize + 8])
                        .read_u64::<LittleEndian>()
                        .unwrap();
                });
            }
            _ => {}
        }
    }
    map
}

fn try_disassemble(code: &[u8], addr: u64) -> Result<Vec<Instruction>> {
    disasm(code, addr)
        .map(|res| res.map_err(Il2CppBinaryError::Disassemble))
        .collect()
}

fn nth_bl(elf: &Elf, addr: u64, n: usize) -> Result<u64> {
    let offset = vaddr_conv(elf, addr)?;
    let mut count = 0;

    for i in 0.. {
        let offset = offset + i * 4;
        let code = &elf.data()[offset as usize..offset as usize + 4];
        let ins = &try_disassemble(code, addr + i * 4)?[0];
        if let (Op::BL, [Operand::Label(Imm::Unsigned(target))]) = (ins.op(), ins.operands()) {
            count += 1;
            if count == n {
                return Ok(*target);
            }
        }
    }

    unreachable!()
}

/// Finds and returns the address of the first `blr` instruction it comes across starting from `addr`.
fn find_blr(elf: &Elf, addr: u64, limit: usize) -> Result<Option<(u64, Reg)>> {
    let offset = vaddr_conv(elf, addr)?;
    for i in 0..limit {
        let offset = offset + i as u64 * 4;
        let code = &elf.data()[offset as usize..offset as usize + 4];
        let ins = &try_disassemble(code, addr + i as u64 * 4)?[0];
        if let (Op::BLR, [Operand::Reg { reg, .. }]) = (ins.op(), ins.operands()) {
            return Ok(Some((offset, *reg)));
        }
    }
    Ok(None)
}

fn process_relocations(elf: &Elf) -> Result<Vec<u8>> {
    let mut elf_rel = elf.data().to_vec();

    if let Some(relocations) = elf.dynamic_relocations() {
        for (addr, rel) in relocations {
            // R_AARCH64_RELATIVE
            if rel.kind() != RelocationKind::Elf(1027) {
                // TODO: handle more relocation types
                continue;
            }

            assert_eq!(rel.target(), RelocationTarget::Absolute);
            let target = rel.addend() as u64;

            let mut cur = Cursor::new(&mut elf_rel);
            cur.set_position(vaddr_conv(elf, addr)?);
            cur.write_u64::<LittleEndian>(target)?;
        }
    }

    Ok(elf_rel)
}

/// Returns address to (g_CodeRegistration, g_MetadataRegistration)
fn find_registration(elf: &Elf, elf_rel: &[u8]) -> Result<(u64, u64)> {
    let il2cpp_init = elf
        .dynamic_symbols()
        .find(|s| s.name() == Ok("il2cpp_init"))
        .ok_or(Il2CppBinaryError::MissingIl2CppInit)?
        .address();
    let runtime_init = nth_bl(elf, il2cpp_init, 2)?;
    let runtime_init_offset = vaddr_conv(elf, runtime_init)?;

    let (blr_offset, blr_reg) =
        find_blr(elf, runtime_init, 200)?.ok_or(Il2CppBinaryError::MissingBlr)?;

    let instructions = try_disassemble(
        &elf.data()[runtime_init_offset as usize..blr_offset as usize],
        runtime_init,
    )?;
    let regs = analyze_reg_rel(elf, &elf_rel, &instructions);

    let fn_addr = vaddr_conv(elf, regs[&blr_reg])?;
    let code = &elf.data()[fn_addr as usize..fn_addr as usize + 7 * 4];
    let instructions = try_disassemble(code, regs[&blr_reg])?;
    let regs = analyze_reg_rel(elf, &elf_rel, instructions.as_slice());

    Ok((regs[&Reg::X0], regs[&Reg::X1]))
}

struct ElfReader<'elf, 'data, 'elf_rel> {
    elf: &'elf Elf<'data>,
    elf_rel: &'elf_rel [u8],
}

impl<'elf, 'data, 'elf_rel> ElfReader<'elf, 'data, 'elf_rel> {
    fn new(elf: &'elf Elf<'data>, elf_rel: &'elf_rel [u8]) -> Self {
        Self { elf, elf_rel }
    }

    fn make_cur(&self, vaddr: u64) -> Result<Cursor<&[u8]>> {
        let pos = vaddr_conv(self.elf, vaddr)?;
        let mut cur = Cursor::new(self.elf_rel);
        cur.set_position(pos);
        Ok(cur)
    }

    fn get_str(&self, vaddr: u64) -> Result<&'data str> {
        let ptr = vaddr_conv(self.elf, vaddr)?;
        get_str(self.elf.data(), ptr as usize)
    }
}

fn read_arr<T>(reader: &ElfReader, vaddr: u64, len: usize) -> Result<Vec<T>>
where
    T: BinRead,
{
    let mut cur = reader.make_cur(vaddr)?;
    let mut vec = Vec::with_capacity(len);
    for _ in 0..len {
        vec.push(cur.read_le()?);
    }
    Ok(vec)
}

fn read_len_arr<T>(reader: &ElfReader, cur: &mut Cursor<&[u8]>) -> Result<Vec<T>>
where
    T: BinRead,
{
    let count = cur.read_u32::<LittleEndian>()? as usize;
    let _padding = cur.read_u32::<LittleEndian>()?;
    let addr = cur.read_u64::<LittleEndian>()?;
    read_arr(reader, addr, count)
}

fn read_len_arr_nullable<T>(reader: &ElfReader, cur: &mut Cursor<&[u8]>) -> Result<Vec<T>>
where
    T: BinRead + Default + Clone,
{
    let count = cur.read_u32::<LittleEndian>()? as usize;
    let _padding = cur.read_u32::<LittleEndian>()?;
    let addr = cur.read_u64::<LittleEndian>()?;
    if addr_in_bss(reader.elf, addr) {
        Ok(vec![Default::default(); count])
    } else {
        read_arr(reader, addr, count)
    }
}

impl<'data> Il2CppCodeGenModule<'data> {
    fn read<'elf>(reader: &ElfReader<'elf, 'data, '_>, vaddr: u64) -> Result<Self> {
        let mut cur = reader.make_cur(vaddr)?;

        let name = reader.get_str(cur.read_u64::<LittleEndian>()?)?;

        let method_pointers = read_len_arr_nullable(reader, &mut cur)?;
        let adjustor_thunks = read_len_arr(reader, &mut cur)?;

        let addr = cur.read_u64::<LittleEndian>()?;
        let invoker_indices = read_arr(reader, addr, method_pointers.len())?;

        // reverse_pinvoke_wrapper_indices
        let _todo = cur.read_u128::<LittleEndian>()?;

        let rgctx_ranges = read_len_arr(reader, &mut cur)?;
        let rgctxs = read_len_arr(reader, &mut cur)?;
        Ok(Self {
            name,
            method_pointers,
            adjustor_thunks,
            invoker_indices,
            rgctx_ranges,
            rgctxs,
        })
    }
}

impl<'data> Il2CppCodeRegistration<'data> {
    fn read(elf: &Elf<'data>, elf_rel: &[u8], addr: u64) -> Result<Self> {
        let reader = ElfReader::new(elf, elf_rel);
        let mut cur = reader.make_cur(addr)?;

        let reverse_pinvoke_wrappers = read_len_arr(&reader, &mut cur)?;

        let generic_method_pointers = read_len_arr(&reader, &mut cur)?;
        let addr = cur.read_u64::<LittleEndian>()?;
        let generic_adjustor_thunks = read_arr(&reader, addr, generic_method_pointers.len())?;

        let invoker_pointers = read_len_arr(&reader, &mut cur)?;
        // unresolvedIndirectCallCount
        // unresolvedVirtualCallPointers
        let unresolved_virtual_call_pointers: Vec<u64> = read_len_arr(&reader, &mut cur)?;
        let _unresolved_instance_call_pointers = cur.read_u64::<LittleEndian>()?;
        let _unresolved_static_call_pointers = cur.read_u64::<LittleEndian>()?;

        // interopDataCount
        // interopData
        let _interop_data: Vec<u64> = read_len_arr(&reader, &mut cur)?;

        // windowsRuntimeFactoryCount
        // windowsRuntimeFactoryTable
        let _windows_runtime_factory_table: Vec<u64> = read_len_arr(&reader, &mut cur)?;

        let module_addrs = read_len_arr(&reader, &mut cur)?;
        let mut code_gen_modules = Vec::with_capacity(module_addrs.len());
        for addr in module_addrs {
            code_gen_modules.push(Il2CppCodeGenModule::read(&reader, addr)?);
        }

        Ok(Self {
            reverse_pinvoke_wrappers,
            generic_method_pointers,
            generic_adjustor_thunks,
            invoker_pointers,
            unresolved_indirect_call_pointers: unresolved_virtual_call_pointers,
            code_gen_modules,
        })
    }
}

impl Il2CppType {
    fn read(
        reader: &ElfReader,
        vaddr: u64,
        type_map: &HashMap<u64, usize>,
        generic_class_map: &HashMap<u64, usize>,
        array_types: &mut Vec<Il2CppArrayType>,
        array_type_map: &mut HashMap<u64, usize>,
    ) -> Result<Il2CppType> {
        let mut cur = reader.make_cur(vaddr)?;

        let raw_data = cur.read_u64::<LittleEndian>()?;
        let attrs = cur.read_u16::<LittleEndian>()?;
        let ty_id = cur.read_u8()?;
        let ty = Il2CppTypeEnum::from_ty(ty_id).ok_or(Il2CppBinaryError::InvalidType(ty_id))?;
        let bitfield = cur.read_u8()?;

        let data = match ty {
            Il2CppTypeEnum::Var | Il2CppTypeEnum::Mvar => TypeData::GenericParameterIndex(GenericParameterIndex::new(raw_data as u32)),
            Il2CppTypeEnum::Ptr | Il2CppTypeEnum::Szarray => TypeData::TypeIndex(type_map[&raw_data]),
            Il2CppTypeEnum::Array => TypeData::ArrayType({
                match array_type_map.get(&raw_data) {
                    Some(idx) => *idx,
                    None => {
                        let idx = array_types.len();
                        array_types.push(Il2CppArrayType::read(reader, raw_data, type_map)?);
                        array_type_map.insert(raw_data, idx);
                        idx
                    }
                }
            }),
            Il2CppTypeEnum::Genericinst => TypeData::GenericClassIndex(generic_class_map[&raw_data]),
            _ => TypeData::TypeDefinitionIndex(TypeDefinitionIndex::new(raw_data as u32)),
        };
        let byref = (bitfield >> 5) != 0;
        let pinned = (bitfield >> 6) != 0;
        let valuetype = (bitfield >> 7) != 0;

        Ok(Il2CppType {
            data,
            attrs,
            ty,
            byref,
            pinned,
            valuetype,
        })
    }
}

impl Il2CppGenericClass {
    fn read(
        reader: &ElfReader,
        vaddr: u64,
        generic_inst_map: &HashMap<u64, usize>,
        type_map: &HashMap<u64, usize>,
    ) -> Result<Self> {
        let mut cur = reader.make_cur(vaddr)?;

        let type_ptr = cur.read_u64::<LittleEndian>()?;
        let type_index = type_map[&type_ptr];

        let context = Il2CppGenericContext::read(&mut cur, generic_inst_map)?;
        Ok(Self {
            type_index,
            context,
        })
    }
}

impl Il2CppGenericContext {
    fn read(cur: &mut Cursor<&[u8]>, generic_inst_map: &HashMap<u64, usize>) -> Result<Self> {
        Ok(Self {
            class_inst_idx: generic_inst_map
                .get(&cur.read_u64::<LittleEndian>()?)
                .copied(),
            method_inst_idx: generic_inst_map
                .get(&cur.read_u64::<LittleEndian>()?)
                .copied(),
        })
    }
}

impl Il2CppGenericInst {
    fn read(reader: &ElfReader, vaddr: u64, types_map: &HashMap<u64, usize>) -> Result<Self> {
        let mut cur = reader.make_cur(vaddr)?;

        let type_ptrs = read_len_arr(reader, &mut cur)?;
        let mut types = Vec::with_capacity(type_ptrs.len());
        for addr in type_ptrs {
            types.push(types_map[&addr]);
        }
        Ok(Self { types })
    }
}

impl Il2CppArrayType {
    fn read(reader: &ElfReader, vaddr: u64, types_map: &HashMap<u64, usize>) -> Result<Self> {
        let mut cur = reader.make_cur(vaddr)?;

        let elem_ty_ptr = cur.read_u64::<LittleEndian>()?;
        let elem_ty = types_map[&elem_ty_ptr];

        let rank = cur.read_u8()?;
        let num_sizes = cur.read_u8()?;
        let num_lobounds = cur.read_u8()?;

        let _padding = cur.read_u32::<LittleEndian>()?;
        let _padding = cur.read_u8()?;

        let sizes_ptr = cur.read_u64::<LittleEndian>()?;
        let sizes = read_arr(reader, sizes_ptr, num_sizes as usize)?;

        let lobounds_ptr = cur.read_u64::<LittleEndian>()?;
        let lower_bounds = read_arr(reader, lobounds_ptr, num_lobounds as usize)?;

        Ok(Self { elem_ty, rank, sizes, lower_bounds })
    }
}

impl Il2CppMetadataRegistration {
    fn read(elf: &Elf, elf_rel: &[u8], addr: u64, metadata: &GlobalMetadata) -> Result<Self> {
        let reader = ElfReader::new(elf, elf_rel);
        let mut cur = reader.make_cur(addr)?;

        let generic_class_addrs = read_len_arr(&reader, &mut cur)?;
        let generic_inst_addrs = read_len_arr(&reader, &mut cur)?;
        let generic_method_table = read_len_arr(&reader, &mut cur)?;
        let type_addrs = read_len_arr(&reader, &mut cur)?;
        let method_specs = read_len_arr(&reader, &mut cur)?;
        let field_offset_ptrs = read_len_arr(&reader, &mut cur)?;
        let type_definition_sizes_ptrs = read_len_arr(&reader, &mut cur)?;

        let mut generic_inst_map = HashMap::new();
        for (i, &addr) in generic_inst_addrs.iter().enumerate() {
            generic_inst_map.insert(addr, i);
        }

        let mut type_map = HashMap::new();
        for (i, &addr) in type_addrs.iter().enumerate() {
            type_map.insert(addr, i);
        }

        let mut generic_classes = Vec::with_capacity(type_addrs.len());
        let mut generic_class_map = HashMap::new();
        for (i, addr) in generic_class_addrs.into_iter().enumerate() {
            generic_classes.push(Il2CppGenericClass::read(&reader, addr, &generic_inst_map, &type_map)?);
            generic_class_map.insert(addr, i);
        }

        let mut types = Vec::with_capacity(type_addrs.len());
        let mut array_types = Vec::new();
        let mut array_type_map = HashMap::new();
        for addr in type_addrs {
            types.push(Il2CppType::read(&reader, addr, &type_map, &generic_class_map, &mut array_types, &mut array_type_map)?);
        }

        let mut generic_insts = Vec::with_capacity(generic_inst_addrs.len());
        for addr in generic_inst_addrs {
            generic_insts.push(Il2CppGenericInst::read(&reader, addr, &type_map)?);
        }

        let mut type_definition_sizes = Vec::with_capacity(type_definition_sizes_ptrs.len());
        for addr in type_definition_sizes_ptrs {
            let mut cur = reader.make_cur(addr)?;
            type_definition_sizes.push(cur.read_le()?);
        }

        let mut field_offsets = Vec::with_capacity(field_offset_ptrs.len());
        for (i, addr) in field_offset_ptrs.into_iter().enumerate() {
            if addr == 0 {
                field_offsets.push(Vec::new());
                continue;
            }
            let mut cur = reader.make_cur(addr)?;

            let type_def_idx = TypeDefinitionIndex::new(i as u32);
            let arr_len = metadata.type_definitions[type_def_idx].field_count as usize;
            let mut arr = Vec::with_capacity(arr_len);
            for _ in 0..arr_len {
                arr.push(cur.read_u32::<LittleEndian>()?);
            }
            field_offsets.push(arr);
        }

        Ok(Il2CppMetadataRegistration {
            generic_classes,
            generic_insts,
            generic_method_table,
            types,
            array_types,
            method_specs,
            field_offsets: Some(field_offsets),
            type_definition_sizes: Some(type_definition_sizes),
        })
    }
}

impl<'data> RuntimeMetadata<'data> {
    /// Read runtime metadata information from an [`Elf`].
    pub fn read(elf: &Elf<'data>, global_metadata: &GlobalMetadata) -> Result<Self> {
        let elf_rel = process_relocations(elf)?;

        let (cr_addr, mr_addr) = find_registration(elf, &elf_rel)?;
        let code_registration = Il2CppCodeRegistration::read(elf, &elf_rel, cr_addr)?;
        let metadata_registration = Il2CppMetadataRegistration::read(elf, &elf_rel, mr_addr, global_metadata)?;
        Ok(RuntimeMetadata {
            code_registration,
            metadata_registration,
        })
    }

    /// Read runtime metadata information from raw ELF data.
    pub fn read_elf(elf_data: &'data [u8], global_metadata: &GlobalMetadata) -> Result<Self> {
        let elf = Elf::parse(elf_data)?;
        Self::read(&elf, global_metadata)
    }
}
