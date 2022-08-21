use anyhow::{bail, ensure, Context, Result};
use bad64::{disasm, DecodeError, Imm, Instruction, Op, Operand, Reg};
use binread::{BinRead, BinReaderExt};
use byteorder::{LittleEndian, ReadBytesExt};
use il2cpp_metadata_raw::Metadata;
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
fn find_registration(elf: &Elf) -> Result<(u64, u64)> {
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
    // reverse_pinvoke_wrapper_indices: Vec<TokenIndexMethodTuple>,

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
    fn read(elf: &'a Elf, addr: u64) -> Result<Self> {
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

#[derive(Clone, Copy, Debug)]
pub enum TypeEnum {
    Void,
    Boolean,
    Char,
    I1,
    U1,
    I2,
    U2,
    I4,
    U4,
    I8,
    U8,
    R4,
    R8,
    String,
    Ptr,
    Valuetype,
    Class,
    Var,
    Array,
    Genericinst,
    Typedbyref,
    I,
    U,
    Object,
    Szarray,
    Mvar,
}

impl TypeEnum {
    fn from_ty(ty: u8) -> Result<Self> {
        Ok(match ty {
            0x01 => TypeEnum::Void,
            0x02 => TypeEnum::Boolean,
            0x03 => TypeEnum::Char,
            0x04 => TypeEnum::I1,
            0x05 => TypeEnum::U1,
            0x06 => TypeEnum::I2,
            0x07 => TypeEnum::U2,
            0x08 => TypeEnum::I4,
            0x09 => TypeEnum::U4,
            0x0a => TypeEnum::I8,
            0x0b => TypeEnum::U8,
            0x0c => TypeEnum::R4,
            0x0d => TypeEnum::R8,
            0x0e => TypeEnum::String,
            0x0f => TypeEnum::Ptr,
            0x11 => TypeEnum::Valuetype,
            0x12 => TypeEnum::Class,
            0x13 => TypeEnum::Var,
            0x14 => TypeEnum::Array,
            0x15 => TypeEnum::Genericinst,
            0x16 => TypeEnum::Typedbyref,
            0x18 => TypeEnum::I,
            0x19 => TypeEnum::U,
            0x1c => TypeEnum::Object,
            0x1d => TypeEnum::Szarray,
            0x1e => TypeEnum::Mvar,
            _ => bail!("unknown Il2CppType type {}", ty)
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum TypeData {
    TypeDefinitionIndex(u32),
    /// For TypeEnum::Ptr and TypeEnum::Szarray
    TypeIndex(usize),
    /// For TypeEnum::Var and TypeEnum::Mvar
    GenericParameterIndex(u32),
    /// For TypeEnum::Genericinst
    GenericClassIndex(usize),
    // TODO
    /// FOr TypeEnum::Array
    ArrayType
}

#[derive(Clone, Copy, Debug)]
pub struct Type {
    pub data: TypeData,
    pub attrs: u16,
    pub ty: TypeEnum,
    pub byref: bool,
    pub pinned: bool,
}

impl Type {
    fn read(reader: &ElfReader, vaddr: u64, type_map: &HashMap<u64, usize>, generic_class_map: &HashMap<u64, usize>) -> Result<Type> {
        let mut cur = reader.make_cur(vaddr)?;
        
        let raw_data = cur.read_u64::<LittleEndian>()?;
        let attrs = cur.read_u16::<LittleEndian>()?;
        let ty = TypeEnum::from_ty(cur.read_u8()?)?;
        let bitfield = cur.read_u8()?;

        let data = match ty {
            TypeEnum::Var | TypeEnum::Mvar => TypeData::GenericParameterIndex(raw_data as u32),
            TypeEnum::Ptr | TypeEnum::Szarray => TypeData::TypeIndex(type_map[&raw_data]),
            TypeEnum::Array => TypeData::ArrayType,
            TypeEnum::Genericinst => TypeData::GenericClassIndex(generic_class_map[&raw_data]),
            _ => TypeData::TypeDefinitionIndex(raw_data as u32)
        };
        let byref = (bitfield >> 6) != 0;
        let pinned = (bitfield >> 7) != 0;
        
        Ok(Type {
            data,
            attrs,
            ty,
            byref,
            pinned,
        })
    }
}

pub struct GenericClass {
    pub type_definition_index: u32,
    pub context: GenericContext,
}

impl GenericClass {
    fn read(reader: &ElfReader, vaddr: u64, generic_inst_map: &HashMap<u64, usize>) -> Result<Self> {
        let mut cur = reader.make_cur(vaddr)?;

        let type_definition_index = cur.read_u32::<LittleEndian>()?;
        let _padding = cur.read_u32::<LittleEndian>()?;
        
        let context = cur.read_le()?;
        let context = GenericContext::read(&mut cur, generic_inst_map)?;
        Ok(Self {
            type_definition_index,
            context
        })
    }
}

pub struct GenericContext {
    /// Indices into MetadataRegistration generic_insts field
    pub class_inst_idx: Option<usize>,
    /// Indices into MetadataRegistration generic_insts field
    pub method_inst_idx: Option<usize>,
}

#[derive(BinRead)]
pub struct MethodSpec {
    pub method_definition_index: u32,
    /// Indices into MetadataRegistration generic_insts field
    pub class_inst_index: u32,
    /// Indices into MetadataRegistration generic_insts field
    pub method_inst_index: u32,
}

impl GenericContext {
    fn read(cur: &mut Cursor<&[u8]>, generic_inst_map: &HashMap<u64, usize>) -> Result<Self> {

        Ok(Self {
            class_inst_idx: generic_inst_map.get(&cur.read_u64::<LittleEndian>()?).copied(),
            method_inst_idx: generic_inst_map.get(&cur.read_u64::<LittleEndian>()?).copied(),
        })
    }
}

pub struct GenericInst {
    /// Indices into MetadataRegistration types field
    pub types: Vec<usize>,
}

impl GenericInst {
    fn read(reader: &ElfReader, vaddr: u64, types_map: &HashMap<u64, usize>) -> Result<Self> {
        let mut cur = reader.make_cur(vaddr)?;

        let type_ptrs = read_len_arr(reader, &mut cur)?;
        let mut types = Vec::with_capacity(type_ptrs.len());
        for addr in type_ptrs {
            types.push(types_map[&addr]);
        }
        Ok(Self {
            types
        })
    }
}

#[derive(BinRead)]
pub struct GenericMethodIndices {
    pub method_index: u32,
    pub invoker_index: u32,
    pub adjustor_thunk_index: u32,
}

#[derive(BinRead)]
pub struct GenericMethodFunctionsDefinitions {
    pub generic_method_index: u32,
    pub indices: GenericMethodIndices,
}

/// Compiler calculated values
#[derive(BinRead)]
pub struct TypeDefinitionSizes {
    pub instance_size: u32,
    pub native_size: i32,
    pub static_fields_size: u32,
    pub thread_static_fields_size: u32,
}

pub struct MetadataRegistration {
    pub generic_classes: Vec<GenericClass>,
    pub generic_insts: Vec<GenericInst>,
    pub generic_method_table: Vec<GenericMethodFunctionsDefinitions>,
    pub types: Vec<Type>,
    pub method_specs: Vec<MethodSpec>,
    pub field_offsets: Vec<Vec<u32>>,
    pub type_definition_sizes: Vec<TypeDefinitionSizes>,

    // TODO:
    // pub metadata_usages: ??
}

impl MetadataRegistration {
    fn read(elf: &Elf, addr: u64, metadata: &Metadata) -> Result<Self> {
        let reader = ElfReader::new(elf);
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

        let mut generic_classes = Vec::with_capacity(type_addrs.len());
        let mut generic_class_map = HashMap::new();
        for (i, addr) in generic_class_addrs.into_iter().enumerate() {
            generic_classes.push(GenericClass::read(&reader, addr, &generic_inst_map)?);
            generic_class_map.insert(addr, i);
        }

        let mut type_map = HashMap::new();
        for (i, &addr) in type_addrs.iter().enumerate() {
            type_map.insert(addr, i);
        }
        let mut types = Vec::with_capacity(type_addrs.len());
        for addr in type_addrs {
            types.push(Type::read(&reader, addr, &type_map, &generic_class_map)?);
        }

        let mut generic_insts = Vec::with_capacity(generic_inst_addrs.len());
        for addr in generic_inst_addrs {
            let mut cur = reader.make_cur(addr)?;
            generic_insts.push(GenericInst::read(&reader, addr, &type_map)?);
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

            let arr_len = metadata.type_definitions[i].field_count as usize;
            let mut arr = Vec::with_capacity(arr_len);
            for _ in 0..arr_len {
                arr.push(cur.read_u32::<LittleEndian>()?);
            }
            field_offsets.push(arr);
        }

        Ok(MetadataRegistration {
            generic_classes,
            generic_insts,
            generic_method_table,
            types,
            method_specs,
            field_offsets: field_offsets,
            type_definition_sizes,
        })
    }
}

pub fn registrations<'a>(elf: &'a Elf<'a>, metadata: &Metadata) -> Result<(CodeRegistration<'a>, MetadataRegistration)> {
    let (cr_addr, mr_addr) = find_registration(&elf)?;
    let code_registration = CodeRegistration::read(&elf, cr_addr)?;
    let metadata_registration = MetadataRegistration::read(&elf, mr_addr, metadata)?;
    Ok((code_registration, metadata_registration))
}