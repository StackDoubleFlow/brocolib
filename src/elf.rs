use crate::global_metadata::{GlobalMetadata, MetadataIndex};
use bad64::{disasm, DecodeError, Imm, Instruction, Op, Operand, Reg};
use binread::{BinRead, BinReaderExt};
use byteorder::{LittleEndian, ReadBytesExt};
use object::read::elf::ElfFile64;
use object::{Endianness, Object, ObjectSection, ObjectSegment, ObjectSymbol};
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

    #[error("failed to convert vitual address {0:016x}")]
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

fn analyze_reg_rel(elf: &Elf, instructions: &[Instruction]) -> HashMap<Reg, u64> {
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
                    let ptr = vaddr_conv(elf, (*v as i64 + imm) as u64).unwrap();
                    *v = (&elf.data()[ptr as usize..ptr as usize + 8])
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
    let mut count = 0;

    for i in 0.. {
        let addr = addr + i * 4;
        let code = &elf.data()[addr as usize..addr as usize + 4];
        let ins = &try_disassemble(code, addr)?[0];
        if let (Op::BL, [Operand::Label(Imm::Unsigned(addr))]) = (ins.op(), ins.operands()) {
            count += 1;
            if count == n {
                return Ok(*addr);
            }
        }
    }

    unreachable!()
}

/// Finds and returns the address of the first `blr` instruction it comes across starting from `addr`.
fn find_blr(elf: &Elf, addr: u64, limit: usize) -> Result<Option<(u64, Reg)>> {
    for i in 0..limit {
        let addr = addr + i as u64 * 4;
        let code = &elf.data()[addr as usize..addr as usize + 4];
        let ins = &try_disassemble(code, addr)?[0];
        if let (Op::BLR, [Operand::Reg { reg, .. }]) = (ins.op(), ins.operands()) {
            return Ok(Some((addr, *reg)));
        }
    }
    Ok(None)
}

/// Returns address to (g_CodeRegistration, g_MetadataRegistration)
fn find_registration(elf: &Elf) -> Result<(u64, u64)> {
    let il2cpp_init = elf
        .dynamic_symbols()
        .find(|s| s.name() == Ok("il2cpp_init"))
        .ok_or(Il2CppBinaryError::MissingIl2CppInit)?
        .address();
    let runtime_init = nth_bl(elf, il2cpp_init, 2)?;

    let (blr_addr, blr_reg) =
        find_blr(elf, runtime_init, 200)?.ok_or(Il2CppBinaryError::MissingBlr)?;
    let instructions = try_disassemble(
        &elf.data()[runtime_init as usize..blr_addr as usize],
        runtime_init,
    )?;
    let regs = analyze_reg_rel(elf, &instructions);

    let fn_addr = vaddr_conv(elf, regs[&blr_reg])?;
    let code = &elf.data()[fn_addr as usize..fn_addr as usize + 7 * 4];
    let instructions = try_disassemble(code, fn_addr)?;
    let regs = analyze_reg_rel(elf, instructions.as_slice());

    Ok((regs[&Reg::X0], regs[&Reg::X1]))
}

struct ElfReader<'elf, 'data> {
    elf: &'elf Elf<'data>,
}

impl<'elf, 'data> ElfReader<'elf, 'data> {
    fn new(elf: &'elf Elf<'data>) -> Self {
        Self { elf }
    }

    fn make_cur(&self, vaddr: u64) -> Result<Cursor<&[u8]>> {
        let pos = vaddr_conv(self.elf, vaddr)?;
        let mut cur = Cursor::new(self.elf.data());
        cur.set_position(pos);
        Ok(cur)
    }

    fn get_str(&self, vaddr: u64) -> Result<&'data str> {
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
#[br(repr = u64)]
pub enum RGCTXDataType {
    Invalid,
    Type,
    Class,
    Method,
    Array,
    Constrained,
}

#[derive(BinRead)]
pub struct RGCTXDefinition {
    pub ty: RGCTXDataType,
    pub data: u64,
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

pub struct CodeGenModule<'data> {
    pub name: &'data str,
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

impl<'data> CodeGenModule<'data> {
    fn read<'elf>(reader: &ElfReader<'elf, 'data>, vaddr: u64) -> Result<Self> {
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

pub struct CodeRegistration<'data> {
    pub reverse_pinvoke_wrappers: Vec<u64>,
    pub generic_method_pointers: Vec<u64>,
    pub generic_adjustor_thunks: Vec<u64>,
    pub invoker_pointers: Vec<u64>,
    pub unresolved_virtual_call_pointers: Vec<u64>,

    // TODO
    // pub interop_data: Vec<InteropData>,
    // pub windows_runtime_factory_table: Vec<WindowsRuntimeFactoryTableEntry>,
    pub code_gen_modules: Vec<CodeGenModule<'data>>,
}

impl<'data> CodeRegistration<'data> {
    fn read(elf: &Elf<'data>, addr: u64) -> Result<Self> {
        let reader = ElfReader::new(elf);
        let mut cur = reader.make_cur(addr)?;

        let reverse_pinvoke_wrappers = read_len_arr(&reader, &mut cur)?;

        let generic_method_pointers = read_len_arr(&reader, &mut cur)?;
        let addr = cur.read_u64::<LittleEndian>()?;
        let generic_adjustor_thunks = read_arr(&reader, addr, generic_method_pointers.len())?;

        let invoker_pointers = read_len_arr(&reader, &mut cur)?;
        let unresolved_virtual_call_pointers = read_len_arr(&reader, &mut cur)?;

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
            unresolved_virtual_call_pointers,
            code_gen_modules,
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
            _ => return Err(Il2CppBinaryError::InvalidType(ty)),
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
    /// For TypeEnum::Array
    ArrayType,
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
    fn read(
        reader: &ElfReader,
        vaddr: u64,
        type_map: &HashMap<u64, usize>,
        generic_class_map: &HashMap<u64, usize>,
    ) -> Result<Type> {
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
            _ => TypeData::TypeDefinitionIndex(raw_data as u32),
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
    fn read(
        reader: &ElfReader,
        vaddr: u64,
        generic_inst_map: &HashMap<u64, usize>,
    ) -> Result<Self> {
        let mut cur = reader.make_cur(vaddr)?;

        let type_definition_index = cur.read_u32::<LittleEndian>()?;
        let _padding = cur.read_u32::<LittleEndian>()?;

        let context = GenericContext::read(&mut cur, generic_inst_map)?;
        Ok(Self {
            type_definition_index,
            context,
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
            class_inst_idx: generic_inst_map
                .get(&cur.read_u64::<LittleEndian>()?)
                .copied(),
            method_inst_idx: generic_inst_map
                .get(&cur.read_u64::<LittleEndian>()?)
                .copied(),
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
        Ok(Self { types })
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
    fn read(elf: &Elf, addr: u64, metadata: &GlobalMetadata) -> Result<Self> {
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

            let type_def_idx = MetadataIndex::new(i as u32);
            let arr_len = metadata.type_definitions[type_def_idx].field_count as usize;
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
            field_offsets,
            type_definition_sizes,
        })
    }
}

pub struct RuntimeMetadata<'data> {
    pub code_registration: CodeRegistration<'data>,
    pub metadata_registration: MetadataRegistration,
}

impl<'data> RuntimeMetadata<'data> {
    pub fn read(elf: &Elf<'data>, global_metadata: &GlobalMetadata) -> Result<Self> {
        let (cr_addr, mr_addr) = find_registration(elf)?;
        let code_registration = CodeRegistration::read(elf, cr_addr)?;
        let metadata_registration = MetadataRegistration::read(elf, mr_addr, global_metadata)?;
        Ok(RuntimeMetadata {
            code_registration,
            metadata_registration,
        })
    }

    pub fn read_elf(elf_data: &'data [u8], global_metadata: &GlobalMetadata) -> Result<Self> {
        let elf = Elf::parse(elf_data)?;
        Self::read(&elf, global_metadata)
    }
}
