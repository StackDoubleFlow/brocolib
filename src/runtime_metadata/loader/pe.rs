//! PE runtime metadata parsing.
//!
//! For IL2CPP Unity games built for Windows, the runtime metadata lives
//! inside the `GameAssembly.dll` (PE/PE32+). This module mirrors the ELF
//! loader and exposes `RuntimeMetadata::read_pe` which locates the
//! registration structures in a PE image and reads the metadata.

use super::*;
use crate::global_metadata::{GenericParameterIndex, GlobalMetadata, TypeDefinitionIndex};
use crate::runtime_metadata::{Il2CppArrayType, Il2CppCodeGenModule, Il2CppCodeRegistration, Il2CppGenericClass,
    Il2CppGenericContext, Il2CppGenericInst, Il2CppMetadataRegistration, Il2CppType,
    Il2CppTypeEnum, RuntimeMetadata, TypeData};
use binread::{BinRead, BinReaderExt};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use object::read::pe::PeFile64;
use object::{Object, ObjectSection, ObjectSymbol};
use std::collections::HashMap;
use std::io::Cursor;
use std::str;

type Pe<'data> = PeFile64<'data>;

fn vaddr_conv(pe: &Pe, vaddr: u64) -> Result<u64> {
    for section in pe.sections() {
        let addr = section.address();
        let size = section.size();
        if addr <= vaddr && vaddr - addr < size {
            if let Some((file_off, _)) = section.file_range() {
                let offset = file_off + (vaddr - addr) as usize;
                return Ok(offset as u64);
            }
        }
    }
    Err(Il2CppBinaryError::VAddrConv(vaddr))
}

struct PeReader<'pe, 'data> {
    pe: &'pe Pe<'data>,
    pe_data: &'data [u8],
}

impl<'pe, 'data> PeReader<'pe, 'data> {
    fn new(pe: &'pe Pe<'data>, pe_data: &'data [u8]) -> Self {
        Self { pe, pe_data }
    }

    fn make_cur(&self, rva: u64) -> Result<Cursor<&'data [u8]>> {
        let pos = vaddr_conv(self.pe, rva)? as u64;
        let mut cur = Cursor::new(self.pe_data);
        cur.set_position(pos);
        Ok(cur)
    }

    fn get_str(&self, rva: u64) -> Result<&'data str> {
        let offset = vaddr_conv(self.pe, rva)?;
        get_str(self.pe_data, offset as usize)
    }
}

fn read_arr<'pe, 'data, T>(reader: &PeReader<'pe, 'data>, rva: u64, len: usize) -> Result<Vec<T>>
where
    T: BinRead,
{
    let mut cur = reader.make_cur(rva)?;
    let mut vec = Vec::with_capacity(len);
    for _ in 0..len {
        vec.push(cur.read_le()?);
    }
    Ok(vec)
}

fn read_len_arr<'pe, 'data, T>(reader: &PeReader<'pe, 'data>, cur: &mut Cursor<&'data [u8]>) -> Result<Vec<T>>
where
    T: BinRead,
{
    let count = cur.read_u32::<LittleEndian>()? as usize;
    let _padding = cur.read_u32::<LittleEndian>()?;
    let addr = cur.read_u64::<LittleEndian>()?;
    read_arr(reader, addr, count)
}

fn read_len_arr_nullable<'pe, 'data, T>(reader: &PeReader<'pe, 'data>, cur: &mut Cursor<&'data [u8]>) -> Result<Vec<T>>
where
    T: BinRead + Default + Clone,
{
    let count = cur.read_u32::<LittleEndian>()? as usize;
    let _padding = cur.read_u32::<LittleEndian>()?;
    let addr = cur.read_u64::<LittleEndian>()?;
    if addr == 0 {
        Ok(vec![Default::default(); count])
    } else {
        read_arr(reader, addr, count)
    }
}

fn read_code_gen_module_pe<'pe, 'data>(reader: &PeReader<'pe, 'data>, vaddr: u64) -> Result<Il2CppCodeGenModule<'data>> {
    let mut cur = reader.make_cur(vaddr)?;

    let name = reader.get_str(cur.read_u64::<LittleEndian>()?)?;

    let method_pointers = read_len_arr_nullable(reader, &mut cur)?;
    let adjustor_thunks = read_len_arr(reader, &mut cur)?;

    let addr = cur.read_u64::<LittleEndian>()?;
    let invoker_indices = read_arr(reader, addr, method_pointers.len())?;

    let _todo = cur.read_u128::<LittleEndian>()?;

    let rgctx_ranges = read_len_arr(reader, &mut cur)?;
    let rgctxs = read_len_arr(reader, &mut cur)?;
    Ok(Il2CppCodeGenModule {
        name,
        method_pointers,
        adjustor_thunks,
        invoker_indices,
        rgctx_ranges,
        rgctxs,
    })
}

fn read_code_registration_pe<'pe, 'data>(pe: &'pe Pe<'data>, pe_data: &'data [u8], addr: u64) -> Result<Il2CppCodeRegistration<'data>> {
    let reader = PeReader::new(pe, pe_data);
    let mut cur = reader.make_cur(addr)?;

    let reverse_pinvoke_wrappers = read_len_arr(&reader, &mut cur)?;

    let generic_method_pointers = read_len_arr(&reader, &mut cur)?;
    let addr = cur.read_u64::<LittleEndian>()?;
    let generic_adjustor_thunks = read_arr(&reader, addr, generic_method_pointers.len())?;

    let invoker_pointers = read_len_arr(&reader, &mut cur)?;
    let unresolved_virtual_call_pointers: Vec<u64> = read_len_arr(&reader, &mut cur)?;
    let _unresolved_instance_call_pointers = cur.read_u64::<LittleEndian>()?;
    let _unresolved_static_call_pointers = cur.read_u64::<LittleEndian>()?;

    let _interop_data: Vec<u64> = read_len_arr(&reader, &mut cur)?;
    let _windows_runtime_factory_table: Vec<u64> = read_len_arr(&reader, &mut cur)?;

    let module_addrs = read_len_arr(&reader, &mut cur)?;
    let mut code_gen_modules = Vec::with_capacity(module_addrs.len());
    for maddr in module_addrs {
        code_gen_modules.push(read_code_gen_module_pe(&reader, maddr)?);
    }

    Ok(Il2CppCodeRegistration {
        reverse_pinvoke_wrappers,
        generic_method_pointers,
        generic_adjustor_thunks,
        invoker_pointers,
        unresolved_indirect_call_pointers: unresolved_virtual_call_pointers,
        code_gen_modules,
    })
}

fn read_type_pe<'pe, 'data>(reader: &PeReader<'pe, 'data>, vaddr: u64, type_map: &HashMap<u64, usize>, generic_class_map: &HashMap<u64, usize>, array_types: &mut Vec<Il2CppArrayType>, array_type_map: &mut HashMap<u64, usize>) -> Result<Il2CppType> {
    let mut cur = reader.make_cur(vaddr)?;

    let raw_data = cur.read_u64::<LittleEndian>()?;
    let attrs = cur.read_u16::<LittleEndian>()?;
    let ty_id = cur.read_u8()?;
    let ty = Il2CppTypeEnum::from_ty(ty_id).ok_or(Il2CppBinaryError::InvalidType(ty_id))?;
    let bitfield = cur.read_u8()?;

    let data = match ty {
        Il2CppTypeEnum::Var | Il2CppTypeEnum::Mvar => {
            TypeData::GenericParameterIndex(GenericParameterIndex::new(raw_data as u32))
        }
        Il2CppTypeEnum::Ptr | Il2CppTypeEnum::Szarray => TypeData::TypeIndex(type_map[&raw_data]),
        Il2CppTypeEnum::Array => {
            match array_type_map.get(&raw_data) {
                Some(idx) => TypeData::ArrayType(*idx),
                None => {
                    let idx = array_types.len();
                    array_types.push(read_array_type_pe(reader, raw_data, type_map)?);
                    array_type_map.insert(raw_data, idx);
                    TypeData::ArrayType(idx)
                }
            }
        }
        Il2CppTypeEnum::Genericinst => TypeData::GenericClassIndex(generic_class_map[&raw_data]),
        _ => TypeData::TypeDefinitionIndex(TypeDefinitionIndex::new(raw_data as u32)),
    };
    let byref = (bitfield >> 5) != 0;
    let pinned = (bitfield >> 6) != 0;
    let valuetype = (bitfield >> 7) != 0;

    Ok(Il2CppType { data, attrs, ty, byref, pinned, valuetype })
}

fn read_generic_class_pe<'pe, 'data>(reader: &PeReader<'pe, 'data>, vaddr: u64, generic_inst_map: &HashMap<u64, usize>, type_map: &HashMap<u64, usize>) -> Result<Il2CppGenericClass> {
    let mut cur = reader.make_cur(vaddr)?;

    let type_ptr = cur.read_u64::<LittleEndian>()?;
    let type_index = type_map[&type_ptr];

    let context = read_generic_context_pe(&mut cur, generic_inst_map)?;
    Ok(Il2CppGenericClass { type_index, context })
}

fn read_generic_context_pe(cur: &mut Cursor<&[u8]>, generic_inst_map: &HashMap<u64, usize>) -> Result<Il2CppGenericContext> {
    Ok(Il2CppGenericContext {
        class_inst_idx: generic_inst_map.get(&cur.read_u64::<LittleEndian>()?).copied(),
        method_inst_idx: generic_inst_map.get(&cur.read_u64::<LittleEndian>()?).copied(),
    })
}

fn read_generic_inst_pe<'pe, 'data>(reader: &PeReader<'pe, 'data>, vaddr: u64, types_map: &HashMap<u64, usize>) -> Result<Il2CppGenericInst> {
    let mut cur = reader.make_cur(vaddr)?;

    let type_ptrs: Vec<u64> = read_len_arr(reader, &mut cur)?;
    let mut types = Vec::with_capacity(type_ptrs.len());
    for addr in type_ptrs {
        types.push(types_map[&addr]);
    }
    Ok(Il2CppGenericInst { types })
}

fn read_array_type_pe<'pe, 'data>(reader: &PeReader<'pe, 'data>, vaddr: u64, types_map: &HashMap<u64, usize>) -> Result<Il2CppArrayType> {
    let mut cur = reader.make_cur(vaddr)?;

    let elem_ty_ptr = cur.read_u64::<LittleEndian>()?;
    let elem_ty = types_map[&elem_ty_ptr];

    let rank = cur.read_u8()?;
    let num_sizes = cur.read_u8()?;
    let num_lobounds = cur.read_u8()?;

    let _padding = cur.read_u32::<LittleEndian>()?;
    let _padding2 = cur.read_u8()?;

    let sizes_ptr = cur.read_u64::<LittleEndian>()?;
    let sizes = read_arr(reader, sizes_ptr, num_sizes as usize)?;

    let lobounds_ptr = cur.read_u64::<LittleEndian>()?;
    let lower_bounds = read_arr(reader, lobounds_ptr, num_lobounds as usize)?;

    Ok(Il2CppArrayType { elem_ty, rank, sizes, lower_bounds })
}

fn read_metadata_registration_pe<'pe, 'data>(pe: &'pe Pe<'data>, pe_data: &'data [u8], addr: u64, metadata: &GlobalMetadata) -> Result<Il2CppMetadataRegistration> {
    let reader = PeReader::new(pe, pe_data);
    let mut cur = reader.make_cur(addr)?;

    let generic_class_addrs: Vec<u64> = read_len_arr(&reader, &mut cur)?;
    let generic_inst_addrs: Vec<u64> = read_len_arr(&reader, &mut cur)?;
    let generic_method_table = read_len_arr(&reader, &mut cur)?;
    let type_addrs: Vec<u64> = read_len_arr(&reader, &mut cur)?;
    let method_specs = read_len_arr(&reader, &mut cur)?;
    let field_offset_ptrs: Vec<u64> = read_len_arr(&reader, &mut cur)?;
    let type_definition_sizes_ptrs: Vec<u64> = read_len_arr(&reader, &mut cur)?;

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
        generic_classes.push(read_generic_class_pe(&reader, addr, &generic_inst_map, &type_map)?);
        generic_class_map.insert(addr, i);
    }

    let mut types = Vec::with_capacity(type_addrs.len());
    let mut array_types = Vec::new();
    let mut array_type_map = HashMap::new();
    for addr in type_addrs {
        types.push(read_type_pe(&reader, addr, &type_map, &generic_class_map, &mut array_types, &mut array_type_map)?);
    }

    let mut generic_insts = Vec::with_capacity(generic_inst_addrs.len());
    for addr in generic_inst_addrs {
        generic_insts.push(read_generic_inst_pe(&reader, addr, &type_map)?);
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

fn find_registration(pe: &Pe) -> Result<(u64, u64)> {
    let mut cr_addr: Option<u64> = None;
    let mut mr_addr: Option<u64> = None;

    // Try exports first
        if let Ok(exports) = pe.exports() {
            for export in exports {
                if let Some(name) = export.name() {
                    if let Ok(s) = std::str::from_utf8(name) {
                        if s.contains("Il2CppCodegenRegistration") || s.contains("s_Il2CppCodegenRegistration") {
                            cr_addr = Some(export.address());
                        }
                        if s.contains("Il2CppMetadataRegistration") || s.contains("s_Il2CppMetadataRegistration") {
                            mr_addr = Some(export.address());
                        }
                    }
                }
            }
        }

    // Try symbol table if exports didn't work
    if cr_addr.is_none() || mr_addr.is_none() {
            if let Ok(symbols) = pe.symbols() {
                for symbol in symbols {
                    if let Ok(name) = symbol.name() {
                        if cr_addr.is_none() && name.contains("Il2CppCodegenRegistration") {
                            cr_addr = Some(symbol.address());
                        }
                        if mr_addr.is_none() && name.contains("Il2CppMetadataRegistration") {
                            mr_addr = Some(symbol.address());
                        }
                    }
                }
            }
    }

    match (cr_addr, mr_addr) {
        (Some(c), Some(m)) => Ok((c, m)),
        _ => Err(Il2CppBinaryError::MissingRegistration),
    }
}

impl<'data> RuntimeMetadata<'data> {
    pub fn read_pe(pe: &Pe<'data>, global_metadata: &GlobalMetadata) -> Result<Self> {
        let pe_data = pe.data();
        let (cr_addr, mr_addr) = find_registration(pe)?;

        let code_registration = Il2CppCodeRegistration::read_pe(pe, pe_data, cr_addr)?;
        let metadata_registration = Il2CppMetadataRegistration::read_pe(pe, pe_data, mr_addr, global_metadata)?;
        Ok(RuntimeMetadata { code_registration, metadata_registration })
    }

    pub fn read_pe_bytes(pe_data: &'data [u8], global_metadata: &GlobalMetadata) -> Result<Self> {
        let pe = PeFile64::parse(pe_data)?;
        Self::read_pe(&pe,  global_metadata)
    }
}
