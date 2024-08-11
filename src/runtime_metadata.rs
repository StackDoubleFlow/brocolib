pub mod source;
pub mod elf;

use binread::BinRead;
use crate::global_metadata::{Token, TypeDefinitionIndex, GenericParameterIndex, MethodIndex};
use crate::Metadata;

/// Defined at `il2cpp-class-internals:570`
#[derive(BinRead, Debug)]
pub struct Il2CppTokenAdjustorThunkPair {
    pub token: Token,
    #[br(align_before = 8)]
    pub adjustor_thunk: u64,
}

/// Defined at `il2cpp-class-internals:550`
#[derive(BinRead, Debug)]
pub struct Il2CppRange {
    pub start: u32,
    pub length: u32,
}

/// Defined at `il2cpp-class-internals:556`
#[derive(BinRead, Debug)]
pub struct Il2CppTokenRangePair {
    pub token: Token,
    pub range: Il2CppRange,
}

/// Defined at `il2cpp-metadata.h:69`
#[derive(BinRead, Debug)]
#[br(repr = u64)]
pub enum Il2CppRGCTXDataType {
    Invalid,
    Type,
    Class,
    Method,
    Array,
    Constrained,
}

/// A runtime generic context.
/// 
/// Defined at `il2cpp-metadata.h:92`
#[derive(BinRead, Debug)]
pub struct Il2CppRGCTXDefinition {
    pub ty: Il2CppRGCTXDataType,
    // TODO
    pub data: u64,
}

/// Defined at `il2cpp-runtime-metadata.h:11`
#[derive(Debug)]
pub struct Il2CppArrayType {
    pub elem_ty: usize,
    pub rank: u8,
    pub sizes: Vec<u32>,
    pub lower_bounds: Vec<u32>,
}

/// Defined at `il2cpp-class-internals:582`
#[derive(Debug)]
pub struct Il2CppCodeGenModule<'data> {
    /// Module names have `.dll` at the end
    pub name: &'data str,
    pub method_pointers: Vec<u64>,
    pub adjustor_thunks: Vec<Il2CppTokenAdjustorThunkPair>,
    pub invoker_indices: Vec<u32>,

    // TODO:
    // reverse_pinvoke_wrapper_indices: Vec<TokenIndexMethodTuple>,

    pub rgctx_ranges: Vec<Il2CppTokenRangePair>,
    pub rgctxs: Vec<Il2CppRGCTXDefinition>,

    // TODO:
    // debugger_metadata: Il2CppDebuggerMetadataRegistration,
    // module_initializer: Il2CppMethodPointer,
    // static_constructor_type_indices: Vec<TypeDefinitionIndex>,
    // /// Per-assembly mode only
    // metadata_registration: Option<Il2CppMetadataRegistration>,
    // /// Per-assembly mode only
    // code_registration: Option<Il2CppCodeRegistration>,
}

/// Defined at `il2cpp-class-internals:603`
#[derive(Debug)]
pub struct Il2CppCodeRegistration<'data> {
    pub reverse_pinvoke_wrappers: Vec<u64>,
    pub generic_method_pointers: Vec<u64>,
    pub generic_adjustor_thunks: Vec<u64>,
    pub invoker_pointers: Vec<u64>,
    pub unresolved_indirect_call_pointers: Vec<u64>,

    // TODO
    // pub interop_data: Vec<InteropData>,
    // pub windows_runtime_factory_table: Vec<WindowsRuntimeFactoryTableEntry>,
    pub code_gen_modules: Vec<Il2CppCodeGenModule<'data>>,
}

/// Corresponds to element type signatures.
/// See ECMA-335, II.23.1.16
/// 
/// Defined at `il2cpp-blob.h:6`
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Il2CppTypeEnum {
    /// End of list
    End,
    /// System.Void (void)
    Void,
    /// System.Boolean (bool)
    Boolean,
    /// System.Char (char)
    Char,
    /// System.SByte (sbyte)
    I1,
    /// System.Byte (byte)
    U1,
    /// System.Int16 (short)
    I2,
    /// System.UInt16 (ushort)
    U2,
    /// System.Int32 (int)
    I4,
    /// System.UInt32 (uint)
    U4,
    /// System.Int64 (long)
    I8,
    /// System.UInt64 (ulong)
    U8,
    /// System.Single (float)
    R4,
    /// System.Double (double)
    R8,
    /// System.String (string)
    String,
    Ptr,
    Byref,
    Valuetype,
    Class,
    /// Class generic parameter
    Var,
    Array,
    Genericinst,
    /// System.TypedReference
    Typedbyref,
    /// System.IntPtr
    I,
    /// System.UIntPtr
    U,
    Fnptr,
    /// System.Object (object)
    Object,
    /// Single-dimensioned zero-based array type
    Szarray,
    /// Method generic parameter
    Mvar,
    /// Required modifier
    CmodReqd,
    /// Optional modifier
    CmodOpt,
    Internal,
    Modifier,
    /// Sentinel for vararg method signature
    Sentinel,
    /// Denotes a local variable points to a pinned object
    Pinned,
    /// Used in custom attributes to specify an enum
    Enum
}

impl Il2CppTypeEnum {
    fn from_ty(ty: u8) -> Option<Self> {
        Some(match ty {
            0x00 => Il2CppTypeEnum::End,
            0x01 => Il2CppTypeEnum::Void,
            0x02 => Il2CppTypeEnum::Boolean,
            0x03 => Il2CppTypeEnum::Char,
            0x04 => Il2CppTypeEnum::I1,
            0x05 => Il2CppTypeEnum::U1,
            0x06 => Il2CppTypeEnum::I2,
            0x07 => Il2CppTypeEnum::U2,
            0x08 => Il2CppTypeEnum::I4,
            0x09 => Il2CppTypeEnum::U4,
            0x0a => Il2CppTypeEnum::I8,
            0x0b => Il2CppTypeEnum::U8,
            0x0c => Il2CppTypeEnum::R4,
            0x0d => Il2CppTypeEnum::R8,
            0x0e => Il2CppTypeEnum::String,
            0x0f => Il2CppTypeEnum::Ptr,
            0x10 => Il2CppTypeEnum::Byref,
            0x11 => Il2CppTypeEnum::Valuetype,
            0x12 => Il2CppTypeEnum::Class,
            0x13 => Il2CppTypeEnum::Var,
            0x14 => Il2CppTypeEnum::Array,
            0x15 => Il2CppTypeEnum::Genericinst,
            0x16 => Il2CppTypeEnum::Typedbyref,
            0x18 => Il2CppTypeEnum::I,
            0x19 => Il2CppTypeEnum::U,
            0x1b => Il2CppTypeEnum::Fnptr,
            0x1c => Il2CppTypeEnum::Object,
            0x1d => Il2CppTypeEnum::Szarray,
            0x1e => Il2CppTypeEnum::Mvar,
            0x1f => Il2CppTypeEnum::CmodReqd,
            0x20 => Il2CppTypeEnum::CmodOpt,
            0x21 => Il2CppTypeEnum::Internal,
            0x40 => Il2CppTypeEnum::Modifier,
            0x41 => Il2CppTypeEnum::Sentinel,
            0x45 => Il2CppTypeEnum::Pinned,
            0x55 => Il2CppTypeEnum::Enum,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TypeData {
    TypeDefinitionIndex(TypeDefinitionIndex),
    /// For [`Il2CppTypeEnum::Ptr`] and [`Il2CppTypeEnum::Szarray`]
    TypeIndex(usize),
    /// For [`Il2CppTypeEnum::Var`] and [`Il2CppTypeEnum::Mvar`]
    GenericParameterIndex(GenericParameterIndex),
    /// For [`Il2CppTypeEnum::Genericinst`]
    GenericClassIndex(usize),
    /// For [`Il2CppTypeEnum::Array`]
    ArrayType(usize),
}

/// Defined at `il2cpp-runtime-metadata.h:48`
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Il2CppType {
    pub data: TypeData,
    /// Param attributes or field flags. See `il2cpp-tabledef.h`
    pub attrs: u16,
    pub ty: Il2CppTypeEnum,
    pub byref: bool,
    /// valid when included in a local var signature
    pub pinned: bool,
    pub valuetype: bool,
}

impl Il2CppType {
    pub fn full_name(&self, metadata: &Metadata) -> String {
        let mr = &metadata.runtime_metadata.metadata_registration;
        let types = &mr.types;
        let type_defs = &metadata.global_metadata.type_definitions;

        String::from(match self.ty {
            Il2CppTypeEnum::Void => "System.Void",
            Il2CppTypeEnum::Boolean => "System.Boolean",
            Il2CppTypeEnum::Char => "System.Char",
            Il2CppTypeEnum::I1 => "System.SByte",
            Il2CppTypeEnum::U1 => "System.Byte",
            Il2CppTypeEnum::I2 => "System.Int16",
            Il2CppTypeEnum::U2 => "System.UInt16",
            Il2CppTypeEnum::I4 => "System.Int32",
            Il2CppTypeEnum::U4 => "System.UInt32",
            Il2CppTypeEnum::U8 => "System.Int64",
            Il2CppTypeEnum::I8 => "System.UInt64",
            Il2CppTypeEnum::R4 => "System.Float",
            Il2CppTypeEnum::R8 => "System.Double",
            Il2CppTypeEnum::String => "System.String",
            Il2CppTypeEnum::Typedbyref => "System.TypedReference",
            Il2CppTypeEnum::I => "System.IntPtr",
            Il2CppTypeEnum::U => "System.UIntPtr",
            Il2CppTypeEnum::Object => "System.Object",
            Il2CppTypeEnum::Sentinel => "<<SENTINEL>>",
            _ => return match (self.ty, self.data) {
                (Il2CppTypeEnum::Var | Il2CppTypeEnum::Mvar, TypeData::GenericParameterIndex(idx)) => metadata.global_metadata.generic_parameters[idx].name(metadata).to_string(),
                (Il2CppTypeEnum::Ptr, TypeData::TypeIndex(ty_idx)) => format!("{}*", types[ty_idx].full_name(metadata)),
                (Il2CppTypeEnum::Szarray, TypeData::TypeIndex(ty_idx)) => format!("{}[]", types[ty_idx].full_name(metadata)),
                (Il2CppTypeEnum::Array, TypeData::ArrayType(arr_ty_idx)) => {
                    let arr_type = &mr.array_types[arr_ty_idx];
                    let mut str = types[arr_type.elem_ty].full_name(metadata);
                    str.push('[');
                    for _ in 0..arr_type.rank - 1 {
                        str.push(',');
                    }
                    str.push(']');
                    str
                },
                (Il2CppTypeEnum::Class | Il2CppTypeEnum::Valuetype, TypeData::TypeDefinitionIndex(ty_idx)) => type_defs[ty_idx].full_name(metadata, false),
                (Il2CppTypeEnum::Genericinst, TypeData::GenericClassIndex(gc)) => {
                    let gc = &mr.generic_classes[gc];
                    let inst = &mr.generic_insts[gc.context.class_inst_idx.unwrap()];
                    let generic_args = inst.types.iter().map(|ty| types[*ty].full_name(metadata)).collect::<Vec<_>>().join(", ");
                    format!("{}<{}>", types[gc.type_index].full_name(metadata), generic_args)
                }
                _ => format!("({:?}?)", self.ty)
            }
        })
    }
}

/// A generic class instantiation.
///
/// Defined at `il2cpp-runtime-metadata.h:40`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Il2CppGenericClass {
    /// The generic type definition.
    ///
    /// Indices into the [`Il2CppMetadataRegistration::types`] field.
    pub type_index: usize,

    /// A context that contains the type instantiation doesn't contain any method instantiation.
    pub context: Il2CppGenericContext,
}

/// Defined at `il2cpp-runtime-metadata.h:27`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Il2CppGenericContext {
    /// Indices into the [`Il2CppMetadataRegistration::generic_insts`] field
    pub class_inst_idx: Option<usize>,

    /// Indices into the [`Il2CppMetadataRegistration::generic_insts`] field
    pub method_inst_idx: Option<usize>,
}

/// A generic method instantiation.
/// 
/// It is not possible for both `class_inst_index` and `method_inst_index` to
/// be invalid since if both the class and method are not generic, you cannot
/// make a generic instance.
/// 
/// Defined at `il2cpp-metadata.h:67`
#[derive(BinRead, Debug)]
pub struct Il2CppMethodSpec {
    /// The method definition.
    pub method_definition_index: MethodIndex,

    /// The class generic argument list (if class is generic).
    ///
    /// Indices into the [`Il2CppMetadataRegistration::generic_insts`] field
    pub class_inst_index: u32,

    /// The method generic argument list (if method is generic).
    ///
    /// Indices into the [`Il2CppMetadataRegistration::generic_insts`] field
    pub method_inst_index: u32,
}

/// A list of types used for a generic instantiation.
/// 
/// Defined at `il2cpp-runtime-metadata.h:21`
#[derive(Debug)]
pub struct Il2CppGenericInst {
    /// Indices into the [`Il2CppMetadataRegistration::types`] field
    pub types: Vec<usize>,
}

#[derive(BinRead, Debug)]
pub struct GenericMethodIndices {
    /// Index for the [`Il2CppCodeRegistration::generic_method_pointers`] field
    pub method_index: u32,

    /// Index for the [`Il2CppCodeRegistration::invoker_pointers`] field
    pub invoker_index: u32,

    /// Index for the [`Il2CppCodeRegistration::generic_adjustor_thunks`] field (optional)
    pub adjustor_thunk_index: u32,
}

/// Defined at `il2cpp-metadata.h:105`
#[derive(BinRead, Debug)]
pub struct Il2CppGenericMethodFunctionsDefinitions {
    /// Index for [`Il2CppMetadataRegistration::method_specs`]
    pub generic_method_index: u32,
    pub indices: GenericMethodIndices,
}

/// Compiler calculated values
/// 
/// Defined at `il2cpp-class-internals:475`
#[derive(BinRead, Debug)]
pub struct Il2CppTypeDefinitionSizes {
    pub instance_size: u32,
    pub native_size: i32,
    pub static_fields_size: u32,
    pub thread_static_fields_size: u32,
}

/// Defined at `il2cpp-class-internals.h:622`
#[derive(Debug)]
pub struct Il2CppMetadataRegistration {
    pub generic_classes: Vec<Il2CppGenericClass>,
    pub generic_insts: Vec<Il2CppGenericInst>,
    pub generic_method_table: Vec<Il2CppGenericMethodFunctionsDefinitions>,
    pub types: Vec<Il2CppType>,
    /// This is not a real field in the metadata. It is here to provide the
    /// ability to access array types by index instead of by pointer.
    pub array_types: Vec<Il2CppArrayType>,
    pub method_specs: Vec<Il2CppMethodSpec>,
    /// Compiler calculated field offset values. Only exists when read from an
    /// ELF. Since this is platform dependent, it cannot be read from C++
    /// sources.
    pub field_offsets: Option<Vec<Vec<u32>>>,
    /// Compiler calculated size values. Only exists when read from an ELF.
    /// Since this is platform dependent, it cannot be read from C++ sources.
    pub type_definition_sizes: Option<Vec<Il2CppTypeDefinitionSizes>>,
    // TODO:
    // pub metadata_usages: ??
}

#[derive(Debug)]
pub struct RuntimeMetadata<'data> {
    pub code_registration: Il2CppCodeRegistration<'data>,
    pub metadata_registration: Il2CppMetadataRegistration,
}
