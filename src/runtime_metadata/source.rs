use std::collections::HashMap;
use std::path::Path;
use std::fs;
use thiserror::Error;
use super::*;

#[derive(Error, Debug)]
pub enum SourceParseError {
    #[error("could not parse Il2CppType with type {0}")]
    InvalidTypeEnum(String),

    #[error("could not find {0}")]
    TableNotFound(String),

    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
}

type Result<T> = std::result::Result<T, SourceParseError>;

pub struct SourceArrIterator<'src> {
    lines: std::str::Lines<'src>,
    // TODO: size hint
}

impl<'src> Iterator for SourceArrIterator<'src> {
    type Item = &'src str;

    fn next(&mut self) -> Option<Self::Item> {
        self.lines
            .next()
            .filter(|line| !line.starts_with('}'))
            .map(|line| line.trim().trim_end_matches(','))
    }
}

pub struct SourceDir {
    pub(crate) global_metadata_data: Vec<u8>,
    source_files: HashMap<String, String>
}

impl SourceDir {
    pub fn new<P>(path: P) -> std::io::Result<Self>
    where 
        P: AsRef<Path>
    {
        let path = path.as_ref();
        let global_metadata_path = path.join("Data/Metadata/global-metadata.dat");
        let global_metadata_data = fs::read(global_metadata_path)?;

        let mut source_files = HashMap::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }

            let name = entry.file_name();
            let name = name.to_str().unwrap();
            let data = fs::read_to_string(entry.path())?;
            source_files.insert(name.to_string(), data);

        }

        Ok(Self {
            global_metadata_data,
            source_files,
        })
    }

    fn parse_array(&self, ty: &str, name: &str, file: &str) -> Result<SourceArrIterator> {
        let src = &self.source_files[file];
        let mut lines = src.lines();
        let header = format!("{ty} {name}");
        loop {
            let Some(line) = lines.next() else {
                return Err(SourceParseError::TableNotFound(name.to_string()))
            };
            if line.starts_with(&header) {
                break;
            }
        }

        // skip opening bracket
        let _ = lines.next();

        Ok(SourceArrIterator { lines })
    }
}

impl Il2CppTypeEnum {
    fn read_src(name: &str) -> Result<Self> {
        Ok(match name {
            "IL2CPP_TYPE_END" => Il2CppTypeEnum::End,
            "IL2CPP_TYPE_VOID" => Il2CppTypeEnum::Void,
            "IL2CPP_TYPE_BOOLEAN" => Il2CppTypeEnum::Boolean,
            "IL2CPP_TYPE_CHAR" => Il2CppTypeEnum::Char,
            "IL2CPP_TYPE_I1" => Il2CppTypeEnum::I1,
            "IL2CPP_TYPE_U1" => Il2CppTypeEnum::U1,
            "IL2CPP_TYPE_I2" => Il2CppTypeEnum::I2,
            "IL2CPP_TYPE_U2" => Il2CppTypeEnum::U2,
            "IL2CPP_TYPE_I4" => Il2CppTypeEnum::I4,
            "IL2CPP_TYPE_U4" => Il2CppTypeEnum::U4,
            "IL2CPP_TYPE_I8" => Il2CppTypeEnum::I8,
            "IL2CPP_TYPE_U8" => Il2CppTypeEnum::U8,
            "IL2CPP_TYPE_R4" => Il2CppTypeEnum::R4,
            "IL2CPP_TYPE_R8" => Il2CppTypeEnum::R8,
            "IL2CPP_TYPE_STRING" => Il2CppTypeEnum::String,
            "IL2CPP_TYPE_PTR" => Il2CppTypeEnum::Ptr,
            "IL2CPP_TYPE_BYREF" => Il2CppTypeEnum::Byref,
            "IL2CPP_TYPE_VALUETYPE" => Il2CppTypeEnum::Valuetype,
            "IL2CPP_TYPE_CLASS" => Il2CppTypeEnum::Class,
            "IL2CPP_TYPE_VAR" => Il2CppTypeEnum::Var,
            "IL2CPP_TYPE_ARRAY" => Il2CppTypeEnum::Array,
            "IL2CPP_TYPE_GENERICINST" => Il2CppTypeEnum::Genericinst,
            "IL2CPP_TYPE_TYPEDBYREF" => Il2CppTypeEnum::Typedbyref,
            "IL2CPP_TYPE_I" => Il2CppTypeEnum::I,
            "IL2CPP_TYPE_U" => Il2CppTypeEnum::U,
            "IL2CPP_TYPE_FNPTR" => Il2CppTypeEnum::Fnptr,
            "IL2CPP_TYPE_OBJECT" => Il2CppTypeEnum::Object,
            "IL2CPP_TYPE_SZARRAY" => Il2CppTypeEnum::Szarray,
            "IL2CPP_TYPE_MVAR" => Il2CppTypeEnum::Mvar,
            "IL2CPP_TYPE_CMOD_REQD" => Il2CppTypeEnum::CmodReqd,
            "IL2CPP_TYPE_CMOD_OPT" => Il2CppTypeEnum::CmodOpt,
            "IL2CPP_TYPE_INTERNAL" => Il2CppTypeEnum::Internal,
            "IL2CPP_TYPE_MODIFIER" => Il2CppTypeEnum::Modifier,
            "IL2CPP_TYPE_SENTINEL" => Il2CppTypeEnum::Sentinel,
            "IL2CPP_TYPE_PINNED" => Il2CppTypeEnum::Pinned,
            "IL2CPP_TYPE_ENUM" => Il2CppTypeEnum::Enum,
            _ => return Err(SourceParseError::InvalidTypeEnum(name.to_string())),
        })
    }
}

impl Il2CppType {
    fn read_src<'s>(line: &'s str, name_mappings: &NameMappings) -> Result<(&'s str, Self)> {
        let offset = if line.starts_with("const") {
            1
        } else {
            0
        };
        let words: Vec<&str> = line.split_whitespace().collect();
        let name = words[1 + offset];
        let data_str = words[4 + offset].trim_end_matches(',').trim_start_matches("(void*)").trim_start_matches('&');
        let attrs: u16 = words[5 + offset].trim_end_matches(',').parse()?;
        let ty = Il2CppTypeEnum::read_src(words[6 + offset].trim_end_matches(','))?;
        // This isn't actually used
        // let num_mods = words[7].trim_end_matches(',').parse::<u8>()?;
        let byref = words[8 + offset].trim_end_matches(',').parse::<u8>()? != 0;
        let pinned = words[9 + offset].trim_end_matches(',').parse::<u8>()? != 0;
        let valuetype = words[10 + offset].parse::<u8>()? != 0;

        let data = match ty {
            Il2CppTypeEnum::Var | Il2CppTypeEnum::Mvar => TypeData::GenericParameterIndex(GenericParameterIndex::new(data_str.parse()?)),
            Il2CppTypeEnum::Ptr | Il2CppTypeEnum::Szarray => TypeData::TypeIndex(name_mappings.types[data_str]),
            Il2CppTypeEnum::Array => TypeData::ArrayType(todo!()),
            Il2CppTypeEnum::Genericinst => TypeData::GenericClassIndex(name_mappings.generic_classes[data_str]),
            _ => TypeData::TypeDefinitionIndex(TypeDefinitionIndex::new(data_str.parse()?)),
        };

        Ok((name, Self {
            data,
            attrs,
            ty,
            byref,
            pinned,
            valuetype
        }))
    }

    pub fn read_src_all(src_dir: &SourceDir, name_mappings: &NameMappings) -> Result<Vec<Self>> {
        let src = &src_dir.source_files["Il2CppTypeDefinitions.c"];

        let mut map = HashMap::new();
        for line in src.lines() {
            if !line.starts_with("Il2CppType ") && !line.starts_with("const Il2CppType ") {
                continue;
            }
            let (name, item) = Self::read_src(line, name_mappings)?;
            map.insert(name, item);
        }

        let mut vec = Vec::with_capacity(map.len());
        for name in &name_mappings.types_list {
            vec.push(map[name]);
        }

        Ok(vec)
    }
}

impl Il2CppGenericClass {
    fn read_src<'s>(line: &'s str, name_mappings: &NameMappings) -> Result<(&'s str, Self)> {
        let words: Vec<&str> = line.split_whitespace().collect();
        let name = words[1];
        let type_name = words[4].trim_start_matches('&').trim_end_matches(',');
        let type_index = name_mappings.types[type_name];
        let class_inst = words[6].trim_start_matches('&').trim_end_matches(',');
        let class_inst_idx = Some(name_mappings.generic_insts[class_inst]);
        let method_inst_idx = match words[7].trim_start_matches('&') {
            "NULL" => None,
            gi => {
                println!("Woah, there's something interesting happening here:");
                println!("There's a generic class with its method inst field filled in.");
                println!("Please open an issue on https://github.com/StackDoubleFlow/brocolib");
                Some(name_mappings.generic_insts[gi])
            }
        };
        Ok((name, Self {
            type_index,
            context: Il2CppGenericContext { class_inst_idx, method_inst_idx }
        }))
    }

    pub fn read_src_all(src_dir: &SourceDir, name_mappings: &NameMappings) -> Result<Vec<Self>> {
        let src = &src_dir.source_files["Il2CppTypeDefinitions.c"];

        let mut map = HashMap::new();
        for line in src.lines() {
            if !line.starts_with("Il2CppGenericClass ") {
                continue;
            }
            let (name, item) = Self::read_src(line, name_mappings)?;
            map.insert(name, item);
        }

        // For some reason this list has duplicates, even though it's used to
        // initialize a hashset at runtime. I doubt it's intentional.
        // TODO: Maybe we can change the indices so we don't have duplicates?

        let mut vec = Vec::with_capacity(map.len());
        for name in &name_mappings.generic_classes_list {
            vec.push(map[name].clone());
        }

        Ok(vec)
    }
}

impl Il2CppGenericInst {
    /// Only the line with the types (Il2CppType*)
    fn read_src<'s>(line: &'s str, name_mappings: &NameMappings) -> Result<(&'s str, Self)> {
        let words = line.split_whitespace().collect::<Vec<_>>();
        let name = words[3].strip_suffix("_Types[]").unwrap();
            // .context("generic inst def has wrong name suffix")?;
        let types = words[6..words.len() - 1]
            .iter()
            .map(|item| {
                item.trim_end_matches(',')
                    .trim_end_matches(')')
                    .trim_start_matches("(&")
            })
            .map(|item| name_mappings.types[item])
            .collect();
        Ok((name, Self {
            types,
        }))
    }

    pub fn read_src_all(src_dir: &SourceDir, name_mappings: &NameMappings) -> Result<Vec<Self>> {
        let src = &src_dir.source_files["Il2CppGenericInstDefinitions.c"];
        let start_loc = src.find("static const Il2CppType* ").ok_or(SourceParseError::TableNotFound("generic inst definitions".to_string()))?;

        let mut map = HashMap::new();
        for line in src[start_loc..].lines().step_by(3) {
            if !line.starts_with("static const Il2CppType* ") {
                break;
            }
            let (name, item) = Self::read_src(line, name_mappings)?;
            map.insert(name, item);
        }

        let mut vec = Vec::with_capacity(map.len());
        for name in &name_mappings.generic_insts_list {
            vec.push(map.remove(name).unwrap());
        }

        Ok(vec)
    }
}

impl Il2CppGenericMethodFunctionsDefinitions {
    fn read_src(line: &str) -> Result<Self> {
        let words = line.split_whitespace().collect::<Vec<_>>();
        let generic_method_index = words[1].trim_end_matches(',').parse()?;
        let method_index = words[2].trim_end_matches(',').parse()?;
        let invoker_index = words[3].trim_end_matches(',').parse()?;
        let adjustor_thunk_index = words[4].trim_end_matches('}').parse::<i32>()? as u32;
        Ok(Self {
            generic_method_index,
            indices: GenericMethodIndices {
                method_index,
                invoker_index,
                adjustor_thunk_index,
            }
        })
    }

    pub fn read_src_all(src_dir: &SourceDir) -> Result<Vec<Self>> {
        src_dir.parse_array("const Il2CppGenericMethodFunctionsDefinitions", "g_Il2CppGenericMethodFunctions", "Il2CppGenericMethodTable.c")?
            .map(Self::read_src)
            .collect()
    }
}

impl Il2CppMethodSpec {
    fn read_src(line: &str) -> Result<Self> {
        let words = line.split_whitespace().collect::<Vec<_>>();
        let method_definition_index = words[1].trim_end_matches(',').parse()?;
        let class_inst_index = words[2].trim_end_matches(',').parse::<i32>()? as u32;
        let method_inst_index = words[3].parse::<i32>()? as u32;
        Ok(Self {
            method_definition_index: MethodIndex::new(method_definition_index),
            class_inst_index,
            method_inst_index,
        })
    }

    fn read_src_all(src_dir: &SourceDir) -> Result<Vec<Self>> {
        src_dir.parse_array("const Il2CppMethodSpec", "g_Il2CppMethodSpecTable", "Il2CppGenericMethodDefinitions.c")?
            .map( Self::read_src)
            .collect()
    }
}

// TODO: remove pub
pub struct NameMappings<'s> {
    types: HashMap<&'s str, usize>,
    types_list: Vec<&'s str>,
    generic_classes: HashMap<&'s str, usize>,
    generic_classes_list: Vec<&'s str>,
    generic_insts: HashMap<&'s str, usize>,
    generic_insts_list: Vec<&'s str>,
}

impl<'s> NameMappings<'s> {
    // TODO: temp pub
    pub fn from_src(src_dir: &'s SourceDir) -> Result<Self> {
        let mut types = HashMap::new();
        let mut types_list = Vec::new();
        let src = &src_dir.source_files["Il2CppTypeDefinitions.c"];
        let arr_start = src
            .find("const Il2CppType* const  g_Il2CppTypeTable")
            .ok_or(SourceParseError::TableNotFound("g_Il2CppTypeTable".to_string()))?;
        for (i, line) in src[arr_start..].lines().skip(3).enumerate() {
            if line.starts_with('}') {
                break;
            }
            let name = line.trim().trim_start_matches('&').trim_end_matches(',');
            types_list.push(name);
            types.insert(name, i);
        }

        let mut generic_classes = HashMap::new();
        let mut generic_classes_list = Vec::new();
        let src = &src_dir.source_files["Il2CppGenericClassTable.c"];
        let arr_start = src
            .find("Il2CppGenericClass* const g_Il2CppGenericTypes")
            .ok_or(SourceParseError::TableNotFound("g_Il2CppGenericTypes".to_string()))?;
        for (i, line) in src[arr_start..].lines().skip(3).enumerate() {
            if line.starts_with('}') {
                break;
            }
            let name = line.trim().trim_start_matches('&').trim_end_matches(',');
            generic_classes_list.push(name);
            generic_classes.insert(name, i);
        }

        let mut generic_insts = HashMap::new();
        let mut generic_insts_list = Vec::new();
        src_dir.parse_array("const Il2CppGenericInst* const", "g_Il2CppGenericInstTable", "Il2CppGenericInstDefinitions.c")?
            .enumerate()
            .for_each(|(i, str)| {
                let name = str.trim_start_matches('&');
                generic_insts_list.push(name);
                generic_insts.insert(name, i);
            });

        Ok(Self {
            types,
            types_list,
            generic_classes,
            generic_classes_list,
            generic_insts,
            generic_insts_list,
        })
    }
}

impl Il2CppMetadataRegistration {
    pub fn read_src(src_dir: &SourceDir, name_mappings: &NameMappings) -> Result<Self> {
        let generic_classes = Il2CppGenericClass::read_src_all(src_dir, name_mappings)?;
        let generic_insts = Il2CppGenericInst::read_src_all(src_dir, name_mappings)?;
        let generic_method_table = Il2CppGenericMethodFunctionsDefinitions::read_src_all(src_dir)?;
        let types = Il2CppType::read_src_all(src_dir, name_mappings)?;
        let method_specs = Il2CppMethodSpec::read_src_all(src_dir)?;

        Ok(Il2CppMetadataRegistration {
            generic_classes,
            generic_insts,
            generic_method_table,
            array_types: Vec::new(), // TODO
            types,
            method_specs,
            field_offsets: None,
            type_definition_sizes: None,
        })
    }
}

impl<'data> RuntimeMetadata<'data> {
    pub fn read_src(src_dir: &SourceDir) -> Result<Self> {
        let name_mappings = NameMappings::from_src(src_dir)?;
        Ok(RuntimeMetadata {
            code_registration: todo!(),
            metadata_registration: Il2CppMetadataRegistration::read_src(src_dir, &name_mappings)?
        })

    }
}