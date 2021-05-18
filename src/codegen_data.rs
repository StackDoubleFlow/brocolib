use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Index;

#[derive(Deserialize, Serialize, Debug)]
pub enum TypeEnum {
    Struct,
    Class,
    Enum,
    Interface,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TypeDataThis {
    pub namespace: String,
    pub name: String,
    pub qualified_cpp_name: String,
    pub is_generic_template: bool,
    pub is_nested: bool,
    pub element_type: Option<TypeRef>,
    pub generic_parameter_constraints: Vec<TypeRef>,
    pub generics: Vec<TypeRef>,
}

#[derive(Deserialize, Serialize, Debug)]
pub enum LayoutKind {
    Auto,
    Sequential,
    Explicit,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TypeData {
    pub this: TypeDataThis,
    pub attributes: Vec<Attribute>,
    pub implementing_interfaces: Vec<TypeRef>,
    pub instance_fields: Vec<Field>,
    pub layout: LayoutKind,
    pub methods: Vec<Method>,
    pub nested_types: Vec<TypeData>,
    pub parent: Option<TypeRef>,
    pub properties: Vec<Property>,
    pub specifiers: Vec<String>,
    pub static_fields: Vec<Field>,
    #[serde(rename = "Type")]
    pub type_enum: TypeEnum,
    pub type_def_index: i32,
    pub size: i32,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TypeRef {
    pub namespace: String,
    pub name: String,
    pub type_id: i32,
    pub generics: Vec<TypeRef>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Method {
    pub attributes: Vec<Attribute>,
    pub generic: bool,
    pub generic_parameters: Vec<TypeRef>,
    pub hides_base: bool,
    #[serde(rename = "Il2CppName")]
    pub il2cpp_name: String,
    pub implemented_from: Option<TypeRef>,
    pub is_special_name: bool,
    pub is_virtual: bool,
    pub name: String,
    pub offset: i32,
    pub parameters: Vec<Parameter>,
    pub return_type: TypeRef,
    #[serde(rename = "RVA")]
    pub rva: i32,
    pub slot: i32,
    pub specifiers: Vec<String>,
    #[serde(rename = "VA")]
    pub va: i32,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Field {
    pub attributes: Vec<Attribute>,
    pub name: String,
    pub offset: i32,
    pub layout_offset: i32,
    pub specifiers: Vec<String>,
    #[serde(rename = "Type")]
    pub field_type: TypeRef,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Attribute {
    pub name: String,
    #[serde(rename = "RVA")]
    pub rva: i32,
    pub offset: i32,
    #[serde(rename = "VA")]
    pub va: i32,
}

// #[derive(Deserialize, Debug)]
// pub struct Specifier {
//     #[serde(rename = "Value")]
//     pub value: String,
// }

#[derive(Deserialize, Serialize, Debug)]
pub enum ParameterModifier {
    None,
    Ref,
    Out,
    In,
    Params,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Parameter {
    #[serde(rename = "Type")]
    pub parameter_type: TypeRef,
    pub name: String,
    pub modifier: ParameterModifier,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Property {
    pub attributes: Vec<Attribute>,
    pub specifiers: Vec<String>,
    pub get_method: bool,
    pub set_method: bool,
    pub name: String,
    #[serde(rename = "Type")]
    pub property_type: TypeRef,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DllData {
    pub types: Vec<TypeData>,
}

impl Index<TypeRef> for DllData {
    type Output = TypeData;

    fn index(&self, type_ref: TypeRef) -> &Self::Output {
        &self.types[type_ref.type_id as usize]
    }
}
