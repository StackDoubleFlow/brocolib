use binde::BinaryDeserialize;

#[derive(BinaryDeserialize)]
pub struct Il2CppMethodDefinition {
    pub name_index: i32,
    pub declaring_type: i32,
    pub return_type: i32,
    pub parameter_start: i32,
    pub generic_container_index: i32,
    pub token: u32,
    pub flags: u16,
    pub iflags: u16,
    pub slot: u16,
    pub parameter_count: u16,
}

#[derive(BinaryDeserialize)]
pub struct Il2CppParameterDefinition {
    pub name_index: i32,
    pub token: u32,
    pub type_index: i32,
}

#[derive(BinaryDeserialize)]
pub struct Il2CppTypeDefinition {
    pub name_index: i32,
    pub namespace_index: i32,
    pub byval_type_index: i32,
    pub byref_type_index: i32,

    pub declaring_type_index: i32,
    pub parent_index: i32,
    pub element_type_index: i32,

    pub generic_container_index: i32,

    pub flags: u32,

    pub field_start: i32,
    pub method_start: i32,
    pub event_start: i32,
    pub property_start: i32,
    pub nested_types_start: i32,
    pub interfaces_start: i32,
    pub vtable_start: i32,
    pub interface_offsets_start: i32,

    pub method_count: u16,
    pub property_count: u16,
    pub field_count: u16,
    pub event_count: u16,
    pub nested_type_count: u16,
    pub vtable_count: u16,
    pub interfaces_count: u16,
    pub interface_offsets_count: u16,

    pub bitfield: u32,
    pub token: u32,
}

#[derive(BinaryDeserialize)]
pub struct Il2CppImageDefinition {
    pub name_index: i32,
    pub assembly_index: i32,

    pub type_start: i32,
    pub type_count: u32,

    pub exported_type_start: i32,
    pub exported_type_count: u32,

    pub entry_point_index: i32,
    pub token: u32,

    pub custom_attribute_start: i32,
    pub custom_attribute_count: u32,
}

#[derive(BinaryDeserialize)]
pub struct Il2CppFieldDefinition {
    pub name_index: i32,
    pub type_index: i32,
    pub token: u32,
}
