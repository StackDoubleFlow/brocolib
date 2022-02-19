use crate::binary_deserialize::BinaryDeserialize;

// struct Il2CppMethodDefinition {
//     StringIndex nameIndex;
//     TypeDefinitionIndex declaringType;
//     TypeIndex returnType;
//     ParameterIndex parameterStart;
//     GenericContainerIndex genericContainerIndex;
//     uint32_t token;
//     uint16_t flags;
//     uint16_t iflags;
//     uint16_t slot;
//     uint16_t parameterCount;
// }

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
