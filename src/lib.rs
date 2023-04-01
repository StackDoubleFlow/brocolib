use il2cpp_elf::{Il2CppBinaryError, RuntimeMetadata};
use il2cpp_global_metadata::{GlobalMetadata, MetadataDeserializeError};
use thiserror::Error;

pub struct Metadata<'gmd, 'rmd> {
    pub global_metadata: GlobalMetadata<'gmd>,
    pub runtime_metadata: RuntimeMetadata<'rmd>,
}

#[derive(Error, Debug)]
pub enum MetadataParseError {
    #[error("could not parse global metadata")]
    GlobalMetadata(#[from] MetadataDeserializeError),

    #[error("could not parse runtime metadata")]
    Binary(#[from] Il2CppBinaryError),
}

impl<'gmd, 'rmd> Metadata<'gmd, 'rmd> {
    pub fn parse(global_metadata: &'gmd [u8], elf: &'rmd [u8]) -> Result<Self, MetadataParseError> {
        let global_metadata = il2cpp_global_metadata::deserialize(global_metadata)?;
        let runtime_metadata = RuntimeMetadata::read_elf(elf, &global_metadata)?;
        Ok(Metadata {
            global_metadata,
            runtime_metadata,
        })
    }
}
