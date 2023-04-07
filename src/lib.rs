//! This library provides a convenient way to parse the metadata structures for
//! a Unity IL2CPP game.
//! 
//! The documentation contains many references to C/C++ header source files.
//! You can find these files in a Unity install at the following path:
//! `UnityEditor/2021.3.16f1/Editor/Data/il2cpp/libil2cpp`

pub mod global_metadata;
pub mod runtime_metadata;

use runtime_metadata::elf::Il2CppBinaryError;
use runtime_metadata::RuntimeMetadata;
use global_metadata::{GlobalMetadata, MetadataDeserializeError};
use thiserror::Error;

/// A container for all of the applications metadata structures.
/// 
/// A Unity IL2CPP application stores metadata in two different ways, the
/// global metadata and the runtime metadata.
///
/// The global metadata is generally the `global-metadata.dat` file in the
/// application. See [`GlobalMetadata`] for more information.
///
/// The runtime metadata is stored inside the game binary itself. This is
/// generally the `libil2cpp.so` file in the application. See
/// [`RuntimeMetadata`] for more information.
pub struct Metadata<'gmd, 'rmd> {
    /// The application's global metadata.
    ///
    /// See [`GlobalMetadata`] for more information.
    pub global_metadata: GlobalMetadata<'gmd>,

    /// The application's runtime metadata.
    ///
    /// See [`RuntimeMetadata`] for more information.
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
        let global_metadata = global_metadata::deserialize(global_metadata)?;
        let runtime_metadata = RuntimeMetadata::read_elf(elf, &global_metadata)?;
        Ok(Metadata {
            global_metadata,
            runtime_metadata,
        })
    }
}
