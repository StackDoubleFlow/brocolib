//! This library provides a convenient way to parse the metadata structures for
//! a Unity IL2CPP game.
//!
//! The documentation contains many references to C/C++ header source files.
//! You can find these files in a Unity install at the following path:
//! `UnityEditor/2021.3.16f1/Editor/Data/il2cpp/libil2cpp`

pub mod global_metadata;
pub mod runtime_metadata;
#[cfg(feature = "il2cpp_v39")]
pub(crate) mod variable_length_integer;

use global_metadata::{GlobalMetadata, MetadataDeserializeError};
use runtime_metadata::RuntimeMetadata;
use thiserror::Error;

use crate::runtime_metadata::loader::Il2CppBinaryError;

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
    pub fn parse(global_metadata: &'gmd [u8], lib: &'rmd [u8]) -> Result<Self, MetadataParseError> {
        #[cfg(feature = "il2cpp_v31")]
        let global_metadata = global_metadata::deserialize(global_metadata)?;
        // v39's global metadata needs the runtime types count up front to
        // size its variable-width `TypeIndex` fields, so peek it from the
        // binary before global metadata (which `read_obj` itself needs) can
        // be parsed. See `runtime_metadata::loader::peek_types_count`.
        #[cfg(feature = "il2cpp_v39")]
        let global_metadata = {
            let types_count = runtime_metadata::loader::peek_types_count(lib)?;
            global_metadata::deserialize(global_metadata, types_count)?
        };
        let runtime_metadata = RuntimeMetadata::read_obj(lib, &global_metadata)?;

        Ok(Metadata {
            global_metadata,
            runtime_metadata,
        })
    }
}
