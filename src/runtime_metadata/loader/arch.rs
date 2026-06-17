use object::Object;

use super::object_reader::ObjectReader;
use super::{Il2CppBinaryError, Result};

#[cfg(feature = "aarch64")]
pub mod aarch64;
#[cfg(feature = "x86_64")]
pub mod x86_64;

pub fn find_registration(obj: &ObjectReader) -> Result<(u64, u64)> {
    let arch = obj.file().architecture();
    match arch {
        #[cfg(feature = "aarch64")]
        object::Architecture::Aarch64 => aarch64::find_registration(obj),
        #[cfg(feature = "x86_64")]
        object::Architecture::X86_64 => x86_64::find_registration(obj),
        _ => return Err(Il2CppBinaryError::UnsupportedArchitecture(arch)),
    }
}
