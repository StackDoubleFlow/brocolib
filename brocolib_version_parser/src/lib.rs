const SANITY: u32 = 0xFAB11BAF;

// struct Il2CppHeaderSimple {
//     sanity: u32,
//     version: u32,
// }

/// Parses the first 8 bytes of the given data to extract the Il2Cpp version if the sanity check passes.
/// The first 4 bytes are expected to be the sanity value (0xFAB11BAF) in little-endian format, and the next 4 bytes are the version number.
/// Returns `Some(version)` if the sanity check passes, or `None` if it fails or if the data is too short.
pub fn get_il2cpp_version(data: &[u8]) -> Option<u32> {
    // deserialize little endian
    let sanity = u32::from_le_bytes(data[0..4].try_into().ok()?);

    if sanity != SANITY {
        return None;
    }

    let version = u32::from_le_bytes(data[4..8].try_into().ok()?);

    Some(version)
}