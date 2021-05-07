mod codegen_data;

use anyhow::{Context, Result};
use codegen_data::DllData;
use std::fs::File;
use std::path::Path;

fn read_dll_data() -> Result<DllData> {
    Ok(if Path::new("codegen.bc").exists() {
        let input = File::open("codegen.bc").context("Failed to open JSON dump cache")?;
        bincode::deserialize_from(input).context("Failed to parse JSON dump cache")?
    } else {
        let input = File::open("codegen.json").context("Failed to open JSON dump")?;
        let dll_data: DllData =
            serde_json::from_reader(input).context("Failed to parse JSON dump")?;
        let cache_file = File::create("codegen.bc").context("Failed to create JSON dump cache")?;
        bincode::serialize_into(cache_file, &dll_data)
            .context("Failed to serialize JSON dump cache")?;
        dll_data
    })
}

fn main() -> Result<()> {
    let dll_data = read_dll_data()?;

    println!("Done reading data");

    Ok(())
}
