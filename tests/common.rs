use std::path::Path;

use anyhow::{ensure, Context};

fn read_fixture(path: &str) -> anyhow::Result<Vec<u8>> {
    let base = std::env::var("CARGO_MANIFEST_DIR")?;
    let p = Path::new(&base).join(path);
    std::fs::read(&p).context(format!("reading fixture file {}", p.display()))
}

pub fn run_checks_helper(
    unity_version: &str,
    os: &str,
    lib_name: &str,
) -> Result<(), anyhow::Error> {
    let global_p = format!("tests/{}/{}/global-metadata.dat", unity_version, os);
    let lib_p = format!("tests/{}/{}/{}", unity_version, os, lib_name);

    run_checks(&global_p, &lib_p).context(format!("Unity {unity_version} {os}"))
}

pub fn run_checks(global_p: &str, lib_p: &str) -> Result<(), anyhow::Error> {
    let global = read_fixture(global_p).context("read global metadata fixture")?;
    let lib = read_fixture(lib_p).context("read library fixture")?;

    let md = brocolib::Metadata::parse(&global, &lib).context("metadata")?;

    ensure!(
        !md.global_metadata.type_definitions.as_vec().is_empty(),
        "no type definitions found"
    );
    ensure!(
        !md.global_metadata.images.as_vec().is_empty(),
        "no images found"
    );
    ensure!(
        !md.runtime_metadata.metadata_registration.types.is_empty(),
        "no runtime types found"
    );
    ensure!(
        !md.runtime_metadata
            .code_registration
            .code_gen_modules
            .is_empty(),
        "no codegen modules found"
    );

    let mut found_gameobject = false;
    let mut found_color = false;
    for td in md.global_metadata.type_definitions.as_vec().iter() {
        let full = td.full_name(&md, false);
        if full == "UnityEngine.GameObject" {
            found_gameobject = true;
        }
        if full == "UnityEngine.Color" {
            found_color = true;
        }
        if found_gameobject && found_color {
            break;
        }
    }

    ensure!(
        found_gameobject,
        "UnityEngine.GameObject not found in global metadata"
    );
    ensure!(
        found_color,
        "UnityEngine.Color not found in global metadata"
    );
    Ok(())
}
