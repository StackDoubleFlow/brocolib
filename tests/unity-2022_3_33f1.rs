mod common;
use anyhow::Context;

const VERSION: &str = "unity-2022.3.33f1";
// ELF tests (linux/android). Compiled only when `elf` feature is enabled.
#[cfg(feature = "elf")]
mod elf_tests {
    use super::*;

    #[test]
    #[cfg(feature = "x86_64")]
    fn elf_linux_fixture() -> anyhow::Result<()> {
        common::run_checks_helper(VERSION, "linux", "GameAssembly.so")
            .context("running linux elf fixture")
    }

    #[test]
    #[cfg(feature = "aarch64")]
    fn elf_android_fixture() -> anyhow::Result<()> {
        common::run_checks_helper(VERSION, "android", "libil2cpp.so")
            .context("running android elf fixture")
    }
}

// PE tests (windows). Compiled only when `pe` feature is enabled.
#[cfg(feature = "pe")]
mod pe_tests {
    use super::*;

    #[test]
    #[cfg(feature = "x86_64")]
    fn pe_windows_fixture() -> anyhow::Result<()> {
        common::run_checks_helper(VERSION, "windows", "GameAssembly.dll")
            .context("running windows pe fixture")
    }
}
