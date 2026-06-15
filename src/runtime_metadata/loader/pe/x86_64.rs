use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};
use object::Object;

use crate::runtime_metadata::loader::{self, pe::PeFile, read_u64, vaddr_conv, Il2CppBinaryError};

/// Returns address to (g_CodegenRegistration, g_MetadataRegistration)
pub fn find_registration(pe: &PeFile, pe_rel: &[u8]) -> loader::Result<(u64, u64)> {
    // il2cpp_init -> Runtime::Init -> s_Il2CppCodegenRegistration
    // From there, we read the arguments being passed into il2cpp_codegen_register

    let il2cpp_init = pe
        .exports()
        .map_err(Il2CppBinaryError::Object)?
        .iter()
        .find(|n| str::from_utf8(n.name()) == Ok("il2cpp_init"))
        .ok_or(Il2CppBinaryError::MissingIl2CppInit)?
        .address();

    let runtime_init_instr = nth_call(pe, il2cpp_init, 2)? as usize;
    let code_registration = nth_indirect_call(pe, pe_rel, runtime_init_instr as u64, 3)?
        .ok_or(Il2CppBinaryError::MissingRegistration)?;

    // Collect the arguments to il2cpp_codegen_register
    let il2cpp_codegen_register_call =
        nth_matching(pe, code_registration, 1, |t| t.is_jmp_short_or_near())?;
    let start_offset = vaddr_conv(pe, code_registration)? as usize;
    let call_instr_offset = vaddr_conv(pe, il2cpp_codegen_register_call)? as usize;
    let instructions = try_disassemble(
        &pe.data()[start_offset as usize..call_instr_offset],
        code_registration,
    )?;
    let regs = analyze_reg_rel(pe, pe_rel, &instructions)?;

    Ok((regs[&Register::RCX], regs[&Register::RDX]))
}

/// Simple static register analysis for RIP-relative memory loads.
/// Tracks the latest known values of registers in straight-line code.
///
/// # Arguments
/// * `pe` - The PE file
/// * `pe_rel` - Raw PE file data with relocations applied
/// * `instructions` - Slice of Instructions to analyze
pub fn analyze_reg_rel(
    _pe: &PeFile,
    _pe_rel: &[u8],
    instructions: &[Instruction],
) -> loader::Result<HashMap<Register, u64>> {
    let mut registry: HashMap<Register, u64> = HashMap::new();

    for instr in instructions {
        match instr.code() {
            // lea reg, [disp]
            iced_x86::Code::Lea_r64_m => {
                let reg = instr.op0_register();
                let addr = instr.memory_displacement64();
                registry.insert(reg, addr);
            }

            _ => {}
        }
    }

    Ok(registry)
}

fn try_disassemble(code: &[u8], start_addr: u64) -> loader::Result<Vec<Instruction>> {
    let decoder = Decoder::with_ip(64, code, start_addr, DecoderOptions::NONE);

    Ok(decoder.into_iter().collect::<Vec<Instruction>>())
}

fn nth_indirect_call(
    pe: &PeFile,
    pe_rel: &[u8],
    start_vaddr: u64,
    n: usize,
) -> loader::Result<Option<u64>> {
    let decoder = Decoder::with_ip(
        64,
        &pe.data()[vaddr_conv(pe, start_vaddr)? as usize..],
        start_vaddr,
        DecoderOptions::NONE,
    );

    let Some(indirect_call) = decoder
        .into_iter()
        .filter(|t| t.is_call_near_indirect())
        .nth(n - 1)
    else {
        return Ok(None);
    };

    // ---- Resolve the indirect call target ----

    let target = match indirect_call.op0_kind() {
        // ---------------------------------------
        // call qword ptr [disp]
        // ---------------------------------------
        OpKind::Memory => {
            let addr = indirect_call.memory_displacement64();
            read_u64(pe, addr, pe_rel)?
        }

        _ => {
            return Err(Il2CppBinaryError::BadInstruction(
                "Unsupported indirect call operand".to_string(),
                indirect_call.ip(),
            ));
        }
    };

    Ok(Some(target))
}

/// Find the nth call instruction starting from addr. n=1 is the first call.
/// Returns the target address of the call
fn nth_call(pe: &PeFile, addr: u64, n: usize) -> loader::Result<u64> {
    let decoder = Decoder::with_ip(
        64,
        &pe.data()[vaddr_conv(pe, addr)? as usize..],
        addr,
        DecoderOptions::NONE,
    );
    let call_instr = decoder
        .into_iter()
        .filter(|t| t.is_call_near())
        .nth(n - 1)
        .ok_or_else(|| {
            Il2CppBinaryError::BadInstruction("Could not find nth call".to_string(), addr)
        })?;

    Ok(call_instr.near_branch_target())
}

/// Returns the address of the nth instruction that matches the predicate
fn nth_matching(
    pe: &PeFile,
    addr: u64,
    n: usize,
    predicate: impl Fn(&Instruction) -> bool,
) -> loader::Result<u64> {
    let decoder = Decoder::with_ip(
        64,
        &pe.data()[vaddr_conv(pe, addr)? as usize..],
        addr,
        DecoderOptions::NONE,
    );

    let instr = decoder
        .into_iter()
        .filter(|t| predicate(t))
        .nth(n - 1)
        .ok_or_else(|| {
            Il2CppBinaryError::BadInstruction(
                "Could not find nth matching instruction".to_string(),
                addr,
            )
        })?;

    Ok(instr.ip())
}
