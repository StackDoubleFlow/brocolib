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
    pe: &PeFile,
    pe_rel: &[u8],
    instructions: &[Instruction],
) -> loader::Result<HashMap<Register, u64>> {
    let mut registry: HashMap<Register, u64> = HashMap::new();

    for instr in instructions {
        match instr.code() {
            // mov reg, imm64
            iced_x86::Code::Mov_r64_imm64 => {
                if let OpKind::Register = instr.op0_kind() {
                    if let OpKind::Immediate64 = instr.op1_kind() {
                        let reg = instr.op0_register();
                        let val = instr.immediate64();
                        registry.insert(reg, val);
                    }
                }
            }

            // mov reg, [rip+disp]
            iced_x86::Code::Mov_r64_rm64 => {
                if let OpKind::Register = instr.op0_kind() {
                    if let OpKind::Memory = instr.op1_kind() {
                        let reg = instr.op0_register();
                        let base = instr.memory_base();

                        // displacements can be 4 or 8 bytes. If 4 bytes, they are
                        // signed 32-bit and must be sign-extended before adding.
                        let disp_signed: i64 = if instr.memory_displ_size() == 4 {
                            instr.memory_displacement32() as i64
                        } else {
                            instr.memory_displacement64() as i64
                        };

                        let addr = if base == Register::RIP {
                            (instr.ip() as i64 + instr.len() as i64 + disp_signed) as u64
                        } else if let Some(base_val) = registry.get(&base) {
                            (*base_val as i64 + disp_signed) as u64
                        } else {
                            continue; // cannot resolve base
                        };

                        // convert virtual address to file offset and read 8 bytes
                        let file_off = vaddr_conv(pe, addr)?;
                        if let Some(val_bytes) =
                            pe_rel.get(file_off as usize..file_off as usize + 8)
                        {
                            let val = u64::from_le_bytes(val_bytes.try_into().unwrap());
                            registry.insert(reg, val);
                        }
                    }
                }
            }

            // add reg, imm64
            iced_x86::Code::Add_rm64_imm32 | iced_x86::Code::Add_rm64_imm8 => {
                if let OpKind::Register = instr.op0_kind() {
                    let reg = instr.op0_register();
                    if let Some(cur) = registry.get_mut(&reg) {
                        let imm = instr.immediate64();
                        *cur = cur.wrapping_add(imm);
                    }
                }
            }

            // mov reg, reg (copy)
            iced_x86::Code::Mov_rm64_r64 => {
                if let (OpKind::Register, OpKind::Register) = (instr.op0_kind(), instr.op1_kind()) {
                    let dst = instr.op0_register();
                    let src = instr.op1_register();
                    if let Some(val) = registry.get(&src).copied() {
                        registry.insert(dst, val);
                    }
                }
            }

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
        // call qword ptr [rip + disp]
        // ---------------------------------------
        OpKind::Memory => {
            let addr = indirect_call.memory_displacement64();
            read_u64(pe, addr, pe_rel)?
        }

        // ---------------------------------------
        // call rax / call rcx / etc
        // ---------------------------------------
        OpKind::Register => {
            let start_offset = vaddr_conv(pe, start_vaddr)? as usize;
            let call_instr_offset = vaddr_conv(pe, indirect_call.ip())? as usize;
            let instructions = try_disassemble(
                &pe.data()[start_offset as usize..call_instr_offset],
                start_vaddr,
            )?;
            let registry: HashMap<Register, u64> = analyze_reg_rel(pe, pe_rel, &instructions)?;

            let reg = indirect_call.op0_register();
            let target = *registry.get(&reg).ok_or_else(|| {
                Il2CppBinaryError::BadInstruction(
                    format!("Unresolved register {:?}", reg),
                    indirect_call.ip(),
                )
            })?;
            target
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
