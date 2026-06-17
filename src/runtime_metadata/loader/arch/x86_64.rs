use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};

use crate::runtime_metadata::loader::{self, Il2CppBinaryError, object_reader::ObjectReader};

/// Returns address to (g_CodegenRegistration, g_MetadataRegistration)
pub fn find_registration(obj: &ObjectReader) -> loader::Result<(u64, u64)> {
    // il2cpp_init -> Runtime::Init -> s_Il2CppCodegenRegistration
    // From there, we read the arguments being passed into il2cpp_codegen_register
    let il2cpp_init = obj
        .find_export("il2cpp_init")?
        .ok_or(Il2CppBinaryError::MissingIl2CppInit)?;

    let runtime_init = nth_call(obj, il2cpp_init, 2)? as usize;
    let code_registration = nth_indirect_call(
        obj,
        runtime_init as u64,
        if obj.format() == object::BinaryFormat::Pe {
            // On windows, there are extra calls to Thread::GetCurrentThreadId and SystemFutex::Wait in il2cpp_baselib.
            // These are not present in linux as they are instead standard syscalls.
            3
        } else {
            1
        },
    )?
    .ok_or(Il2CppBinaryError::MissingRegistration)?;

    // Collect the arguments to il2cpp_codegen_register
    let il2cpp_codegen_register_call =
        nth_matching(obj, code_registration, 1, |t| t.is_jmp_short_or_near())?;
    let start_offset = obj.vaddr_conv(code_registration)? as usize;
    let call_instr_offset = obj.vaddr_conv(il2cpp_codegen_register_call)? as usize;
    let instructions = try_disassemble(
        &obj.data()[start_offset as usize..call_instr_offset],
        code_registration,
    )?;
    let regs = analyze_reg_rel(obj, &instructions)?;

    Ok(if obj.format() == object::BinaryFormat::Pe {
        // Microsoft x64 calling convention
        (regs[&Register::RCX], regs[&Register::RDX])
    } else {
        // System V AMD64 ABI
        (regs[&Register::RDI], regs[&Register::RSI])
    })
}

/// Simple static register analysis for RIP-relative memory loads.
/// Tracks the latest known values of registers in straight-line code.
///
/// # Arguments
/// * `pe` - The PE file
/// * `instructions` - Slice of Instructions to analyze
pub fn analyze_reg_rel(
    obj: &ObjectReader,
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

            // mov reg, [disp]
            iced_x86::Code::Mov_r64_rm64 => {
                let reg = instr.op0_register();
                if let Some(addr) = mem_operand_target(instr, 1, &registry)
                    && let Ok(val) = obj.read_u64(addr)
                {
                    registry.insert(reg, val);
                }
            }

            _ => {}
        }
    }

    Ok(registry)
}

fn mem_operand_target(
    instr: &Instruction,
    operand: u32,
    regs: &HashMap<Register, u64>,
) -> Option<u64> {
    instr.virtual_address(operand, 0, |reg, _, _| {
        match reg {
            // The base address of ES, CS, SS and DS is always 0 in 64-bit mode
            Register::ES | Register::CS | Register::SS | Register::DS => Some(0),
            _ => regs.get(&reg).cloned(),
        }
    })
}

fn try_disassemble(code: &[u8], start_addr: u64) -> loader::Result<Vec<Instruction>> {
    let decoder = Decoder::with_ip(64, code, start_addr, DecoderOptions::NONE);

    Ok(decoder.into_iter().collect::<Vec<Instruction>>())
}

fn nth_indirect_call(
    obj: &ObjectReader,
    start_vaddr: u64,
    n: usize,
) -> loader::Result<Option<u64>> {
    let start_offset = obj.vaddr_conv(start_vaddr)?;
    let decoder = Decoder::with_ip(
        64,
        &obj.data()[start_offset as usize..],
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
        OpKind::Memory => {
            // Determine reg values that may be used as part of memory operand
            let call_offset = obj.vaddr_conv(indirect_call.ip())?;
            let instructions = try_disassemble(
                &obj.data()[start_offset as usize..call_offset as usize],
                start_vaddr,
            )?;
            let regs = analyze_reg_rel(obj, &instructions)?;

            let addr = mem_operand_target(&indirect_call, 0, &regs).ok_or_else(|| {
                Il2CppBinaryError::BadInstruction(indirect_call.to_string(), indirect_call.ip())
            })?;

            obj.read_u64(addr)?
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
fn nth_call(obj: &ObjectReader, addr: u64, n: usize) -> loader::Result<u64> {
    let decoder = Decoder::with_ip(
        64,
        &obj.data()[obj.vaddr_conv(addr)? as usize..],
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
    obj: &ObjectReader,
    addr: u64,
    n: usize,
    predicate: impl Fn(&Instruction) -> bool,
) -> loader::Result<u64> {
    let decoder = Decoder::with_ip(
        64,
        &obj.data()[obj.vaddr_conv(addr)? as usize..],
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
