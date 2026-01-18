use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};
use object::{Object, ObjectSymbol};

use crate::runtime_metadata::loader::{self, pe::PeFile, vaddr_conv, Il2CppBinaryError};
use iced_x86::Mnemonic;

/// Returns address to (g_CodeRegistration, g_MetadataRegistration)
pub fn find_registration(pe: &PeFile) -> loader::Result<(u64, u64)> {
    let il2cpp_init = pe
        .dynamic_symbols()
        .find(|s| s.name() == Ok("il2cpp_init"))
        .ok_or(Il2CppBinaryError::MissingIl2CppInit)?
        .address();
    let mut code_registration: Option<u64> = None;
    let mut metadata_registration: Option<u64> = None;

    // find `call` to Runtime::Init
    let runtime_init_instr = nth_call(pe, il2cpp_init, 1)?;
    let runtime_init_instr = vaddr_conv(pe, runtime_init_instr)? as usize;

    // disassemble Runtime::Init to find the call to s_Il2CppCodegenRegistration
    // it is 1802b4973		CALL qword ptr [->FUN_18019c2a0]	Read
    // find the first indirect call (call via register)

    let instructions = try_disassemble(
        &pe.data()[runtime_init_instr..runtime_init_instr + 200],
        runtime_init_instr as u64,
    )?;

    // find this indirect call
    /*
          1802b4973 ff 15 cf        CALL       qword ptr [->FUN_18019c2a0]                      undefined FUN_18019c2a0()
                d5 9a 02                                                                    = 18019c2a0

    */
    for instr in &instructions {
        if instr.is_call_near_indirect()
            && instr.op0_kind() == OpKind::Memory
            && instr.memory_base() == Register::RIP
        {
            let target_addr = instr.near_branch_target();
            let target_offset = vaddr_conv(pe, target_addr)? as usize;
            let code = &pe.data()[target_offset..target_offset + 7 * 4];
            let instructions = try_disassemble(code, target_addr)?;

            // Look for the first 2 store instructions

            for (idx, ins) in instructions.iter().enumerate() {
                match (ins.mnemonic(), ins.op_count()) {
                    (iced_x86::Mnemonic::Mov, 2)
                        if ins.op0_kind() == OpKind::Memory
                            && ins.op1_kind() == OpKind::Register =>
                    {
                        let regs = analyze_reg_rel(pe, &instructions[0..idx]);
                        if let Some(code_registration) = code_registration {
                            return Ok((code_registration, regs[&ins.op1_register()]));
                        } else {
                            code_registration = Some(regs[&ins.op1_register()]);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // now to find s_Il2CppMetadataRegistration, we look for call to MetadataCache::Initialize,
    // immediately after codegen registration store and call

    /*
              1802b4979 e8 62 a1        CALL       FUN_1802ceae0                                    undefined FUN_1802ceae0()
                    01 00
    */
    let metadata_cache_init_instr = nth_call(pe, il2cpp_init, 1)?;
    let metadata_cache_init_offset = vaddr_conv(pe, metadata_cache_init_instr)? as usize;

    // time to find the address of g_MetadataRegistration
    // in the following asm, it is `DAT_182ef38d0`

    /*
              1802ceb17 48 8b 0d        MOV        RCX,qword ptr [DAT_182ef38d0]
                    b2 4d c2 02
          1802ceb1e 8b 11           MOV        EDX,dword ptr [RCX]
    */
    let instructions = try_disassemble(
        &pe.data()[metadata_cache_init_offset..metadata_cache_init_offset + 100],
        metadata_cache_init_instr,
    )?;
    for instr in &instructions {
        if instr.mnemonic() == Mnemonic::Mov
            && instr.op_count() == 2
            && instr.op0_kind() == OpKind::Register
            && instr.op1_kind() == OpKind::Memory
        {
            let regs = analyze_reg_rel(pe, &instructions);
            let reg = instr.op0_register();
            if let Some(&addr) = regs.get(&reg) {
                metadata_registration = Some(addr);
                break;
            }
        }
    }

    Ok((
        code_registration.ok_or(Il2CppBinaryError::MissingRegistration)?,
        metadata_registration.ok_or(Il2CppBinaryError::MissingRegistration)?,
    ))
}

/// Analyze instructions to find the values of registers
fn analyze_reg_rel(
    pe: &object::read::pe::PeFile<'_, object::pe::ImageNtHeaders64>,
    idx: &[Instruction],
) -> HashMap<Register, u64> {
    let mut regs: HashMap<Register, u64> = HashMap::new();

    for ins in idx {
        // helper to read a u64 from a virtual address in the PE
        let read_u64 = |addr: u64| -> Option<u64> {
            if let Ok(off) = vaddr_conv(pe, addr) {
                let off = off as usize;
                let data = pe.data();
                if off + 8 <= data.len() {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&data[off..off + 8]);
                    return Some(u64::from_le_bytes(arr));
                }
            }
            None
        };

        match ins.mnemonic() {
            Mnemonic::Mov => {
                if ins.op_count() >= 2 && ins.op0_kind() == OpKind::Register {
                    let dst = ins.op0_register();

                    match ins.op1_kind() {
                        // mov reg, imm
                        OpKind::Immediate8
                        | OpKind::Immediate16
                        | OpKind::Immediate32
                        | OpKind::Immediate64 => {
                            regs.insert(dst, ins.immediate64());
                        }

                        // mov reg, reg
                        OpKind::Register => {
                            let src = ins.op1_register();
                            if let Some(&v) = regs.get(&src) {
                                regs.insert(dst, v);
                            }
                        }

                        // mov reg, [mem]
                        OpKind::Memory => {
                            // rip-relative: address = ip + len + disp
                            if ins.memory_base() == Register::RIP {
                                let addr = ins
                                    .ip()
                                    .wrapping_add(ins.len() as u64)
                                    .wrapping_add(ins.memory_displacement64());
                                if let Some(v) = read_u64(addr) {
                                    regs.insert(dst, v);
                                }
                            } else {
                                // base register + disp (if base value known)
                                let base = ins.memory_base();
                                if base != Register::None {
                                    if let Some(&base_val) = regs.get(&base) {
                                        let addr =
                                            base_val.wrapping_add(ins.memory_displacement64());
                                        if let Some(v) = read_u64(addr) {
                                            regs.insert(dst, v);
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            Mnemonic::Lea => {
                if ins.op_count() >= 2
                    && ins.op0_kind() == OpKind::Register
                    && ins.op1_kind() == OpKind::Memory
                {
                    let dst = ins.op0_register();
                    if ins.memory_base() == Register::RIP {
                        let addr = ins
                            .ip()
                            .wrapping_add(ins.len() as u64)
                            .wrapping_add(ins.memory_displacement64());
                        regs.insert(dst, addr);
                    } else {
                        let base = ins.memory_base();
                        if base != Register::None {
                            if let Some(&base_val) = regs.get(&base) {
                                let addr = base_val.wrapping_add(ins.memory_displacement64());
                                regs.insert(dst, addr);
                            }
                        }
                    }
                }
            }

            Mnemonic::Xor => {
                // xor reg, reg -> zero the register
                if ins.op_count() >= 2
                    && ins.op0_kind() == OpKind::Register
                    && ins.op1_kind() == OpKind::Register
                {
                    let dst = ins.op0_register();
                    let src = ins.op1_register();
                    if dst == src {
                        regs.insert(dst, 0);
                    }
                }
            }

            _ => {}
        }
    }
    regs
}

fn try_disassemble(code: &[u8], addr: u64) -> loader::Result<Vec<Instruction>> {
    let decoder = Decoder::with_ip(64, code, addr, DecoderOptions::NONE);

    Ok(decoder.into_iter().collect::<Vec<Instruction>>())
}

fn nth_call(pe: &PeFile, addr: u64, n: usize) -> loader::Result<u64> {
    let mut target = None;
    matching_call(pe, addr, n, |addr| {
        target = Some(addr);
        Ok(false)
    })?;
    Ok(target.unwrap())
}

/// Find the nth call instruction starting from addr
/// If the closure returns true, the search stops and the address is returned
/// If the limit is reached, None is returned
///
/// The closure is called with the target address of the call instruction
fn matching_call<F>(elf: &PeFile, addr: u64, limit: usize, mut f: F) -> loader::Result<Option<u64>>
where
    F: FnMut(u64) -> loader::Result<bool>,
{
    // https://docs.rs/iced-x86/latest/iced_x86/#get-the-virtual-address-of-a-memory-operand
    let offset = vaddr_conv(elf, addr)? as usize;
    let mut count = 0;

    for i in 0.. {
        let offset = offset + i * 4;
        let code = &elf.data()[offset..offset + 4];
        let ins = &try_disassemble(code, addr + i as u64 * 4)?[0];

        if ins.flow_control() == iced_x86::FlowControl::Call {
            let target = ins.near_branch_target();
            if f(target)? {
                return Ok(Some(target));
            }
            count += 1;
            if count == limit {
                return Ok(None);
            }
        }
    }

    unreachable!()
}
