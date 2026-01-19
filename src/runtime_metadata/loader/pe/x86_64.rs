use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};
use object::Object;

use crate::runtime_metadata::loader::{self, pe::PeFile, vaddr_conv, Il2CppBinaryError};
use iced_x86::Mnemonic;

/// Returns address to (g_CodeRegistration, g_MetadataRegistration)
pub fn find_registration(pe: &PeFile, pe_rel: &[u8]) -> loader::Result<(u64, u64)> {
    /*

                                **************************************************************
                            *                          FUNCTION                          *
                            **************************************************************
                            undefined il2cpp_init()
                              assume GS_OFFSET = 0xff00000000
            undefined         <UNASSIGNED>   <RETURN>
                            0x34cd20  133  il2cpp_init
                            Ordinal_133                                     XREF[3]:     Entry Point(*), 1820304d8(*),
                            il2cpp_init                                                  1824dd290(*)
      18034cd20 40 53           PUSH       RBX
      18034cd22 48 83 ec 20     SUB        RSP,0x20
      18034cd26 48 8b d9        MOV        RBX,RCX
      18034cd29 48 8d 15        LEA        RDX,[DAT_181ebf51c]
                ec 27 b7 01
      18034cd30 33 c9           XOR        ECX,ECX
      18034cd32 e8 7d 11        CALL       setlocale                                        char * setlocale(int _Category,
                03 00
      18034cd37 48 8b cb        MOV        RCX,RBX
      18034cd3a e8 41 43        CALL       FUN_1802e1080                                    undefined FUN_1802e1080()
                f9 ff
      18034cd3f 0f b6 c0        MOVZX      EAX,AL
      18034cd42 48 83 c4 20     ADD        RSP,0x20
      18034cd46 5b              POP        RBX
      18034cd47 c3              RET
      18034cd48 cc              ??         CCh
      18034cd49 cc              ??         CCh
      18034cd4a cc              ??         CCh
      18034cd4b cc              ??         CCh
      18034cd4c cc              ??         CCh
      18034cd4d cc              ??         CCh
      18034cd4e cc              ??         CCh
      18034cd4f cc              ??         CCh

    */
    let il2cpp_init = pe
        .exports()
        .map_err(Il2CppBinaryError::Object)?
        .iter()
        .find(|n| str::from_utf8(n.name()) == Ok("il2cpp_init"))
        .ok_or(Il2CppBinaryError::MissingIl2CppInit)?
        .address();

    let mut code_registration: Option<u64> = None;
    let mut metadata_registration: Option<u64> = None;

    // find `call` to Runtime::Init
    let runtime_init_instr = nth_call(pe, il2cpp_init, 2)? as usize;
    println!("runtime_init_instr: {:#x}", runtime_init_instr);
    assert_eq!(
        0x1802e1080,
        runtime_init_instr,
        "{}",
        runtime_init_instr.wrapping_sub(0x1802e1080)
    );

    println!();
    println!();

    let code_registration_call = nth_indirect_call(pe, runtime_init_instr as u64, 1)?;
    println!("code_registration address: {:#x?}", code_registration);

    assert_eq!(
        0x1802e1187,
        code_registration_call,
        "{}",
        code_registration_call.wrapping_sub(0x1802e1187)
    );

    let runtime_init_instr_vaddr = vaddr_conv(pe, runtime_init_instr as u64)? as usize;
    let code_registration_call_vaddr = vaddr_conv(pe, code_registration_call)? as usize;

    // disassemble Runtime::Init to find the call to s_Il2CppCodegenRegistration
    // it is 1802b4973		CALL qword ptr [->FUN_18019c2a0]	Read
    // find the first indirect call (call via register)
    let instructions = try_disassemble(
        &pe.data()[runtime_init_instr_vaddr..code_registration_call_vaddr as usize],
        runtime_init_instr as u64,
    )?;

    // This relocation points to s_Il2CppCodegenRegistration
    let regs = analyze_reg_rel(pe, pe_rel, &instructions);

    // find this indirect call in Runtime::Init
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
        }
    }

    println!("code_registration address: {:#x?}", code_registration);

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
            let regs = analyze_reg_rel(pe, pe_rel, &instructions);
            let reg = instr.op0_register();
            if let Some(&addr) = regs.get(&reg) {
                metadata_registration = Some(addr);
                break;
            }
        }
    }

    println!(
        "metadata_registration address: {:#x?}",
        metadata_registration
    );

    Ok((
        code_registration.ok_or(Il2CppBinaryError::MissingRegistration)?,
        metadata_registration.ok_or(Il2CppBinaryError::MissingRegistration)?,
    ))
}

/// Analyze instructions to find the values of registers
fn analyze_reg_rel(
    pe: &object::read::pe::PeFile<'_, object::pe::ImageNtHeaders64>,
    pe_rel: &[u8],
    idx: &[Instruction],
) -> HashMap<Register, u64> {
    let mut regs: HashMap<Register, u64> = HashMap::new();

    for ins in idx {
        // helper to read a u64 from a virtual address in the PE
        let read_u64 = |addr: u64| -> Option<u64> {
            if let Ok(off) = vaddr_conv(pe, addr) {
                let off = off as usize;
                if off + 8 <= pe_rel.len() {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&pe_rel[off..off + 8]);
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

fn nth_indirect_call(pe: &PeFile, addr: u64, n: usize) -> loader::Result<u64> {
    let target = matching_call(pe, addr, n, |addr, call| Ok(call.is_call_near_indirect()))?;
    target.ok_or(Il2CppBinaryError::BadInstruction(
        "Could not find nth indirect call".to_string(),
        addr,
    ))
}

/// Find the nth call instruction starting from addr
/// Returns the target address of the call
fn nth_call(pe: &PeFile, addr: u64, n: usize) -> loader::Result<u64> {
    let mut target = None;
    matching_call(pe, addr, n, |addr, ins| {
        target = Some(addr);
        Ok(false)
    })?;
    target.ok_or(Il2CppBinaryError::BadInstruction(
        "Could not find nth call".to_string(),
        addr,
    ))
}

/// Find the nth call instruction starting from addr
/// If the closure returns true, the search stops and the address is returned
/// If the limit is reached, None is returned
///
/// The closure is called with the target address of the call instruction
fn matching_call<F>(elf: &PeFile, addr: u64, limit: usize, mut f: F) -> loader::Result<Option<u64>>
where
    F: FnMut(u64, &Instruction) -> loader::Result<bool>,
{
    // Disassemble a contiguous window of bytes starting at `addr` instead
    // of stepping fixed 4-byte chunks (instructions are variable length).
    let start_off = vaddr_conv(elf, addr)? as usize;
    println!(
        "matching_call: start disassemble at offset {:#x}",
        start_off
    );

    let data = &elf.data()[start_off..];
    let max_bytes = std::cmp::min(data.len(), 0x10000); // cap to avoid huge disassembly
    let instructions = try_disassemble(&data[..max_bytes], addr)?;

    let mut count = 0;
    for ins in &instructions {
        if matches!(ins.flow_control(), iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall) {
            // Only handle direct (near) calls which have an immediate branch target.

            if ins.is_call_near() {
                let target = ins.near_branch_target();
                println!("found call to {:#x}", target);
                if f(target, ins)? {
                    return Ok(Some(target));
                }
            }

            if ins.is_call_far() {
                eprintln!("encountered far call at {:#x}, unsupported", ins.ip());
                continue;
            }

            count += 1;
            if count == limit {
                return Ok(None);
            }
        }
    }

    Ok(None)
}
