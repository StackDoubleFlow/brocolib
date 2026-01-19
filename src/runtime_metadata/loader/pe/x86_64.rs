use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};
use object::{Object, ObjectSection};

use crate::runtime_metadata::loader::{self, pe::PeFile, vaddr_conv, Il2CppBinaryError};
use iced_x86::Mnemonic;

/// Returns address to (g_CodegenRegistration, g_MetadataRegistration)
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
    let runtime_init_instr = nth_call(pe, il2cpp_init, 1)? as usize;
    println!("runtime_init_instr: {:#x}", runtime_init_instr);
    assert_eq!(
        0x1802e1080,
        runtime_init_instr,
        "{}",
        runtime_init_instr.abs_diff(0x1802e1080)
    );

    println!();
    println!("code_registration search:");

    // disassemble Runtime::Init to find the call to s_Il2CppCodegenRegistration
    // find the first indirect call (call via register)
    // find this indirect call in Runtime::Init
    /*
          1802b4973 ff 15 cf        CALL       qword ptr [->FUN_18019c2a0]                      undefined FUN_18019c2a0()
                d5 9a 02                                                                    = 18019c2a0

    */
    code_registration = nth_indirect_call(pe, pe_rel, runtime_init_instr as u64, 2)?;
    println!("code_registration_global: {:#x?}", code_registration);

    if let Some(code_registration) = code_registration {
        assert_eq!(
            0x1802e118d,
            code_registration,
            "0x{:x}",
            code_registration.abs_diff(0x1802e118d)
        );

        // now to find s_Il2CppMetadataRegistration, we look for call to MetadataCache::Initialize,
        // immediately after codegen registration store and call

        /*
                  1802b4979 e8 62 a1        CALL       FUN_1802ceae0                                    undefined FUN_1802ceae0()
                        01 00
        */

        // this is MetadataCache::Initialize
        let metadata_cache_init_call = nth_call(
            pe,
            code_registration, // after the store and call
            0,
        )?;
        let metadata_cache_init_call_vaddr = vaddr_conv(pe, metadata_cache_init_call)? as usize;

        debug_assert_eq!(
            0x180336250,
            metadata_cache_init_call,
            "0x{:x}",
            metadata_cache_init_call.abs_diff(0x180336250)
        );

        // s_MetadataRegistration is the first argument to MetadataCache::Initialize which is dereferenced [DAT_1821f1c28]

        /*
                18033628f 48 8b 0d        MOV        RCX,qword ptr [DAT_1821f1c28]
                  92 b9 eb 01
        180336296 8b 11           MOV        EDX,dword ptr [RCX]
        180336298 48 8b 49 08     MOV        RCX,qword ptr [RCX + 0x8]

        18033629c e8 5f f6        CALL       FUN_180345900                                    undefined FUN_180345900()
            00 00


          */
        // we need to disassemble to the 2nd call to get the parameters
        let decoder = Decoder::with_ip(
            64,
            &pe.data()[metadata_cache_init_call_vaddr..],
            runtime_init_instr as u64,
            DecoderOptions::NONE,
        );

        // il2cpp::metadata::GenericMetadata::RegisterGenericClasses(
        //  s_MetadataCache_Il2CppMetadataRegistration->genericClasses,
        //  s_MetadataCache_Il2CppMetadataRegistration->genericClassesCount
        // )
        let register_generic_classes_call = decoder
            .into_iter()
            .inspect(|i| {
                println!(
                    "{:#016x} {:<10} {}",
                    i.ip(),
                    format!("{:?}", i.mnemonic()),
                    i
                );
            })
            .filter(|t| t.is_call_near())
            .nth(1)
            .ok_or(Il2CppBinaryError::BadInstruction(
                "Could not find 2nd call to MetadataCache::Initialize".to_string(),
                runtime_init_instr as u64,
            ))?;
        let register_generic_classes_call_vaddr =
            vaddr_conv(pe, register_generic_classes_call.ip())? as usize;

        debug_assert_eq!(
            0x18033629c,
            register_generic_classes_call.ip(),
            "0x{:x}",
            register_generic_classes_call.ip().abs_diff(0x18033629c)
        );

        let registry = analyze_reg_rel(
            pe,
            pe_rel,
            &try_disassemble(
                &pe.data()[metadata_cache_init_call_vaddr..register_generic_classes_call_vaddr],
                runtime_init_instr as u64,
            )?,
        )?;

        // finally get s_Il2CppMetadataRegistration
        metadata_registration = registry.get(&Register::RCX).copied();
        debug_assert_eq!(
            0x1821f1c28,
            metadata_registration.unwrap(),
            "0x{:x}",
            metadata_registration.unwrap().abs_diff(0x1821f1c28)
        );
    }

    // time to find the address of g_MetadataRegistration
    // in the following asm, it is `DAT_182ef38d0`

    /*
              1802ceb17 48 8b 0d        MOV        RCX,qword ptr [DAT_182ef38d0]
                    b2 4d c2 02
          1802ceb1e 8b 11           MOV        EDX,dword ptr [RCX]
    */

    println!(
        "metadata_registration address: {:#x?}",
        metadata_registration
    );

    Ok((
        code_registration.ok_or(Il2CppBinaryError::MissingRegistration)?,
        metadata_registration.ok_or(Il2CppBinaryError::MissingRegistration)?,
    ))
}

/// Simple static register analysis for RIP-relative memory loads.
/// Tracks the latest known values of registers in straight-line code.
///
/// # Arguments
/// * `pe` - The PE file (needed if you want file-to-VA mapping; optional here)
/// * `pe_rel` - Virtual memory image of the PE
/// * `idx` - Slice of Instructions to analyze
///
/// # Returns
/// HashMap mapping `Register` → known `u64` value
///
/// Generated by AI
pub fn analyze_reg_rel(
    pe: &PeFile,
    pe_rel: &[u8],
    idx: &[Instruction],
) -> loader::Result<HashMap<Register, u64>> {
    let mut registry: HashMap<Register, u64> = HashMap::new();

    for instr in idx {
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

            _ => {}
        }
    }

    Ok(registry)
}

fn try_disassemble(code: &[u8], addr: u64) -> loader::Result<Vec<Instruction>> {
    let decoder = Decoder::with_ip(64, code, addr, DecoderOptions::NONE);

    Ok(decoder.into_iter().collect::<Vec<Instruction>>())
}

fn nth_indirect_call(
    pe: &PeFile,
    pe_rel: &[u8],
    start_addr: u64,
    n: usize,
) -> loader::Result<Option<u64>> {
    let decoder = Decoder::with_ip(
        64,
        &pe.data()[vaddr_conv(pe, start_addr)? as usize..],
        start_addr,
        DecoderOptions::NONE,
    );

    let Some(indirect_call) = decoder
        .into_iter()
        .filter(|t| t.is_call_near_indirect())
        .nth(n)
    else {
        return Ok(None);
    };

    let start_addr_vaddr = vaddr_conv(pe, start_addr)? as usize;

    let offset = indirect_call.ip();
    let file_offset_vaddr = vaddr_conv(pe, offset)? as usize;

    println!(
        "nth_indirect_call: disassemble from {:#x} to {:#x}",
        start_addr_vaddr, file_offset_vaddr
    );
    let instructions = try_disassemble(
        &pe.data()[start_addr_vaddr as usize..file_offset_vaddr],
        start_addr,
    )?;

    assert_eq!(
        0x1802e1187,
        indirect_call.ip(),
        "0x{:x}",
        indirect_call.ip().abs_diff(0x1802e1187)
    );

    // ---- Resolve the indirect call target ----

    let target = match indirect_call.op0_kind() {
        // ---------------------------------------
        // call qword ptr [rip + disp]
        // ---------------------------------------
        OpKind::Memory => indirect_call.next_ip(),

        // ---------------------------------------
        // call rax / call rcx / etc
        // ---------------------------------------
        OpKind::Register => {
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

/// Find the nth call instruction starting from addr
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
        .nth(n)
        .ok_or_else(|| {
            Il2CppBinaryError::BadInstruction("Could not find nth call".to_string(), addr)
        })?;

    Ok(call_instr.near_branch_target())

    // let mut target = None;
    // matching_call(pe, addr, n, |addr, _| {
    //     target = Some(addr);
    //     Ok(false)
    // })?;
    // target.ok_or(Il2CppBinaryError::BadInstruction(
    //     "Could not find nth call".to_string(),
    //     addr,
    // ))
}
