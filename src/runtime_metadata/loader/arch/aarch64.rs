use crate::runtime_metadata::loader::object_reader::ObjectReader;
use crate::runtime_metadata::loader::{self, Il2CppBinaryError};
use bad64::{disasm, Imm, Instruction, Op, Operand, Reg};
use std::collections::HashMap;

/// Returns address to (g_CodeRegistration, g_MetadataRegistration)
pub fn find_registration(obj: &ObjectReader) -> loader::Result<(u64, u64)> {
    let il2cpp_init = obj
        .find_export("il2cpp_init")?
        .ok_or(Il2CppBinaryError::MissingIl2CppInit)?;
    let runtime_init = nth_bl(obj, il2cpp_init, 2)?;
    let runtime_init_offset = obj.vaddr_conv(runtime_init)? as usize;

    // Here we try to find g_CodegenRegistration. There are 2 options:
    // - Without LTO, this will be the only indirect branch in Runtime::Init
    // - With LTO, this will be a normal bl, so we look at all calls to find a function with a first
    //   instructions being adrps. This is probably g_CodegenRegistration given its adrp density.
    if let Some((blr_offset, blr_reg)) = find_blr(obj, runtime_init, 200)? {
        let instructions =
            try_disassemble(&obj.data()[runtime_init_offset..blr_offset], runtime_init)?;

        // This relocation points to s_Il2CppCodegenRegistration
        let regs = analyze_reg_rel(obj, &instructions);
        let fn_addr = regs[&blr_reg];
        let fn_offset = obj.vaddr_conv(fn_addr)? as usize;

        let code = &obj.data()[fn_offset..fn_offset + 7 * 4];
        let instructions = try_disassemble(code, fn_addr)?;
        let regs = analyze_reg_rel(obj, instructions.as_slice());
        Ok((regs[&Reg::X0], regs[&Reg::X1]))
    } else {
        // This is call directly to s_Il2CppCodegenRegistration
        let fn_addr = matching_bl(obj, runtime_init, 200, |target_addr| {
            let target_offset = obj.vaddr_conv(target_addr)? as usize;
            let code = &obj.data()[target_offset..target_offset + 4 * 4];
            let instructions = try_disassemble(code, target_addr)?;
            Ok(instructions
                .iter()
                .filter(|ins| ins.op() == Op::ADRP)
                .count()
                >= 3)
        })?
        .ok_or(Il2CppBinaryError::MissingRegistration)?;
        let fn_offset = obj.vaddr_conv(fn_addr)? as usize;

        let code = &obj.data()[fn_offset..fn_offset + 10 * 4];
        let instructions = try_disassemble(code, fn_addr)?;

        // Look for the first 2 store instructions
        let mut code_registration = None;
        for (idx, ins) in instructions.iter().enumerate() {
            match (ins.op(), ins.operands()) {
                (Op::STR, [Operand::Reg { reg, .. }, ..]) => {
                    let regs = analyze_reg_rel(obj, &instructions[0..idx]);
                    if let Some(code_registration) = code_registration {
                        return Ok((code_registration, regs[reg]));
                    } else {
                        code_registration = Some(regs[reg])
                    }
                }
                _ => {}
            }
        }
        Err(Il2CppBinaryError::MissingRegistration)
    }
}

/// Finds and returns the elf offset of the first `blr` instruction it comes across starting from `addr`.
fn find_blr(obj: &ObjectReader, addr: u64, limit: usize) -> loader::Result<Option<(usize, Reg)>> {
    let offset = obj.vaddr_conv(addr)? as usize;
    for i in 0..limit {
        let offset = offset + i * 4;
        let code = &obj.data()[offset..offset + 4];
        let ins = &try_disassemble(code, addr + i as u64 * 4)?[0];
        if let (Op::BLR, [Operand::Reg { reg, .. }]) = (ins.op(), ins.operands()) {
            return Ok(Some((offset, *reg)));
        }
    }
    Ok(None)
}

fn try_disassemble(code: &[u8], addr: u64) -> loader::Result<Vec<Instruction>> {
    disasm(code, addr)
        .map(|res| res.map_err(Il2CppBinaryError::Disassemble))
        .collect()
}

/// Find the nth `bl` instruction starting from addr
fn nth_bl(obj: &ObjectReader, addr: u64, n: usize) -> loader::Result<u64> {
    let mut target = None;
    matching_bl(obj, addr, n, |addr| {
        target = Some(addr);
        Ok(false)
    })?;
    Ok(target.unwrap())
}

/// Find a `bl` instruction starting from addr that matches f
fn matching_bl<F>(
    obj: &ObjectReader,
    addr: u64,
    limit: usize,
    mut f: F,
) -> loader::Result<Option<u64>>
where
    F: FnMut(u64) -> loader::Result<bool>,
{
    let offset = obj.vaddr_conv(addr)? as usize;
    let mut count = 0;

    for i in 0.. {
        let offset = offset + i * 4;
        let code = &obj.data()[offset..offset + 4];
        let ins = &try_disassemble(code, addr + i as u64 * 4)?[0];
        if let (Op::BL, [Operand::Label(Imm::Unsigned(target))]) = (ins.op(), ins.operands()) {
            if f(*target)? {
                return Ok(Some(*target));
            }
            count += 1;
            if count == limit {
                return Ok(None);
            }
        }
    }

    unreachable!()
}

fn analyze_reg_rel(obj: &ObjectReader, instructions: &[Instruction]) -> HashMap<Reg, u64> {
    let mut map = HashMap::new();
    for ins in instructions {
        match (ins.op(), ins.operands()) {
            (Op::ADRP, [Operand::Reg { reg, .. }, Operand::Label(Imm::Unsigned(imm))]) => {
                map.insert(*reg, *imm);
            }
            (
                Op::ADD,
                [Operand::Reg { reg: a, .. }, Operand::Reg { reg: b, .. }, Operand::Imm64 {
                    imm: Imm::Unsigned(imm),
                    ..
                }],
            ) => {
                if a != b {
                    continue;
                }
                map.entry(*a).and_modify(|v| *v += imm);
            }
            (
                Op::LDR,
                [Operand::Reg { reg: a, .. }, Operand::MemOffset {
                    reg: b,
                    offset: Imm::Signed(imm),
                    ..
                }],
            ) => {
                if a != b {
                    continue;
                }
                map.entry(*a).and_modify(|v| {
                    // TODO: propogate error
                    *v = obj.read_u64((*v as i64 + imm) as u64).unwrap();
                });
            }
            _ => {}
        }
    }
    map
}
