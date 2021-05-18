use super::MethodInfo;
use crate::codegen_data::DllData;
use bad64::{disasm, Instruction};

pub fn decompile(codegen_data: &DllData, mi: MethodInfo, data: &[u8]) {
    let instrs = disasm(data, mi.offset).map(Result::unwrap).collect();
    let dis_method = DisassembledMethod { info: mi, instrs };

    for inst in dis_method.instrs {
        println!("{}", inst);
    }
}

#[derive(Debug)]
struct DisassembledMethod<'a> {
    info: MethodInfo<'a>,
    instrs: Vec<Instruction>,
}
