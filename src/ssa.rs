use std::collections::HashMap;
use std::fmt;
use super::MethodInfo;
use crate::codegen_data::{DllData, Method, TypeData, Field};
use bad64::{disasm, Imm, Instruction, Op, Operand, Reg};
use petgraph::EdgeDirection;
use petgraph::dot::{Config, Dot};
use petgraph::graph::{Graph, NodeIndex};

pub fn decompile(
    codegen_data: &DllData,
    methods: HashMap<u64, &Method>,
    mi: MethodInfo,
    data: &[u8],
) {
    let instrs: Vec<_> = disasm(data, mi.offset).map(Result::unwrap).collect();

}