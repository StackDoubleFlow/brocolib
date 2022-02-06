use super::MethodInfo;
use crate::codegen_data::DllData;
use bad64::{disasm, Instruction, Op, Operand};
use petgraph::Graph;
use petgraph::dot::{Dot, Config};
use id_arena::Id;

type RawGraph<'a> = Graph<RawNode<'a>, RawEdge>;

struct StackValue {
    offset: i32,
    size: u32,
}

enum Value {
    Param(usize),
    General
}
type ValueId = Id<Value>;

#[derive(Debug)]
enum RawNode<'a> {
    EntryToken,
    Op(Op),
    Operand(&'a Operand),
    Value(ValueId),
}

#[derive(Debug)]
enum RawEdge {
    Value,
    Chain,
}

pub fn decompile(codegen_data: &DllData, mi: MethodInfo, data: &[u8]) {
    let instrs = disasm(data, mi.offset).map(Result::unwrap).collect();
    let dis_method = DisassembledMethod { info: mi, instrs };

    let mut graph = RawGraph::new();
    let entry = graph.add_node(RawNode::EntryToken);

    // let reg_values = Vec<

    // let mut stack_frame_size = 0;
    let mut chain = entry;
    for inst in &dis_method.instrs {
        let op = inst.op();
        let operands = inst.operands();

        let node = graph.add_node(RawNode::Op(op));
        for operand in operands {
            let operand_node = graph.add_node(RawNode::Operand(operand));
            graph.add_edge(node, operand_node, RawEdge::Value);
        }
        graph.add_edge(node, chain, RawEdge::Chain);
        chain = node;
        
        println!("{}", inst);
        // let addr = (inst.address() - dis_method.info.offset) as usize;
        // println!("{:02x}{:02x}{:02x}{:02x}  {:?}  {}", data[addr + 3], data[addr + 2], data[addr + 1], data[addr], inst.op(), inst);
    }

    println!("{:?}", Dot::with_config(&graph, &[]));
}

#[derive(Debug)]
struct DisassembledMethod<'a> {
    info: MethodInfo<'a>,
    instrs: Vec<Instruction>,
}
