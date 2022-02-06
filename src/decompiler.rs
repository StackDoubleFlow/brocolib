use super::MethodInfo;
use crate::codegen_data::DllData;
use bad64::{disasm, Instruction, Op, Operand, Imm, Reg};
use petgraph::dot::{Dot, Config};
use petgraph::graph::{Graph, NodeIndex};
use id_arena::Id;

type RawGraph<'a> = Graph<RawNode<'a>, RawEdge>;

struct StackValue {
    offset: i32,
    size: u32,
}

enum ValueSource {
    Node {
        idx: NodeIndex,
        define: usize,
    }
}

#[derive(Debug)]
enum RawNode<'a> {
    EntryToken,
    Param(usize),
    Op { 
        op: Op,
        num_defines: usize,
    },
    Operand(&'a Operand),
}

// next instruction analysis
// 1. loop through each input operand
// 2. check to see which node the value was defined in
// 3. create link from node found in last step to current node with concat or split if necessary 
// 4. put new defines in map

#[derive(Debug)]
enum RawEdge {
    Value {
        define: usize,
        operand: usize,
    },
    Chain,
}

pub fn decompile(codegen_data: &DllData, mi: MethodInfo, data: &[u8]) {
    let instrs = disasm(data, mi.offset).map(Result::unwrap).collect();
    let dis_method = DisassembledMethod { info: mi, instrs };

    let mut graph = RawGraph::new();
    let entry = graph.add_node(RawNode::EntryToken);

    // let stack = Vec::new();

    // let reg_values = Vec<

    let mut stack_frame_size = 0;
    let mut chain = entry;
    for inst in &dis_method.instrs {
        let op = inst.op();
        let operands = inst.operands();

        match op {
            Op::STR => {
                let addr = match operands[1] {
                    Operand::MemPreIdx { reg, imm: Imm::Signed(imm) } => { 
                        if reg == Reg::SP {
                            stack_frame_size -= imm;
                            (reg, imm + stack_frame_size)
                        } else {
                            (reg, imm)
                        }
                    }
                    Operand::MemOffset { reg, offset: Imm::Signed(imm), .. } => (reg, imm),
                    _ => unreachable!()
                };
                dbg!(operands[1]);
                if addr.0 == Reg::SP {
                    println!("Adding to stack space with size 8 and offset {}", addr.1);
                } else {
                    unimplemented!()
                }
            }
            _ => unimplemented!()
        }

        let node = graph.add_node(RawNode::Op { op, num_defines: 0 });
        for operand in operands {
            
            let operand_node = graph.add_node(RawNode::Operand(operand));
            graph.add_edge(node, operand_node, RawEdge::Value { define: 0, operand: 0 });
        }
        graph.add_edge(node, chain, RawEdge::Chain);
        chain = node;
        
        println!("{}", inst);
        // let addr = (inst.address() - dis_method.info.offset) as usize;
        // println!("{:02x}{:02x}{:02x}{:02x}  {:?}  {}", data[addr + 3], data[addr + 2], data[addr + 1], data[addr], inst.op(), inst);
    }

    // println!("{:?}", Dot::with_config(&graph, &[]));
}

#[derive(Debug)]
struct DisassembledMethod<'a> {
    info: MethodInfo<'a>,
    instrs: Vec<Instruction>,
}
