use super::MethodInfo;
use crate::codegen_data::DllData;
use bad64::{disasm, Imm, Instruction, Op, Operand, Reg};
use petgraph::dot::{Config, Dot};
use petgraph::graph::{Graph, NodeIndex};

type RawGraph<'a> = Graph<RawNode<'a>, RawEdge>;

#[derive(Debug)]
struct StackValue {
    offset: i64,
    size: u32,
    source: ValueSource,
}

#[derive(Debug)]
struct VectorValue {
    offset: i32,
    size: u32,
    source: ValueSource,
}

#[derive(Debug, Clone)]
struct ValueSource {
    idx: NodeIndex,
    define: usize,
}

#[derive(Debug)]
enum RawNode<'a> {
    EntryToken,
    Param(usize),
    CalleeSaved,
    Op { op: Op, num_defines: usize },
    Operand(&'a Operand),
}

// next instruction analysis
// 1. loop through each input operand
// 2. check to see which node the value was defined in
// 3. create link from node found in last step to current node with concat or split if necessary
// 4. put new defines in map

#[derive(Debug)]
enum RawEdge {
    Value { define: usize, operand: usize },
    Chain,
}

#[derive(Default, Debug)]
struct ValueContext {
    r: [Option<ValueSource>; 31],
    v: [Vec<VectorValue>; 32],
    s: Vec<StackValue>,
}

fn decode_vreg(reg: u32) -> (u32, u32) {
    if (Reg::B0 as u32..=Reg::B31 as u32).contains(&reg) {
        (1, reg - Reg::B0 as u32)
    } else if (Reg::H0 as u32..=Reg::H31 as u32).contains(&reg) {
        (2, reg - Reg::B0 as u32)
    } else if (Reg::S0 as u32..=Reg::S31 as u32).contains(&reg) {
        (4, reg - Reg::B0 as u32)
    } else if (Reg::D0 as u32..=Reg::D31 as u32).contains(&reg) {
        (8, reg - Reg::B0 as u32)
    } else if (Reg::Q0 as u32..=Reg::Q31 as u32).contains(&reg)
        || (Reg::V0 as u32..=Reg::V31 as u32).contains(&reg)
    {
        (16, reg - Reg::B0 as u32)
    } else {
        unreachable!()
    }
}

impl ValueContext {
    fn read_reg(&self, reg: Reg) -> &ValueSource {
        let reg = reg as u32;
        // TODO: Zero registers
        if (Reg::X0 as u32..=Reg::X30 as u32).contains(&reg) {
            dbg!((reg - Reg::X0 as u32) as usize);
            return self.r[(reg - Reg::X0 as u32) as usize].as_ref().unwrap();
        } else if (Reg::W0 as u32..=Reg::W30 as u32).contains(&reg) {
            return self.r[(reg - Reg::W0 as u32) as usize].as_ref().unwrap();
        }
        let (size, n) = decode_vreg(reg);
        // TODO: Reading partial
        return &self.v[n as usize].first().unwrap().source;
    }

    fn write_reg(&mut self, reg: Reg, val: ValueSource) {
        let reg = reg as u32;
        if (Reg::X0 as u32..=Reg::X30 as u32).contains(&reg) {
            self.r[(reg - Reg::X0 as u32) as usize] = Some(val);
            return;
        } else if (Reg::W0 as u32..=Reg::W30 as u32).contains(&reg) {
            self.r[(reg - Reg::W0 as u32) as usize] = Some(val);
            return;
        }
        let (size, n) = decode_vreg(reg);
        self.v[n as usize].push(VectorValue {
            offset: 0, // TOOD
            size,
            source: val,
        })
    }
}

fn load_params(
    codegen_data: &DllData,
    mi: &MethodInfo,
    graph: &mut RawGraph,
    ctx: &mut ValueContext,
) {
    let param_nodes: Vec<_> = mi
        .codegen_data
        .parameters
        .iter()
        .enumerate()
        .map(|(i, _)| graph.add_node(RawNode::Param(i)))
        .collect();

    let mut cur_v = 0;
    let mut cur_r = 0;
    for (i, param) in mi.codegen_data.parameters.iter().enumerate() {
        let ty_id = param.parameter_type.type_id;
        let ty = &codegen_data.types[ty_id as usize];

        if ty.this.namespace == "System" && (ty.this.name == "Single" || ty.this.name == "Double") {
            let val = VectorValue {
                offset: 0,
                // I think the size here should always be 8? not sure
                // size: if ty.this.name == "Single" { 4 } else { 8 },
                size: 8,
                source: ValueSource {
                    idx: param_nodes[i],
                    define: 0,
                },
            };
            ctx.v[cur_v].push(val);
            cur_v += 1;
            continue;
        }

        ctx.r[cur_r] = Some(ValueSource {
            idx: param_nodes[i],
            define: 0,
        });
        cur_r += 1;
    }

    let calee_saved = graph.add_node(RawNode::CalleeSaved);
    for i in 19..=29 {
        ctx.r[i] = Some(ValueSource {
            idx: calee_saved,
            define: 0,
        })
    }
}

fn unwrap_reg(operand: &Operand) -> Reg {
    match operand {
        Operand::Reg { reg, .. } => *reg,
        _ => unreachable!(),
    }
} 

pub fn decompile(codegen_data: &DllData, mi: MethodInfo, data: &[u8]) {
    let instrs = disasm(data, mi.offset).map(Result::unwrap).collect();
    let dis_method = DisassembledMethod { info: mi, instrs };

    let mut graph = RawGraph::new();
    let entry = graph.add_node(RawNode::EntryToken);

    let mut ctx = Default::default();
    load_params(codegen_data, &dis_method.info, &mut graph, &mut ctx);
    // dbg!(ctx);

    let mut stack_frame_size = 0;
    let mut chain = entry;
    for inst in &dis_method.instrs {
        println!("{}", inst);
        let op = inst.op();
        let operands = inst.operands();

        match op {
            Op::STR | Op::STP => {
                let mem_operand = if op == Op::STR { 1 } else { 2 };
                let addr = match operands[mem_operand] {
                    Operand::MemPreIdx {
                        reg,
                        imm: Imm::Signed(imm),
                    } => {
                        if reg == Reg::SP {
                            stack_frame_size -= imm;
                            (reg, imm + stack_frame_size)
                        } else {
                            (reg, imm)
                        }
                    }
                    Operand::MemOffset {
                        reg,
                        offset: Imm::Signed(imm),
                        ..
                    } => (reg, imm),
                    o => unreachable!("{:?}", o),
                };
                let regs = if op == Op::STR {
                    &operands[..0]
                } else {
                    &operands[..1]
                };
                // dbg!(operands[1]);
                if addr.0 == Reg::SP {
                    for reg in regs {
                        let reg = unwrap_reg(reg);
                        ctx.s.push(StackValue {
                            offset: addr.1,
                            size: 8,
                            source: ctx.read_reg(reg).clone(),
                        })
                    }

                    println!("Adding to stack space with size 8 and offset {}", addr.1);
                } else {
                    // unimplemented!()
                }
            }
            Op::MOV => {
                let dest = unwrap_reg(&operands[0]);
                let src = unwrap_reg(&operands[1]);
                dbg!(&ctx);
                ctx.write_reg(dest, ctx.read_reg(src).clone());
            }
            _ => {}
        }

        // let node = graph.add_node(RawNode::Op { op, num_defines: 0 });
        // for operand in operands {
        //     let operand_node = graph.add_node(RawNode::Operand(operand));
        //     graph.add_edge(
        //         node,
        //         operand_node,
        //         RawEdge::Value {
        //             define: 0,
        //             operand: 0,
        //         },
        //     );
        // }
        // graph.add_edge(node, chain, RawEdge::Chain);
        // chain = node;

        // let addr = (inst.address() - dis_method.info.offset) as usize;
        // println!("{:02x}{:02x}{:02x}{:02x}  {:?}  {}", data[addr + 3], data[addr + 2], data[addr + 1], data[addr], inst.op(), inst);
    }
    dbg!(stack_frame_size);

    // println!("{:?}", Dot::with_config(&graph, &[]));
}

#[derive(Debug)]
struct DisassembledMethod<'a> {
    info: MethodInfo<'a>,
    instrs: Vec<Instruction>,
}
