use std::collections::HashMap;
use std::fmt;

use super::MethodInfo;
use crate::metadata::{Field, Metadata, Method, Type};
use bad64::{disasm, Imm, Instruction, Op, Operand, Reg};
use petgraph::dot::{Config, Dot};
use petgraph::graph::{Graph, NodeIndex};
use petgraph::EdgeDirection;

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
enum ValueSource {
    Node { idx: NodeIndex, define: usize },
    SPOffset { offset: i64 },
}

impl ValueSource {
    fn create_edge(&self, graph: &mut RawGraph, to: NodeIndex, operand: usize) {
        match *self {
            ValueSource::Node { idx, define } => {
                let edge = RawEdge::Value { define, operand };
                graph.add_edge(idx, to, edge);
            }
            _ => panic!("Cannot create edge to non-node value source"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SpecialParam {
    This,
    MethodInfo,
}

struct CallTarget<'a>(&'a Method<'a>);

impl<'a> fmt::Debug for CallTarget<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.name)
    }
}

#[derive(Debug)]
enum RawNode<'a> {
    EntryToken,
    Param(usize),
    SpecialParam(SpecialParam),
    CalleeSaved,
    Imm(u64),
    Op { op: Op, num_defines: usize },
    Call { to: CallTarget<'a> },
    LoadField(&'a Field),
    StoreField(&'a Field),
    Ret,
    MemOffset,
    Operand(Operand),
}

// next instruction analysis
// 1. loop through each input operand
// 2. check to see which node the value was defined in
// 3. create link from node found in last step to current node with concat or split if necessary
// 4. put new defines in map

#[derive(Debug, PartialEq, Eq)]
enum RawEdge {
    Value { define: usize, operand: usize },
    Chain,
}

#[derive(Default, Debug)]
struct ValueContext {
    r: [Option<ValueSource>; 31],
    v: [Vec<VectorValue>; 32],
    s: Vec<StackValue>,
    s_offset: i64,
}

fn decode_vreg(reg: u32) -> (u32, u32) {
    if (Reg::B0 as u32..=Reg::B31 as u32).contains(&reg) {
        (1, reg - Reg::B0 as u32)
    } else if (Reg::H0 as u32..=Reg::H31 as u32).contains(&reg) {
        (2, reg - Reg::H0 as u32)
    } else if (Reg::S0 as u32..=Reg::S31 as u32).contains(&reg) {
        (4, reg - Reg::S0 as u32)
    } else if (Reg::D0 as u32..=Reg::D31 as u32).contains(&reg) {
        (8, reg - Reg::D0 as u32)
    } else if (Reg::Q0 as u32..=Reg::Q31 as u32).contains(&reg) {
        (16, reg - Reg::Q0 as u32)
    } else if (Reg::V0 as u32..=Reg::V31 as u32).contains(&reg) {
        (16, reg - Reg::V0 as u32)
    } else {
        unreachable!(reg)
    }
}

impl ValueContext {
    fn read_reg(&self, graph: &mut RawGraph, reg: Reg) -> ValueSource {
        if reg == Reg::XZR || reg == Reg::WZR {
            let imm = graph.add_node(RawNode::Imm(0));
            return ValueSource::Node {
                idx: imm,
                define: 0,
            };
        }

        let reg = reg as u32;
        if (Reg::X0 as u32..=Reg::X30 as u32).contains(&reg) {
            return self.r[(reg - Reg::X0 as u32) as usize].clone().unwrap();
        } else if (Reg::W0 as u32..=Reg::W30 as u32).contains(&reg) {
            return self.r[(reg - Reg::W0 as u32) as usize].clone().unwrap();
        }
        let (size, n) = decode_vreg(reg);
        // TODO: Reading partial
        return self.v[n as usize].first().unwrap().source.clone();
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
        self.write_vector(n as usize, 0, size, val);
    }

    fn write_stack(&mut self, offset: i64, size: u32, val: ValueSource) {
        let offset = self.s_offset + offset;
        // TODO: Overlapping writes to stack
        for entry in &mut self.s {
            if entry.offset == offset && entry.size == size {
                entry.source = val;
                return;
            }
        }
        self.s.push(StackValue {
            offset,
            size,
            source: val,
        });
    }

    fn write_vector(&mut self, n: usize, offset: i32, size: u32, val: ValueSource) {
        // TODO: Overlapping writes to v space
        for entry in &mut self.v[n] {
            if entry.offset == offset && entry.size == size {
                entry.source = val;
                return;
            }
        }
        self.v[n].push(VectorValue {
            offset,
            size,
            source: val,
        });
    }
}

fn is_instance(mi: &Method) -> bool {
    // METHOD_ATTRIBUTE_STATIC
    (mi.flags & 0x0010) != 0
}

fn is_fp_type(ty: &Type) -> bool {
    // IL2CPP_TYPE_R4 or IL2CPP_TYPE_R8
    ty.ty == 0xc || ty.ty == 0xd
}

/// Find the number of register and vector paramters of a method
fn num_params(codegen_data: &Metadata, mi: &Method) -> (usize, usize) {
    let mut num_r = 0;
    let mut num_v = 0;
    if is_instance(mi) {
        num_r += 1;
    }

    for param in &mi.params {
        let ty = &codegen_data[param.ty];
        if is_fp_type(ty) {
            num_v += 1;
        } else {
            num_r += 1;
        }
    }

    (num_r, num_v)
}

fn load_params(
    codegen_data: &Metadata,
    mi: &MethodInfo,
    graph: &mut RawGraph,
    ctx: &mut ValueContext,
) {
    let param_nodes: Vec<_> = mi
        .metadata
        .params
        .iter()
        .enumerate()
        .map(|(i, _)| graph.add_node(RawNode::Param(i)))
        .collect();

    let mut cur_v = 0;
    let mut cur_r = 0;

    if is_instance(mi.metadata) {
        let this = graph.add_node(RawNode::SpecialParam(SpecialParam::This));
        ctx.r[cur_r] = Some(ValueSource::Node {
            idx: this,
            define: 0,
        });
        cur_r += 1;
    }

    for (i, param) in mi.metadata.params.iter().enumerate() {
        let ty_id = param.ty;
        let ty = &codegen_data[ty_id];

        if is_fp_type(ty) {
            let val = VectorValue {
                offset: 0,
                // I think the size here should always be 8? not sure
                // size: if ty.this.name == "Single" { 4 } else { 8 },
                size: 8,
                source: ValueSource::Node {
                    idx: param_nodes[i],
                    define: 0,
                },
            };
            ctx.v[cur_v].push(val);
            cur_v += 1;
            continue;
        }

        ctx.r[cur_r] = Some(ValueSource::Node {
            idx: param_nodes[i],
            define: 0,
        });
        cur_r += 1;
    }

    let method_info = graph.add_node(RawNode::SpecialParam(SpecialParam::MethodInfo));
    ctx.r[cur_r] = Some(ValueSource::Node {
        idx: method_info,
        define: 0,
    });

    let calee_saved = graph.add_node(RawNode::CalleeSaved);
    for i in 19..=30 {
        ctx.r[i] = Some(ValueSource::Node {
            idx: calee_saved,
            define: 0,
        })
    }
    for i in 0..=8 {
        ctx.v[i].push(VectorValue {
            source: ValueSource::Node {
                idx: calee_saved,
                define: 0,
            },
            offset: 0,
            size: 8,
        });
    }
}

fn unwrap_reg(operand: Operand) -> Reg {
    match operand {
        Operand::Reg { reg, .. } => reg,
        _ => unreachable!("{:?}", operand),
    }
}

struct WalkChain {
    cur: NodeIndex,
}

impl WalkChain {
    fn new(entry: NodeIndex) -> Self {
        Self { cur: entry }
    }

    fn next(&mut self, graph: &RawGraph) -> Option<NodeIndex> {
        let mut neighbors = graph
            .neighbors_directed(self.cur, EdgeDirection::Outgoing)
            .detach();
        while let Some((e, n)) = neighbors.next(graph) {
            if graph.edge_weight(e) == Some(&RawEdge::Chain) {
                self.cur = n;
                return Some(n);
            }
        }
        None
    }
}

fn dag_operand(graph: &RawGraph, node: NodeIndex, n: usize) -> Option<NodeIndex> {
    let mut neighbors = graph
        .neighbors_directed(node, EdgeDirection::Incoming)
        .detach();
    while let Some((neighbor_e, neighbor_n)) = neighbors.next(graph) {
        match graph[neighbor_e] {
            RawEdge::Value { operand, .. } if operand == n => return Some(neighbor_n),
            _ => {}
        }
    }
    None
}

fn load(
    chain: &mut NodeIndex,
    ctx: &mut ValueContext,
    graph: &mut RawGraph,
    reg: Operand,
    addr: (Reg, i64),
) {
    let node = graph.add_node(RawNode::Op {
        op: Op::LDR,
        num_defines: 1,
    });
    let reg = unwrap_reg(reg);
    ctx.write_reg(
        reg,
        ValueSource::Node {
            idx: node,
            define: 0,
        },
    );

    let base = ctx.read_reg(graph, addr.0);
    let offset = graph.add_node(RawNode::Imm(addr.1 as u64));
    let mem_operand_node = graph.add_node(RawNode::MemOffset);
    base.create_edge(graph, mem_operand_node, 0);
    graph.add_edge(
        offset,
        mem_operand_node,
        RawEdge::Value {
            define: 0,
            operand: 1,
        },
    );
    graph.add_edge(
        mem_operand_node,
        node,
        RawEdge::Value {
            define: 0,
            operand: 1,
        },
    );
    graph.add_edge(*chain, node, RawEdge::Chain);
    *chain = node;
}

pub fn decompile(
    codegen_data: &Metadata,
    methods: HashMap<u64, &Method>,
    mi: MethodInfo,
    data: &[u8],
) {
    let instrs: Vec<_> = disasm(data, mi.metadata.offset)
        .map(Result::unwrap)
        .collect();

    let mut graph = RawGraph::new();
    let entry = graph.add_node(RawNode::EntryToken);

    let mut ctx = Default::default();
    load_params(codegen_data, &mi, &mut graph, &mut ctx);
    // dbg!(ctx);

    let mut chain = entry;
    for inst in &instrs {
        println!("{}", inst);
        let op = inst.op();
        let operands = inst.operands();

        match op {
            Op::BL | Op::B => {
                let addr = match operands[0] {
                    Operand::Label(Imm::Unsigned(addr)) => addr,
                    _ => unreachable!(),
                };
                let to = match methods.get(&addr) {
                    Some(&mi) => mi,
                    None => continue,
                };
                let node = graph.add_node(RawNode::Call { to: CallTarget(to) });
                let (num_r, num_v) = num_params(codegen_data, to);

                // TODO: Fix operand index
                for i in 0..num_r {
                    use Reg::*;
                    let arg_regs = [X0, X1, X2, X3, X4, X5, X6, X7];
                    let reg = ctx.read_reg(&mut graph, arg_regs[i]);
                    reg.create_edge(&mut graph, node, i);
                }
                for i in 0..num_v {
                    let reg = &ctx.v[i].first().unwrap().source;
                    reg.create_edge(&mut graph, node, num_r + i);
                }

                graph.add_edge(chain, node, RawEdge::Chain);
                chain = node;

                if op == Op::B {
                    let node = graph.add_node(RawNode::Ret);
                    graph.add_edge(chain, node, RawEdge::Chain);
                    chain = node;
                }
            }
            Op::LDR | Op::LDP => {
                let num_regs = if op == Op::LDR { 1 } else { 2 };
                let regs = &operands[..num_regs];
                let mem_operand = operands[num_regs];
                let addr = match mem_operand {
                    Operand::MemOffset {
                        reg,
                        offset: Imm::Signed(imm),
                        ..
                    } => (reg, imm),
                    // TODO: Other addressing modes
                    // o => unreachable!("{:?}", o),
                    _ => continue,
                };
                if addr.0 != Reg::SP {
                    for &reg in regs {
                        load(&mut chain, &mut ctx, &mut graph, reg, addr);
                    }
                }
            }
            Op::STR | Op::STP => {
                let (regs, mem_operand) = if op == Op::STR {
                    (&operands[..1], operands[1])
                } else {
                    (&operands[..2], operands[2])
                };
                let addr = match mem_operand {
                    Operand::MemPreIdx {
                        reg,
                        imm: Imm::Signed(imm),
                    } => {
                        if reg == Reg::SP {
                            ctx.s_offset += imm;
                        }
                        // TODO: pre-idx addressing writes
                        (reg, 0)
                    }
                    Operand::MemOffset {
                        reg,
                        offset: Imm::Signed(imm),
                        ..
                    } => (reg, imm),
                    o => unreachable!("{:?}", o),
                };
                if addr.0 == Reg::SP {
                    for (i, &reg) in regs.iter().enumerate() {
                        let reg = unwrap_reg(reg);
                        let offset = addr.1 + i as i64 * 8;
                        ctx.write_stack(offset, 8, ctx.read_reg(&mut graph, reg));
                    }
                } else {
                    let node = graph.add_node(RawNode::Op { op, num_defines: 0 });
                    for (i, &reg) in regs.iter().enumerate() {
                        let reg = ctx.read_reg(&mut graph, unwrap_reg(reg));
                        reg.create_edge(&mut graph, node, i);
                    }

                    let base = ctx.read_reg(&mut graph, addr.0);
                    let offset = graph.add_node(RawNode::Imm(addr.1 as u64));
                    let mem_operand_node = graph.add_node(RawNode::MemOffset);
                    base.create_edge(&mut graph, mem_operand_node, 0);
                    graph.add_edge(
                        offset,
                        mem_operand_node,
                        RawEdge::Value {
                            define: 0,
                            operand: 1,
                        },
                    );
                    graph.add_edge(
                        mem_operand_node,
                        node,
                        RawEdge::Value {
                            define: 0,
                            operand: regs.len(),
                        },
                    );
                    graph.add_edge(chain, node, RawEdge::Chain);
                    chain = node;
                }
            }
            Op::MOV => {
                let dest = unwrap_reg(operands[0]);
                let src = unwrap_reg(operands[1]);
                ctx.write_reg(dest, ctx.read_reg(&mut graph, src));
            }
            Op::ORR | Op::ADD => {
                let dest = unwrap_reg(operands[0]);
                if dest == Reg::X29 {
                    // ignore writes to frame pointer
                    continue;
                }

                let a = unwrap_reg(operands[1]);
                let b = match &operands[2] {
                    Operand::Imm32 {
                        imm: Imm::Unsigned(imm),
                        ..
                    }
                    | Operand::Imm64 {
                        imm: Imm::Unsigned(imm),
                        ..
                    } => {
                        let imm = graph.add_node(RawNode::Imm(*imm));
                        ValueSource::Node {
                            idx: imm,
                            define: 0,
                        }
                    }
                    _ => ctx.read_reg(&mut graph, unwrap_reg(operands[2])),
                };
                if a == Reg::XZR || a == Reg::WZR {
                    ctx.write_reg(dest, b);
                    continue;
                }

                let a = ctx.read_reg(&mut graph, a);
                let node = graph.add_node(RawNode::Op { op, num_defines: 1 });
                a.create_edge(&mut graph, node, 1);
                b.create_edge(&mut graph, node, 2);
            }
            _ => {}
        }
    }

    let mut walk = WalkChain::new(entry);
    // if let Some(n) = walk.next(&graph) {
    //     match graph.node_weight(n) {

    //     }
    // }

    println!("{:?}", Dot::with_config(&graph, &[]));
}
