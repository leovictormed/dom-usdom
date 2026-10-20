//! Exact RandomX v1 superscalar program generator.

use crate::{
    dataset::{
        RandomXSuperscalarInstruction, RandomXSuperscalarOpcode, RandomXSuperscalarProgram,
        RANDOMX_CACHE_ACCESSES, RANDOMX_SUPERSCALAR_MAX_SIZE,
    },
    reciprocal, RandomXBlake2Generator,
};

const LATENCY: i32 = 170;
const CYCLE_MAP_SIZE: usize = LATENCY as usize + 4;
const LOOK_FORWARD: i32 = 4;
const MAX_THROWAWAY: i32 = 256;
const P0: u8 = 1;
const P1: u8 = 2;
const P5: u8 = 4;
const P01: u8 = P0 | P1;
const P05: u8 = P0 | P5;
const P015: u8 = P0 | P1 | P5;

#[derive(Clone, Copy)]
struct MacroOp {
    size: i32,
    latency: i32,
    first: u8,
    second: u8,
    dependent: bool,
}

const fn op(size: i32, latency: i32, first: u8, second: u8, dependent: bool) -> MacroOp {
    MacroOp {
        size,
        latency,
        first,
        second,
        dependent,
    }
}

const MOV: MacroOp = op(3, 0, 0, 0, false);
const SUB: MacroOp = op(3, 1, P015, 0, false);
const XOR: MacroOp = op(3, 1, P015, 0, false);
const LEA: MacroOp = op(4, 1, P01, 0, false);
const IMUL: MacroOp = op(4, 3, P1, 0, false);
const MULH: MacroOp = op(3, 4, P1, P5, false);
const ADD_IMM: MacroOp = op(7, 1, P015, 0, false);
const XOR_IMM: MacroOp = op(7, 1, P015, 0, false);
const ROR: MacroOp = op(4, 1, P05, 0, false);
const MOV_IMM: MacroOp = op(10, 1, P015, 0, false);
const IMUL_DEP: MacroOp = op(4, 3, P1, 0, true);

fn op_count(kind: RandomXSuperscalarOpcode) -> usize {
    match kind {
        RandomXSuperscalarOpcode::ImulhR | RandomXSuperscalarOpcode::IsmulhR => 3,
        RandomXSuperscalarOpcode::ImulRcp => 2,
        _ => 1,
    }
}

fn macro_op(kind: RandomXSuperscalarOpcode, index: usize) -> MacroOp {
    match kind {
        RandomXSuperscalarOpcode::IsubR => SUB,
        RandomXSuperscalarOpcode::IxorR => XOR,
        RandomXSuperscalarOpcode::IaddRs => LEA,
        RandomXSuperscalarOpcode::ImulR => IMUL,
        RandomXSuperscalarOpcode::IrorC => ROR,
        RandomXSuperscalarOpcode::IaddC7
        | RandomXSuperscalarOpcode::IaddC8
        | RandomXSuperscalarOpcode::IaddC9 => ADD_IMM,
        RandomXSuperscalarOpcode::IxorC7
        | RandomXSuperscalarOpcode::IxorC8
        | RandomXSuperscalarOpcode::IxorC9 => XOR_IMM,
        RandomXSuperscalarOpcode::ImulhR | RandomXSuperscalarOpcode::IsmulhR => {
            if index == 1 {
                MULH
            } else {
                MOV
            }
        }
        RandomXSuperscalarOpcode::ImulRcp => {
            if index == 0 {
                MOV_IMM
            } else {
                IMUL_DEP
            }
        }
    }
}

fn source_op(kind: RandomXSuperscalarOpcode) -> i32 {
    match kind {
        RandomXSuperscalarOpcode::IrorC
        | RandomXSuperscalarOpcode::IaddC7
        | RandomXSuperscalarOpcode::IaddC8
        | RandomXSuperscalarOpcode::IaddC9
        | RandomXSuperscalarOpcode::IxorC7
        | RandomXSuperscalarOpcode::IxorC8
        | RandomXSuperscalarOpcode::IxorC9
        | RandomXSuperscalarOpcode::ImulRcp => -1,
        RandomXSuperscalarOpcode::ImulhR | RandomXSuperscalarOpcode::IsmulhR => 1,
        _ => 0,
    }
}

fn destination_op(kind: RandomXSuperscalarOpcode) -> usize {
    if kind == RandomXSuperscalarOpcode::ImulRcp {
        1
    } else {
        0
    }
}

fn result_op(kind: RandomXSuperscalarOpcode) -> usize {
    match kind {
        RandomXSuperscalarOpcode::ImulhR
        | RandomXSuperscalarOpcode::IsmulhR
        | RandomXSuperscalarOpcode::ImulRcp => 1,
        _ => 0,
    }
}

#[derive(Clone, Copy)]
struct RegisterInfo {
    latency: i32,
    last_group: i32,
    last_parameter: i32,
}

const EMPTY_REGISTER: RegisterInfo = RegisterInfo {
    latency: 0,
    last_group: -1,
    last_parameter: -1,
};

#[derive(Clone, Copy)]
struct PendingInstruction {
    kind: RandomXSuperscalarOpcode,
    source: i32,
    destination: i32,
    modifier: u8,
    immediate: u32,
    group: i32,
    group_parameter: i32,
    can_reuse: bool,
    parameter_is_source: bool,
}

impl PendingInstruction {
    fn create(kind: RandomXSuperscalarOpcode, generator: &mut RandomXBlake2Generator) -> Self {
        let mut instruction = Self {
            kind,
            source: -1,
            destination: -1,
            modifier: 0,
            immediate: 0,
            group: kind as i32,
            group_parameter: -1,
            can_reuse: false,
            parameter_is_source: false,
        };
        match kind {
            RandomXSuperscalarOpcode::IsubR => {
                instruction.group = RandomXSuperscalarOpcode::IaddRs as i32;
                instruction.parameter_is_source = true;
            }
            RandomXSuperscalarOpcode::IxorR | RandomXSuperscalarOpcode::ImulR => {
                instruction.parameter_is_source = true;
            }
            RandomXSuperscalarOpcode::IaddRs => {
                instruction.modifier = generator.next_byte();
                instruction.parameter_is_source = true;
            }
            RandomXSuperscalarOpcode::IrorC => {
                while instruction.immediate == 0 {
                    instruction.immediate = u32::from(generator.next_byte() & 63);
                }
            }
            RandomXSuperscalarOpcode::IaddC7
            | RandomXSuperscalarOpcode::IaddC8
            | RandomXSuperscalarOpcode::IaddC9 => {
                instruction.immediate = generator.next_u32();
                instruction.group = RandomXSuperscalarOpcode::IaddC7 as i32;
            }
            RandomXSuperscalarOpcode::IxorC7
            | RandomXSuperscalarOpcode::IxorC8
            | RandomXSuperscalarOpcode::IxorC9 => {
                instruction.immediate = generator.next_u32();
                instruction.group = RandomXSuperscalarOpcode::IxorC7 as i32;
            }
            RandomXSuperscalarOpcode::ImulhR | RandomXSuperscalarOpcode::IsmulhR => {
                instruction.can_reuse = true;
                instruction.group_parameter = generator.next_u32() as i32;
            }
            RandomXSuperscalarOpcode::ImulRcp => loop {
                instruction.immediate = generator.next_u32();
                if instruction.immediate != 0 && !instruction.immediate.is_power_of_two() {
                    break;
                }
            },
        }
        instruction
    }

    fn select_source(
        &mut self,
        cycle: i32,
        registers: &[RegisterInfo; 8],
        generator: &mut RandomXBlake2Generator,
    ) -> bool {
        let mut available = [0u8; 8];
        let mut length = 0;
        for (index, register) in registers.iter().enumerate() {
            if register.latency <= cycle {
                available[length] = index as u8;
                length += 1;
            }
        }
        if length == 2
            && self.kind == RandomXSuperscalarOpcode::IaddRs
            && (available[0] == 5 || available[1] == 5)
        {
            self.source = 5;
            self.group_parameter = 5;
            return true;
        }
        let Some(selected) = select_register(&available[..length], generator) else {
            return false;
        };
        self.source = i32::from(selected);
        if self.parameter_is_source {
            self.group_parameter = self.source;
        }
        true
    }

    fn select_destination(
        &mut self,
        cycle: i32,
        allow_chained_mul: bool,
        registers: &[RegisterInfo; 8],
        generator: &mut RandomXBlake2Generator,
    ) -> bool {
        let mut available = [0u8; 8];
        let mut length = 0;
        for (index, register) in registers.iter().enumerate() {
            let valid = register.latency <= cycle
                && (self.can_reuse || index as i32 != self.source)
                && (allow_chained_mul
                    || self.group != RandomXSuperscalarOpcode::ImulR as i32
                    || register.last_group != RandomXSuperscalarOpcode::ImulR as i32)
                && (register.last_group != self.group
                    || register.last_parameter != self.group_parameter)
                && (self.kind != RandomXSuperscalarOpcode::IaddRs || index != 5);
            if valid {
                available[length] = index as u8;
                length += 1;
            }
        }
        let Some(selected) = select_register(&available[..length], generator) else {
            return false;
        };
        self.destination = i32::from(selected);
        true
    }

    fn finish(self) -> RandomXSuperscalarInstruction {
        RandomXSuperscalarInstruction {
            opcode: self.kind,
            destination: self.destination as u8,
            source: if self.source >= 0 {
                self.source as u8
            } else {
                self.destination as u8
            },
            modifier: self.modifier,
            immediate: self.immediate,
        }
    }
}

fn select_register(available: &[u8], generator: &mut RandomXBlake2Generator) -> Option<u8> {
    match available.len() {
        0 => None,
        1 => Some(available[0]),
        length => Some(available[generator.next_u32() as usize % length]),
    }
}

const BUFFERS: [&[u8]; 6] = [
    &[4, 8, 4],
    &[7, 3, 3, 3],
    &[3, 7, 3, 3],
    &[4, 9, 3],
    &[4, 4, 4, 4],
    &[3, 3, 10],
];

fn next_buffer(
    previous: Option<RandomXSuperscalarOpcode>,
    cycle: i32,
    multiply_count: i32,
    generator: &mut RandomXBlake2Generator,
) -> usize {
    if matches!(
        previous,
        Some(RandomXSuperscalarOpcode::ImulhR | RandomXSuperscalarOpcode::IsmulhR)
    ) {
        5
    } else if multiply_count < cycle + 1 {
        4
    } else if previous == Some(RandomXSuperscalarOpcode::ImulRcp) {
        if generator.next_byte() & 1 != 0 {
            0
        } else {
            3
        }
    } else {
        [0usize, 1, 2, 3][usize::from(generator.next_byte() & 3)]
    }
}

fn create_for_slot(
    generator: &mut RandomXBlake2Generator,
    slot: u8,
    buffer: usize,
    last: bool,
) -> PendingInstruction {
    let kind = match slot {
        3 if last => [
            RandomXSuperscalarOpcode::IsubR,
            RandomXSuperscalarOpcode::IxorR,
            RandomXSuperscalarOpcode::ImulhR,
            RandomXSuperscalarOpcode::IsmulhR,
        ][usize::from(generator.next_byte() & 3)],
        3 => [
            RandomXSuperscalarOpcode::IsubR,
            RandomXSuperscalarOpcode::IxorR,
        ][usize::from(generator.next_byte() & 1)],
        4 if buffer == 4 && !last => RandomXSuperscalarOpcode::ImulR,
        4 => [
            RandomXSuperscalarOpcode::IrorC,
            RandomXSuperscalarOpcode::IaddRs,
        ][usize::from(generator.next_byte() & 1)],
        7 => [
            RandomXSuperscalarOpcode::IxorC7,
            RandomXSuperscalarOpcode::IaddC7,
        ][usize::from(generator.next_byte() & 1)],
        8 => [
            RandomXSuperscalarOpcode::IxorC8,
            RandomXSuperscalarOpcode::IaddC8,
        ][usize::from(generator.next_byte() & 1)],
        9 => [
            RandomXSuperscalarOpcode::IxorC9,
            RandomXSuperscalarOpcode::IaddC9,
        ][usize::from(generator.next_byte() & 1)],
        10 => RandomXSuperscalarOpcode::ImulRcp,
        _ => unreachable!("canonical decoder slot"),
    };
    PendingInstruction::create(kind, generator)
}

fn schedule_uop(
    port: u8,
    busy: &mut [[u8; 3]; CYCLE_MAP_SIZE],
    mut cycle: i32,
    commit: bool,
) -> i32 {
    while cycle < CYCLE_MAP_SIZE as i32 {
        for (mask, index) in [(P5, 2usize), (P0, 0), (P1, 1)] {
            if port & mask != 0 && busy[cycle as usize][index] == 0 {
                if commit {
                    busy[cycle as usize][index] = port;
                }
                return cycle;
            }
        }
        cycle += 1;
    }
    -1
}

fn schedule(
    operation: MacroOp,
    busy: &mut [[u8; 3]; CYCLE_MAP_SIZE],
    mut cycle: i32,
    dependency: i32,
    commit: bool,
) -> i32 {
    if operation.dependent {
        cycle = cycle.max(dependency);
    }
    if operation.first == 0 {
        return cycle;
    }
    if operation.second == 0 {
        return schedule_uop(operation.first, busy, cycle, commit);
    }
    while cycle < CYCLE_MAP_SIZE as i32 {
        let first = schedule_uop(operation.first, busy, cycle, false);
        let second = schedule_uop(operation.second, busy, cycle, false);
        if first >= 0 && first == second {
            if commit {
                schedule_uop(operation.first, busy, first, true);
                schedule_uop(operation.second, busy, second, true);
            }
            return first;
        }
        cycle += 1;
    }
    -1
}

fn generate_one(generator: &mut RandomXBlake2Generator) -> RandomXSuperscalarProgram {
    let mut busy = [[0u8; 3]; CYCLE_MAP_SIZE];
    let mut registers = [EMPTY_REGISTER; 8];
    let mut instructions = Vec::with_capacity(RANDOMX_SUPERSCALAR_MAX_SIZE);
    let mut pending = None;
    let mut macro_index = 0usize;
    let mut cycle = 0i32;
    let mut dependency_cycle = 0i32;
    let mut saturated = false;
    let mut multiply_count = 0i32;
    let mut throwaways = 0i32;

    for decode_cycle in 0..LATENCY {
        if saturated || instructions.len() >= RANDOMX_SUPERSCALAR_MAX_SIZE {
            break;
        }
        let buffer_index = next_buffer(
            pending
                .as_ref()
                .map(|instruction: &PendingInstruction| instruction.kind),
            decode_cycle,
            multiply_count,
            generator,
        );
        let slots = BUFFERS[buffer_index];
        let mut slot_index = 0usize;
        while slot_index < slots.len() {
            let top_cycle = cycle;
            if pending.is_none()
                || macro_index
                    >= op_count(
                        pending
                            .as_ref()
                            .map(|value: &PendingInstruction| value.kind)
                            .unwrap_or(RandomXSuperscalarOpcode::IsubR),
                    )
            {
                if saturated || instructions.len() >= RANDOMX_SUPERSCALAR_MAX_SIZE {
                    break;
                }
                pending = Some(create_for_slot(
                    generator,
                    slots[slot_index],
                    buffer_index,
                    slot_index + 1 == slots.len(),
                ));
                macro_index = 0;
            }
            let Some(mut current) = pending else {
                break;
            };
            let operation = macro_op(current.kind, macro_index);
            let mut schedule_cycle = schedule(operation, &mut busy, cycle, dependency_cycle, false);
            if schedule_cycle < 0 {
                saturated = true;
                break;
            }
            if macro_index as i32 == source_op(current.kind) {
                let mut forward = 0;
                while forward < LOOK_FORWARD
                    && !current.select_source(schedule_cycle, &registers, generator)
                {
                    forward += 1;
                    schedule_cycle += 1;
                    cycle += 1;
                }
                if forward == LOOK_FORWARD {
                    if throwaways < MAX_THROWAWAY {
                        throwaways += 1;
                        macro_index = op_count(current.kind);
                        pending = Some(current);
                        continue;
                    }
                    pending = None;
                    break;
                }
            }
            if macro_index == destination_op(current.kind) {
                let mut forward = 0;
                while forward < LOOK_FORWARD
                    && !current.select_destination(
                        schedule_cycle,
                        throwaways > 0,
                        &registers,
                        generator,
                    )
                {
                    forward += 1;
                    schedule_cycle += 1;
                    cycle += 1;
                }
                if forward == LOOK_FORWARD {
                    if throwaways < MAX_THROWAWAY {
                        throwaways += 1;
                        macro_index = op_count(current.kind);
                        pending = Some(current);
                        continue;
                    }
                    pending = None;
                    break;
                }
            }
            throwaways = 0;
            schedule_cycle = schedule(operation, &mut busy, schedule_cycle, schedule_cycle, true);
            if schedule_cycle < 0 {
                saturated = true;
                break;
            }
            dependency_cycle = schedule_cycle + operation.latency;
            if macro_index == result_op(current.kind) {
                let destination = current.destination as usize;
                registers[destination] = RegisterInfo {
                    latency: dependency_cycle,
                    last_group: current.group,
                    last_parameter: current.group_parameter,
                };
            }
            let _code_size = operation.size;
            slot_index += 1;
            macro_index += 1;
            if schedule_cycle >= LATENCY {
                saturated = true;
            }
            cycle = top_cycle;
            if macro_index >= op_count(current.kind) {
                if matches!(
                    current.kind,
                    RandomXSuperscalarOpcode::ImulR
                        | RandomXSuperscalarOpcode::ImulhR
                        | RandomXSuperscalarOpcode::IsmulhR
                        | RandomXSuperscalarOpcode::ImulRcp
                ) {
                    multiply_count += 1;
                }
                instructions.push(current.finish());
            }
            pending = Some(current);
        }
        cycle += 1;
    }

    let mut latencies = [0i32; 8];
    for instruction in &instructions {
        let destination = usize::from(instruction.destination);
        let source = usize::from(instruction.source);
        let destination_latency = latencies[destination] + 1;
        let source_latency = if destination != source {
            latencies[source] + 1
        } else {
            0
        };
        latencies[destination] = destination_latency.max(source_latency);
    }
    let mut address_register = 0u8;
    let mut maximum = 0i32;
    for (index, latency) in latencies.into_iter().enumerate() {
        if latency > maximum {
            maximum = latency;
            address_register = index as u8;
        }
    }
    RandomXSuperscalarProgram {
        instructions,
        address_register,
    }
}

/// The eight programs and reciprocal table derived from one RandomX epoch key.
#[derive(Debug, Clone)]
pub struct RandomXSuperscalarConfiguration {
    /// Generated programs in cache-access order.
    pub programs: [RandomXSuperscalarProgram; RANDOMX_CACHE_ACCESSES],
    /// Generated reciprocals referenced by `IMUL_RCP` instructions.
    pub reciprocals: Vec<u64>,
}

/// Generate the canonical RandomX v1 superscalar configuration for a key.
#[must_use]
pub fn generate_randomx_superscalar_configuration(key: &[u8]) -> RandomXSuperscalarConfiguration {
    let mut generator = RandomXBlake2Generator::new(key, 0);
    let mut reciprocals = Vec::new();
    let programs = core::array::from_fn(|_| {
        let mut program = generate_one(&mut generator);
        for instruction in &mut program.instructions {
            if instruction.opcode == RandomXSuperscalarOpcode::ImulRcp {
                if let Some(value) = reciprocal(instruction.immediate) {
                    instruction.immediate = reciprocals.len() as u32;
                    reciprocals.push(value);
                }
            }
        }
        program
    });
    RandomXSuperscalarConfiguration {
        programs,
        reciprocals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_randomx_superscalar_generation_shape_matches() {
        let configuration =
            generate_randomx_superscalar_configuration(b"RandomX portable cache vector");
        assert_eq!(
            configuration
                .programs
                .each_ref()
                .map(|program| program.instructions.len()),
            [450, 447, 442, 435, 438, 448, 464, 436]
        );
        assert_eq!(
            configuration
                .programs
                .each_ref()
                .map(|program| program.address_register),
            [3, 3, 3, 3, 3, 6, 5, 4]
        );
        assert_eq!(configuration.reciprocals.len(), 241);
    }
}
