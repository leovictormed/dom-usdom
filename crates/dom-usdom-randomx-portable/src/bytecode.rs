//! Portable compiler and interpreter for one generated RandomX program.

use crate::{
    hash_aes_1rx4, reciprocal, rotate_left, rotate_right, signed_multiply_high,
    unsigned_multiply_high, InvalidAesLength, RandomXFloatVector, RandomXInstruction,
    RandomXInstructionKind, RandomXProgram, RandomXProgramConfiguration, RandomXRoundingMode,
    RANDOMX_PROGRAM_INSTRUCTIONS,
};
use blake2::{digest::consts::U32, Blake2b, Blake2b512, Digest};

/// RandomX v1 scratchpad size in bytes.
pub const RANDOMX_SCRATCHPAD_BYTES: usize = 2_097_152;

const L1_MASK: u64 = 16_376;
const L2_MASK: u64 = 262_136;
const L3_MASK: u64 = 2_097_144;
const L3_64_MASK: u32 = 2_097_088;
const DATASET_ALIGNMENT_MASK: u32 = 0x7fff_ffc0;
const PROGRAM_ITERATIONS: usize = 2_048;

/// Complete register file used by the portable RandomX interpreter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RandomXRegisterFile {
    /// Eight integer registers.
    pub integer: [u64; 8],
    /// Four additive floating-point registers.
    pub float: [RandomXFloatVector; 4],
    /// Four multiplicative floating-point registers.
    pub exponent: [RandomXFloatVector; 4],
    /// Four immutable per-program floating-point registers.
    pub constant: [RandomXFloatVector; 4],
}

impl RandomXRegisterFile {
    /// Construct the zeroed VM register file with program-derived constants.
    #[must_use]
    pub const fn new(configuration: &RandomXProgramConfiguration) -> Self {
        Self {
            integer: [0; 8],
            float: [RandomXFloatVector::from_bits(0, 0); 4],
            exponent: [RandomXFloatVector::from_bits(0, 0); 4],
            constant: configuration.initial_a,
        }
    }

    /// Encode the exact 256-byte little-endian RandomX register-file layout.
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; 256] {
        let mut output = [0u8; 256];
        let mut offset = 0;
        for value in self.integer {
            output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            offset += 8;
        }
        for bank in [self.float, self.exponent, self.constant] {
            for value in bank {
                output[offset..offset + 8].copy_from_slice(&value.lo.to_le_bytes());
                output[offset + 8..offset + 16].copy_from_slice(&value.hi.to_le_bytes());
                offset += 16;
            }
        }
        output
    }

    /// Derive the Blake2b-512 seed for the next chained RandomX program.
    #[must_use]
    pub fn next_program_seed(&self) -> [u8; 64] {
        Blake2b512::digest(self.canonical_bytes()).into()
    }
}

/// Hash the final scratchpad into the `a` registers and return RandomX's
/// 32-byte Blake2b result over the complete register file.
pub fn finalize_hash(
    scratchpad: &[u8],
    registers: &mut RandomXRegisterFile,
) -> Result<[u8; 32], InvalidAesLength> {
    let aes_hash = hash_aes_1rx4(scratchpad)?;
    for (index, register) in registers.constant.iter_mut().enumerate() {
        let offset = index * 16;
        register.lo = load_u64(&aes_hash, offset);
        register.hi = load_u64(&aes_hash, offset + 8);
    }
    Ok(Blake2b::<U32>::digest(registers.canonical_bytes()).into())
}

/// Error returned before bytecode execution when the scratchpad shape is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidScratchpadLength;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntegerSource {
    Register(u8),
    Immediate(u64),
    Zero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FloatBank {
    Float,
    Exponent,
}

#[derive(Debug, Clone, Copy)]
struct CompiledInstruction {
    kind: RandomXInstructionKind,
    destination: u8,
    source: IntegerSource,
    float_bank: FloatBank,
    immediate: u64,
    shift: u8,
    memory_mask: u64,
    branch_target: i16,
}

const EMPTY_COMPILED: CompiledInstruction = CompiledInstruction {
    kind: RandomXInstructionKind::Nop,
    destination: 0,
    source: IntegerSource::Zero,
    float_bank: FloatBank::Float,
    immediate: 0,
    shift: 0,
    memory_mask: 0,
    branch_target: 0,
};

/// Compile and execute one 256-instruction program over the supplied state.
///
/// The caller owns the rounding state because eight chained RandomX programs
/// share it. This function performs one bytecode pass; the surrounding 2,048
/// iteration dataset/scratchpad loop is implemented separately.
pub fn execute_program_once(
    program: &RandomXProgram,
    registers: &mut RandomXRegisterFile,
    scratchpad: &mut [u8],
    configuration: &RandomXProgramConfiguration,
    rounding: &mut RandomXRoundingMode,
) -> Result<(), InvalidScratchpadLength> {
    if scratchpad.len() != RANDOMX_SCRATCHPAD_BYTES {
        return Err(InvalidScratchpadLength);
    }
    let bytecode = compile(program);
    execute_compiled_once(&bytecode, registers, scratchpad, configuration, rounding);
    Ok(())
}

/// Execute the complete 2,048-iteration VM loop for one generated program.
///
/// `read_dataset` receives an aligned byte address and returns its eight
/// little-endian 64-bit words. The callback boundary permits the same VM to use
/// either a full dataset or the independently verified light-cache derivation.
pub fn execute_vm_iterations<F>(
    program: &RandomXProgram,
    registers: &mut RandomXRegisterFile,
    scratchpad: &mut [u8],
    configuration: &RandomXProgramConfiguration,
    rounding: &mut RandomXRoundingMode,
    mut read_dataset: F,
) -> Result<(), InvalidScratchpadLength>
where
    F: FnMut(u64) -> [u64; 8],
{
    if scratchpad.len() != RANDOMX_SCRATCHPAD_BYTES {
        return Err(InvalidScratchpadLength);
    }
    let bytecode = compile(program);
    let mut memory_a = configuration.memory_a;
    let mut memory_x = configuration.memory_x;
    let mut scratch_address_0 = memory_x;
    let mut scratch_address_1 = memory_a;

    for _ in 0..PROGRAM_ITERATIONS {
        let mix = registers.integer[configuration.read_registers[0]]
            ^ registers.integer[configuration.read_registers[1]];
        scratch_address_0 ^= mix as u32;
        scratch_address_0 &= L3_64_MASK;
        scratch_address_1 ^= (mix >> 32) as u32;
        scratch_address_1 &= L3_64_MASK;

        for (index, register) in registers.integer.iter_mut().enumerate() {
            *register ^= load_u64(scratchpad, scratch_address_0 as usize + index * 8);
        }
        for index in 0..4 {
            registers.float[index] =
                load_packed_float(scratchpad, scratch_address_1 as usize + index * 8);
            registers.exponent[index] =
                load_packed_float(scratchpad, scratch_address_1 as usize + (4 + index) * 8)
                    .mask_exponent_mantissa(configuration.exponent_masks);
        }

        execute_compiled_once(&bytecode, registers, scratchpad, configuration, rounding);

        memory_x ^= (registers.integer[configuration.read_registers[2]]
            ^ registers.integer[configuration.read_registers[3]]) as u32;
        memory_x &= DATASET_ALIGNMENT_MASK;
        let dataset = read_dataset(configuration.dataset_offset + u64::from(memory_a));
        for (register, value) in registers.integer.iter_mut().zip(dataset) {
            *register ^= value;
        }
        core::mem::swap(&mut memory_x, &mut memory_a);

        for (index, register) in registers.integer.iter().copied().enumerate() {
            store_u64(scratchpad, scratch_address_1 as usize + index * 8, register);
        }
        for index in 0..4 {
            registers.float[index] = RandomXFloatVector::from_bits(
                registers.float[index].lo ^ registers.exponent[index].lo,
                registers.float[index].hi ^ registers.exponent[index].hi,
            );
            store_u64(
                scratchpad,
                scratch_address_0 as usize + index * 16,
                registers.float[index].lo,
            );
            store_u64(
                scratchpad,
                scratch_address_0 as usize + index * 16 + 8,
                registers.float[index].hi,
            );
        }
        scratch_address_0 = 0;
        scratch_address_1 = 0;
    }
    Ok(())
}

fn execute_compiled_once(
    bytecode: &[CompiledInstruction; RANDOMX_PROGRAM_INSTRUCTIONS],
    registers: &mut RandomXRegisterFile,
    scratchpad: &mut [u8],
    configuration: &RandomXProgramConfiguration,
    rounding: &mut RandomXRoundingMode,
) {
    let mut pc = 0i16;
    while pc < RANDOMX_PROGRAM_INSTRUCTIONS as i16 {
        let instruction = bytecode[pc as usize];
        execute(
            instruction,
            &mut pc,
            registers,
            scratchpad,
            configuration,
            rounding,
        );
        pc += 1;
    }
}

fn compile(program: &RandomXProgram) -> [CompiledInstruction; RANDOMX_PROGRAM_INSTRUCTIONS] {
    let mut output = [EMPTY_COMPILED; RANDOMX_PROGRAM_INSTRUCTIONS];
    let mut usage = [-1i16; 8];
    for (index, raw) in program.instructions().iter().copied().enumerate() {
        output[index] = compile_one(raw, index as i16, &mut usage);
    }
    output
}

fn compile_one(raw: RandomXInstruction, index: i16, usage: &mut [i16; 8]) -> CompiledInstruction {
    let mut result = EMPTY_COMPILED;
    result.kind = raw.kind();
    let destination = raw.destination & 7;
    let source = raw.source & 7;
    result.destination = destination;
    result.immediate = raw.signed_immediate();

    match result.kind {
        RandomXInstructionKind::IaddRs => {
            result.source = IntegerSource::Register(source);
            result.shift = raw.shift_mode();
            result.immediate = if destination == 5 {
                raw.signed_immediate()
            } else {
                0
            };
            usage[destination as usize] = index;
        }
        RandomXInstructionKind::IaddM
        | RandomXInstructionKind::IsubM
        | RandomXInstructionKind::ImulM
        | RandomXInstructionKind::ImulhM
        | RandomXInstructionKind::IsmulhM
        | RandomXInstructionKind::IxorM => {
            set_memory_source(&mut result, raw, destination, source);
            usage[destination as usize] = index;
        }
        RandomXInstructionKind::IsubR
        | RandomXInstructionKind::ImulR
        | RandomXInstructionKind::IxorR => {
            result.source = register_or_signed_immediate(raw, destination, source);
            usage[destination as usize] = index;
        }
        RandomXInstructionKind::ImulhR | RandomXInstructionKind::IsmulhR => {
            result.source = IntegerSource::Register(source);
            usage[destination as usize] = index;
        }
        RandomXInstructionKind::ImulRcp => {
            if let Some(value) = reciprocal(raw.immediate) {
                result.kind = RandomXInstructionKind::ImulR;
                result.source = IntegerSource::Immediate(value);
                usage[destination as usize] = index;
            } else {
                result.kind = RandomXInstructionKind::Nop;
            }
        }
        RandomXInstructionKind::InegR => usage[destination as usize] = index,
        RandomXInstructionKind::IrorR | RandomXInstructionKind::IrolR => {
            result.source = if source == destination {
                IntegerSource::Immediate(u64::from(raw.immediate))
            } else {
                IntegerSource::Register(source)
            };
            usage[destination as usize] = index;
        }
        RandomXInstructionKind::IswapR => {
            if source == destination {
                result.kind = RandomXInstructionKind::Nop;
            } else {
                result.source = IntegerSource::Register(source);
                usage[destination as usize] = index;
                usage[source as usize] = index;
            }
        }
        RandomXInstructionKind::FswapR => {
            result.destination = raw.destination & 3;
            result.float_bank = if raw.destination & 7 < 4 {
                FloatBank::Float
            } else {
                FloatBank::Exponent
            };
        }
        RandomXInstructionKind::FaddR | RandomXInstructionKind::FsubR => {
            result.destination = raw.destination & 3;
            result.source = IntegerSource::Register(raw.source & 3);
        }
        RandomXInstructionKind::FaddM | RandomXInstructionKind::FsubM => {
            result.destination = raw.destination & 3;
            result.source = IntegerSource::Register(source);
            result.memory_mask = l1_or_l2(raw);
        }
        RandomXInstructionKind::FscalR => result.destination = raw.destination & 3,
        RandomXInstructionKind::FmulR => {
            result.destination = raw.destination & 3;
            result.source = IntegerSource::Register(raw.source & 3);
            result.float_bank = FloatBank::Exponent;
        }
        RandomXInstructionKind::FdivM => {
            result.destination = raw.destination & 3;
            result.source = IntegerSource::Register(source);
            result.memory_mask = l1_or_l2(raw);
            result.float_bank = FloatBank::Exponent;
        }
        RandomXInstructionKind::FsqrtR => {
            result.destination = raw.destination & 3;
            result.float_bank = FloatBank::Exponent;
        }
        RandomXInstructionKind::Cbranch => {
            result.branch_target = usage[destination as usize];
            let shift = u32::from(raw.condition_mode()) + 8;
            result.immediate = raw.signed_immediate() | (1u64 << shift);
            result.immediate &= !(1u64 << (shift - 1));
            result.memory_mask = 0xffu64 << shift;
            usage.fill(index);
        }
        RandomXInstructionKind::Cfround => {
            result.source = IntegerSource::Register(source);
            result.immediate = u64::from(raw.immediate & 63);
        }
        RandomXInstructionKind::Istore => {
            result.source = IntegerSource::Register(source);
            result.memory_mask = if raw.condition_mode() < 14 {
                l1_or_l2(raw)
            } else {
                L3_MASK
            };
        }
        RandomXInstructionKind::Nop => {}
    }
    result
}

fn set_memory_source(
    result: &mut CompiledInstruction,
    raw: RandomXInstruction,
    destination: u8,
    source: u8,
) {
    if source == destination {
        result.source = IntegerSource::Zero;
        result.memory_mask = L3_MASK;
    } else {
        result.source = IntegerSource::Register(source);
        result.memory_mask = l1_or_l2(raw);
    }
}

const fn register_or_signed_immediate(
    raw: RandomXInstruction,
    destination: u8,
    source: u8,
) -> IntegerSource {
    if source == destination {
        IntegerSource::Immediate(raw.signed_immediate())
    } else {
        IntegerSource::Register(source)
    }
}

const fn l1_or_l2(raw: RandomXInstruction) -> u64 {
    if raw.memory_mode() == 0 {
        L2_MASK
    } else {
        L1_MASK
    }
}

#[allow(clippy::too_many_arguments)]
fn execute(
    instruction: CompiledInstruction,
    pc: &mut i16,
    registers: &mut RandomXRegisterFile,
    scratchpad: &mut [u8],
    configuration: &RandomXProgramConfiguration,
    rounding: &mut RandomXRoundingMode,
) {
    let destination = instruction.destination as usize;
    let source = integer_source(instruction.source, registers);
    match instruction.kind {
        RandomXInstructionKind::IaddRs => {
            registers.integer[destination] = registers.integer[destination]
                .wrapping_add(source.wrapping_shl(u32::from(instruction.shift)))
                .wrapping_add(instruction.immediate);
        }
        RandomXInstructionKind::IaddM => {
            let value = load_memory(instruction, registers, scratchpad);
            registers.integer[destination] = registers.integer[destination].wrapping_add(value);
        }
        RandomXInstructionKind::IsubR => {
            registers.integer[destination] = registers.integer[destination].wrapping_sub(source);
        }
        RandomXInstructionKind::IsubM => {
            let value = load_memory(instruction, registers, scratchpad);
            registers.integer[destination] = registers.integer[destination].wrapping_sub(value);
        }
        RandomXInstructionKind::ImulR => {
            registers.integer[destination] = registers.integer[destination].wrapping_mul(source);
        }
        RandomXInstructionKind::ImulM => {
            let value = load_memory(instruction, registers, scratchpad);
            registers.integer[destination] = registers.integer[destination].wrapping_mul(value);
        }
        RandomXInstructionKind::ImulhR => {
            registers.integer[destination] =
                unsigned_multiply_high(registers.integer[destination], source);
        }
        RandomXInstructionKind::ImulhM => {
            let value = load_memory(instruction, registers, scratchpad);
            registers.integer[destination] =
                unsigned_multiply_high(registers.integer[destination], value);
        }
        RandomXInstructionKind::IsmulhR => {
            registers.integer[destination] =
                signed_multiply_high(registers.integer[destination], source);
        }
        RandomXInstructionKind::IsmulhM => {
            let value = load_memory(instruction, registers, scratchpad);
            registers.integer[destination] =
                signed_multiply_high(registers.integer[destination], value);
        }
        RandomXInstructionKind::InegR => {
            registers.integer[destination] = registers.integer[destination].wrapping_neg();
        }
        RandomXInstructionKind::IxorR => registers.integer[destination] ^= source,
        RandomXInstructionKind::IxorM => {
            registers.integer[destination] ^= load_memory(instruction, registers, scratchpad);
        }
        RandomXInstructionKind::IrorR => {
            registers.integer[destination] = rotate_right(registers.integer[destination], source);
        }
        RandomXInstructionKind::IrolR => {
            registers.integer[destination] = rotate_left(registers.integer[destination], source);
        }
        RandomXInstructionKind::IswapR => {
            if let IntegerSource::Register(source) = instruction.source {
                registers.integer.swap(destination, source as usize);
            }
        }
        RandomXInstructionKind::FswapR => {
            let value = *float_destination(registers, instruction.float_bank, destination);
            *float_destination(registers, instruction.float_bank, destination) = value.swap();
        }
        RandomXInstructionKind::FaddR => {
            let source = source_index(instruction.source);
            registers.float[destination] =
                registers.float[destination].add(registers.constant[source], *rounding);
        }
        RandomXInstructionKind::FaddM => {
            let value = load_float_memory(instruction, registers, scratchpad);
            registers.float[destination] = registers.float[destination].add(value, *rounding);
        }
        RandomXInstructionKind::FsubR => {
            let source = source_index(instruction.source);
            registers.float[destination] =
                registers.float[destination].sub(registers.constant[source], *rounding);
        }
        RandomXInstructionKind::FsubM => {
            let value = load_float_memory(instruction, registers, scratchpad);
            registers.float[destination] = registers.float[destination].sub(value, *rounding);
        }
        RandomXInstructionKind::FscalR => {
            registers.float[destination] = registers.float[destination].scale();
        }
        RandomXInstructionKind::FmulR => {
            let source = source_index(instruction.source);
            registers.exponent[destination] =
                registers.exponent[destination].mul(registers.constant[source], *rounding);
        }
        RandomXInstructionKind::FdivM => {
            let value = load_float_memory(instruction, registers, scratchpad)
                .mask_exponent_mantissa(configuration.exponent_masks);
            registers.exponent[destination] = registers.exponent[destination].div(value, *rounding);
        }
        RandomXInstructionKind::FsqrtR => {
            registers.exponent[destination] = registers.exponent[destination].sqrt(*rounding);
        }
        RandomXInstructionKind::Cbranch => {
            registers.integer[destination] =
                registers.integer[destination].wrapping_add(instruction.immediate);
            if registers.integer[destination] & instruction.memory_mask == 0 {
                *pc = instruction.branch_target;
            }
        }
        RandomXInstructionKind::Cfround => {
            *rounding =
                RandomXRoundingMode::from_state(rotate_right(source, instruction.immediate));
        }
        RandomXInstructionKind::Istore => {
            let address = registers.integer[destination].wrapping_add(instruction.immediate)
                & instruction.memory_mask;
            store_u64(scratchpad, address as usize, source);
        }
        RandomXInstructionKind::ImulRcp | RandomXInstructionKind::Nop => {}
    }
}

fn integer_source(source: IntegerSource, registers: &RandomXRegisterFile) -> u64 {
    match source {
        IntegerSource::Register(index) => registers.integer[index as usize],
        IntegerSource::Immediate(value) => value,
        IntegerSource::Zero => 0,
    }
}

fn source_index(source: IntegerSource) -> usize {
    match source {
        IntegerSource::Register(index) => index as usize,
        IntegerSource::Immediate(_) | IntegerSource::Zero => 0,
    }
}

fn memory_address(instruction: CompiledInstruction, registers: &RandomXRegisterFile) -> usize {
    (integer_source(instruction.source, registers).wrapping_add(instruction.immediate)
        & instruction.memory_mask) as usize
}

fn load_memory(
    instruction: CompiledInstruction,
    registers: &RandomXRegisterFile,
    scratchpad: &[u8],
) -> u64 {
    load_u64(scratchpad, memory_address(instruction, registers))
}

fn load_float_memory(
    instruction: CompiledInstruction,
    registers: &RandomXRegisterFile,
    scratchpad: &[u8],
) -> RandomXFloatVector {
    let address = memory_address(instruction, registers);
    load_packed_float(scratchpad, address)
}

fn load_packed_float(scratchpad: &[u8], address: usize) -> RandomXFloatVector {
    RandomXFloatVector::from_packed_i32(
        load_u32(scratchpad, address),
        load_u32(scratchpad, address + 4),
    )
}

fn float_destination(
    registers: &mut RandomXRegisterFile,
    bank: FloatBank,
    index: usize,
) -> &mut RandomXFloatVector {
    match bank {
        FloatBank::Float => &mut registers.float[index],
        FloatBank::Exponent => &mut registers.exponent[index],
    }
}

fn load_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn load_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn store_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
