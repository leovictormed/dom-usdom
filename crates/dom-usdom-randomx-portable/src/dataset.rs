//! Portable RandomX superscalar execution and light-cache dataset derivation.
//!
//! The 256 MiB Argon2d cache and eight superscalar programs are derived once
//! from the epoch key. This module consumes those independently derived values
//! and reproduces one 64-byte RandomX dataset item without native code or JIT.

use crate::{
    bytecode::{
        execute_vm_iterations, finalize_hash, RandomXRegisterFile, RANDOMX_SCRATCHPAD_BYTES,
    },
    initialize_scratchpad, rotate_right, signed_multiply_high, unsigned_multiply_high,
    RandomXProgram, RandomXRoundingMode, RandomXSuperscalarConfiguration,
};
use argon2::{Algorithm, Argon2, Block, Params, Version};

/// RandomX v1 Argon2d light-cache size in bytes.
pub const RANDOMX_CACHE_BYTES: usize = 268_435_456;
/// Number of superscalar programs applied to each dataset item.
pub const RANDOMX_CACHE_ACCESSES: usize = 8;
/// Maximum instruction count admitted for one superscalar program.
pub const RANDOMX_SUPERSCALAR_MAX_SIZE: usize = 512;

const CACHE_LINE_BYTES: usize = 64;
const RANDOMX_CACHE_BLOCKS: usize = RANDOMX_CACHE_BYTES / Block::SIZE;
const RANDOMX_ARGON_SALT: &[u8] = b"RandomX\x03";
const SUPERSCALAR_MUL0: u64 = 6_364_136_223_846_793_005;
const SUPERSCALAR_ADD: [u64; 7] = [
    9_298_411_001_130_361_340,
    12_065_312_585_734_608_966,
    9_306_329_213_124_626_780,
    5_281_919_268_842_080_866,
    10_536_153_434_571_861_004,
    3_398_623_926_847_679_864,
    9_549_104_520_008_361_294,
];

/// One of the fourteen instructions emitted by the RandomX superscalar generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RandomXSuperscalarOpcode {
    /// Subtract a source register.
    IsubR = 0,
    /// Exclusive-or a source register.
    IxorR = 1,
    /// Add a shifted source register.
    IaddRs = 2,
    /// Multiply by a source register.
    ImulR = 3,
    /// Rotate right by an immediate count.
    IrorC = 4,
    /// Add a sign-extended immediate (seven-byte encoding class).
    IaddC7 = 5,
    /// Exclusive-or a sign-extended immediate (seven-byte encoding class).
    IxorC7 = 6,
    /// Add a sign-extended immediate (eight-byte encoding class).
    IaddC8 = 7,
    /// Exclusive-or a sign-extended immediate (eight-byte encoding class).
    IxorC8 = 8,
    /// Add a sign-extended immediate (nine-byte encoding class).
    IaddC9 = 9,
    /// Exclusive-or a sign-extended immediate (nine-byte encoding class).
    IxorC9 = 10,
    /// Replace the destination with the high half of an unsigned product.
    ImulhR = 11,
    /// Replace the destination with the high half of a signed product.
    IsmulhR = 12,
    /// Multiply by a generated reciprocal.
    ImulRcp = 13,
}

impl RandomXSuperscalarOpcode {
    /// Decode the canonical RandomX opcode byte.
    pub const fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::IsubR,
            1 => Self::IxorR,
            2 => Self::IaddRs,
            3 => Self::ImulR,
            4 => Self::IrorC,
            5 => Self::IaddC7,
            6 => Self::IxorC7,
            7 => Self::IaddC8,
            8 => Self::IxorC8,
            9 => Self::IaddC9,
            10 => Self::IxorC9,
            11 => Self::ImulhR,
            12 => Self::IsmulhR,
            13 => Self::ImulRcp,
            _ => return None,
        })
    }
}

/// Canonical, architecture-independent superscalar instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomXSuperscalarInstruction {
    /// Instruction class.
    pub opcode: RandomXSuperscalarOpcode,
    /// Destination integer register, from zero through seven.
    pub destination: u8,
    /// Source integer register, from zero through seven.
    pub source: u8,
    /// Shift modifier; bits 2-3 select the `IADD_RS` shift.
    pub modifier: u8,
    /// Immediate word, or reciprocal-table index for `IMUL_RCP`.
    pub immediate: u32,
}

/// One generated RandomX superscalar program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RandomXSuperscalarProgram {
    pub(crate) instructions: Vec<RandomXSuperscalarInstruction>,
    pub(crate) address_register: u8,
}

impl RandomXSuperscalarProgram {
    /// Validate and construct a generated program.
    pub fn new(
        instructions: Vec<RandomXSuperscalarInstruction>,
        address_register: u8,
    ) -> Result<Self, InvalidSuperscalarProgram> {
        if instructions.is_empty()
            || instructions.len() > RANDOMX_SUPERSCALAR_MAX_SIZE
            || address_register >= 8
            || instructions
                .iter()
                .any(|instruction| instruction.destination >= 8 || instruction.source >= 8)
        {
            return Err(InvalidSuperscalarProgram);
        }
        Ok(Self {
            instructions,
            address_register,
        })
    }

    /// Return the program's canonical instruction sequence.
    #[must_use]
    pub fn instructions(&self) -> &[RandomXSuperscalarInstruction] {
        &self.instructions
    }

    /// Return the register that selects the next cache line.
    #[must_use]
    pub const fn address_register(&self) -> u8 {
        self.address_register
    }
}

/// A supplied superscalar program is structurally invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSuperscalarProgram;

/// Dataset derivation input is not a canonical RandomX v1 cache configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatasetDerivationError {
    /// The Argon2d cache is not exactly 256 MiB.
    InvalidCacheLength,
    /// An `IMUL_RCP` instruction names a missing reciprocal.
    InvalidReciprocalIndex,
}

/// Failure while constructing the canonical RandomX Argon2d light cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomXCacheError;

/// Failure while evaluating the complete portable RandomX light-mode hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomXHashError {
    /// The initial 2 MiB scratchpad could not be generated.
    ScratchpadInitialization,
    /// A generated VM program could not execute over the canonical scratchpad.
    VmExecution,
    /// A light-cache dataset access was structurally invalid.
    DatasetDerivation,
    /// The final AES/Blake2 hash could not be produced.
    Finalization,
}

/// Exact 256 MiB RandomX v1 Argon2d light cache.
///
/// Keeping the cache as public Argon2 blocks avoids an additional 256 MiB
/// byte copy. Words are exposed only through checked, little-endian-neutral
/// accessors used by the portable dataset derivation.
#[derive(Clone)]
pub struct RandomXArgonCache {
    blocks: Vec<Block>,
}

impl RandomXArgonCache {
    /// Return the fixed cache size in bytes.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        RANDOMX_CACHE_BYTES
    }

    fn word(&self, index: usize) -> u64 {
        let block = index / (Block::SIZE / 8);
        let word = index % (Block::SIZE / 8);
        self.blocks[block].as_ref()[word]
    }
}

/// Build the exact RandomX v1 cache for an epoch key.
///
/// Parameters are Argon2d v1.3, 262,144 KiB, three passes, one lane, no
/// output, and the eight-byte `RandomX\x03` salt used by upstream RandomX.
pub fn build_randomx_argon_cache(key: &[u8]) -> Result<RandomXArgonCache, RandomXCacheError> {
    let parameters =
        Params::new(RANDOMX_CACHE_BLOCKS as u32, 3, 1, None).map_err(|_| RandomXCacheError)?;
    let argon = Argon2::new(Algorithm::Argon2d, Version::V0x13, parameters);
    let mut blocks = vec![Block::new(); RANDOMX_CACHE_BLOCKS];
    argon
        .fill_memory(key, RANDOMX_ARGON_SALT, &mut blocks)
        .map_err(|_| RandomXCacheError)?;
    Ok(RandomXArgonCache { blocks })
}

/// Execute one generated superscalar program over eight integer registers.
pub fn execute_superscalar(
    registers: &mut [u64; 8],
    program: &RandomXSuperscalarProgram,
    reciprocals: &[u64],
) -> Result<(), DatasetDerivationError> {
    for instruction in program.instructions() {
        let destination = usize::from(instruction.destination);
        let source = usize::from(instruction.source);
        match instruction.opcode {
            RandomXSuperscalarOpcode::IsubR => {
                registers[destination] = registers[destination].wrapping_sub(registers[source]);
            }
            RandomXSuperscalarOpcode::IxorR => registers[destination] ^= registers[source],
            RandomXSuperscalarOpcode::IaddRs => {
                let shift = (instruction.modifier >> 2) & 3;
                registers[destination] = registers[destination]
                    .wrapping_add(registers[source].wrapping_shl(u32::from(shift)));
            }
            RandomXSuperscalarOpcode::ImulR => {
                registers[destination] = registers[destination].wrapping_mul(registers[source]);
            }
            RandomXSuperscalarOpcode::IrorC => {
                registers[destination] =
                    rotate_right(registers[destination], u64::from(instruction.immediate));
            }
            RandomXSuperscalarOpcode::IaddC7
            | RandomXSuperscalarOpcode::IaddC8
            | RandomXSuperscalarOpcode::IaddC9 => {
                registers[destination] =
                    registers[destination].wrapping_add(instruction.immediate as i32 as i64 as u64);
            }
            RandomXSuperscalarOpcode::IxorC7
            | RandomXSuperscalarOpcode::IxorC8
            | RandomXSuperscalarOpcode::IxorC9 => {
                registers[destination] ^= instruction.immediate as i32 as i64 as u64;
            }
            RandomXSuperscalarOpcode::ImulhR => {
                registers[destination] =
                    unsigned_multiply_high(registers[destination], registers[source]);
            }
            RandomXSuperscalarOpcode::IsmulhR => {
                registers[destination] =
                    signed_multiply_high(registers[destination], registers[source]);
            }
            RandomXSuperscalarOpcode::ImulRcp => {
                let value = reciprocals
                    .get(instruction.immediate as usize)
                    .copied()
                    .ok_or(DatasetDerivationError::InvalidReciprocalIndex)?;
                registers[destination] = registers[destination].wrapping_mul(value);
            }
        }
    }
    Ok(())
}

/// Derive one 64-byte RandomX dataset item from the exact light cache.
pub fn derive_dataset_item(
    cache: &[u8],
    programs: &[RandomXSuperscalarProgram; RANDOMX_CACHE_ACCESSES],
    reciprocals: &[u64],
    item_number: u64,
) -> Result<[u64; 8], DatasetDerivationError> {
    if cache.len() != RANDOMX_CACHE_BYTES {
        return Err(DatasetDerivationError::InvalidCacheLength);
    }
    derive_dataset_item_with_words(
        cache.len() / 8,
        |index| load_u64(cache, index * 8),
        programs,
        reciprocals,
        item_number,
    )
}

/// Derive one 64-byte item directly from an exact Argon2d light cache.
pub fn derive_dataset_item_from_argon_cache(
    cache: &RandomXArgonCache,
    programs: &[RandomXSuperscalarProgram; RANDOMX_CACHE_ACCESSES],
    reciprocals: &[u64],
    item_number: u64,
) -> Result<[u64; 8], DatasetDerivationError> {
    derive_dataset_item_with_words(
        RANDOMX_CACHE_BYTES / 8,
        |index| cache.word(index),
        programs,
        reciprocals,
        item_number,
    )
}

/// Evaluate the complete RandomX v1 hash in portable light mode.
///
/// The caller supplies the cache and superscalar configuration derived from
/// the same epoch key. The function performs all eight chained VM programs,
/// all 2,048 iterations per program, light-cache dataset derivation, and the
/// final AES/Blake2b-256 hash.
pub fn calculate_randomx_light_hash(
    input: &[u8],
    cache: &RandomXArgonCache,
    configuration: &RandomXSuperscalarConfiguration,
) -> Result<[u8; 32], RandomXHashError> {
    let mut scratchpad = vec![0u8; RANDOMX_SCRATCHPAD_BYTES];
    let mut seed = initialize_scratchpad(input, &mut scratchpad)
        .map_err(|_| RandomXHashError::ScratchpadInitialization)?;
    let mut rounding = RandomXRoundingMode::Nearest;
    let mut final_registers = None;

    for chain in 0..8 {
        let program = RandomXProgram::generate(&seed)
            .map_err(|_| RandomXHashError::ScratchpadInitialization)?;
        let program_configuration = program.configuration();
        let mut registers = RandomXRegisterFile::new(&program_configuration);
        let mut dataset_failed = false;
        execute_vm_iterations(
            &program,
            &mut registers,
            &mut scratchpad,
            &program_configuration,
            &mut rounding,
            |address| match derive_dataset_item_from_argon_cache(
                cache,
                &configuration.programs,
                &configuration.reciprocals,
                address / CACHE_LINE_BYTES as u64,
            ) {
                Ok(item) => item,
                Err(_) => {
                    dataset_failed = true;
                    [0; 8]
                }
            },
        )
        .map_err(|_| RandomXHashError::VmExecution)?;
        if dataset_failed {
            return Err(RandomXHashError::DatasetDerivation);
        }
        if chain == 7 {
            final_registers = Some(registers);
        } else {
            seed = registers.next_program_seed();
        }
    }

    let Some(mut registers) = final_registers else {
        return Err(RandomXHashError::VmExecution);
    };
    finalize_hash(&scratchpad, &mut registers).map_err(|_| RandomXHashError::Finalization)
}

#[cfg(test)]
fn derive_dataset_item_inner(
    cache: &[u8],
    programs: &[RandomXSuperscalarProgram; RANDOMX_CACHE_ACCESSES],
    reciprocals: &[u64],
    item_number: u64,
) -> Result<[u64; 8], DatasetDerivationError> {
    derive_dataset_item_with_words(
        cache.len() / 8,
        |index| load_u64(cache, index * 8),
        programs,
        reciprocals,
        item_number,
    )
}

fn derive_dataset_item_with_words<F>(
    cache_words: usize,
    mut read_word: F,
    programs: &[RandomXSuperscalarProgram; RANDOMX_CACHE_ACCESSES],
    reciprocals: &[u64],
    item_number: u64,
) -> Result<[u64; 8], DatasetDerivationError>
where
    F: FnMut(usize) -> u64,
{
    debug_assert_eq!((cache_words * 8) % CACHE_LINE_BYTES, 0);
    debug_assert!((cache_words * 8).is_power_of_two());
    let first = item_number.wrapping_add(1).wrapping_mul(SUPERSCALAR_MUL0);
    let mut registers = [0u64; 8];
    registers[0] = first;
    for (register, addend) in registers[1..].iter_mut().zip(SUPERSCALAR_ADD) {
        *register = first ^ addend;
    }

    let mut selector = item_number;
    let line_mask = cache_words / (CACHE_LINE_BYTES / 8) - 1;
    for program in programs {
        execute_superscalar(&mut registers, program, reciprocals)?;
        let line = selector as usize & line_mask;
        let word_offset = line * (CACHE_LINE_BYTES / 8);
        for (index, register) in registers.iter_mut().enumerate() {
            *register ^= read_word(word_offset + index);
        }
        selector = registers[usize::from(program.address_register())];
    }
    Ok(registers)
}

fn load_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(word)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reciprocal;
    use blake2::{Blake2b512, Digest};

    fn instruction(
        opcode: RandomXSuperscalarOpcode,
        destination: u8,
        source: u8,
        modifier: u8,
        immediate: u32,
    ) -> RandomXSuperscalarInstruction {
        RandomXSuperscalarInstruction {
            opcode,
            destination,
            source,
            modifier,
            immediate,
        }
    }

    fn program(
        instructions: Vec<RandomXSuperscalarInstruction>,
        address_register: u8,
    ) -> Result<RandomXSuperscalarProgram, &'static str> {
        RandomXSuperscalarProgram::new(instructions, address_register)
            .map_err(|_| "valid test program rejected")
    }

    #[test]
    fn upstream_randomx_superscalar_execution_matches_every_instruction_class(
    ) -> Result<(), &'static str> {
        let program = program(
            vec![
                instruction(RandomXSuperscalarOpcode::IsubR, 0, 1, 0, 0),
                instruction(RandomXSuperscalarOpcode::IxorR, 1, 2, 0, 0),
                instruction(RandomXSuperscalarOpcode::IaddRs, 2, 3, 12, 0),
                instruction(RandomXSuperscalarOpcode::ImulR, 3, 4, 0, 0),
                instruction(RandomXSuperscalarOpcode::IrorC, 4, 4, 0, 17),
                instruction(RandomXSuperscalarOpcode::IaddC7, 5, 5, 0, 0x8000_0001),
                instruction(RandomXSuperscalarOpcode::IxorC8, 6, 6, 0, 0xffff_ff80),
                instruction(RandomXSuperscalarOpcode::IaddC9, 7, 7, 0, 0x7fff_ffff),
                instruction(RandomXSuperscalarOpcode::ImulhR, 0, 5, 0, 0),
                instruction(RandomXSuperscalarOpcode::IsmulhR, 1, 6, 0, 0),
                instruction(RandomXSuperscalarOpcode::ImulRcp, 2, 2, 0, 0),
            ],
            3,
        )?;
        let mut registers = [
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            0x8877_6655_4433_2211,
            0x1234_5678_9abc_def0,
            0x0fed_cba9_8765_4321,
            0x1111_2222_3333_4444,
            0x9999_aaaa_bbbb_cccc,
            0x5555_6666_7777_8888,
        ];
        let expected_reciprocal = reciprocal(3).ok_or("three must have a reciprocal")?;
        assert_eq!(
            execute_superscalar(&mut registers, &program, &[expected_reciprocal]),
            Ok(())
        );
        assert_eq!(
            registers,
            [
                0x0026_d634_a328_4726,
                0x2f77_ea02_52dc_db63,
                0x43ee_9943_ee99_444a,
                0x2236_d88f_e561_8cf0,
                0xa190_87f6_e5d4_c3b2,
                0x1111_2221_b333_4445,
                0x6666_5555_4444_334c,
                0x5555_6666_f777_8887,
            ]
        );
        Ok(())
    }

    #[test]
    fn compact_cache_fixture_binds_dataset_address_chaining() -> Result<(), &'static str> {
        let program = program(
            vec![instruction(RandomXSuperscalarOpcode::IxorR, 0, 1, 0, 0)],
            0,
        )?;
        let programs = core::array::from_fn(|_| program.clone());
        let mut cache = vec![0u8; 1_024];
        for (index, byte) in cache.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(29).wrapping_add(7);
        }
        assert_eq!(
            derive_dataset_item_inner(&cache, &programs, &[], 0x1234_5678_9abc_def0),
            Ok([
                0x662d_0e71_3491_bfdd,
                0x2767_d93b_ada4_5e61,
                0x011d_576e_4c93_a7db,
                0x27cb_772d_cbf3_3641,
                0x6fa0_6ba6_e34e_f57f,
                0xb45a_a188_3a7b_1311,
                0x0947_18c5_98b7_d2e5,
                0x22e8_f546_c27d_9ad3,
            ])
        );
        Ok(())
    }

    #[test]
    fn invalid_shapes_fail_closed() -> Result<(), &'static str> {
        let invalid_instruction = instruction(RandomXSuperscalarOpcode::ImulR, 8, 0, 0, 0);
        assert_eq!(
            RandomXSuperscalarProgram::new(vec![invalid_instruction], 0),
            Err(InvalidSuperscalarProgram)
        );
        let valid = program(
            vec![instruction(RandomXSuperscalarOpcode::ImulRcp, 0, 0, 0, 4)],
            0,
        )?;
        let mut registers = [1; 8];
        assert_eq!(
            execute_superscalar(&mut registers, &valid, &[]),
            Err(DatasetDerivationError::InvalidReciprocalIndex)
        );
        let programs = core::array::from_fn(|_| valid.clone());
        assert_eq!(
            derive_dataset_item(&[], &programs, &[], 0),
            Err(DatasetDerivationError::InvalidCacheLength)
        );
        Ok(())
    }

    #[test]
    #[ignore = "allocates and hashes the canonical 256 MiB RandomX cache"]
    fn upstream_randomx_argon2d_cache_vector_matches() -> Result<(), &'static str> {
        let cache = build_randomx_argon_cache(b"RandomX portable cache vector")
            .map_err(|_| "RandomX cache construction failed")?;
        assert_eq!(cache.byte_len(), RANDOMX_CACHE_BYTES);
        assert_eq!(
            (0..8).map(|index| cache.word(index)).collect::<Vec<_>>(),
            vec![
                0xaf9e_233e_61b6_eae5,
                0xbdc4_3d06_e110_ea26,
                0x0b1d_4c3a_606b_c88e,
                0x78f4_4aff_dcd1_96af,
                0x8daf_8fef_1a1d_2355,
                0x6547_ef8a_52f2_57ab,
                0x9ff0_9aa6_2761_b185,
                0xd4fd_42ac_9fe8_ebe3,
            ]
        );
        let last = RANDOMX_CACHE_BYTES / 8 - 8;
        assert_eq!(
            (last..last + 8)
                .map(|index| cache.word(index))
                .collect::<Vec<_>>(),
            vec![
                0xa39b_198b_88aa_e726,
                0xa384_014b_f294_4fb6,
                0xe50d_d554_acad_7e62,
                0xf30a_bf3a_f7f7_8d5a,
                0xc2cf_7349_24f4_8261,
                0x5531_402e_5446_5097,
                0xeb07_880a_9005_e4b0,
                0x20b9_8d9c_a3d7_adc8,
            ]
        );
        let mut digest = Blake2b512::new();
        for block in &cache.blocks {
            for word in block.as_ref() {
                digest.update(word.to_le_bytes());
            }
        }
        assert_eq!(
            &digest.finalize()[..],
            &[
                0x6d, 0x9e, 0x49, 0x12, 0xc0, 0x93, 0xa9, 0x4e, 0x3c, 0x54, 0x97, 0xd9, 0xbe, 0x3d,
                0x3e, 0xa9, 0x36, 0xdd, 0xf1, 0x50, 0x2b, 0x17, 0xc8, 0xcd, 0xda, 0x70, 0xe1, 0x56,
                0xd5, 0x8b, 0xd2, 0x72, 0xa5, 0xec, 0x11, 0x80, 0xbe, 0x05, 0xf6, 0x99, 0xd3, 0xe0,
                0x03, 0xec, 0x25, 0x6b, 0x99, 0x88, 0xbb, 0x76, 0x4a, 0x93, 0x6e, 0x01, 0xe8, 0x34,
                0xdf, 0xa3, 0x57, 0xbc, 0x94, 0x30, 0x58, 0x41,
            ]
        );
        let configuration =
            crate::generate_randomx_superscalar_configuration(b"RandomX portable cache vector");
        assert_eq!(
            derive_dataset_item_from_argon_cache(
                &cache,
                &configuration.programs,
                &configuration.reciprocals,
                0,
            ),
            Ok([
                0x9909_4638_6817_0426,
                0x23f8_e945_cfeb_fecd,
                0xca53_1562_fd65_6031,
                0x0484_d5c0_d7ee_f3e3,
                0x04ca_2129_0b84_60fe,
                0x8b0d_379a_c758_17cd,
                0xb3be_7001_0e05_d935,
                0xd1a0_bd73_4693_9acc,
            ])
        );
        assert_eq!(
            calculate_randomx_light_hash(b"RandomX portable full hash", &cache, &configuration),
            Ok([
                0x2d, 0xc2, 0xbf, 0xdd, 0x28, 0x02, 0xc2, 0x40, 0x73, 0x4e, 0x57, 0xdb, 0xf9, 0x34,
                0x90, 0x3d, 0xa9, 0xdd, 0x71, 0x40, 0x38, 0xbc, 0x6a, 0x87, 0x53, 0x77, 0x69, 0x6f,
                0x12, 0xe2, 0xe2, 0xef,
            ])
        );
        Ok(())
    }
}
