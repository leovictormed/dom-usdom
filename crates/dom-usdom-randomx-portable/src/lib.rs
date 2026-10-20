//! Bit-exact portable arithmetic used by the RandomX v1 proof relation.
//!
//! RandomX changes the IEEE-754 rounding direction while executing generated
//! programs. RISC Zero's RV32IM target has no hardware floating-point unit, so
//! ordinary Rust `f64` operations cannot reproduce that state machine. This
//! module operates only on the raw binary64 representation and applies an
//! explicit rounding mode to every arithmetic instruction.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod bytecode;
pub mod dataset;
mod superscalar;

pub use superscalar::{
    generate_randomx_superscalar_configuration, RandomXSuperscalarConfiguration,
};

use blake2::{Blake2b512, Digest};
use ieee_apsqrt::sqrt_accurate;
use rustc_apfloat::{ieee::Double, Float, Round};

/// Mask used by RandomX `FSCAL_R`.
pub const RANDOMX_FLOAT_SCALE_MASK: u64 = 0x80f0_0000_0000_0000;
/// Mantissa and four dynamic exponent bits retained by `FDIV_M`.
pub const RANDOMX_DYNAMIC_MANTISSA_MASK: u64 = (1u64 << 56) - 1;
/// Number of generated instructions in one RandomX v1 program.
pub const RANDOMX_PROGRAM_INSTRUCTIONS: usize = 256;
/// Serialized byte length of one RandomX v1 program.
pub const RANDOMX_PROGRAM_BYTES: usize = 128 + RANDOMX_PROGRAM_INSTRUCTIONS * 8;

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// One 128-bit RandomX AES lane in the reference little-endian byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomXAesBlock(pub [u8; 16]);

impl RandomXAesBlock {
    /// Execute the RandomX/AES `AESENC` round with the supplied round key.
    #[must_use]
    pub fn encrypt_round(self, key: Self) -> Self {
        let mut shifted = [0u8; 16];
        for column in 0..4 {
            for row in 0..4 {
                shifted[row + 4 * column] =
                    AES_SBOX[usize::from(self.0[row + 4 * ((column + row) & 3)])];
            }
        }

        let mut output = [0u8; 16];
        for column in 0..4 {
            let offset = 4 * column;
            let lane = [
                shifted[offset],
                shifted[offset + 1],
                shifted[offset + 2],
                shifted[offset + 3],
            ];
            output[offset] = gf_multiply(lane[0], 2) ^ gf_multiply(lane[1], 3) ^ lane[2] ^ lane[3];
            output[offset + 1] =
                lane[0] ^ gf_multiply(lane[1], 2) ^ gf_multiply(lane[2], 3) ^ lane[3];
            output[offset + 2] =
                lane[0] ^ lane[1] ^ gf_multiply(lane[2], 2) ^ gf_multiply(lane[3], 3);
            output[offset + 3] =
                gf_multiply(lane[0], 3) ^ lane[1] ^ lane[2] ^ gf_multiply(lane[3], 2);
        }
        xor_block(output, key.0)
    }

    /// Execute the RandomX/AES `AESDEC` round with the supplied round key.
    #[must_use]
    pub fn decrypt_round(self, key: Self) -> Self {
        let mut shifted = [0u8; 16];
        for column in 0..4 {
            for row in 0..4 {
                shifted[row + 4 * column] =
                    AES_INV_SBOX[usize::from(self.0[row + 4 * ((column + 4 - row) & 3)])];
            }
        }

        let mut output = [0u8; 16];
        for column in 0..4 {
            let offset = 4 * column;
            let lane = [
                shifted[offset],
                shifted[offset + 1],
                shifted[offset + 2],
                shifted[offset + 3],
            ];
            output[offset] = gf_multiply(lane[0], 14)
                ^ gf_multiply(lane[1], 11)
                ^ gf_multiply(lane[2], 13)
                ^ gf_multiply(lane[3], 9);
            output[offset + 1] = gf_multiply(lane[0], 9)
                ^ gf_multiply(lane[1], 14)
                ^ gf_multiply(lane[2], 11)
                ^ gf_multiply(lane[3], 13);
            output[offset + 2] = gf_multiply(lane[0], 13)
                ^ gf_multiply(lane[1], 9)
                ^ gf_multiply(lane[2], 14)
                ^ gf_multiply(lane[3], 11);
            output[offset + 3] = gf_multiply(lane[0], 11)
                ^ gf_multiply(lane[1], 13)
                ^ gf_multiply(lane[2], 9)
                ^ gf_multiply(lane[3], 14);
        }
        xor_block(output, key.0)
    }
}

/// Input-size failure for a RandomX AES generator or hash operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidAesLength;

/// Deterministic byte stream used by RandomX program and superscalar creation.
///
/// This is the exact 64-byte state machine from RandomX v1. Seeds longer than
/// 60 bytes are intentionally truncated before the little-endian nonce.
#[derive(Debug, Clone)]
pub struct RandomXBlake2Generator {
    data: [u8; 64],
    index: usize,
}

/// One raw eight-byte RandomX v1 instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomXInstruction {
    /// Weighted opcode byte.
    pub opcode: u8,
    /// Destination selector byte.
    pub destination: u8,
    /// Source selector byte.
    pub source: u8,
    /// Memory, shift and condition modifier byte.
    pub modifier: u8,
    /// Little-endian immediate word.
    pub immediate: u32,
}

impl RandomXInstruction {
    /// Decode the weighted opcode into its RandomX v1 instruction class.
    #[must_use]
    pub const fn kind(self) -> RandomXInstructionKind {
        RandomXInstructionKind::from_opcode(self.opcode)
    }

    /// Decode modifier bits 0-1, which select a scratchpad tier.
    #[must_use]
    pub const fn memory_mode(self) -> u8 {
        self.modifier & 3
    }

    /// Decode modifier bits 2-3, which select an integer shift.
    #[must_use]
    pub const fn shift_mode(self) -> u8 {
        (self.modifier >> 2) & 3
    }

    /// Decode modifier bits 4-7, which select a branch/store condition.
    #[must_use]
    pub const fn condition_mode(self) -> u8 {
        self.modifier >> 4
    }

    /// Sign-extend the immediate word to its 64-bit register representation.
    #[must_use]
    pub const fn signed_immediate(self) -> u64 {
        self.immediate as i32 as i64 as u64
    }
}

/// One of the thirty RandomX v1 instruction classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RandomXInstructionKind {
    /// Integer add with scaled register.
    IaddRs,
    /// Integer add from scratchpad memory.
    IaddM,
    /// Integer subtract register/immediate.
    IsubR,
    /// Integer subtract from scratchpad memory.
    IsubM,
    /// Integer multiply register/immediate.
    ImulR,
    /// Integer multiply from scratchpad memory.
    ImulM,
    /// Unsigned high multiply register.
    ImulhR,
    /// Unsigned high multiply memory.
    ImulhM,
    /// Signed high multiply register.
    IsmulhR,
    /// Signed high multiply memory.
    IsmulhM,
    /// Integer multiply by generated reciprocal.
    ImulRcp,
    /// Two's-complement negation.
    InegR,
    /// Integer exclusive-or register/immediate.
    IxorR,
    /// Integer exclusive-or memory.
    IxorM,
    /// Integer rotate right.
    IrorR,
    /// Integer rotate left.
    IrolR,
    /// Integer register swap.
    IswapR,
    /// Floating lane swap.
    FswapR,
    /// Floating add register.
    FaddR,
    /// Floating add memory.
    FaddM,
    /// Floating subtract register.
    FsubR,
    /// Floating subtract memory.
    FsubM,
    /// Floating exponent scaling transform.
    FscalR,
    /// Floating multiply register.
    FmulR,
    /// Floating divide by masked memory.
    FdivM,
    /// Floating square root.
    FsqrtR,
    /// Conditional branch.
    Cbranch,
    /// Change floating-point rounding state.
    Cfround,
    /// Store integer register to scratchpad.
    Istore,
    /// No operation. The standard v1 frequency for this class is zero.
    Nop,
}

impl RandomXInstructionKind {
    /// Map every possible weighted opcode to the canonical v1 class.
    #[must_use]
    pub const fn from_opcode(opcode: u8) -> Self {
        match opcode {
            0..=15 => Self::IaddRs,
            16..=22 => Self::IaddM,
            23..=38 => Self::IsubR,
            39..=45 => Self::IsubM,
            46..=61 => Self::ImulR,
            62..=65 => Self::ImulM,
            66..=69 => Self::ImulhR,
            70 => Self::ImulhM,
            71..=74 => Self::IsmulhR,
            75 => Self::IsmulhM,
            76..=83 => Self::ImulRcp,
            84..=85 => Self::InegR,
            86..=100 => Self::IxorR,
            101..=105 => Self::IxorM,
            106..=113 => Self::IrorR,
            114..=115 => Self::IrolR,
            116..=119 => Self::IswapR,
            120..=123 => Self::FswapR,
            124..=139 => Self::FaddR,
            140..=144 => Self::FaddM,
            145..=160 => Self::FsubR,
            161..=165 => Self::FsubM,
            166..=171 => Self::FscalR,
            172..=203 => Self::FmulR,
            204..=207 => Self::FdivM,
            208..=213 => Self::FsqrtR,
            214..=238 => Self::Cbranch,
            239 => Self::Cfround,
            240..=255 => Self::Istore,
        }
    }
}

/// Raw entropy and instruction stream generated for one RandomX VM program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RandomXProgram {
    entropy: [u64; 16],
    instructions: [RandomXInstruction; RANDOMX_PROGRAM_INSTRUCTIONS],
}

/// VM configuration deterministically derived from program entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomXProgramConfiguration {
    /// Initial positive floating-point `a` registers.
    pub initial_a: [RandomXFloatVector; 4],
    /// Initial dataset memory address register.
    pub memory_a: u32,
    /// Initial dataset memory XOR register.
    pub memory_x: u32,
    /// Integer registers that control scratchpad and dataset addressing.
    pub read_registers: [usize; 4],
    /// Byte offset into the RandomX extra dataset region.
    pub dataset_offset: u64,
    /// Program-specific exponent and mantissa masks.
    pub exponent_masks: [u64; 2],
}

impl RandomXProgram {
    /// Generate and parse one program from a 512-bit VM seed.
    pub fn generate(seed: &[u8; 64]) -> Result<Self, InvalidAesLength> {
        let mut bytes = [0u8; RANDOMX_PROGRAM_BYTES];
        fill_aes_4rx4(seed, &mut bytes)?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Return one of the sixteen raw entropy words.
    #[must_use]
    pub const fn entropy(&self, index: usize) -> u64 {
        self.entropy[index]
    }

    /// Return the complete generated instruction stream.
    #[must_use]
    pub const fn instructions(&self) -> &[RandomXInstruction; RANDOMX_PROGRAM_INSTRUCTIONS] {
        &self.instructions
    }

    /// Derive the initial VM configuration from the program entropy.
    #[must_use]
    pub fn configuration(&self) -> RandomXProgramConfiguration {
        let mut selector = self.entropy[12];
        let mut read_registers = [0usize; 4];
        for (index, base) in [0usize, 2, 4, 6].into_iter().enumerate() {
            read_registers[index] = base + (selector & 1) as usize;
            selector >>= 1;
        }
        RandomXProgramConfiguration {
            initial_a: core::array::from_fn(|index| {
                RandomXFloatVector::from_bits(
                    small_positive_float_bits(self.entropy[index * 2]),
                    small_positive_float_bits(self.entropy[index * 2 + 1]),
                )
            }),
            memory_a: self.entropy[8] as u32 & 0x7fff_ffc0,
            memory_x: self.entropy[10] as u32,
            read_registers,
            dataset_offset: (self.entropy[13] % 524_288) * 64,
            exponent_masks: [float_mask(self.entropy[14]), float_mask(self.entropy[15])],
        }
    }

    fn from_bytes(bytes: &[u8; RANDOMX_PROGRAM_BYTES]) -> Self {
        let mut entropy = [0u64; 16];
        for (index, word) in entropy.iter_mut().enumerate() {
            let offset = index * 8;
            *word = u64::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
        }
        let empty = RandomXInstruction {
            opcode: 0,
            destination: 0,
            source: 0,
            modifier: 0,
            immediate: 0,
        };
        let mut instructions = [empty; RANDOMX_PROGRAM_INSTRUCTIONS];
        for (index, instruction) in instructions.iter_mut().enumerate() {
            let offset = 128 + index * 8;
            *instruction = RandomXInstruction {
                opcode: bytes[offset],
                destination: bytes[offset + 1],
                source: bytes[offset + 2],
                modifier: bytes[offset + 3],
                immediate: u32::from_le_bytes([
                    bytes[offset + 4],
                    bytes[offset + 5],
                    bytes[offset + 6],
                    bytes[offset + 7],
                ]),
            };
        }
        Self {
            entropy,
            instructions,
        }
    }
}

const fn small_positive_float_bits(entropy: u64) -> u64 {
    let exponent = ((entropy >> 59) + 1023) & 0x7ff;
    (exponent << 52) | (entropy & ((1u64 << 52) - 1))
}

const fn float_mask(entropy: u64) -> u64 {
    let static_exponent = (0x300 | ((entropy >> 60) << 4)) << 52;
    (entropy & ((1u64 << 22) - 1)) | static_exponent
}

impl RandomXBlake2Generator {
    /// Construct a generator for `seed` and the signed RandomX nonce bits.
    #[must_use]
    pub fn new(seed: &[u8], nonce: i32) -> Self {
        let mut data = [0u8; 64];
        let seed_length = seed.len().min(60);
        data[..seed_length].copy_from_slice(&seed[..seed_length]);
        data[60..].copy_from_slice(&nonce.to_le_bytes());
        Self { data, index: 64 }
    }

    /// Return the next byte from the RandomX Blake2 stream.
    pub fn next_byte(&mut self) -> u8 {
        self.refill_if_needed(1);
        let value = self.data[self.index];
        self.index += 1;
        value
    }

    /// Return the next little-endian 32-bit word from the stream.
    pub fn next_u32(&mut self) -> u32 {
        self.refill_if_needed(4);
        let offset = self.index;
        self.index += 4;
        u32::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ])
    }

    fn refill_if_needed(&mut self, needed: usize) {
        if self.index + needed > self.data.len() {
            let digest = Blake2b512::digest(self.data);
            self.data.copy_from_slice(&digest);
            self.index = 0;
        }
    }
}

const AES_HASH_STATE: [RandomXAesBlock; 4] = [
    aes_block_from_set_words(0xd7983aad, 0xcc82db47, 0x9fa856de, 0x92b52c0d),
    aes_block_from_set_words(0xace78057, 0xf59e125a, 0x15c7b798, 0x338d996e),
    aes_block_from_set_words(0xe8a07ce4, 0x5079506b, 0xae62c7d0, 0x6a770017),
    aes_block_from_set_words(0x7e994948, 0x79a10005, 0x07ad828d, 0x630a240c),
];
const AES_HASH_XKEYS: [RandomXAesBlock; 2] = [
    aes_block_from_set_words(0x06890201, 0x90dc56bf, 0x8b24949f, 0xf6fa8389),
    aes_block_from_set_words(0xed18f99b, 0xee1043c6, 0x51f4e03c, 0x61b263d1),
];
const AES_GEN_1R_KEYS: [RandomXAesBlock; 4] = [
    aes_block_from_set_words(0xb4f44917, 0xdbb5552b, 0x62716609, 0x6daca553),
    aes_block_from_set_words(0x0da1dc4e, 0x1725d378, 0x846a710d, 0x6d7caf07),
    aes_block_from_set_words(0x3e20e345, 0xf4c0794f, 0x9f947ec6, 0x3f1262f1),
    aes_block_from_set_words(0x49169154, 0x16314c88, 0xb1ba317c, 0x6aef8135),
];
const AES_GEN_4R_KEYS: [RandomXAesBlock; 8] = [
    aes_block_from_set_words(0x99e5d23f, 0x2f546d2b, 0xd1833ddb, 0x6421aadd),
    aes_block_from_set_words(0xa5dfcde5, 0x06f79d53, 0xb6913f55, 0xb20e3450),
    aes_block_from_set_words(0x171c02bf, 0x0aa4679f, 0x515e7baf, 0x5c3ed904),
    aes_block_from_set_words(0xd8ded291, 0xcd673785, 0xe78f5d08, 0x85623763),
    aes_block_from_set_words(0x229effb4, 0x3d518b6d, 0xe3d6a7a6, 0xb5826f73),
    aes_block_from_set_words(0xb272b7d2, 0xe9024d4e, 0x9c10b3d9, 0xc7566bf3),
    aes_block_from_set_words(0xf63befa7, 0x2ba9660a, 0xf765a38b, 0xf273c9e7),
    aes_block_from_set_words(0xc0b0762d, 0x0c06d1fd, 0x915839de, 0x7a7cd609),
];

/// Fill a buffer using the RandomX one-round, four-lane AES generator.
///
/// `output.len()` must be a multiple of 64. The final generator state is
/// written back exactly as in `fillAes1Rx4` from RandomX v1.
pub fn fill_aes_1rx4(state: &mut [u8; 64], output: &mut [u8]) -> Result<(), InvalidAesLength> {
    if output.len() & 63 != 0 {
        return Err(InvalidAesLength);
    }
    let mut lanes = read_lanes(state);
    for block_index in 0..output.len() / 64 {
        lanes[0] = lanes[0].decrypt_round(AES_GEN_1R_KEYS[0]);
        lanes[1] = lanes[1].encrypt_round(AES_GEN_1R_KEYS[1]);
        lanes[2] = lanes[2].decrypt_round(AES_GEN_1R_KEYS[2]);
        lanes[3] = lanes[3].encrypt_round(AES_GEN_1R_KEYS[3]);
        write_lanes(&mut output[block_index * 64..(block_index + 1) * 64], lanes);
    }
    write_lanes(state, lanes);
    Ok(())
}

/// Fill a buffer using the RandomX four-round, four-lane AES generator.
///
/// `output.len()` must be a multiple of 64. RandomX leaves the caller's input
/// state unchanged for this generator.
pub fn fill_aes_4rx4(state: &[u8; 64], output: &mut [u8]) -> Result<(), InvalidAesLength> {
    if output.len() & 63 != 0 {
        return Err(InvalidAesLength);
    }
    let mut lanes = read_lanes(state);
    for block_index in 0..output.len() / 64 {
        for round in 0..4 {
            lanes[0] = lanes[0].decrypt_round(AES_GEN_4R_KEYS[round]);
            lanes[1] = lanes[1].encrypt_round(AES_GEN_4R_KEYS[round]);
            lanes[2] = lanes[2].decrypt_round(AES_GEN_4R_KEYS[round + 4]);
            lanes[3] = lanes[3].encrypt_round(AES_GEN_4R_KEYS[round + 4]);
        }
        write_lanes(&mut output[block_index * 64..(block_index + 1) * 64], lanes);
    }
    Ok(())
}

/// Calculate the 512-bit RandomX one-round, four-lane AES hash.
///
/// `input.len()` must be a multiple of 64.
pub fn hash_aes_1rx4(input: &[u8]) -> Result<[u8; 64], InvalidAesLength> {
    if input.len() & 63 != 0 {
        return Err(InvalidAesLength);
    }
    let mut lanes = AES_HASH_STATE;
    for block_index in 0..input.len() / 64 {
        let keys = read_lanes(&input[block_index * 64..(block_index + 1) * 64]);
        lanes[0] = lanes[0].encrypt_round(keys[0]);
        lanes[1] = lanes[1].decrypt_round(keys[1]);
        lanes[2] = lanes[2].encrypt_round(keys[2]);
        lanes[3] = lanes[3].decrypt_round(keys[3]);
    }
    for key in AES_HASH_XKEYS {
        lanes[0] = lanes[0].encrypt_round(key);
        lanes[1] = lanes[1].decrypt_round(key);
        lanes[2] = lanes[2].encrypt_round(key);
        lanes[3] = lanes[3].decrypt_round(key);
    }
    let mut output = [0u8; 64];
    write_lanes(&mut output, lanes);
    Ok(output)
}

/// Derive the initial Blake2b-512 seed and fill the 2 MiB RandomX scratchpad.
///
/// The returned seed is the post-generator state used to create the first VM
/// program, matching the in-place mutation in `fillAes1Rx4`.
pub fn initialize_scratchpad(
    input: &[u8],
    scratchpad: &mut [u8],
) -> Result<[u8; 64], InvalidAesLength> {
    if scratchpad.len() != bytecode::RANDOMX_SCRATCHPAD_BYTES {
        return Err(InvalidAesLength);
    }
    let mut seed: [u8; 64] = Blake2b512::digest(input).into();
    fill_aes_1rx4(&mut seed, scratchpad)?;
    Ok(seed)
}

const fn aes_block_from_set_words(i3: u32, i2: u32, i1: u32, i0: u32) -> RandomXAesBlock {
    let a = i0.to_le_bytes();
    let b = i1.to_le_bytes();
    let c = i2.to_le_bytes();
    let d = i3.to_le_bytes();
    RandomXAesBlock([
        a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1], d[2],
        d[3],
    ])
}

fn read_lanes(bytes: &[u8]) -> [RandomXAesBlock; 4] {
    let mut lanes = [RandomXAesBlock([0u8; 16]); 4];
    for (index, lane) in lanes.iter_mut().enumerate() {
        lane.0.copy_from_slice(&bytes[index * 16..(index + 1) * 16]);
    }
    lanes
}

fn write_lanes(bytes: &mut [u8], lanes: [RandomXAesBlock; 4]) {
    for (index, lane) in lanes.into_iter().enumerate() {
        bytes[index * 16..(index + 1) * 16].copy_from_slice(&lane.0);
    }
}

fn gf_multiply(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0;
    for _ in 0..8 {
        if right & 1 != 0 {
            product ^= left;
        }
        let high = left & 0x80;
        left <<= 1;
        if high != 0 {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    product
}

fn xor_block(mut left: [u8; 16], right: [u8; 16]) -> RandomXAesBlock {
    for index in 0..16 {
        left[index] ^= right[index];
    }
    RandomXAesBlock(left)
}

/// Return the upper 64 bits of an unsigned 64-by-64-bit product (`IMULH_R`).
#[must_use]
pub const fn unsigned_multiply_high(left: u64, right: u64) -> u64 {
    ((left as u128).wrapping_mul(right as u128) >> 64) as u64
}

/// Return the upper 64 bits of a signed 64-by-64-bit product (`ISMULH_R`).
///
/// The result is returned as its two's-complement bit representation, matching
/// the RandomX integer register file.
#[must_use]
pub const fn signed_multiply_high(left: u64, right: u64) -> u64 {
    let product = (left as i64 as i128).wrapping_mul(right as i64 as i128);
    (product >> 64) as u64
}

/// Rotate a RandomX integer register right by the low six bits of `shift`.
#[must_use]
pub const fn rotate_right(value: u64, shift: u64) -> u64 {
    value.rotate_right((shift & 63) as u32)
}

/// Rotate a RandomX integer register left by the low six bits of `shift`.
#[must_use]
pub const fn rotate_left(value: u64, shift: u64) -> u64 {
    value.rotate_left((shift & 63) as u32)
}

/// Compute the 64-bit fixed-point reciprocal used by `IMUL_RCP`.
///
/// RandomX never generates this instruction for zero or powers of two. Those
/// invalid encodings return `None`, keeping malformed witness data from
/// triggering a divide-by-zero panic inside a proof guest.
#[must_use]
pub const fn reciprocal(divisor: u32) -> Option<u64> {
    if divisor == 0 || divisor.is_power_of_two() {
        return None;
    }

    let divisor = divisor as u64;
    let quotient = (1u64 << 63) / divisor;
    let remainder = (1u64 << 63) % divisor;
    let shift = 64 - divisor.leading_zeros();
    Some((quotient << shift).wrapping_add(((remainder as u128) << shift) as u64 / divisor))
}

/// RandomX v1 floating-point rounding state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RandomXRoundingMode {
    /// Round to nearest, with halfway values rounded to even.
    Nearest = 0,
    /// Round toward negative infinity.
    Down = 1,
    /// Round toward positive infinity.
    Up = 2,
    /// Round toward zero.
    Zero = 3,
}

impl RandomXRoundingMode {
    /// Decode the low two RandomX rounding-state bits.
    #[must_use]
    pub const fn from_state(state: u64) -> Self {
        match state & 3 {
            0 => Self::Nearest,
            1 => Self::Down,
            2 => Self::Up,
            _ => Self::Zero,
        }
    }

    fn apfloat(self) -> Round {
        match self {
            Self::Nearest => Round::NearestTiesToEven,
            Self::Down => Round::TowardNegative,
            Self::Up => Round::TowardPositive,
            Self::Zero => Round::TowardZero,
        }
    }
}

/// Two binary64 lanes in the exact little-endian RandomX register order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomXFloatVector {
    /// Lane stored at the lower address.
    pub lo: u64,
    /// Lane stored at the higher address.
    pub hi: u64,
}

impl RandomXFloatVector {
    /// Construct a vector from its raw IEEE-754 lane representations.
    #[must_use]
    pub const fn from_bits(lo: u64, hi: u64) -> Self {
        Self { lo, hi }
    }

    /// Convert two little-endian signed 32-bit scratchpad words to binary64.
    #[must_use]
    pub fn from_packed_i32(lo: u32, hi: u32) -> Self {
        Self {
            lo: signed_i32_to_binary64(lo),
            hi: signed_i32_to_binary64(hi),
        }
    }

    /// Swap the two lanes (`FSWAP_R`).
    #[must_use]
    pub const fn swap(self) -> Self {
        Self {
            lo: self.hi,
            hi: self.lo,
        }
    }

    /// Add both lanes with the current RandomX rounding state.
    #[must_use]
    pub fn add(self, other: Self, mode: RandomXRoundingMode) -> Self {
        map_binary(self, other, mode, Double::add_r)
    }

    /// Subtract both lanes with the current RandomX rounding state.
    #[must_use]
    pub fn sub(self, other: Self, mode: RandomXRoundingMode) -> Self {
        map_binary(self, other, mode, Double::sub_r)
    }

    /// Multiply both lanes with the current RandomX rounding state.
    #[must_use]
    pub fn mul(self, other: Self, mode: RandomXRoundingMode) -> Self {
        map_binary(self, other, mode, Double::mul_r)
    }

    /// Divide both lanes with the current RandomX rounding state.
    #[must_use]
    pub fn div(self, other: Self, mode: RandomXRoundingMode) -> Self {
        map_binary(self, other, mode, Double::div_r)
    }

    /// Compute both square roots with the current RandomX rounding state.
    #[must_use]
    pub fn sqrt(self, mode: RandomXRoundingMode) -> Self {
        let round = mode.apfloat();
        Self {
            lo: sqrt_accurate(self.lo, round).0.value,
            hi: sqrt_accurate(self.hi, round).0.value,
        }
    }

    /// Apply the RandomX `FSCAL_R` bit transform.
    #[must_use]
    pub const fn scale(self) -> Self {
        Self {
            lo: self.lo ^ RANDOMX_FLOAT_SCALE_MASK,
            hi: self.hi ^ RANDOMX_FLOAT_SCALE_MASK,
        }
    }

    /// Apply the `FDIV_M` exponent/mantissa mask generated for one program.
    #[must_use]
    pub const fn mask_exponent_mantissa(self, exponent_mask: [u64; 2]) -> Self {
        Self {
            lo: (self.lo & RANDOMX_DYNAMIC_MANTISSA_MASK) | exponent_mask[0],
            hi: (self.hi & RANDOMX_DYNAMIC_MANTISSA_MASK) | exponent_mask[1],
        }
    }
}

fn signed_i32_to_binary64(value: u32) -> u64 {
    Double::from_i128(i128::from(value as i32)).value.to_bits() as u64
}

fn map_binary(
    left: RandomXFloatVector,
    right: RandomXFloatVector,
    mode: RandomXRoundingMode,
    operation: fn(Double, Double, Round) -> rustc_apfloat::StatusAnd<Double>,
) -> RandomXFloatVector {
    let round = mode.apfloat();
    let lane = |a: u64, b: u64| {
        operation(
            Double::from_bits(u128::from(a)),
            Double::from_bits(u128::from(b)),
            round,
        )
        .value
        .to_bits() as u64
    };
    RandomXFloatVector {
        lo: lane(left.lo, right.lo),
        hi: lane(left.hi, right.hi),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const N: usize>(encoded: &str) -> [u8; N] {
        assert_eq!(encoded.len(), N * 2);
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            let nibble = |value: u8| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => 0,
            };
            *byte = (nibble(encoded.as_bytes()[index * 2]) << 4)
                | nibble(encoded.as_bytes()[index * 2 + 1]);
        }
        output
    }

    const ADD_LEFT: RandomXFloatVector =
        RandomXFloatVector::from_bits(0xc1ce_30b3_c422_3576, 0x3ffd_2c97_cc4e_f015);
    const ADD_RIGHT: RandomXFloatVector =
        RandomXFloatVector::from_bits(0x40b8_f684_057a_59e1, 0x402a_26a8_6a60_c8fb);
    const MUL_LEFT: RandomXFloatVector =
        RandomXFloatVector::from_bits(0x40fd_fdab_b617_3d07, 0x41db_c35c_ef24_8783);
    const MUL_RIGHT: RandomXFloatVector =
        RandomXFloatVector::from_bits(0x41c4_5612_12ae_2d50, 0x40eb_a861_aa31_c7c0);
    const SQRT_INPUT: RandomXFloatVector =
        RandomXFloatVector::from_bits(0x4052_6a7e_778d_9824, 0x41b6_b21c_11af_fea7);

    #[test]
    fn upstream_randomx_add_vectors_match_every_rounding_mode() {
        let expected = [
            RandomXFloatVector::from_bits(0xc1ce_30a7_48e0_32b9, 0x402d_cc3b_63ea_a6fe),
            RandomXFloatVector::from_bits(0xc1ce_30a7_48e0_32b9, 0x402d_cc3b_63ea_a6fd),
            RandomXFloatVector::from_bits(0xc1ce_30a7_48e0_32b8, 0x402d_cc3b_63ea_a6fe),
            RandomXFloatVector::from_bits(0xc1ce_30a7_48e0_32b8, 0x402d_cc3b_63ea_a6fd),
        ];
        for (state, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                ADD_LEFT.add(ADD_RIGHT, RandomXRoundingMode::from_state(state as u64)),
                expected
            );
        }
    }

    #[test]
    fn upstream_randomx_multiply_vectors_match_every_rounding_class() {
        let nearest = RandomXFloatVector::from_bits(0x42d3_0f35_ff7a_6969, 0x42d7_feec_cd89_152f);
        let down_or_zero =
            RandomXFloatVector::from_bits(0x42d3_0f35_ff7a_6969, 0x42d7_feec_cd89_152e);
        let up = RandomXFloatVector::from_bits(0x42d3_0f35_ff7a_696a, 0x42d7_feec_cd89_152f);
        assert_eq!(
            MUL_LEFT.mul(MUL_RIGHT, RandomXRoundingMode::Nearest),
            nearest
        );
        assert_eq!(
            MUL_LEFT.mul(MUL_RIGHT, RandomXRoundingMode::Down),
            down_or_zero
        );
        assert_eq!(
            MUL_LEFT.mul(MUL_RIGHT, RandomXRoundingMode::Zero),
            down_or_zero
        );
        assert_eq!(MUL_LEFT.mul(MUL_RIGHT, RandomXRoundingMode::Up), up);
    }

    #[test]
    fn upstream_randomx_divide_vectors_bind_conversion_and_program_mask() {
        let divisor = RandomXFloatVector::from_packed_i32(0xd350_a1b6, 0x8b24_60d9)
            .mask_exponent_mantissa([0x3a00_0000_0005_d11a, 0x3900_0000_001b_a31e]);
        let dividend = RandomXFloatVector::from_bits(0x411b_4142_96ce_93b6, 0x4193_7f76_fede_16ee);
        let nearest = RandomXFloatVector::from_bits(0x4643_8494_6369_b2e7, 0x47a5_5b63_664a_4732);
        let down_or_zero =
            RandomXFloatVector::from_bits(0x4643_8494_6369_b2e6, 0x47a5_5b63_664a_4732);
        let up = RandomXFloatVector::from_bits(0x4643_8494_6369_b2e7, 0x47a5_5b63_664a_4733);
        assert_eq!(dividend.div(divisor, RandomXRoundingMode::Nearest), nearest);
        assert_eq!(
            dividend.div(divisor, RandomXRoundingMode::Down),
            down_or_zero
        );
        assert_eq!(
            dividend.div(divisor, RandomXRoundingMode::Zero),
            down_or_zero
        );
        assert_eq!(dividend.div(divisor, RandomXRoundingMode::Up), up);
    }

    #[test]
    fn upstream_randomx_square_root_vectors_match_every_rounding_class() {
        let nearest = RandomXFloatVector::from_bits(0x4021_2a61_0b30_1fe8, 0x40d3_0e57_3fa3_ba8d);
        let down_or_zero =
            RandomXFloatVector::from_bits(0x4021_2a61_0b30_1fe8, 0x40d3_0e57_3fa3_ba8c);
        let up = RandomXFloatVector::from_bits(0x4021_2a61_0b30_1fe9, 0x40d3_0e57_3fa3_ba8d);
        assert_eq!(SQRT_INPUT.sqrt(RandomXRoundingMode::Nearest), nearest);
        assert_eq!(SQRT_INPUT.sqrt(RandomXRoundingMode::Down), down_or_zero);
        assert_eq!(SQRT_INPUT.sqrt(RandomXRoundingMode::Zero), down_or_zero);
        assert_eq!(SQRT_INPUT.sqrt(RandomXRoundingMode::Up), up);
    }

    #[test]
    fn bitwise_randomx_vector_operations_are_exact() {
        let value = RandomXFloatVector::from_bits(0x40fd_fdab_b617_3d07, 0x41db_c35c_ef24_8783);
        assert_eq!(value.swap().swap(), value);
        assert_eq!(value.scale().scale(), value);
        assert_eq!(
            value.scale(),
            RandomXFloatVector::from_bits(0xc00d_fdab_b617_3d07, 0xc12b_c35c_ef24_8783)
        );
        for state in 0..256 {
            assert_eq!(
                RandomXRoundingMode::from_state(state),
                RandomXRoundingMode::from_state(state & 3)
            );
        }
    }

    #[test]
    fn upstream_randomx_integer_instruction_vectors_match() {
        let left = 0xbc55_0e96_ba88_a72b;
        let right = 0xf539_1fa9_f18d_6273;
        assert_eq!(unsigned_multiply_high(left, right), 0xb467_6d31_d2b3_4883);
        assert_eq!(signed_multiply_high(left, right), 0x02d9_3ef1_269d_3ee5);

        let value = 953_360_005_391_419_562;
        let shift = 4_569_451_684_712_230_561;
        assert_eq!(rotate_right(value, shift), 0xd835_c455_069d_81ef);
        assert_eq!(rotate_left(value, shift), 6_978_065_200_552_740_799);
    }

    #[test]
    fn upstream_randomx_reciprocal_vectors_match_and_invalid_values_fail_closed() {
        let vectors = [
            (3, 12_297_829_382_473_034_410),
            (13, 11_351_842_506_898_185_609),
            (33, 17_887_751_829_051_686_415),
            (65_537, 18_446_462_603_027_742_720),
            (15_000_001, 10_316_166_306_300_415_204),
            (3_845_182_035, 10_302_264_209_224_146_340),
            (u32::MAX, 9_223_372_039_002_259_456),
        ];
        for (divisor, expected) in vectors {
            assert_eq!(reciprocal(divisor), Some(expected));
        }

        assert_eq!(reciprocal(0), None);
        for exponent in 0..32 {
            assert_eq!(reciprocal(1u32 << exponent), None);
        }
    }

    #[test]
    fn upstream_randomx_software_aes_round_vectors_match() {
        let input = RandomXAesBlock([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);
        let key = RandomXAesBlock([
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ]);
        assert_eq!(
            input.encrypt_round(key),
            RandomXAesBlock([
                0x9a, 0x9b, 0xae, 0xb6, 0xd8, 0x98, 0xc5, 0xa6, 0x48, 0x20, 0xa7, 0x9a, 0xdb, 0x61,
                0xdf, 0xa3,
            ])
        );
        assert_eq!(
            input.decrypt_round(key),
            RandomXAesBlock([
                0xe3, 0x52, 0x64, 0xef, 0xda, 0xec, 0xdf, 0x99, 0xef, 0xb6, 0x08, 0x49, 0x3a, 0x40,
                0x65, 0xae,
            ])
        );

        for value in 0u8..=u8::MAX {
            assert_eq!(
                AES_INV_SBOX[usize::from(AES_SBOX[usize::from(value)])],
                value
            );
        }
    }

    #[test]
    fn upstream_randomx_aes_generator_and_hash_vectors_match() {
        let initial = core::array::from_fn(|index| index as u8);

        let mut state_1r = initial;
        let mut output_1r = [0u8; 128];
        assert_eq!(fill_aes_1rx4(&mut state_1r, &mut output_1r), Ok(()));
        assert_eq!(
            output_1r,
            decode_hex(
                "40063a71277f580c3c1a4769d1f46fe501eaeb488ad327cdf79dae6d1839db32fd41d3d7f308eeb30d160fe0637559e8695cf99a0b0391a456fae2342c020d72b021956c7406c3b7c93a9ff213da3f88920bd02df831d545ca024a356d174cd200ac7ec2a88cf753097386d3ec2bc6d2897d8619329ada5db8ea05a2f1f41c21"
            )
        );
        assert_eq!(state_1r, output_1r[64..]);

        let mut output_4r = [0u8; 128];
        assert_eq!(fill_aes_4rx4(&initial, &mut output_4r), Ok(()));
        assert_eq!(
            output_4r,
            decode_hex(
                "a538dbfc063d80173f9675cede6f3488df3d1d77433a0f3ce53c7c765b137f59aec395841ddef079efc977b1ad77f31694fe1b588d163cb25e55f05ba9de36a4b84c537dc87ca08619d955608966685bf80f446930c6a8e6ba20d5b4ad23c13ad72dadad6ffdc4f3c754d499f3d4e991cb9c47ff7fc2c3ba32d5b133692dca10"
            )
        );
        assert_eq!(initial, core::array::from_fn(|index| index as u8));

        assert_eq!(
            hash_aes_1rx4(&output_1r),
            Ok(decode_hex(
                "b5a24572ed7c3be7809a1b007b6fb2f3584edd5f4eb697bd8685157c00853b13f08b0303737eccd453b90afc5c3dd634acd27f6ae40901f96ad9a25c05aeed5a"
            ))
        );

        assert_eq!(
            fill_aes_1rx4(&mut state_1r, &mut [0u8; 1]),
            Err(InvalidAesLength)
        );
        assert_eq!(
            fill_aes_4rx4(&initial, &mut [0u8; 63]),
            Err(InvalidAesLength)
        );
        assert_eq!(hash_aes_1rx4(&[0u8; 65]), Err(InvalidAesLength));
    }

    #[test]
    fn upstream_randomx_blake2_generator_vector_matches() {
        let mut generator =
            RandomXBlake2Generator::new(b"RandomX portable generator vector", 123_456_789);
        let bytes = core::array::from_fn::<_, 7, _>(|_| generator.next_byte());
        assert_eq!(bytes, [0x35, 0x22, 0xf4, 0x2e, 0x84, 0x12, 0x3e]);
        let words = core::array::from_fn::<_, 20, _>(|_| generator.next_u32());
        assert_eq!(
            words,
            [
                0x5406_8e01,
                0x52ab_2ded,
                0xaeb7_cd75,
                0x02a5_88ba,
                0x5f0b_7867,
                0x49f9_fcc0,
                0x9ec6_a7f5,
                0xcb9a_cf00,
                0x565d_7509,
                0x5a82_26c1,
                0xe44a_d9b7,
                0xc9e9_7b7e,
                0x634d_3717,
                0x0f36_670b,
                0x2304_145a,
                0x1813_77a5,
                0xdbed_68d2,
                0xfc98_1cc5,
                0x292d_208e,
                0xdc87_20c8,
            ]
        );

        let seed = [0x5au8; 61];
        let mut truncated = RandomXBlake2Generator::new(&seed[..60], -1);
        let mut overlong = RandomXBlake2Generator::new(&seed, -1);
        for _ in 0..128 {
            assert_eq!(truncated.next_byte(), overlong.next_byte());
        }
    }

    #[test]
    fn upstream_randomx_program_and_configuration_vector_matches() {
        let seed = core::array::from_fn(|index| index as u8);
        let program = RandomXProgram::generate(&seed);
        assert!(program.is_ok());
        let program = match program {
            Ok(program) => program,
            Err(_) => return,
        };
        assert_eq!(
            core::array::from_fn::<_, 16, _>(|index| program.entropy(index)),
            [
                0x1780_3d06_fcdb_38a5,
                0x8834_6fde_ce75_963f,
                0x3c0f_3a43_771d_3ddf,
                0x597f_135b_767c_3ce5,
                0x79f0_de1d_8495_c3ae,
                0x16f3_77ad_b177_c9ef,
                0xb23c_168d_581b_fe94,
                0xa436_dea9_5bf0_555e,
                0x86a0_7cc8_7d53_4cb8,
                0x5b68_6689_6055_d919,
                0xe6a8_c630_6944_0ff8,
                0x3ac1_23ad_b4d5_20ba,
                0xf3c4_fd6f_adad_2dd7,
                0x91e9_d4f3_99d4_54c7,
                0xbac3_c27f_ff47_9ccb,
                0x10ca_2d69_33b1_d532,
            ]
        );
        assert_eq!(
            program.instructions()[0],
            RandomXInstruction {
                opcode: 0x46,
                destination: 0x4e,
                source: 0xbc,
                modifier: 0x95,
                immediate: 0xa8b1_5b3e,
            }
        );
        assert_eq!(
            program.instructions()[255],
            RandomXInstruction {
                opcode: 0xcf,
                destination: 0xac,
                source: 0xaa,
                modifier: 0x53,
                immediate: 0xc0b9_8da7,
            }
        );
        assert_eq!(
            program.configuration(),
            RandomXProgramConfiguration {
                initial_a: [
                    RandomXFloatVector::from_bits(0x4010_3d06_fcdb_38a5, 0x4104_6fde_ce75_963f),
                    RandomXFloatVector::from_bits(0x406f_3a43_771d_3ddf, 0x40af_135b_767c_3ce5),
                    RandomXFloatVector::from_bits(0x40e0_de1d_8495_c3ae, 0x4013_77ad_b177_c9ef),
                    RandomXFloatVector::from_bits(0x415c_168d_581b_fe94, 0x4136_dea9_5bf0_555e),
                ],
                memory_a: 0x7d53_4c80,
                memory_x: 0x6944_0ff8,
                read_registers: [1, 3, 5, 6],
                dataset_offset: 18_166_208,
                exponent_masks: [0x3b00_0000_0007_9ccb, 0x3100_0000_0031_d532],
            }
        );
    }

    #[test]
    fn randomx_opcode_frequency_table_and_modifiers_are_exact() {
        let mut counts = [0u16; 30];
        for opcode in 0..=u8::MAX {
            counts[RandomXInstructionKind::from_opcode(opcode) as usize] += 1;
        }
        assert_eq!(
            counts,
            [
                16, 7, 16, 7, 16, 4, 4, 1, 4, 1, 8, 2, 15, 5, 8, 2, 4, 4, 16, 5, 16, 5, 6, 32, 4,
                6, 25, 1, 16, 0,
            ]
        );

        let instruction = RandomXInstruction {
            opcode: 0,
            destination: 0,
            source: 0,
            modifier: 0b1011_0110,
            immediate: 0xffff_ff80,
        };
        assert_eq!(instruction.memory_mode(), 2);
        assert_eq!(instruction.shift_mode(), 1);
        assert_eq!(instruction.condition_mode(), 11);
        assert_eq!(instruction.signed_immediate(), u64::MAX - 127);
    }

    #[test]
    fn upstream_randomx_compiled_bytecode_execution_matches() {
        use crate::bytecode::{
            execute_program_once, RandomXRegisterFile, RANDOMX_SCRATCHPAD_BYTES,
        };

        let seed = core::array::from_fn(|index| index as u8);
        let program = match RandomXProgram::generate(&seed) {
            Ok(program) => program,
            Err(_) => return,
        };
        let configuration = program.configuration();
        let mut registers = RandomXRegisterFile::new(&configuration);
        let mut scratchpad = vec![0u8; RANDOMX_SCRATCHPAD_BYTES];
        for (index, byte) in scratchpad.iter_mut().enumerate() {
            *byte = (index.wrapping_mul(131).wrapping_add(17)) as u8;
        }
        let mut rounding = RandomXRoundingMode::Nearest;
        assert_eq!(
            execute_program_once(
                &program,
                &mut registers,
                &mut scratchpad,
                &configuration,
                &mut rounding,
            ),
            Ok(())
        );
        assert_eq!(rounding, RandomXRoundingMode::Nearest);

        let mut register_bytes = Vec::with_capacity(256);
        for value in registers.integer {
            register_bytes.extend_from_slice(&value.to_le_bytes());
        }
        for bank in [registers.float, registers.exponent, registers.constant] {
            for value in bank {
                register_bytes.extend_from_slice(&value.lo.to_le_bytes());
                register_bytes.extend_from_slice(&value.hi.to_le_bytes());
            }
        }
        assert_eq!(register_bytes.len(), 256);
        assert_eq!(
            &Blake2b512::digest(&register_bytes)[..],
            decode_hex::<64>(
                "68d5b7c59ef5f6fdadb361b147b082dfec9e5c76d3345c4f9a16f7c273b39ca10c40436478e9724a5c0385dcdff073d9856de12ec97df682676f4a7d30ed6b81"
            )
        );
        assert_eq!(
            &Blake2b512::digest(&scratchpad)[..],
            decode_hex::<64>(
                "d44fef03e7ab71f5f05c6b4149568be50f034cde0bc79f9a955000ae0cca459b9772ae5c14f634d3a7b636847451f9fe807a0296354b01a3c378007eed47d380"
            )
        );
    }

    #[test]
    fn upstream_randomx_full_vm_iteration_loop_matches() {
        use crate::bytecode::{
            execute_vm_iterations, finalize_hash, RandomXRegisterFile, RANDOMX_SCRATCHPAD_BYTES,
        };

        let seed = core::array::from_fn(|index| index as u8);
        let program = match RandomXProgram::generate(&seed) {
            Ok(program) => program,
            Err(_) => return,
        };
        let configuration = program.configuration();
        let mut registers = RandomXRegisterFile::new(&configuration);
        let mut scratchpad = vec![0u8; RANDOMX_SCRATCHPAD_BYTES];
        for (index, byte) in scratchpad.iter_mut().enumerate() {
            *byte = (index.wrapping_mul(131).wrapping_add(17)) as u8;
        }
        let mut rounding = RandomXRoundingMode::Nearest;
        assert_eq!(
            execute_vm_iterations(
                &program,
                &mut registers,
                &mut scratchpad,
                &configuration,
                &mut rounding,
                |address| {
                    core::array::from_fn(|index| {
                        address.rotate_left((index * 7) as u32)
                            ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    })
                },
            ),
            Ok(())
        );
        assert_eq!(rounding, RandomXRoundingMode::Nearest);

        assert_eq!(
            registers.next_program_seed(),
            decode_hex::<64>(
                "585fbdffb87c881b06348bf151694bd04ffe239fe28dea21f39e2b7d71a83c4f7151f74dc2ec4ebac2673c9cefd10b5a61eaddf26cb1a7bbd9937da19e0c5e6f"
            )
        );

        let mut register_bytes = Vec::with_capacity(256);
        for value in registers.integer {
            register_bytes.extend_from_slice(&value.to_le_bytes());
        }
        for bank in [registers.float, registers.exponent, registers.constant] {
            for value in bank {
                register_bytes.extend_from_slice(&value.lo.to_le_bytes());
                register_bytes.extend_from_slice(&value.hi.to_le_bytes());
            }
        }
        assert_eq!(
            &Blake2b512::digest(&register_bytes)[..],
            decode_hex::<64>(
                "585fbdffb87c881b06348bf151694bd04ffe239fe28dea21f39e2b7d71a83c4f7151f74dc2ec4ebac2673c9cefd10b5a61eaddf26cb1a7bbd9937da19e0c5e6f"
            )
        );
        assert_eq!(
            &Blake2b512::digest(&scratchpad)[..],
            decode_hex::<64>(
                "4c2739c2abef19928898524f4fcc049c0ebf37ba9b0f56be459c56292d81b5c51f63472e8c7ca79475f3d5b31c310b64b3e0d7a4a0a228d78ac0df2b1a447051"
            )
        );
        assert_eq!(
            finalize_hash(&scratchpad, &mut registers),
            Ok(decode_hex::<32>(
                "a2b19b73fe7d81c3c92f9fa549d2b5a8eaeb21f5fc9cc0676d7c1411f06280bd"
            ))
        );
    }

    #[test]
    fn upstream_randomx_initial_scratchpad_vector_matches() {
        use crate::bytecode::RANDOMX_SCRATCHPAD_BYTES;

        let mut scratchpad = vec![0u8; RANDOMX_SCRATCHPAD_BYTES];
        assert_eq!(
            initialize_scratchpad(b"RandomX portable initial state", &mut scratchpad),
            Ok(decode_hex::<64>(
                "7e319720ee8fb782aff7159e70287c863a98505b32e924a735ccce4e0368cb62657a35eb2c0ecf1a0b9073cb8be6c39a1fddc330edce8b94fa76d4d12e728d36"
            ))
        );
        assert_eq!(
            &Blake2b512::digest(&scratchpad)[..],
            decode_hex::<64>(
                "4eeac8e38cd0564d54f34534cd09475aba8114025beaa59bcd87bf15bfccea28deeb6d2c41bd2112a4b1a2f9501b93c3325c72c852714601a40694db020f6df7"
            )
        );
    }
}
