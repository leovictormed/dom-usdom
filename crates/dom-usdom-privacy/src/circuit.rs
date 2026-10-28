//! Fixed-shape private spend relation shared by transfers and burns.
//!
//! The circuit exposes each consensus effect directly as a public input. It
//! does not accept a caller-provided digest whose preimage could be omitted or
//! only partially constrained.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar,
};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, convert::ToBitsGadget, eq::EqGadget, fields::fp::FpVar,
    prelude::FieldVar, uint64::UInt64,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use std::ops::Not;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    poseidon_config, Scalar, ASSET_USDOM, NODE_DOMAIN, NOTE_DOMAIN, NOTE_ORIGIN_ISSUANCE,
    NOTE_ORIGIN_PRIVATE, NOTE_TREE_DEPTH, NULLIFIER_DOMAIN, OWNER_DOMAIN,
};

/// Maximum hidden inputs consumed by one native USDOM spend proof.
pub const MAX_PRIVATE_INPUTS: usize = 2;
/// Maximum private outputs created by one native USDOM spend proof.
pub const MAX_PRIVATE_OUTPUTS: usize = 2;

/// One hidden input note and its exact fixed-depth membership witness.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InputWitness {
    /// Whether this left-packed input slot is active.
    pub enabled: bool,
    /// Private-output or issuance origin namespace.
    pub origin: u8,
    /// Six-decimal note amount.
    pub value: u64,
    /// Secret whose Poseidon owner commitment controls this note.
    pub owner_secret: Scalar,
    /// Unique note randomness.
    pub rho: Scalar,
    /// Zero-based index under the public note-tree anchor.
    pub leaf_index: u64,
    /// Fixed-depth sibling path from note to anchor.
    pub siblings: [Scalar; NOTE_TREE_DEPTH],
}

impl Default for InputWitness {
    fn default() -> Self {
        Self {
            enabled: false,
            origin: 0,
            value: 0,
            owner_secret: Scalar::ZERO,
            rho: Scalar::ZERO,
            leaf_index: 0,
            siblings: [Scalar::ZERO; NOTE_TREE_DEPTH],
        }
    }
}

/// One private output note opening.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct OutputWitness {
    /// Whether this left-packed output slot is active.
    pub enabled: bool,
    /// Six-decimal note amount.
    pub value: u64,
    /// Nonzero recipient owner commitment.
    pub owner: Scalar,
    /// Unique note randomness.
    pub rho: Scalar,
}

/// Direct public statement authenticated by one spend proof.
#[derive(Clone, Copy, Default)]
pub struct SpendStatement {
    /// Chain/domain scalar fixed by the bridge privacy policy.
    pub chain: Scalar,
    /// Retained fixed-depth Poseidon note-tree root.
    pub anchor: Scalar,
    /// Left-packed spent nullifiers; disabled slots are zero.
    pub nullifiers: [Scalar; MAX_PRIVATE_INPUTS],
    /// Left-packed new note commitments; disabled slots are zero.
    pub output_notes: [Scalar; MAX_PRIVATE_OUTPUTS],
    /// Public amount removed from private circulation; zero means transfer.
    pub burn_amount: u64,
    /// Exact burn-intent effect scalar; zero for a transfer.
    pub effect: Scalar,
    /// Digest scalar of encrypted output memos; zero only with no outputs.
    pub memo: Scalar,
}

impl SpendStatement {
    /// Public field elements in the one frozen verifier order.
    pub fn public_inputs(self) -> [Fr; 9] {
        [
            self.chain.0,
            self.anchor.0,
            self.nullifiers[0].0,
            self.nullifiers[1].0,
            self.output_notes[0].0,
            self.output_notes[1].0,
            Fr::from(self.burn_amount),
            self.effect.0,
            self.memo.0,
        ]
    }
}

/// Fixed two-input/two-output conservation and membership circuit.
#[derive(Clone, Default)]
pub struct SpendCircuit {
    /// Direct public statement.
    pub statement: SpendStatement,
    /// Left-packed hidden input witnesses.
    pub inputs: [InputWitness; MAX_PRIVATE_INPUTS],
    /// Left-packed hidden output witnesses.
    pub outputs: [OutputWitness; MAX_PRIVATE_OUTPUTS],
}

fn hash(
    cs: ConstraintSystemRef<Fr>,
    domain: u64,
    values: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::<Fr>::new(cs, poseidon_config());
    sponge.absorb(&FpVar::Constant(Fr::from(domain)))?;
    sponge.absorb(&values.to_vec())?;
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

fn witness_scalar(cs: ConstraintSystemRef<Fr>, value: Scalar) -> Result<FpVar<Fr>, SynthesisError> {
    FpVar::new_witness(cs, || Ok(value.0))
}

fn witness_u64(
    cs: ConstraintSystemRef<Fr>,
    value: u64,
) -> Result<(UInt64<Fr>, FpVar<Fr>), SynthesisError> {
    let integer = UInt64::new_witness(cs, || Ok(value))?;
    let field = Boolean::le_bits_to_fp(&integer.to_bits_le()?)?;
    Ok((integer, field))
}

fn input_u64(cs: ConstraintSystemRef<Fr>, value: u64) -> Result<FpVar<Fr>, SynthesisError> {
    let public = FpVar::new_input(cs.clone(), || Ok(Fr::from(value)))?;
    let integer = UInt64::new_witness(cs, || Ok(value))?;
    let bounded = Boolean::le_bits_to_fp(&integer.to_bits_le()?)?;
    bounded.enforce_equal(&public)?;
    Ok(public)
}

fn require_nonzero_when(value: &FpVar<Fr>, enabled: &Boolean<Fr>) -> Result<(), SynthesisError> {
    value
        .is_eq(&FpVar::zero())?
        .conditional_enforce_equal(&Boolean::FALSE, enabled)
}

impl ConstraintSynthesizer<Fr> for SpendCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let chain = FpVar::new_input(cs.clone(), || Ok(self.statement.chain.0))?;
        let anchor = FpVar::new_input(cs.clone(), || Ok(self.statement.anchor.0))?;
        let public_nullifiers = self
            .statement
            .nullifiers
            .iter()
            .map(|value| FpVar::new_input(cs.clone(), || Ok(value.0)))
            .collect::<Result<Vec<_>, _>>()?;
        let public_outputs = self
            .statement
            .output_notes
            .iter()
            .map(|value| FpVar::new_input(cs.clone(), || Ok(value.0)))
            .collect::<Result<Vec<_>, _>>()?;
        let burn_amount = input_u64(cs.clone(), self.statement.burn_amount)?;
        let effect = FpVar::new_input(cs.clone(), || Ok(self.statement.effect.0))?;
        let memo = FpVar::new_input(cs.clone(), || Ok(self.statement.memo.0))?;
        require_nonzero_when(&chain, &Boolean::TRUE)?;
        require_nonzero_when(&anchor, &Boolean::TRUE)?;

        let mut input_sum = FpVar::zero();
        let mut previous_enabled = Boolean::TRUE;
        for (slot, input) in self.inputs.iter().enumerate() {
            let enabled = Boolean::new_witness(cs.clone(), || Ok(input.enabled))?;
            (enabled.clone() & previous_enabled.not()).enforce_equal(&Boolean::FALSE)?;
            if slot == 0 {
                enabled.enforce_equal(&Boolean::TRUE)?;
            }
            previous_enabled = enabled.clone();
            let disabled = enabled.clone().not();

            let (_, value) = witness_u64(cs.clone(), input.value)?;
            let origin = FpVar::new_witness(cs.clone(), || Ok(Fr::from(input.origin)))?;
            origin.conditional_enforce_equal(&FpVar::zero(), &disabled)?;
            let valid_origin = origin.is_eq(&FpVar::Constant(Fr::from(NOTE_ORIGIN_PRIVATE)))?
                | origin.is_eq(&FpVar::Constant(Fr::from(NOTE_ORIGIN_ISSUANCE)))?;
            valid_origin.enforce_equal(&enabled)?;
            let (leaf_index, leaf_index_field) = witness_u64(cs.clone(), input.leaf_index)?;
            value.conditional_enforce_equal(&FpVar::zero(), &disabled)?;
            leaf_index_field.conditional_enforce_equal(&FpVar::zero(), &disabled)?;
            require_nonzero_when(&value, &enabled)?;
            let secret = witness_scalar(cs.clone(), input.owner_secret)?;
            let rho = witness_scalar(cs.clone(), input.rho)?;
            secret.conditional_enforce_equal(&FpVar::zero(), &disabled)?;
            rho.conditional_enforce_equal(&FpVar::zero(), &disabled)?;
            require_nonzero_when(&secret, &enabled)?;
            require_nonzero_when(&rho, &enabled)?;

            let owner = hash(cs.clone(), OWNER_DOMAIN, &[chain.clone(), secret.clone()])?;
            let commitment = hash(
                cs.clone(),
                NOTE_DOMAIN,
                &[
                    chain.clone(),
                    FpVar::Constant(Fr::from(ASSET_USDOM)),
                    origin,
                    value.clone(),
                    owner,
                    rho,
                ],
            )?;
            let nullifier = hash(
                cs.clone(),
                NULLIFIER_DOMAIN,
                &[chain.clone(), secret, commitment.clone()],
            )?;
            nullifier.conditional_enforce_equal(&public_nullifiers[slot], &enabled)?;
            public_nullifiers[slot].conditional_enforce_equal(&FpVar::zero(), &disabled)?;
            require_nonzero_when(&public_nullifiers[slot], &enabled)?;

            let index_bits = leaf_index.to_bits_le()?;
            for high_bit in &index_bits[NOTE_TREE_DEPTH..] {
                high_bit.enforce_equal(&Boolean::FALSE)?;
            }
            let mut node = commitment;
            for (level, sibling_value) in input.siblings.iter().enumerate() {
                let sibling = witness_scalar(cs.clone(), *sibling_value)?;
                // Disabled slots have one unique witness representation. Without
                // this constraint their unused Merkle siblings could vary freely,
                // creating witness/proof malleability despite identical effects.
                sibling.conditional_enforce_equal(&FpVar::zero(), &disabled)?;
                let right = &index_bits[level];
                let left_child = right.select(&sibling, &node)?;
                let right_child = right.select(&node, &sibling)?;
                node = hash(
                    cs.clone(),
                    NODE_DOMAIN,
                    &[
                        FpVar::Constant(Fr::from(level as u64)),
                        left_child,
                        right_child,
                    ],
                )?;
            }
            node.conditional_enforce_equal(&anchor, &enabled)?;
            input_sum += value;
        }

        let mut output_sum = FpVar::zero();
        let mut previous_output_enabled = Boolean::TRUE;
        let mut any_output = Boolean::FALSE;
        for (slot, output) in self.outputs.iter().enumerate() {
            let enabled = Boolean::new_witness(cs.clone(), || Ok(output.enabled))?;
            (enabled.clone() & previous_output_enabled.not()).enforce_equal(&Boolean::FALSE)?;
            previous_output_enabled = enabled.clone();
            any_output |= enabled.clone();
            let disabled = enabled.clone().not();

            let (_, value) = witness_u64(cs.clone(), output.value)?;
            let owner = witness_scalar(cs.clone(), output.owner)?;
            let rho = witness_scalar(cs.clone(), output.rho)?;
            for field in [&value, &owner, &rho] {
                field.conditional_enforce_equal(&FpVar::zero(), &disabled)?;
                require_nonzero_when(field, &enabled)?;
            }
            let commitment = hash(
                cs.clone(),
                NOTE_DOMAIN,
                &[
                    chain.clone(),
                    FpVar::Constant(Fr::from(ASSET_USDOM)),
                    FpVar::Constant(Fr::from(NOTE_ORIGIN_PRIVATE)),
                    value.clone(),
                    owner,
                    rho,
                ],
            )?;
            commitment.conditional_enforce_equal(&public_outputs[slot], &enabled)?;
            public_outputs[slot].conditional_enforce_equal(&FpVar::zero(), &disabled)?;
            require_nonzero_when(&public_outputs[slot], &enabled)?;
            output_sum += value;
        }

        let is_transfer = burn_amount.is_eq(&FpVar::zero())?;
        any_output.conditional_enforce_equal(&Boolean::TRUE, &is_transfer)?;
        effect.is_eq(&FpVar::zero())?.enforce_equal(&is_transfer)?;
        memo.is_eq(&FpVar::zero())?
            .enforce_equal(&any_output.clone().not())?;
        (output_sum + burn_amount).enforce_equal(&input_sum)?;
        Ok(())
    }
}

pub(crate) mod tests_support {
    #[cfg(test)]
    use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
    #[cfg(test)]
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    use super::*;
    use crate::{chain_scalar, empty_roots, owner_commitment, privacy_policy_hash, NoteOpening};

    fn scalar(value: u64) -> Scalar {
        Scalar::from_u64(value)
    }

    pub(crate) fn valid_burn_circuit() -> SpendCircuit {
        let chain = chain_scalar([0x11; 32], *privacy_policy_hash().as_bytes());
        let secret = scalar(7);
        let owner = owner_commitment(chain, secret).unwrap();
        let input_note = NoteOpening {
            chain,
            origin: NOTE_ORIGIN_PRIVATE,
            value: 10,
            owner,
            rho: scalar(8),
        };
        let input_commitment = input_note.commitment().unwrap();
        let mut node = input_commitment;
        let siblings = std::array::from_fn(|level| empty_roots()[level]);
        for (level, sibling) in siblings.iter().copied().enumerate() {
            node = super::super::node_hash(level, node, sibling);
        }
        let output = OutputWitness {
            enabled: true,
            value: 7,
            owner: scalar(9),
            rho: scalar(10),
        };
        let output_commitment = NoteOpening {
            chain,
            origin: NOTE_ORIGIN_PRIVATE,
            value: output.value,
            owner: output.owner,
            rho: output.rho,
        }
        .commitment()
        .unwrap();
        SpendCircuit {
            statement: SpendStatement {
                chain,
                anchor: node,
                nullifiers: [input_note.nullifier(secret).unwrap(), Scalar::ZERO],
                output_notes: [output_commitment, Scalar::ZERO],
                burn_amount: 3,
                effect: scalar(11),
                memo: scalar(12),
            },
            inputs: [
                InputWitness {
                    enabled: true,
                    origin: input_note.origin,
                    value: input_note.value,
                    owner_secret: secret,
                    rho: input_note.rho,
                    leaf_index: 0,
                    siblings,
                },
                InputWitness::default(),
            ],
            outputs: [output, OutputWitness::default()],
        }
    }

    pub(crate) fn valid_transfer_circuit() -> SpendCircuit {
        let mut circuit = valid_burn_circuit();
        circuit.outputs[0].value = circuit.inputs[0].value;
        circuit.statement.output_notes[0] = NoteOpening {
            chain: circuit.statement.chain,
            origin: NOTE_ORIGIN_PRIVATE,
            value: circuit.outputs[0].value,
            owner: circuit.outputs[0].owner,
            rho: circuit.outputs[0].rho,
        }
        .commitment()
        .unwrap();
        circuit.statement.burn_amount = 0;
        circuit.statement.effect = Scalar::ZERO;
        circuit
    }

    #[test]
    fn exact_membership_nullifier_commitments_and_conservation_are_satisfied() {
        let cs = ConstraintSystem::new_ref();
        valid_burn_circuit()
            .generate_constraints(cs.clone())
            .unwrap();
        assert_eq!(cs.num_instance_variables(), 10);
        assert!(
            cs.is_satisfied().unwrap(),
            "unsatisfied constraint: {:?}",
            cs.which_is_unsatisfied().unwrap()
        );
    }

    #[test]
    fn changed_public_burn_amount_breaks_conservation() {
        let mut circuit = valid_burn_circuit();
        circuit.statement.burn_amount = 4;
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn disabled_slots_have_one_canonical_zero_witness() {
        for mutation in 0..9 {
            let mut circuit = valid_burn_circuit();
            match mutation {
                0 => circuit.inputs[1].origin = NOTE_ORIGIN_PRIVATE,
                1 => circuit.inputs[1].value = 1,
                2 => circuit.inputs[1].owner_secret = Scalar::from_u64(1),
                3 => circuit.inputs[1].rho = Scalar::from_u64(1),
                4 => circuit.inputs[1].leaf_index = 1,
                5 => circuit.inputs[1].siblings[0] = Scalar::from_u64(1),
                6 => circuit.outputs[1].value = 1,
                7 => circuit.outputs[1].owner = Scalar::from_u64(1),
                8 => circuit.outputs[1].rho = Scalar::from_u64(1),
                _ => unreachable!(),
            }
            let cs = ConstraintSystem::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(!cs.is_satisfied().unwrap(), "mutation {mutation}");
        }
    }

    #[test]
    fn optional_outputs_are_left_packed_and_memo_presence_is_canonical() {
        let mut gap = valid_burn_circuit();
        gap.outputs[0] = OutputWitness::default();
        gap.statement.output_notes[0] = Scalar::ZERO;
        let cs = ConstraintSystem::new_ref();
        gap.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());

        let mut wrong_memo = valid_burn_circuit();
        wrong_memo.outputs = [OutputWitness::default(), OutputWitness::default()];
        wrong_memo.statement.output_notes = [Scalar::ZERO, Scalar::ZERO];
        // Burn conservation remains valid only if all input value is burned.
        wrong_memo.statement.burn_amount = wrong_memo.inputs[0].value;
        let cs = ConstraintSystem::new_ref();
        wrong_memo.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn effect_memo_and_tree_capacity_are_constrained() {
        for mutate in 0..4 {
            let mut circuit = valid_burn_circuit();
            match mutate {
                0 => circuit.statement.effect = Scalar::ZERO,
                1 => circuit.statement.memo = Scalar::ZERO,
                2 => circuit.inputs[0].leaf_index = 1u64 << NOTE_TREE_DEPTH,
                3 => circuit.inputs[0].origin = 3,
                _ => unreachable!(),
            }
            let cs = ConstraintSystem::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(!cs.is_satisfied().unwrap(), "mutation {mutate}");
        }
    }

    #[test]
    fn issuance_origin_input_is_spendable_but_uses_a_distinct_commitment() {
        let mut circuit = valid_burn_circuit();
        let input = &mut circuit.inputs[0];
        input.origin = NOTE_ORIGIN_ISSUANCE;
        let opening = NoteOpening {
            chain: circuit.statement.chain,
            origin: input.origin,
            value: input.value,
            owner: owner_commitment(circuit.statement.chain, input.owner_secret).unwrap(),
            rho: input.rho,
        };
        let commitment = opening.commitment().unwrap();
        let mut root = commitment;
        for (level, sibling) in input.siblings.iter().copied().enumerate() {
            root = super::super::node_hash(level, root, sibling);
        }
        circuit.statement.anchor = root;
        circuit.statement.nullifiers[0] = opening.nullifier(input.owner_secret).unwrap();
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn poseidon_gadgets_match_native_primitives() {
        let circuit = valid_burn_circuit();
        let input = &circuit.inputs[0];
        let cs = ConstraintSystem::new_ref();
        let chain = FpVar::new_witness(cs.clone(), || Ok(circuit.statement.chain.0)).unwrap();
        let secret = FpVar::new_witness(cs.clone(), || Ok(input.owner_secret.0)).unwrap();
        let rho = FpVar::new_witness(cs.clone(), || Ok(input.rho.0)).unwrap();
        let value = FpVar::new_witness(cs.clone(), || Ok(Fr::from(input.value))).unwrap();
        let owner = hash(cs.clone(), OWNER_DOMAIN, &[chain.clone(), secret.clone()]).unwrap();
        assert_eq!(
            owner.value().unwrap(),
            owner_commitment(circuit.statement.chain, input.owner_secret)
                .unwrap()
                .0
        );
        let commitment = hash(
            cs.clone(),
            NOTE_DOMAIN,
            &[
                chain.clone(),
                FpVar::Constant(Fr::from(ASSET_USDOM)),
                FpVar::Constant(Fr::from(input.origin)),
                value,
                owner,
                rho,
            ],
        )
        .unwrap();
        let opening = NoteOpening {
            chain: circuit.statement.chain,
            origin: input.origin,
            value: input.value,
            owner: owner_commitment(circuit.statement.chain, input.owner_secret).unwrap(),
            rho: input.rho,
        };
        assert_eq!(commitment.value().unwrap(), opening.commitment().unwrap().0);
        let nullifier = hash(
            cs.clone(),
            NULLIFIER_DOMAIN,
            &[chain, secret, commitment.clone()],
        )
        .unwrap();
        assert_eq!(
            nullifier.value().unwrap(),
            opening.nullifier(input.owner_secret).unwrap().0
        );
        let mut node = commitment;
        for (level, sibling) in input.siblings.iter().enumerate() {
            node = hash(
                cs.clone(),
                NODE_DOMAIN,
                &[
                    FpVar::Constant(Fr::from(level as u64)),
                    node,
                    FpVar::new_witness(cs.clone(), || Ok(sibling.0)).unwrap(),
                ],
            )
            .unwrap();
        }
        assert_eq!(node.value().unwrap(), circuit.statement.anchor.0);
    }
}
