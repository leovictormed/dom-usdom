use ark_serialize::CanonicalSerialize;
use dom_usdom_privacy::ceremony::{
    circuit_fingerprint, contribute, contribute_with_proof, decode_phase2_artifact,
    encode_phase2_artifact, extract_verifying_key, validate_final_key, verify_contribution,
    verify_contribution_with_proof, Phase2Context,
};
use dom_usdom_privacy::phase1::{
    contribute as phase1_contribute, decode_accumulator, decode_artifact, encode_accumulator,
    encode_artifact, initialize as phase1_initialize, specialize as phase1_specialize,
    verify_contribution as verify_phase1, verify_initial as verify_phase1_initial,
    ContributionArtifact, ContributionContext,
};
use rand::rngs::OsRng;
use std::{
    env, fs,
    io::{self, Write},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().collect();
    match args.get(1).and_then(|v| v.to_str()) {
        Some("phase1-init") if args.len() == 3 => {
            let degree=args[2].to_str().ok_or("invalid degree")?.parse::<usize>()?;
            io::stdout().write_all(&encode_accumulator(&phase1_initialize(degree)?)?)?;
        }
        Some("phase1-contribute") if args.len() == 8 => {
            let before=decode_accumulator(&fs::read(&args[2])?)?;
            let context=parse_context(&args[3..8])?;
            let (accumulator,proof)=phase1_contribute(&before,&context,&mut OsRng)?;
            io::stdout().write_all(&encode_artifact(&ContributionArtifact{accumulator,proof})?)?;
        }
        Some("phase1-verify-initial") if args.len() == 3 => {
            verify_phase1_initial(&decode_accumulator(&fs::read(&args[2])?)?)?;
        }
        Some("phase1-verify") if args.len() == 9 => {
            let before=decode_accumulator(&fs::read(&args[2])?)?;
            let artifact=decode_artifact(&fs::read(&args[3])?)?;
            let context=parse_context(&args[4..9])?;
            verify_phase1(&before,&artifact.accumulator,&context,&artifact.proof)?;
        }
        Some("phase1-extract") if args.len() == 3 => {
            let artifact=decode_artifact(&fs::read(&args[2])?)?;
            io::stdout().write_all(&encode_accumulator(&artifact.accumulator)?)?;
        }
        Some("phase1-specialize") if args.len() == 3 => {
            let key = phase1_specialize(&decode_accumulator(&fs::read(&args[2])?)?)?;
            let mut bytes = Vec::new();
            key.serialize_compressed(&mut bytes)
                .map_err(|_| "failed to encode specialized key")?;
            io::stdout().write_all(&bytes)?;
        }
        Some("contribute") if args.len() == 3 => {
            let next = contribute(&fs::read(&args[2])?, &mut OsRng)?;
            io::stdout().write_all(&next)?;
        }
        Some("phase2-contribute") if args.len() == 8 => {
            let context = parse_phase2_context(&args[3..8])?;
            let artifact = contribute_with_proof(&fs::read(&args[2])?, &context, &mut OsRng)?;
            io::stdout().write_all(&encode_phase2_artifact(&artifact)?)?;
        }
        Some("phase2-verify") if args.len() == 9 => {
            let artifact = decode_phase2_artifact(&fs::read(&args[3])?)?;
            let context = parse_phase2_context(&args[4..9])?;
            verify_contribution_with_proof(&fs::read(&args[2])?, &artifact.proving_key, &context, &artifact.proof)?;
        }
        Some("phase2-extract") if args.len() == 3 => {
            io::stdout().write_all(&decode_phase2_artifact(&fs::read(&args[2])?)?.proving_key)?;
        }
        Some("verify") if args.len() == 4 => verify_contribution(&fs::read(&args[2])?, &fs::read(&args[3])?)?,
        Some("extract-vk") if args.len() == 3 => io::stdout().write_all(&extract_verifying_key(&fs::read(&args[2])?)?)?,
        Some("fingerprint") if args.len() == 2 => {
            let value=circuit_fingerprint()?;
            println!("sha256={} constraints={} instance_variables={} witness_variables={} domain_size={}",
                hex::encode(value.sha256),value.constraints,value.instance_variables,value.witness_variables,value.domain_size);
        }
        Some("validate-final") if args.len() == 3 => {
            let (fingerprint, _, config_hash) = validate_final_key(&fs::read(&args[2])?, &mut OsRng)?;
            println!("r1cs_sha256={} verifier_config_hash={}", hex::encode(fingerprint.sha256), hex::encode(config_hash));
        }
        _ => return Err("usage: dom-usdom-groth16-ceremony phase1-init DEGREE | phase1-contribute BEFORE RELEASE CIRCUIT CONTRIBUTOR ORDINAL PREVIOUS | phase1-verify BEFORE ARTIFACT RELEASE CIRCUIT CONTRIBUTOR ORDINAL PREVIOUS | phase1-extract ARTIFACT | phase1-specialize ACCUMULATOR | contribute PK | verify OLD_PK NEW_PK | extract-vk PK | fingerprint | validate-final PK".into()),
    }
    Ok(())
}

fn digest(value: &std::ffi::OsStr) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let text = value.to_str().ok_or("digest is not UTF-8")?;
    let bytes = hex::decode(text)?;
    bytes
        .try_into()
        .map_err(|_| "digest must contain 32 bytes".into())
}
fn parse_context(
    values: &[std::ffi::OsString],
) -> Result<ContributionContext, Box<dyn std::error::Error>> {
    if values.len() != 5 {
        return Err("invalid contribution context".into());
    }
    Ok(ContributionContext {
        release: digest(&values[0])?,
        circuit: digest(&values[1])?,
        contributor: digest(&values[2])?,
        ordinal: values[3].to_str().ok_or("ordinal is not UTF-8")?.parse()?,
        previous_transcript: digest(&values[4])?,
    })
}

fn parse_phase2_context(
    values: &[std::ffi::OsString],
) -> Result<Phase2Context, Box<dyn std::error::Error>> {
    let value = parse_context(values)?;
    Ok(Phase2Context {
        release: value.release,
        circuit: value.circuit,
        contributor: value.contributor,
        ordinal: value.ordinal,
        previous_transcript: value.previous_transcript,
    })
}
