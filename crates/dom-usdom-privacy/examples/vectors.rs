use dom_usdom_privacy::{
    chain_scalar, issuance_rho, owner_commitment, privacy_policy_hash, NoteOpening, Scalar,
    NOTE_ORIGIN_ISSUANCE,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let policy = *privacy_policy_hash().as_bytes();
    let chain = chain_scalar([0x11; 32], policy);
    let mut secret_bytes = [0u8; 32];
    secret_bytes[31] = 7;
    let secret = Scalar::from_bytes(secret_bytes).expect("canonical fixture scalar");
    let owner = owner_commitment(chain, secret).expect("valid fixture owner");
    let note = NoteOpening {
        chain,
        origin: NOTE_ORIGIN_ISSUANCE,
        value: 1_000_000,
        owner,
        rho: issuance_rho(b"deposit occurrence").expect("valid fixture rho"),
    };
    println!("policy={}", hex(&policy));
    println!("chain={}", hex(&chain.to_bytes()));
    println!("owner={}", hex(&owner.to_bytes()));
    println!("rho={}", hex(&note.rho.to_bytes()));
    println!(
        "note={}",
        hex(&note.commitment().expect("valid fixture note").to_bytes())
    );
    println!(
        "nullifier={}",
        hex(&note
            .nullifier(secret)
            .expect("valid fixture spend")
            .to_bytes())
    );
}
