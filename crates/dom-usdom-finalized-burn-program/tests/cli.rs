use std::{
    io::Write,
    process::{Command, Stdio},
};

fn run(input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dom-usdom-finalized-burn-program"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn finalized-burn program");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input)
        .expect("write private input");
    child.wait_with_output().expect("collect program output")
}

#[test]
fn invalid_private_input_never_emits_partial_public_output() {
    for input in [
        &b""[..],
        &b"UDFINL01"[..],
        &b"UDFINL02"[..],
        &[0u8; 420][..],
    ] {
        let output = run(input);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}
