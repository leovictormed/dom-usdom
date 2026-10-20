use std::{
    io::Write,
    process::{Command, Stdio},
};

fn run(input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dom-usdom-checkpoint-statement"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn checkpoint statement tool");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input)
        .expect("write statement");
    child.wait_with_output().expect("collect statement tool")
}

#[test]
fn invalid_input_never_emits_partial_output() {
    for input in [
        &b""[..],
        &b"UDCPST03"[..],
        &[0u8; 514][..],
        &[0u8; 515][..],
        &[0u8; 518][..],
        &[0u8; 519][..],
    ] {
        let output = run(input);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}
