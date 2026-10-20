use std::{env, fs, path::PathBuf};

use risc0_binfmt::{compute_image_id, ProgramBinary};
use risc0_zkos_v1compat::V1COMPAT_ELF;

fn main() {
    let mut arguments = env::args_os().skip(1);
    let user_elf = PathBuf::from(arguments.next().expect("missing user ELF path"));
    let output = PathBuf::from(arguments.next().expect("missing ProgramBinary output path"));
    assert!(arguments.next().is_none(), "unexpected trailing argument");
    let user_elf = fs::read(user_elf).expect("read user ELF");
    let binary = ProgramBinary::new(&user_elf, V1COMPAT_ELF).encode();
    fs::write(&output, &binary).expect("write ProgramBinary");
    let image_id = compute_image_id(&binary).expect("compute ImageID");
    println!("{}", image_id);
}
