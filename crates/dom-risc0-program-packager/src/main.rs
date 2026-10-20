//! Package one user ELF with the pinned RISC Zero v1 compatibility kernel.

use std::{env, error::Error, fs, io, path::PathBuf};

use risc0_binfmt::{compute_image_id, ProgramBinary};
use risc0_zkos_v1compat::V1COMPAT_ELF;

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let user_elf = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing user ELF path"))?,
    );
    let output = PathBuf::from(arguments.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing ProgramBinary output path",
        )
    })?);
    if arguments.next().is_some() {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "unexpected trailing argument").into(),
        );
    }
    let user_elf = fs::read(user_elf)?;
    let binary = ProgramBinary::new(&user_elf, V1COMPAT_ELF).encode();
    fs::write(&output, &binary)?;
    println!("{}", compute_image_id(&binary)?);
    Ok(())
}
