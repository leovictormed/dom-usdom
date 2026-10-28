#!/usr/bin/env python3
"""Benign regressions for specialized descriptor-bound manifests."""
import hashlib,os,tempfile
from pathlib import Path
from unittest.mock import patch
import specialized_manifest as sm

def rejected(call):
 try:call()
 except SystemExit:return
 raise AssertionError("unsafe fixture accepted")

with tempfile.TemporaryDirectory() as temporary:
 root=Path(temporary);(root/"src").mkdir();(root/"src/lib.rs").write_text("mod child;\n");(root/"src/child.rs").write_text("pub fn ok(){}\n")
 os.chmod(root/"src/lib.rs",0o600);os.chmod(root/"src/child.rs",0o600)
 inventory={"src/lib.rs","src/child.rs"};sm.rust_closure(root,{"src/lib.rs"},inventory)
 rejected(lambda:sm.rust_closure(root,{"src/lib.rs"},{"src/lib.rs"}))
 (root/"src/lib.rs").write_text('#[path = "alternate.rs"]\nmod child;\n');(root/"src/alternate.rs").write_text('pub fn hidden(){}\n');os.chmod(root/"src/alternate.rs",0o600)
 rejected(lambda:sm.rust_closure(root,{"src/lib.rs"},{"src/lib.rs","src/child.rs"}))
 (root/"src/lib.rs").write_text('mod child;\n')
 (root/"src/lib.rs").write_text('const ASSET: &[u8] = include_bytes!("asset.bin");\n');(root/"src/asset.bin").write_bytes(b'asset');os.chmod(root/"src/asset.bin",0o600)
 rejected(lambda:sm.rust_closure(root,{"src/lib.rs"},{"src/lib.rs"}))
 (root/"src/lib.rs").write_text('mod child;\n')
 os.link(root/"src/lib.rs",root/"hard.rs");rejected(lambda:sm.direct(root,"src/lib.rs"));os.unlink(root/"hard.rs")
 (root/"alias").symlink_to("src",target_is_directory=True);rejected(lambda:sm.direct(root,"alias/lib.rs"))
 (root/"Cargo.toml").write_text('[[bin]]\nname="recover"\npath="src/bin/recover.rs"\n');(root/"src/bin").mkdir();(root/"src/bin/recover.rs").write_text("fn main(){}\n")
 for path in (root/"Cargo.toml",root/"src/bin/recover.rs"):os.chmod(path,0o600)
 rejected(lambda:sm.cargo_targets(root,{"Cargo.toml":sm.direct(root,"Cargo.toml")}))
 payloads={name:sm.direct(root,name) for name in ("Cargo.toml","src/bin/recover.rs")};sm.cargo_targets(root,payloads)
 digest=hashlib.sha256((root/"Cargo.toml").read_bytes()).hexdigest();(root/"MANIFEST.sha256").write_text(f'{digest}  Cargo.toml\n');os.chmod(root/"MANIFEST.sha256",0o600)
 (root/"Cargo.toml").write_text('[features]\nchanged=[]\n[dependencies.dep]\npath="../dep"\n')
 rejected(lambda:sm.manifest(root,"MANIFEST.sha256",{"Cargo.toml"}))
 calls=0;original=sm.direct
 def mutate(base,name,maximum=64*1024*1024):
  global calls
  calls+=1
  if calls==2:(root/"Cargo.toml").write_text("[package]\nname='changed'\n")
  return original(base,name,maximum)
 with patch.object(sm,"direct",mutate):rejected(lambda:sm.snapshot(root,{"Cargo.toml"}))
print("PASS: specialized manifests reject parent symlinks, hardlinks, post-read mutation and omitted Rust/Cargo targets")
