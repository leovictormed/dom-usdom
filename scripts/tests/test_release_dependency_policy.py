import importlib.util
import subprocess
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
SCRIPT=ROOT/"scripts"/"check-release-dependency-policy.py"


class ReleaseDependencyPolicyTest(unittest.TestCase):
    def test_current_release_graph_is_fully_pinned(self):
        result=subprocess.run(["python3",str(SCRIPT)],text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("Cargo locks",result.stdout)

    def test_checker_contains_fail_closed_source_rules(self):
        text=SCRIPT.read_text()
        for marker in ("GIT_SOURCE.fullmatch", "checksum", "NPM_INTEGRITY.fullmatch",
                       "NPM_INSTALL_SCRIPT_ALLOWLIST", "branch|tag", "unsafe"):
            self.assertIn(marker,text)

    def test_reviewed_build_script_inventory_is_exact(self):
        spec=importlib.util.spec_from_file_location("release_dependency_policy_build_scripts",SCRIPT)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        reviewed=dict(module.CARGO_BUILD_SCRIPT_ALLOWLIST)
        self.assertEqual(
            reviewed["crates/dom-rpc/build.rs"],
            "8962aed292be3a5bbf0a324bea72b0c25530fce2c3415742e3144f54e55d369c")
        module.validate_build_script_hashes(dict(reviewed),reviewed)
        changed=dict(reviewed)
        changed["crates/dom-rpc/build.rs"]="0"*64
        with self.assertRaisesRegex(SystemExit,"identities differ"):
            module.validate_build_script_hashes(changed,reviewed)
        added=dict(reviewed);added["unreviewed/build.rs"]="1"*64
        with self.assertRaisesRegex(SystemExit,"identities differ"):
            module.validate_build_script_hashes(added,reviewed)

    def test_build_scripts_cannot_spawn_path_selected_tools(self):
        spec=importlib.util.spec_from_file_location("release_dependency_policy_build_exec",SCRIPT)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.validate_build_script_execution('fn main() { println!("ok"); }',"safe/build.rs")
        with self.assertRaisesRegex(SystemExit,"ambient child process"):
            module.validate_build_script_execution(
                'use std::process::Command; fn main(){ Command::new("git").status(); }',
                "unsafe/build.rs")

    def test_generated_trees_are_pruned_before_dependency_parsing(self):
        spec=importlib.util.spec_from_file_location("release_dependency_policy",SCRIPT)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/"Cargo.lock").write_text("version = 4\npackage = []\n")
            (root/"Cargo.toml").write_text("""[package]
name='root'
version='0.1.0'
[workspace]
resolver='2'
[workspace.package]
edition='2021'
rust-version='1.75'
[profile.release]
opt-level=3
lto='fat'
codegen-units=1
panic='abort'
overflow-checks=true
[profile.release-validation]
inherits='release'
debug=1
[profile.dev]
overflow-checks=true
""")
            for generated in ("target","node_modules",".git"):
                hidden=root/generated/"deep"
                hidden.mkdir(parents=True)
                (hidden/"Cargo.lock").write_text("not valid TOML = [")
                (hidden/"Cargo.toml").write_text("not valid TOML = [")
            original=module.ROOT
            module.ROOT=root
            try:
                self.assertEqual(module.cargo_locks(),(1,0,set()))
                manifests=module.release_files("Cargo.toml",frozenset({".git","node_modules","target"}))
                self.assertEqual(manifests,[root/"Cargo.toml"])
                parsed=module.strict_toml(manifests[0].read_text(),"Cargo.toml")
                self.assertEqual(parsed["workspace"]["resolver"],"2")
            finally:
                module.ROOT=original

    def test_unreviewed_symlink_tree_fails_closed(self):
        spec=importlib.util.spec_from_file_location("release_dependency_policy_symlink",SCRIPT)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root=Path(directory)
            (Path(outside)/"Cargo.lock").write_text("version = 4\n")
            (root/"dependency-alias").symlink_to(outside,target_is_directory=True)
            original=module.ROOT
            module.ROOT=root
            try:
                with self.assertRaisesRegex(SystemExit,"symlink directory"):
                    module.cargo_locks()
            finally:
                module.ROOT=original


if __name__ == "__main__": unittest.main()
