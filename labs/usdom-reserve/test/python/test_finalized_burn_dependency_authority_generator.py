import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[4]
GENERATOR = ROOT / "labs/usdom-reserve/scripts/generate-finalized-burn-dependency-authority.py"


class FinalizedBurnDependencyAuthorityGeneratorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("finalized_burn_dependency_generator", GENERATOR)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_canonical_json_is_stable_and_newline_terminated(self):
        payload = self.module.canonical_json({"b": [2], "a": 1})
        self.assertEqual(payload, b'{\n  "b": [\n    2\n  ],\n  "a": 1\n}\n')

    def test_create_once_accepts_equal_and_rejects_drift(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            target = Path(directory) / "authority.json"
            with mock.patch.object(self.module, "TARGET", target):
                self.module.install_create_once(b"canonical\n")
                self.assertEqual(target.read_bytes(), b"canonical\n")
                self.module.install_create_once(b"canonical\n")
                with self.assertRaisesRegex(SystemExit, "exists with different bytes"):
                    self.module.install_create_once(b"drift\n")

    def test_create_once_rejects_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            base = Path(directory)
            source = base / "source"
            source.write_text("x")
            for target in (base / "symlink", base / "hardlink"):
                if target.name == "symlink":
                    target.symlink_to(source)
                else:
                    os.link(source, target)
                with mock.patch.object(self.module, "TARGET", target):
                    with self.assertRaises(SystemExit):
                        self.module.install_create_once(b"x")

    def test_build_uses_exact_closed_schema_inputs(self):
        with mock.patch.object(self.module, "tracked_manifests", return_value=([], {})), \
             mock.patch.object(self.module, "run_cargo_tree", return_value=["a", "root"]), \
             mock.patch.object(self.module, "read_regular", return_value=(b"lock", mock.Mock())):
            value = self.module.build_authority()
        self.assertEqual(set(value), {"schema", "rootPackage", "edgeKinds", "command", "cargoLockSha256", "manifests", "packages"})
        self.assertEqual(value["command"], self.module.COMMAND)
        self.assertEqual(value["edgeKinds"], ["normal"])

    def test_cli_requires_explicit_review_action(self):
        self.assertIn("required=True", GENERATOR.read_text())
        self.assertNotIn("/tmp", GENERATOR.read_text())

    def test_cargo_config_injection_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            config = Path(directory) / "config.toml"
            config.write_text('[source.crates-io]\nreplace-with = "attacker"\n')
            with mock.patch.object(self.module, "cargo_config_paths", return_value=[config]):
                with self.assertRaisesRegex(SystemExit, "dependency-affecting"):
                    self.module.validate_cargo_configs()

    def test_only_non_graph_cargo_config_is_accepted(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            config = Path(directory) / "config.toml"
            config.write_text('[build]\njobs = 3\n[target.x]\nrustflags = ["-C", "opt-level=1"]\n')
            with mock.patch.object(self.module, "cargo_config_paths", return_value=[config]):
                snapshots = self.module.validate_cargo_configs()
                self.module.revalidate_cargo_configs(snapshots)

    def test_fixed_inventory_tool_rejects_aliases_before_execution(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            base = Path(directory)
            source = base / "git"
            source.write_text("#!/bin/sh\n")
            source.chmod(0o755)
            symlink = base / "symlink"
            symlink.symlink_to(source)
            hardlink = base / "hardlink"
            os.link(source, hardlink)
            for candidate in (symlink, hardlink):
                with self.assertRaisesRegex(SystemExit, "cannot open|unique regular file"):
                    self.module.open_fixed_system_tool(candidate)

    def test_post_exec_source_revalidation_rejects_replacement(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source = Path(directory) / "Cargo.lock"
            source.write_bytes(b"before")
            payload, info = self.module.read_regular(source)
            snapshots = {source: (payload, (info.st_dev, info.st_ino))}
            replacement = source.with_suffix(".new")
            replacement.write_bytes(b"after")
            replacement.replace(source)
            with self.assertRaisesRegex(SystemExit, "changed during authenticated cargo tree"):
                self.module.revalidate_source_snapshots(snapshots)

    def test_child_environments_do_not_inherit_injection_variables(self):
        hostile = {
            "CARGO_TARGET_DIR": "/attacker",
            "RUSTC_WRAPPER": "/attacker/wrapper",
            "RUSTFLAGS": "--cfg attacker",
            "GIT_DIR": "/attacker/repository",
            "GIT_CONFIG_GLOBAL": "/attacker/config",
            "PATH": "/attacker/bin",
            "LC_ALL": "attacker_LOCALE",
        }
        with mock.patch.dict(os.environ, hostile, clear=False):
            cargo = self.module.closed_environment(19)
            git = self.module.git_environment()
        self.assertNotIn("CARGO_TARGET_DIR", cargo)
        self.assertNotIn("RUSTC_WRAPPER", cargo)
        self.assertNotIn("RUSTFLAGS", cargo)
        self.assertEqual(cargo["RUSTC"], "/proc/self/fd/19")
        self.assertNotIn("GIT_DIR", git)
        self.assertEqual(git["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(git["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(git["PATH"], "/usr/bin:/bin")
        self.assertEqual(git["LC_ALL"], "C.UTF-8")

    def test_git_inventory_rejects_symlink_and_submodule_modes(self):
        object_id = b"0" * 40
        for mode in (b"120000", b"160000"):
            payload = mode + b" " + object_id + b" 0\tcrate/Cargo.toml\0"
            with self.assertRaisesRegex(SystemExit, "not a regular tracked blob"):
                self.module.parse_git_manifest_inventory(payload)
        valid = b"100644 " + object_id + b" 0\tcrate/Cargo.toml\0"
        self.assertEqual(self.module.parse_git_manifest_inventory(valid), ["crate/Cargo.toml"])

    def test_post_exec_revalidation_rejects_index_replacement(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            index = Path(directory) / "index"
            index.write_bytes(b"index-before")
            payload, info = self.module.read_regular(index)
            snapshots = {index: (payload, (info.st_dev, info.st_ino))}
            replacement = index.with_suffix(".new")
            replacement.write_bytes(b"index-after")
            replacement.replace(index)
            with self.assertRaisesRegex(SystemExit, "changed during authenticated cargo tree"):
                self.module.revalidate_source_snapshots(snapshots)

    def test_git_inventory_rejects_hidden_worktree_flags(self):
        self.assertEqual(
            self.module.parse_git_manifest_flags(b"H a/Cargo.toml\0H b/Cargo.toml\0"),
            ["a/Cargo.toml", "b/Cargo.toml"],
        )
        for marker in (b"h", b"S", b"s"):
            with self.assertRaisesRegex(SystemExit, "assume-unchanged, skip-worktree"):
                self.module.parse_git_manifest_flags(marker + b" a/Cargo.toml\0")


if __name__ == "__main__":
    unittest.main()
