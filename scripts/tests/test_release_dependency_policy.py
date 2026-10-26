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

    def test_generated_trees_are_pruned_before_dependency_parsing(self):
        spec=importlib.util.spec_from_file_location("release_dependency_policy",SCRIPT)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/"Cargo.lock").write_text("version = 4\n")
            (root/"Cargo.toml").write_text("[package]\nname='root'\nversion='0.1.0'\n")
            for generated in ("target","node_modules",".git"):
                hidden=root/generated/"deep"
                hidden.mkdir(parents=True)
                (hidden/"Cargo.lock").write_text("not valid TOML = [")
                (hidden/"Cargo.toml").write_text("not valid TOML = [")
            original=module.ROOT
            module.ROOT=root
            try:
                self.assertEqual(module.cargo_locks(),(1,0))
                self.assertEqual(module.cargo_manifests(),1)
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
