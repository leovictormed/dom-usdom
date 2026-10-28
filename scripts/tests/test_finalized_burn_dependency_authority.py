import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "labs/usdom-reserve/scripts/check-finalized-burn-program-boundary.py"
GENERATOR = ROOT / "labs/usdom-reserve/scripts/generate-finalized-burn-dependency-authority.py"
AUTHORITY = ROOT / "labs/usdom-reserve/config/finalized-burn-dependency-authority.json"


class FinalizedBurnDependencyAuthorityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("finalized_burn_dependency_boundary", CHECKER)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        generator_spec = importlib.util.spec_from_file_location("finalized_burn_dependency_generator", GENERATOR)
        cls.generator = importlib.util.module_from_spec(generator_spec)
        generator_spec.loader.exec_module(cls.generator)

    def invoke_with(self, mutate):
        payload = json.loads(AUTHORITY.read_text())
        mutate(payload)
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "authority.json"
            candidate.write_text(json.dumps(payload) + "\n")
            original = self.module.AUTHORITY
            self.module.AUTHORITY = candidate
            try:
                return self.module.dependency_closure()
            finally:
                self.module.AUTHORITY = original

    def test_current_authority_is_complete(self):
        packages, manifests = self.invoke_with(lambda _: None)
        self.assertIn("dom-usdom-finalized-burn-program", packages)
        self.assertEqual(len(manifests), 234)

    def test_lock_and_manifest_drift_fail_closed(self):
        with self.assertRaisesRegex(SystemExit, "Cargo.lock identity drifted"):
            self.invoke_with(lambda value: value.__setitem__("cargoLockSha256", "0" * 64))
        with self.assertRaisesRegex(SystemExit, "manifest identity drifted"):
            self.invoke_with(lambda value: value["manifests"][0].__setitem__("sha256", "0" * 64))

    def test_package_set_must_be_canonical(self):
        with self.assertRaisesRegex(SystemExit, "package set is noncanonical"):
            self.invoke_with(lambda value: value["packages"].append(value["packages"][0]))

    def test_runtime_closure_is_hash_bound_and_canonical(self):
        with self.assertRaisesRegex(SystemExit, "runtime identity drifted"):
            self.invoke_with(lambda value: value["runtimeFiles"][0].__setitem__("sha256", "0" * 64))
        with self.assertRaisesRegex(SystemExit, "runtime set is noncanonical"):
            self.invoke_with(lambda value: value["runtimeFiles"].append(value["runtimeFiles"][0]))
        with self.assertRaisesRegex(SystemExit, "runtime closure is incomplete"):
            self.invoke_with(lambda value: value["runtimeFiles"].pop())

    def test_loader_trace_parser_rejects_unresolved_and_relative_dependencies(self):
        with self.assertRaisesRegex(SystemExit, "unresolved"):
            self.generator.parse_runtime_trace(b"libattack.so => not found\n")
        with self.assertRaisesRegex(SystemExit, "unsafe dependency path"):
            self.generator.parse_runtime_trace(b"libattack.so => relative/libattack.so (0x1)\n")
        self.assertEqual(
            self.generator.parse_runtime_trace(b"libc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6 (0x1)\n"),
            {Path("/usr/lib/x86_64-linux-gnu/libc.so.6")},
        )

    def test_generator_refuses_direct_python_launch(self):
        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(GENERATOR), "--check"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("launcher", completed.stderr)

    def test_checker_refuses_direct_python_launch(self):
        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(CHECKER)], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("launcher", completed.stderr)

    def test_python_module_closure_is_required_and_hash_bound(self):
        with self.assertRaisesRegex(SystemExit, "Python module identity drifted"):
            self.invoke_with(lambda value: value["pythonModules"][0].__setitem__("sha256", "0" * 64))
        def remove_argparse(value):
            value["pythonModules"] = [entry for entry in value["pythonModules"]
                                      if entry["module"].split(".", 1)[0] != "argparse"]
        with self.assertRaisesRegex(SystemExit, "Python module closure is incomplete"):
            self.invoke_with(remove_argparse)

    def test_checker_runtime_rejects_module_absent_from_authority(self):
        payload = json.loads(AUTHORITY.read_text())
        loaded = {str(Path(os.path.realpath(getattr(module, "__file__", ""))))
                  for module in sys.modules.values() if isinstance(getattr(module, "__file__", None), str)}
        candidates = [entry for entry in payload["pythonModules"] if entry["path"] in loaded]
        self.assertTrue(candidates)
        removed = candidates[0]
        payload["pythonModules"].remove(removed)
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "authority.json"
            candidate.write_text(json.dumps(payload) + "\n")
            original = self.module.AUTHORITY
            self.module.AUTHORITY = candidate
            try:
                with self.assertRaisesRegex(SystemExit, "Python module closure is incomplete|unauthorized Python modules"):
                    self.module.dependency_closure(verify_python_runtime=True)
            finally:
                self.module.AUTHORITY = original

    def test_command_and_manifest_schema_are_closed(self):
        with self.assertRaisesRegex(SystemExit, "command is invalid"):
            self.invoke_with(lambda value: value["command"].append("--all-features"))
        with self.assertRaisesRegex(SystemExit, "manifest entries are malformed"):
            self.invoke_with(lambda value: value["manifests"][0].__setitem__("extra", True))

    def test_authority_rejects_symlink_and_hardlink_aliases(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            base = Path(directory)
            source = base / "source.json"
            source.write_bytes(AUTHORITY.read_bytes())
            for candidate in (base / "symlink.json", base / "hardlink.json"):
                if candidate.name.startswith("sym"):
                    candidate.symlink_to(source)
                else:
                    os.link(source, candidate)
                original = self.module.AUTHORITY
                self.module.AUTHORITY = candidate
                try:
                    with self.assertRaisesRegex(SystemExit, "cannot open|unique regular file"):
                        self.module.dependency_closure()
                finally:
                    self.module.AUTHORITY = original


if __name__ == "__main__":
    unittest.main()
