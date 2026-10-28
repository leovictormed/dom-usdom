from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check-publication-package.py"


class PublicationPackageTests(unittest.TestCase):
    def repo(self, directory: str) -> Path:
        root = Path(directory)
        subprocess.run(["git", "init", "-q", root], check=True)
        subprocess.run(["git", "-C", root, "config", "user.name", "Soren Planck"], check=True)
        subprocess.run(["git", "-C", root, "config", "user.email", "sorenplanck@tutamail.com"], check=True)
        for path in ("LICENSE", "Cargo.toml", "Cargo.lock", ".gitignore"):
            (root / path).write_text("public\n")
        inventory = root / "labs/usdom-reserve/config/rebuild-v3-critical-source-inventory.json"
        inventory.parent.mkdir(parents=True)
        inventory.write_text(json.dumps({"criticalSources": ["scripts/runner.sh"]}) + "\n")
        runner = root / "labs/usdom-reserve/scripts/runner.sh"
        runner.parent.mkdir(parents=True)
        runner.write_text("#!/bin/sh\nexit 0\n")
        vendor = root / "labs/usdom-reserve/vendor/example"
        vendor.mkdir(parents=True)
        (vendor / "LICENSE").write_text("MIT\n")
        (vendor / "source.sol").write_text("contract Example {}\n")
        subprocess.run(["git", "-C", root, "add", "-A"], check=True)
        return root

    def check(self, root: Path):
        return subprocess.run(["python3", CHECKER, root], text=True, capture_output=True)

    def test_clean_exact_index_is_reproducible_and_has_no_push(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.repo(directory)
            first, second = self.check(root), self.check(root)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stdout, second.stdout)
            self.assertIn("PUSH = DISABLED", first.stdout)
            self.assertNotIn("git push", CHECKER.read_text())

    def test_rejects_continuation_private_evidence_and_missing_vendor_license(self):
        cases = (
            "labs/usdom-reserve/docs/CONTINUATION-STATE.md",
            "labs/usdom-reserve/results-stage1/evidence.json",
            "labs/usdom-reserve/private-evidence/operator.json",
        )
        for relative in cases:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root = self.repo(directory)
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("local\n")
                subprocess.run(["git", "-C", root, "add", "-f", relative], check=True)
                self.assertNotEqual(self.check(root).returncode, 0)
        with tempfile.TemporaryDirectory() as directory:
            root = self.repo(directory)
            subprocess.run(["git", "-C", root, "rm", "--cached", "labs/usdom-reserve/vendor/example/LICENSE"], check=True, stdout=subprocess.DEVNULL)
            result = self.check(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("lacks an indexed top-level license", result.stderr)

    def test_rejects_wrong_identity_and_missing_critical_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.repo(directory)
            subprocess.run(["git", "-C", root, "config", "user.name", "Other"], check=True)
            self.assertNotEqual(self.check(root).returncode, 0)
        with tempfile.TemporaryDirectory() as directory:
            root = self.repo(directory)
            subprocess.run(["git", "-C", root, "rm", "--cached", "labs/usdom-reserve/scripts/runner.sh"], check=True, stdout=subprocess.DEVNULL)
            result = self.check(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("required source", result.stderr)

    def test_allows_only_the_required_walletconnect_license_from_node_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.repo(directory)
            inventory = root / "labs/usdom-reserve/config/rebuild-v3-critical-source-inventory.json"
            inventory.write_text(json.dumps({"criticalSources": [
                "scripts/runner.sh",
                "node_modules/@walletconnect/sign-client/LICENSE.md",
            ]}) + "\n")
            license_path = root / "labs/usdom-reserve/node_modules/@walletconnect/sign-client/LICENSE.md"
            license_path.parent.mkdir(parents=True)
            license_path.write_text("WalletConnect license\n")
            subprocess.run(["git", "-C", root, "add", "-f", license_path], check=True)
            self.assertEqual(self.check(root).returncode, 0)

            source_path = root / "labs/usdom-reserve/node_modules/@walletconnect/sign-client/index.js"
            source_path.write_text("export {};\n")
            subprocess.run(["git", "-C", root, "add", "-f", source_path], check=True)
            result = self.check(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("local/private path", result.stderr)


if __name__ == "__main__":
    unittest.main()
