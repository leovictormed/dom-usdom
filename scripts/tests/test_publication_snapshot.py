import importlib.util
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-publication-snapshot.py"


class PublicationSnapshotTest(unittest.TestCase):
    def run_check(self, root, *arguments):
        return subprocess.run(["python3", str(SCRIPT), str(root), *arguments],
                              text=True, capture_output=True)

    def test_clean_complete_index_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); subprocess.run(["git","init","-q",root],check=True)
            (root/"source.rs").write_text("fn main() {}\n")
            subprocess.run(["git","-C",root,"add","source.rs"],check=True)
            self.assertEqual(self.run_check(root,"--verify-git-index").returncode,0)

    def test_rejects_unindexed_secret_names_links_modes_and_content(self):
        cases=(
            ("unindexed", lambda root:(root/"local.txt").write_text("local\n"), ("--verify-git-index",)),
            ("name", lambda root:(root/"operator.seed").write_text("redacted\n"), ()),
            ("link", lambda root:(root/"alias").symlink_to("public.txt"), ()),
            ("mode", lambda root:os.chmod(root/"public.txt",0o666), ()),
            ("content", lambda root:(root/"public.txt").write_text("PRIVATE_KEY="+"a"*64+"\n"), ()),
            ("executable-without-shebang", lambda root:os.chmod(root/"public.txt",0o755), ()),
        )
        for label,mutate,arguments in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); (root/"public.txt").write_text("public\n"); mutate(root)
                self.assertNotEqual(self.run_check(root,*arguments).returncode,0)

    def test_rejects_hardlinks_and_accepts_shebang_executables(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); source=root/"source.txt"; source.write_text("public\n")
            os.link(source,root/"alias.txt")
            result=self.run_check(root)
            self.assertNotEqual(result.returncode,0)
            self.assertIn("multiply-linked file is not publishable",result.stderr)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); script=root/"check.sh"
            script.write_text("#!/bin/sh\nexit 0\n"); script.chmod(0o755)
            self.assertEqual(self.run_check(root).returncode,0)

    def test_rejects_extended_secret_filenames(self):
        for name in (".netrc",".npmrc","operator.kdbx","client.ovpn","key.der"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); (root/name).write_text("redacted\n")
                self.assertNotEqual(self.run_check(root).returncode,0)

    def test_accepts_source_module_named_cache_and_escaped_example_url(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); module=root/"vendor"/"core"/"cache"
            module.mkdir(parents=True)
            (module/"lib.rs").write_text(
                "const EXAMPLE: &str = \\\"https://user:redacted@example.invalid\\\\n\\\";\n")
            self.assertEqual(self.run_check(root).returncode,0)

    def test_rejects_local_results_and_continuation_even_if_indexed(self):
        for relative in (
            "labs/usdom-reserve/results-stage9999/report.json",
            "labs/usdom-reserve/results/local.json",
            "labs/usdom-reserve/docs/CONTINUATION-STATE.md",
            "docs/CONTINUATION-STATE.md",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); subprocess.run(["git","init","-q",root],check=True)
                target=root/relative; target.parent.mkdir(parents=True); target.write_text("local\n")
                subprocess.run(["git","-C",root,"add","-f",relative],check=True)
                result=self.run_check(root,"--verify-git-index")
                self.assertNotEqual(result.returncode,0)
                self.assertIn("local-only path is not publishable",result.stderr)

    def test_usdom_stage_results_are_gitignored(self):
        result=subprocess.run([
            "git","-C",ROOT,"check-ignore","--no-index","-q",
            "labs/usdom-reserve/results-stage9999/generated.json",
        ])
        self.assertEqual(result.returncode,0)


if __name__ == "__main__": unittest.main()
