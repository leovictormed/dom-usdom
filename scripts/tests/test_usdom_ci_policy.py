from pathlib import Path
import json
import re
import unittest

ROOT=Path(__file__).resolve().parents[2]


class UsdomCiPolicyTest(unittest.TestCase):
    def test_ci_runs_current_fail_closed_usdom_gates(self):
        workflow=(ROOT/'.github/workflows/ci.yml').read_text()
        job=re.search(r'^  usdom-security-gates:\n(?P<body>[\s\S]*?)(?=^  [a-z][a-z0-9-]+:\n)',workflow,re.M)
        self.assertIsNotNone(job)
        body=job.group('body')
        for marker in (
            "node-version: '24.19.0'", 'dtolnay/rust-toolchain@1.98.0',
            'version: 1.8.5', 'expected_forge=', 'cargo fetch --locked',
            'cargo metadata --locked --offline --no-deps',
            'check-release-dependency-policy.py', 'test_publication_snapshot',
            'check-publication-snapshot.py . --verify-git-index',
            'npm ci --ignore-scripts', 'npm run --silent check:provenance',
            'npm test', 'npm run --silent test:solidity'):
            self.assertIn(marker,body)
        self.assertNotIn('continue-on-error',body)
        self.assertNotRegex(body,r'\|\|\s*true')

    def test_foundry_commands_are_offline_and_dependency_policy_is_provenance_gate(self):
        package=json.loads((ROOT/'labs/usdom-reserve/package.json').read_text())
        scripts=package['scripts']
        self.assertIn('check:dependency-policy',scripts['check:provenance'])
        for name in ('pretest','test:solidity','test:deep'):
            self.assertIn('--offline',scripts[name])


if __name__=='__main__': unittest.main()
