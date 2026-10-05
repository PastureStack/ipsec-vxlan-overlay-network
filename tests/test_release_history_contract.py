"""Exercise the workflow's actual history guards using a temporary Git DAG."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest


class ReleaseHistoryContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.git = shutil.which("git")
        if not cls.git:
            raise RuntimeError("git is required for the local contract test")
        workflow = Path(__file__).resolve().parents[1] / ".github/workflows/security-release-gate.yml"
        source = workflow.read_text(encoding="utf-8")
        block = re.search(
            r'(          test -z "\$\(git status --porcelain\)".*?)(?=          python3 tests/test_release_history_contract\.py\n)',
            source,
            re.S,
        )
        if not block:
            raise RuntimeError("workflow history guard boundary changed")
        cls.guards = textwrap.dedent(block.group(1)).strip()
        pin = re.search(r"reviewed_base=([0-9a-f]{40})", cls.guards)
        if not pin:
            raise RuntimeError("reviewed base pin is missing")
        cls.reviewed_base = pin.group(1)
        expected = [
            'test -z "$(git status --porcelain)"',
            'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
            "reviewed_base=" + cls.reviewed_base,
            'test "$(git cat-file -t "$reviewed_base")" = commit',
            'git merge-base --is-ancestor "$reviewed_base" HEAD',
            'test "$(git rev-list --count "$reviewed_base"..HEAD)" -ge 1',
        ]
        # Rebind only the fixed base to a synthetic object. Strict source
        # matching prevents a copied predicate from silently drifting.
        if cls.guards.splitlines() != expected:
            raise RuntimeError("workflow history predicates changed")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ipsec-release-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.env = os.environ.copy()
        self.env.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_AUTHOR_NAME": "Release contract fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Release contract fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        })
        self.run_git("init", "--quiet", "--template=")
        self.tree = self.run_git("mktree", input="")
        self.base = self.commit("reviewed base")
        left, right = self.commit("left", self.base), self.commit("right", self.base)
        self.merge = self.commit("normal PR merge", left, right)

    def run_git(self, *args, input=None):
        result = subprocess.run(
            [self.git, *args], input=input, text=True, capture_output=True,
            cwd=self.directory, env=self.env, check=True,
        )
        return result.stdout.strip()

    def commit(self, message, *parents):
        arguments = ["commit-tree", self.tree, "-m", message]
        for parent in parents:
            arguments.extend(["-p", parent])
        return self.run_git(*arguments)

    def accepted(self, head, expected_sha=None):
        self.run_git("update-ref", "HEAD", head)
        if self.run_git("status", "--porcelain"):
            return False
        if self.run_git("rev-parse", "HEAD") != (expected_sha or head):
            return False
        if self.run_git("cat-file", "-t", self.base) != "commit":
            return False
        ancestor = subprocess.run(
            [self.git, "merge-base", "--is-ancestor", self.base, "HEAD"],
            text=True, capture_output=True, cwd=self.directory, env=self.env,
        )
        if ancestor.returncode != 0:
            return False
        return int(self.run_git("rev-list", "--count", self.base + "..HEAD")) >= 1

    def test_reviewed_descendant_merge_is_accepted(self):
        self.assertEqual(len(self.run_git("rev-list", "--parents", "-n", "1", self.merge).split()), 3)
        self.assertTrue(self.accepted(self.merge))

    def test_nonancestor_is_rejected(self):
        self.assertFalse(self.accepted(self.commit("unrelated root")))

    def test_empty_delta_is_rejected(self):
        self.assertFalse(self.accepted(self.base))

    def test_wrong_sha_is_rejected(self):
        self.assertFalse(self.accepted(self.merge, self.base))


if __name__ == "__main__":
    unittest.main()
