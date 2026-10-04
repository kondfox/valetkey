#!/usr/bin/env python3
"""Tests for check_commit_messages.py. Run: python3 scripts/test_check_commit_messages.py"""
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location(
    "check_commit_messages", pathlib.Path(__file__).with_name("check_commit_messages.py")
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class CommitSubjects(unittest.TestCase):
    def test_accepts_the_convention(self):
        for subject in [
            "feat(postgres): ✨ add sql_describe",
            "docs: 📝 add design",
            "refactor!: ♻️ rename things",
            "test(spike): ⚗️ add probes",
            "fix(fence): 🐛 deny writes to the resolved hooks path",
            "ci: 💚 pin LF line endings",
        ]:
            self.assertIsNone(checker.problem(subject), subject)

    def test_rejects_everything_else(self):
        for subject in [
            "Add design",
            "feat: add x",
            "✨ feat: add x",
            "feat:✨ x",
            "feat(Scope): ✨ x",
            "feat: ✨",
            "feat: ✨x",
            "wip: ✨ x",
            "feat : ✨ x",
        ]:
            self.assertIsNotNone(checker.problem(subject), subject)


if __name__ == "__main__":
    unittest.main()
