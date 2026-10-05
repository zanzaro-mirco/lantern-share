"""Target-selection regressions: a deferred checkpoint is never a passed test."""

import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("ci_plan", Path(__file__).with_name("ci-plan.py"))
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class WorkflowContractTests(unittest.TestCase):
    def test_build_only_keeps_runtime_preparation_unconditional_and_before_xcode(self):
        # Configuration regression, not a substitute for running Xcode on macOS.
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/ios.yml").read_text(encoding="utf-8")
        name = "      - name: Install matching simulator runtime\n"
        start = workflow.index(name)
        end = workflow.index("\n      - ", start + len(name))
        step = workflow[start:end]
        self.assertNotIn("\n        if:", step)
        self.assertIn("prepare-ios-simulator.sh", step)
        self.assertLess(start, workflow.index("      - name: Compile app and ordinary XCTest"))
        self.assertEqual(workflow.count("bash .github/scripts/prepare-ios-simulator.sh"), 1)


class PlanTests(unittest.TestCase):
    def test_documentation_has_no_heavy_jobs(self):
        result = ci.plan(["README.md", "docs/COLLAUDO.md", "AGENTS.md"])
        self.assertEqual([result[key] for key in ["jvm", "android", "ios"]], ["false"] * 3)

    def test_platform_specific_paths_are_isolated(self):
        for path, expected in [("iosApp/Tests/Test.swift", {"ios"}),
                               ("ui/src/iosMain/Ui.kt", {"ios"}),
                               ("persistence/src/iosTest/Test.kt", {"ios"}),
                               ("protocol/src/jvmTest/Test.kt", {"jvm"}),
                               ("desktopApp/src/main/App.kt", {"jvm"}),
                               ("androidApp/src/main/App.kt", {"android"}),
                               ("protocol/src/androidMain/Protocol.kt", {"android"})]:
            with self.subTest(path=path):
                self.assertEqual(ci.targets_for(path), expected)

    def test_joint_source_set_keeps_android_and_jvm(self):
        self.assertEqual(ci.targets_for("connectivity/src/jvmAndAndroidMain/Owner.kt"), {"jvm", "android"})

    def test_shared_build_locks_and_unknown_paths_broaden_checks(self):
        for path in ["domain/src/commonMain/Device.kt", "protocol/src/commonTest/Test.kt", "newModule/src/Foo.kt",
                     "settings.gradle.kts", "gradle/libs.versions.toml", "ui/gradle.lockfile", "gradlew"]:
            with self.subTest(path=path):
                self.assertEqual(ci.targets_for(path), ci.ALL)

    def test_workflow_and_script_changes_select_their_consumers(self):
        self.assertEqual(ci.targets_for(".github/workflows/verify.yml"), {"jvm", "android"})
        self.assertEqual(ci.targets_for(".github/workflows/ios.yml"), {"ios"})
        self.assertEqual(ci.targets_for(".github/scripts/ios-bootstrap-interop.py"), {"ios"})
        self.assertEqual(ci.targets_for(".github/scripts/ci-plan.py"), ci.ALL)

    def test_checkpoint_keeps_full_matrix_even_without_source_changes(self):
        full = ci.plan(["README.md"], full=True)
        self.assertEqual([full[key] for key in ["jvm", "android", "ios", "full"]], ["true"] * 4)
        self.assertEqual(len(json.loads(full["desktop_os"])), 4)
        self.assertEqual(json.loads(ci.plan(["desktopApp/App.kt"])["desktop_os"]), ["windows-latest"])

    def test_complete_diff_is_not_limited_to_three_hundred_paths(self):
        paths = [f"docs/{number}.md" for number in range(350)] + ["protocol/src/commonMain/Protocol.kt"]
        self.assertEqual(ci.plan(paths)["ios"], "true")

    def test_push_uses_both_shas_and_nul_delimiters_with_deleted_paths(self):
        base, head = "a" * 40, "b" * 40
        result = subprocess.CompletedProcess([], 0, b"old.swift\0path with spaces.kt\0")
        with patch.object(ci.subprocess, "run", return_value=result) as run:
            self.assertEqual(ci.changed_paths("push", {"before": base, "after": head}),
                             ["old.swift", "path with spaces.kt"])
            self.assertEqual(run.call_args.args[0][-1], base + ".." + head)
            self.assertIn("--no-renames", run.call_args.args[0])

    def test_pr_uses_merge_base_not_only_last_commit(self):
        event = {"pull_request": {"base": {"sha": "a" * 40}, "head": {"sha": "b" * 40}}}
        with patch.object(ci.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"")) as run:
            self.assertEqual(ci.changed_paths("pull_request", event), [])
            self.assertEqual(run.call_args.args[0][-1], "a" * 40 + "..." + "b" * 40)

    def test_missing_or_invalid_comparison_broadens_never_skips(self):
        for base in ["0" * 40, "--unsafe", None]:
            with patch.object(ci.subprocess, "run") as run:
                self.assertIsNone(ci.changed_paths("push", {"before": base, "after": "b" * 40}))
                run.assert_not_called()
        with patch.object(ci.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "git")):
            self.assertIsNone(ci.changed_paths("push", {"before": "a" * 40, "after": "b" * 40}))
        self.assertEqual(ci.plan(["unknown-comparison"])["ios"], "true")


if __name__ == "__main__":
    unittest.main()
