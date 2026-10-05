#!/usr/bin/env python3
"""Conservative CI target selection using the complete Git diff, not API path limits."""

import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess


ALL = {"jvm", "android", "ios"}
MODULES = {"domain", "protocol", "persistence", "ui", "connectivity"}
SHA = re.compile(r"[0-9a-f]{40}")


def targets_for(path):
    parts = PurePosixPath(path).parts
    if not parts:
        return ALL.copy()
    if parts[0] == "docs" or path.endswith(".md") or path in {"LICENSE", ".gitignore", ".editorconfig"}:
        return set()
    if (path.endswith((".gradle.kts", ".gradle", ".lockfile")) or parts[0] == "gradle"
            or path in {"gradlew", "gradlew.bat", "gradle.properties"}):
        return ALL.copy()
    if path == ".github/workflows/verify.yml":
        return {"jvm", "android"}
    if path == ".github/workflows/ios.yml":
        return {"ios"}
    if parts[:2] == (".github", "scripts"):
        if parts[-1] in {"ci-plan.py", "test-ci-plan.py"}:
            return ALL.copy()
        if "ios" in parts[-1]:
            return {"ios"}
        return ALL.copy()
    if parts[0] == "androidApp":
        return {"android"}
    if parts[0] == "desktopApp":
        return {"jvm"}
    if parts[0] == "iosApp":
        return {"ios"}
    if len(parts) >= 3 and parts[0] in MODULES and parts[1] == "src":
        source_set = parts[2]
        if source_set.startswith("jvmAndAndroid"):
            return {"jvm", "android"}
        if source_set.startswith("jvm"):
            return {"jvm"}
        if source_set.startswith("android"):
            return {"android"}
        if source_set.startswith(("ios", "apple", "native")):
            return {"ios"}
    # New modules/layouts cannot silently fall outside the verification perimeter.
    return ALL.copy()


def plan(paths, full=False):
    targets = ALL.copy() if full else set().union(*(targets_for(path) for path in paths))
    return {
        **{target: str(target in targets).lower() for target in sorted(ALL)},
        "full": str(full).lower(),
        "desktop_os": json.dumps(["windows-latest", "ubuntu-24.04", "macos-15", "macos-15-intel"]
                                 if full else ["windows-latest"]),
    }


def changed_paths(event_name, event):
    if event_name == "pull_request":
        # Include earlier commits in the PR; a push diff alone would miss them.
        base, head = event["pull_request"]["base"]["sha"], event["pull_request"]["head"]["sha"]
        separator = "..."
    elif event_name == "push":
        base, head = event["before"], event["after"]
        separator = ".."
    else:
        return None
    if not all(isinstance(sha, str) and SHA.fullmatch(sha) and sha != "0" * 40 for sha in (base, head)):
        return None  # New branch or unavailable comparison: broaden, never skip.
    try:
        result = subprocess.run(["git", "diff", "--name-only", "--no-renames", "-z", base + separator + head],
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        return [path for path in result.stdout.decode("utf-8").split("\0") if path]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, UnicodeDecodeError):
        return None


def main():
    event_name = os.environ["GITHUB_EVENT_NAME"]
    with Path(os.environ["GITHUB_EVENT_PATH"]).open(encoding="utf-8") as source:
        event = json.load(source)
    full = event_name == "workflow_dispatch"
    paths = [] if full else changed_paths(event_name, event)
    outputs = plan(paths if paths is not None else ["unknown-comparison"], full=full)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        for key, value in outputs.items():
            output.write(f"{key}={value}\n")
    print(json.dumps(outputs, sort_keys=True))


if __name__ == "__main__":
    main()
