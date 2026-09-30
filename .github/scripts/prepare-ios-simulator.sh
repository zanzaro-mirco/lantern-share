#!/usr/bin/env bash
set -euo pipefail

# Keep this runtime aligned with Xcode 16.3 and the XCTest destination.
runtime_id=com.apple.CoreSimulator.SimRuntime.iOS-18-4

runtime_available() {
  # Listing first lets CoreSimulator rebuild its caches after switching Xcode.
  # runner-images/issues/12862 documents this prerequisite for downloadPlatform.
  local runtimes
  runtimes=$(xcrun simctl list runtimes --json) || return $?
  printf '%s\n' "$runtimes" >&2
  printf '%s\n' "$runtimes" | node -e '
    const fs = require("fs");
    const data = JSON.parse(fs.readFileSync(0, "utf8"));
    if (!Array.isArray(data.runtimes)) throw new Error("Invalid simctl runtime list");
    console.log(data.runtimes.some(runtime =>
      runtime.identifier === process.argv[1] && runtime.isAvailable === true));
  ' "$runtime_id"
}

xcodebuild -version
xcodebuild -runFirstLaunch
available=$(runtime_available)
if [[ "$available" == true ]]; then
  echo 'iOS 18.4 runtime is already available; download not required.'
else
  xcodebuild -downloadPlatform iOS -buildVersion 18.4
  available=$(runtime_available)
  if [[ "$available" != true ]]; then
    echo '::error::iOS 18.4 runtime is unavailable after installation.' >&2
    exit 1
  fi
fi
