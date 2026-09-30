#!/usr/bin/env bash
set -euo pipefail

# Test orchestration only: these substitutes never run in the macOS CI setup.
xcodebuild() {
  case "$1" in
    -version) echo 'Xcode 16.3' ;;
    -runFirstLaunch) return "${FIRST_LAUNCH_EXIT:-0}" ;;
    -downloadPlatform)
      [[ "$*" == '-downloadPlatform iOS -buildVersion 18.4' ]] || return 98
      [[ "$EXPECT_DOWNLOAD" == true ]] || return 99
      echo 'TEST_DOWNLOAD'
      if [[ "${DOWNLOAD_EXIT:-0}" != 0 ]]; then return "$DOWNLOAD_EXIT"; fi
      export INSTALLED=true
      ;;
    *) return 98 ;;
  esac
}

xcrun() {
  [[ "$*" == 'simctl list runtimes --json' ]] || return 98
  if [[ "${SIMCTL_EXIT:-0}" != 0 ]]; then return "$SIMCTL_EXIT"; fi
  if [[ "${INVALID_JSON:-false}" == true ]]; then echo '{}'; return; fi
  local available=false
  if [[ "$PREINSTALLED" == true || ( "${INSTALLED:-false}" == true && "$INSTALL_AVAILABLE" == true ) ]]; then
    available=true
  fi
  printf '{"runtimes":[{"identifier":"com.apple.CoreSimulator.SimRuntime.iOS-18-4","isAvailable":%s},{"identifier":"com.apple.CoreSimulator.SimRuntime.iOS-18-5","isAvailable":true}]}\n' "$available"
}
export -f xcodebuild xcrun

check() {
  local name=$1 expected_exit=$2 expected_download=$3 output status=0
  shift 3
  output=$(env PREINSTALLED=false EXPECT_DOWNLOAD=true INSTALL_AVAILABLE=true "$@" \
    bash .github/scripts/prepare-ios-simulator.sh 2>&1) || status=$?
  if [[ "$status" != "$expected_exit" ]]; then
    printf 'FAIL %s: exit %s, expected %s\n%s\n' "$name" "$status" "$expected_exit" "$output"
    exit 1
  fi
  if [[ "$expected_download" == true ]]; then
    [[ "$output" == *TEST_DOWNLOAD* ]] || { echo "FAIL $name: no download"; exit 1; }
  else
    [[ "$output" != *TEST_DOWNLOAD* ]] || { echo "FAIL $name: unexpected download"; exit 1; }
  fi
  echo "PASS $name"
}

check preinstalled 0 false PREINSTALLED=true EXPECT_DOWNLOAD=false
check missing-runtime 0 true
check unavailable-after-install 1 true INSTALL_AVAILABLE=false
check download-failure 70 true DOWNLOAD_EXIT=70
check first-launch-failure 71 false FIRST_LAUNCH_EXIT=71
check simctl-failure 72 false SIMCTL_EXIT=72
check malformed-list 1 false INVALID_JSON=true
