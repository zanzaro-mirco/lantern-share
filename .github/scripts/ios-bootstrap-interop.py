#!/usr/bin/env python3
"""Opt-in simulator test controller. Local test control, never product protocol/trust."""

import argparse
import os
from pathlib import Path
import plistlib
import queue
import re
import signal
import socketserver
import subprocess
import sys
import tempfile
import threading
import uuid


PIN = re.compile(r"[0-9a-f]{64}")
MAX_LINE = 256
SCENARIOS = {
    "success": "testJVMAndIOSBootstrapWithExplicitComparisonAndObservedCleanup",
    "mismatch": "testDiscordantComparisonClosesWithoutApprovalOrReady",
    "cancel": "testLocalCancellationBeforeConfirmationClosesBothOwners",
}


class FixtureProcess:
    """Owns a non-daemon Gradle process group, its bounded stdout reader and pipes."""

    def __init__(self, command, cwd):
        self.process = subprocess.Popen(
            command, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            # stderr stays visible; never hide compiler/crypto/process errors.
            start_new_session=os.name == "posix",
        )
        self.events = queue.Queue(maxsize=8)
        self.reader_failure = None
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        try:
            count = 0
            while True:
                line = self.process.stdout.readline(MAX_LINE + 1)
                if not line:
                    self.events.put_nowait(RuntimeError("Fixture stdout ended before expected event"))
                    return
                count += 1
                if count > 3:
                    raise RuntimeError("Unexpected additional fixture event")
                if len(line) > MAX_LINE or not line.endswith(b"\n"):
                    raise RuntimeError("Invalid fixture event length")
                self.events.put_nowait(line.decode("ascii").rstrip("\r\n"))
        except Exception:
            # Enqueue a fixed error, not peer/Gradle-controlled diagnostic content.
            self.reader_failure = RuntimeError("Fixture event reader stopped")
            try:
                self.events.put_nowait(RuntimeError("Fixture event reader stopped"))
            except queue.Full:
                pass

    def event(self, timeout):
        value = self.events.get(timeout=timeout)
        if self.reader_failure is not None:
            raise self.reader_failure
        if isinstance(value, Exception):
            raise value
        return value

    def send(self, command):
        self.process.stdin.write((command + "\n").encode("ascii"))
        self.process.stdin.flush()

    def finish(self, expected_exit=0):
        if self.process.wait(timeout=5) != expected_exit:
            raise RuntimeError("Unexpected fixture exit after terminal event")
        self.reader.join(timeout=5)
        if self.reader.is_alive() or self.reader_failure is not None:
            raise RuntimeError("Fixture output did not finish cleanly")

    def close(self):
        if os.name == "posix":
            # Includes descendants even if the Gradle launcher itself already exited.
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass  # The owned process group is already gone.
        elif self.process.poll() is None:
            self.process.terminate()
        if self.process.poll() is None:
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(self.process.pid, signal.SIGKILL)
                else:
                    self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        if self.reader.is_alive() and os.name == "posix":
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.reader.join(timeout=5)
        self.process.stdin.close()
        self.process.stdout.close()
        if self.reader.is_alive():
            raise RuntimeError("Fixture event reader did not stop")


class Controller:
    """Serial rendezvous. Pins/codes come from test owners, not discovery or TLS TOFU."""

    def __init__(self, launch, scenario="success"):
        if scenario not in SCENARIOS:
            raise ValueError("Invalid interop scenario")
        self.launch = launch
        self.scenario = scenario
        self.fixture = None
        self.phase = "SELECT"
        self.failure = None

    def exchange(self, command, argument):
        if self.failure is not None:
            raise RuntimeError("Interop controller already failed")
        try:
            if command != self.phase:
                raise ValueError("Unexpected test control order")
            if command == "SELECT":
                if not PIN.fullmatch(argument):
                    raise ValueError("Invalid Apple test pin")
                self.fixture = self.launch(argument)
                event = self.fixture.event(90)
                parts = event.split(" ")
                if (len(parts) != 4 or parts[:2] != ["LISTENING", "127.0.0.1"]
                        or not parts[2].isascii() or not parts[2].isdigit()
                        or not 1 <= int(parts[2]) <= 65535 or not PIN.fullmatch(parts[3])):
                    raise ValueError("Invalid fixture endpoint")
                self.phase = {"mismatch": "MISMATCH", "cancel": "ARM_CANCEL"}.get(self.scenario, "COMPARE")
                return event
            if command == "ARM_CANCEL":
                if not PIN.fullmatch(argument) or self.fixture.event(10) != "COMPARISON " + argument:
                    raise ValueError("Cancellation comparison codes differ")
                self.fixture.send("OBSERVE_CLOSE")  # Never CONFIRM; JVM waits for actual Apple closure.
                self.phase = "CANCELLED"
                return "ARMED CANCEL"
            if command == "CANCELLED":
                if argument != "LOCAL" or self.fixture.event(10) != "CLOSED BEFORE_CONFIRMATION":
                    raise ValueError("Both owners must observe cancellation before confirmation")
                self.fixture.finish()  # Real closure marker AND clean exit 0, not killed/failed JVM.
                self.phase = "CLOSED"
                return "CLOSED BEFORE_CONFIRMATION"
            if command == "MISMATCH":
                codes = argument.split(":")
                if len(codes) != 2 or not all(PIN.fullmatch(code) for code in codes) or codes[0] == codes[1]:
                    raise ValueError("Invalid negative comparison fixture")
                original, altered = codes
                if self.fixture.event(10) != "COMPARISON " + original:
                    raise ValueError("Original comparison codes differ")
                # Deliberately invalid test UI input. The JVM MUST reject before owner.confirm().
                self.fixture.send("CONFIRM " + altered)
                if self.fixture.event(10) != "REJECTED COMPARISON":
                    raise ValueError("Fixture did not reject the comparison")
                self.fixture.finish(expected_exit=1)  # Marker alone or an arbitrary crash is insufficient.
                self.phase = "CLOSED"
                return "REJECTED COMPARISON"
            if command == "COMPARE":
                if not PIN.fullmatch(argument):
                    raise ValueError("Invalid comparison code")
                if self.fixture.event(10) != "COMPARISON " + argument:
                    raise ValueError("Comparison codes differ")
                # Test-simulated explicit JVM UI action only after the FULL codes agree.
                self.fixture.send("CONFIRM " + argument)
                self.phase = "READY"
                return "CONFIRM " + argument
            if command == "READY":
                if argument != "receipts,text" or self.fixture.event(10) != "READY receipts,text":
                    raise ValueError("Both owners must report the negotiated features")
                self.fixture.send("CLOSE")  # Apple already observed its own READY.
                self.fixture.finish()       # Require real JVM process exit 0.
                self.phase = "CLOSED"
                return "READY receipts,text"
            if command == "CLOSED":
                if argument != ("LOCAL" if self.scenario == "cancel" else "TRANSPORT"):
                    raise ValueError("Apple must observe transport closure and cleanup")
                self.phase = "COMPLETE"
                return "COMPLETE"
            raise ValueError("Unexpected control command")
        except Exception as error:
            self.failure = error
            if self.fixture is not None:
                self.fixture.close()
            raise

    def close(self):
        if self.fixture is not None:
            self.fixture.close()


class ControlServer(socketserver.TCPServer):
    allow_reuse_address = False

    def __init__(self, controller):
        self.controller = controller
        self.token = uuid.uuid4().hex
        super().__init__(("127.0.0.1", 0), ControlRequest)


class ControlRequest(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(10)
        try:
            line = self.rfile.readline(MAX_LINE + 1)
            if len(line) > MAX_LINE or not line.endswith(b"\n"):
                raise ValueError("Invalid control line")
            token, command, argument = line[:-1].decode("ascii").split(" ")
            if token != self.server.token:
                raise ValueError("Wrong local test token")
            response = self.server.controller.exchange(command, argument)
        except Exception:
            response = "ERROR"  # Details are never echoed into the simulator.
        self.wfile.write((response + "\n").encode("ascii"))


def configured_test_run(template, endpoint):
    """Copy Xcode's test manifest; change only this test target's control environment."""
    document = plistlib.loads(template.read_bytes())
    if "TestConfigurations" in document:  # Xcode format 2 (test plans).
        targets = [target for config in document["TestConfigurations"] for target in config["TestTargets"]
                   if target.get("BlueprintName") == "LanternBootstrapInteropTests"]
    else:  # Xcode format 1 (our existing scheme without a test plan).
        targets = [value for key, value in document.items() if key == "LanternBootstrapInteropTests"]
    if len(targets) != 1:
        raise RuntimeError("Expected exactly one bootstrap test target in Xcode manifest")
    target = targets[0]
    if target.get("IsEnabled") is False:
        raise RuntimeError("Bootstrap test target is disabled")
    target.setdefault("EnvironmentVariables", {})["LANTERN_INTEROP_CONTROL"] = endpoint
    return plistlib.dumps(document)


def run_scenario(root, device_id, scenario, template):
    controller = Controller(lambda pin: FixtureProcess([
        "bash", "./gradlew", ":connectivity:runHandshakeV1InteropFixture",
        "-PinteropPeerPin=" + pin, "--no-daemon", "--quiet", "--console=plain",
    ], root), scenario=scenario)
    with ControlServer(controller) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        port = server.server_address[1]
        endpoint = f"127.0.0.1:{port}:{server.token}"
        # Keep the copy beside Xcode's manifest: __TESTROOT__ must still resolve to the built products.
        manifest = None
        child = None
        try:
            with tempfile.NamedTemporaryFile(prefix="lantern-control-", suffix=".xctestrun",
                                             dir=template.parent, delete=False) as output:
                manifest = Path(output.name)
                output.write(configured_test_run(template, endpoint))
            command = [
                "xcodebuild", "-xctestrun", str(manifest),
                "-destination", "platform=iOS Simulator,id=" + device_id,
                "-resultBundlePath", "build/ios-bootstrap-interop-" + scenario + "-" + uuid.uuid4().hex + ".xcresult",
                "-only-testing:LanternBootstrapInteropTests/BootstrapInteropTests/" + SCENARIOS[scenario],
                "test-without-building",
            ]
            child = subprocess.Popen(command, cwd=root, start_new_session=True)
            exit_code = child.wait(timeout=1200)
            if controller.failure is not None:
                raise RuntimeError("Interop controller failed") from controller.failure
            if exit_code != 0:
                raise RuntimeError("Interop XCTest failed")
            if controller.phase != "COMPLETE":
                raise RuntimeError("Interop control/cleanup did not complete")
            if scenario == "mismatch":
                print("Bootstrap JVM/iOS: comparison rejected without READY; transport/namespace cleanup observed")
            elif scenario == "cancel":
                print("Bootstrap JVM/iOS: local cancellation without READY; both closures/namespace cleanup observed")
            else:
                print("Bootstrap JVM/iOS: both READY and transport/namespace cleanup observed")
        finally:
            if child is not None and child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
            # The server owns the fixture during a request; stop/join before closing its pipes.
            try:
                server.shutdown()
                worker.join(timeout=100)
                controller.close()
                if worker.is_alive():
                    raise RuntimeError("Interop controller did not stop")
            finally:
                if manifest is not None:
                    manifest.unlink()  # Only the temporary copy owned by this run, never compiled products.


def run_batch(scenarios, prepare, run):
    template = prepare()  # One compilation for the whole batch; fresh controllers for each scenario.
    for scenario in scenarios:
        run(scenario, template)  # Propagate any failure. No remaining test is reported as successful.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-id", required=True, help="Existing disposable simulator UDID")
    parser.add_argument("--scenario", choices=["all", *SCENARIOS], default="success")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("The integration launcher requires macOS/Xcode")
    root = Path(__file__).resolve().parents[2]
    (root / "build").mkdir(exist_ok=True)

    def prepare():
        # Warm compilation before the 10-second fixture accept window and XCTest starts.
        subprocess.run(["bash", "./gradlew", ":connectivity:jvmTestClasses", "--console=plain"],
                       cwd=root, check=True, timeout=600)
        derived = root / "build" / "ios-derived"
        subprocess.run([
            "xcodebuild", "-project", "iosApp/Lantern.xcodeproj", "-scheme", "LanternBootstrapInterop",
            "-configuration", "Debug", "-derivedDataPath", str(derived),
            "-destination", "platform=iOS Simulator,id=" + args.device_id,
            "-onlyUsePackageVersionsFromResolvedFile", "CODE_SIGNING_ALLOWED=YES", "CODE_SIGN_IDENTITY=-",
            "build-for-testing",
        ], cwd=root, check=True, timeout=600)
        templates = list((derived / "Build" / "Products").glob("LanternBootstrapInterop_*.xctestrun"))
        if len(templates) != 1:
            raise RuntimeError("Expected exactly one compiled bootstrap test manifest")
        return templates[0]

    scenarios = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    run_batch(scenarios, prepare, lambda scenario, template: run_scenario(root, args.device_id, scenario, template))


if __name__ == "__main__":
    main()
