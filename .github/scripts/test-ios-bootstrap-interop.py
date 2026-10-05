"""Controller/process tests only; substitutes below are NOT Apple/TLS interoperability."""

import importlib.util
from pathlib import Path
import socket
import plistlib
import sys
import threading
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("interop", Path(__file__).with_name("ios-bootstrap-interop.py"))
interop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(interop)

PIN = "a" * 64
CODE = "b" * 64
ENDPOINT = "LISTENING 127.0.0.1 12345 " + "c" * 64


class FakeFixture:
    def __init__(self, events=None, fail_exit=False, exit_code=0):
        self.events = list(events if events is not None else [ENDPOINT, "COMPARISON " + CODE, "READY receipts,text"])
        self.commands = []
        self.finished = False
        self.closed = False
        self.fail_exit = fail_exit
        self.exit_code = exit_code

    def event(self, timeout):
        return self.events.pop(0)

    def send(self, command):
        self.commands.append(command)

    def finish(self, expected_exit=0):
        if self.fail_exit or self.exit_code != expected_exit:
            raise RuntimeError("Test exit failure")
        self.finished = True

    def close(self):
        self.closed = True


class ControllerTests(unittest.TestCase):
    def make_controller(self, fixture=None):
        fixture = fixture or FakeFixture()
        pins = []
        controller = interop.Controller(lambda pin: (pins.append(pin), fixture)[1])
        self.addCleanup(controller.close)
        return controller, fixture, pins

    def test_both_ready_before_close_and_apple_cleanup_before_complete(self):
        controller, fixture, pins = self.make_controller()
        self.assertEqual(controller.exchange("SELECT", PIN), ENDPOINT)
        self.assertEqual(pins, [PIN])
        self.assertEqual(controller.exchange("COMPARE", CODE), "CONFIRM " + CODE)
        self.assertEqual(fixture.commands, ["CONFIRM " + CODE])
        self.assertFalse(fixture.finished)
        self.assertEqual(controller.exchange("READY", "receipts,text"), "READY receipts,text")
        self.assertTrue(fixture.finished)
        self.assertEqual(fixture.commands, ["CONFIRM " + CODE, "CLOSE"])
        self.assertEqual(controller.phase, "CLOSED")
        self.assertEqual(controller.exchange("CLOSED", "TRANSPORT"), "COMPLETE")

    def test_invalid_pin_never_launches(self):
        for pin in ["", "a" * 63, "A" * 64, "g" * 64]:
            controller, fixture, pins = self.make_controller()
            with self.assertRaises(ValueError):
                controller.exchange("SELECT", pin)
            self.assertEqual(pins, [])
            self.assertFalse(fixture.closed)

    def test_mismatch_never_sends_confirmation_and_cannot_resume(self):
        controller, fixture, _ = self.make_controller()
        controller.exchange("SELECT", PIN)
        with self.assertRaises(ValueError):
            controller.exchange("COMPARE", "d" * 64)
        self.assertEqual(fixture.commands, [])
        self.assertTrue(fixture.closed)
        with self.assertRaises(RuntimeError):
            controller.exchange("COMPARE", CODE)

    def test_early_ready_duplicate_selection_or_wrong_features_fail_closed(self):
        for command, argument in [("READY", "receipts,text"), ("SELECT", PIN), ("CLOSED", "TRANSPORT")]:
            controller, fixture, _ = self.make_controller()
            controller.exchange("SELECT", PIN)
            with self.assertRaises(ValueError):
                controller.exchange(command, argument)
            self.assertTrue(fixture.closed)
            self.assertNotIn("CLOSE", fixture.commands)
        controller, fixture, _ = self.make_controller()
        controller.exchange("SELECT", PIN)
        controller.exchange("COMPARE", CODE)
        with self.assertRaises(ValueError):
            controller.exchange("READY", "text")
        self.assertNotIn("CLOSE", fixture.commands)

    def test_non_loopback_or_invalid_endpoint_fails_closed(self):
        for endpoint in [ENDPOINT.replace("127.0.0.1", "192.168.1.2"), ENDPOINT.replace("12345", "65536"),
                         ENDPOINT.replace("12345", "0"), ENDPOINT.replace("c" * 64, "C" * 64)]:
            fixture = FakeFixture([endpoint])
            controller, _, _ = self.make_controller(fixture)
            with self.assertRaises(ValueError):
                controller.exchange("SELECT", PIN)
            self.assertTrue(fixture.closed)

    def test_failed_process_exit_never_acknowledges_ready(self):
        controller, fixture, _ = self.make_controller(FakeFixture(fail_exit=True))
        controller.exchange("SELECT", PIN)
        controller.exchange("COMPARE", CODE)
        with self.assertRaises(RuntimeError):
            controller.exchange("READY", "receipts,text")
        self.assertNotEqual(controller.phase, "CLOSED")
        self.assertTrue(fixture.closed)

    def test_missing_fixture_comparison_times_out_without_confirming(self):
        controller, fixture, _ = self.make_controller()
        controller.exchange("SELECT", PIN)
        with patch.object(fixture, "event", side_effect=TimeoutError("Test deadline")):
            with self.assertRaises(TimeoutError):
                controller.exchange("COMPARE", CODE)
        self.assertEqual(fixture.commands, [])
        self.assertTrue(fixture.closed)

    def test_negative_scenario_requires_typed_rejection_exit_one_and_cleanup(self):
        fixture = FakeFixture([ENDPOINT, "COMPARISON " + CODE, "REJECTED COMPARISON"], exit_code=1)
        controller = interop.Controller(lambda pin: fixture, scenario="mismatch")
        self.addCleanup(controller.close)
        controller.exchange("SELECT", PIN)
        changed = "0" + CODE[1:]
        self.assertEqual(controller.exchange("MISMATCH", CODE + ":" + changed), "REJECTED COMPARISON")
        self.assertEqual(fixture.commands, ["CONFIRM " + changed])
        self.assertTrue(fixture.finished)
        self.assertEqual(controller.phase, "CLOSED")
        self.assertEqual(controller.exchange("CLOSED", "TRANSPORT"), "COMPLETE")

    def test_negative_scenario_is_not_available_in_positive_controller(self):
        controller, fixture, _ = self.make_controller()
        controller.exchange("SELECT", PIN)
        with self.assertRaises(ValueError):
            controller.exchange("MISMATCH", CODE + ":" + "d" * 64)
        self.assertEqual(fixture.commands, [])
        self.assertTrue(fixture.closed)

    def test_negative_scenario_rejects_same_codes_wrong_original_and_wrong_marker(self):
        cases = [
            (CODE + ":" + CODE, "COMPARISON " + CODE, "REJECTED COMPARISON"),
            (CODE + ":" + "d" * 64, "COMPARISON " + "e" * 64, "REJECTED COMPARISON"),
            (CODE + ":" + "d" * 64, "COMPARISON " + CODE, "READY receipts,text"),
            (CODE + ":invalid", "COMPARISON " + CODE, "REJECTED COMPARISON"),
        ]
        for codes, comparison, terminal in cases:
            fixture = FakeFixture([ENDPOINT, comparison, terminal], exit_code=1)
            controller = interop.Controller(lambda pin: fixture, scenario="mismatch")
            controller.exchange("SELECT", PIN)
            with self.assertRaises(ValueError):
                controller.exchange("MISMATCH", codes)
            self.assertTrue(fixture.closed)
            self.assertFalse(fixture.finished)
            self.assertIsNotNone(controller.failure)

    def test_rejection_marker_with_success_or_arbitrary_exit_is_not_negative_success(self):
        for exit_code in [0, 2]:
            fixture = FakeFixture([ENDPOINT, "COMPARISON " + CODE, "REJECTED COMPARISON"], exit_code=exit_code)
            controller = interop.Controller(lambda pin: fixture, scenario="mismatch")
            controller.exchange("SELECT", PIN)
            with self.assertRaises(RuntimeError):
                controller.exchange("MISMATCH", CODE + ":" + "d" * 64)
            self.assertTrue(fixture.closed)
            self.assertNotEqual(controller.phase, "CLOSED")


class CancellationControllerTests(unittest.TestCase):
    def controller(self, terminal="CLOSED BEFORE_CONFIRMATION", exit_code=0):
        fixture = FakeFixture([ENDPOINT, "COMPARISON " + CODE, terminal], exit_code=exit_code)
        controller = interop.Controller(lambda pin: fixture, scenario="cancel")
        self.addCleanup(controller.close)
        controller.exchange("SELECT", PIN)
        return controller, fixture

    def test_cancellation_requires_both_closures_and_cleanup_without_confirm(self):
        controller, fixture = self.controller()
        self.assertEqual(controller.exchange("ARM_CANCEL", CODE), "ARMED CANCEL")
        self.assertEqual(fixture.commands, ["OBSERVE_CLOSE"])
        self.assertFalse(fixture.finished)
        self.assertEqual(controller.exchange("CANCELLED", "LOCAL"), "CLOSED BEFORE_CONFIRMATION")
        self.assertTrue(fixture.finished)
        self.assertEqual(controller.exchange("CLOSED", "LOCAL"), "COMPLETE")
        self.assertEqual(fixture.commands, ["OBSERVE_CLOSE"])

    def test_wrong_digest_and_early_closure_fail_without_arming(self):
        for command, argument in [("ARM_CANCEL", "d" * 64), ("ARM_CANCEL", "invalid"),
                                  ("CANCELLED", "LOCAL"), ("COMPARE", CODE), ("READY", "receipts,text")]:
            controller, fixture = self.controller()
            with self.assertRaises(ValueError):
                controller.exchange(command, argument)
            self.assertEqual(fixture.commands, [])
            self.assertTrue(fixture.closed)

    def test_missing_wrong_marker_or_failed_exit_cannot_attest_cancellation(self):
        for terminal, exit_code in [("READY receipts,text", 0), ("REJECTED COMPARISON", 1),
                                    ("CLOSED BEFORE_CONFIRMATION", 1)]:
            controller, fixture = self.controller(terminal, exit_code)
            controller.exchange("ARM_CANCEL", CODE)
            with self.assertRaises((ValueError, RuntimeError)):
                controller.exchange("CANCELLED", "LOCAL")
            self.assertNotEqual(controller.phase, "CLOSED")
            self.assertTrue(fixture.closed)
        controller, fixture = self.controller()
        controller.exchange("ARM_CANCEL", CODE)
        with patch.object(fixture, "event", side_effect=TimeoutError("Test missing closure")):
            with self.assertRaises(TimeoutError):
                controller.exchange("CANCELLED", "LOCAL")
        self.assertTrue(fixture.closed)

    def test_cancel_requires_local_cleanup_and_is_unavailable_in_other_scenarios(self):
        controller, fixture = self.controller()
        controller.exchange("ARM_CANCEL", CODE)
        controller.exchange("CANCELLED", "LOCAL")
        with self.assertRaises(ValueError):
            controller.exchange("CLOSED", "TRANSPORT")
        self.assertNotEqual(controller.phase, "COMPLETE")
        for scenario in ["success", "mismatch"]:
            fixture = FakeFixture()
            controller = interop.Controller(lambda pin: fixture, scenario=scenario)
            controller.exchange("SELECT", PIN)
            with self.assertRaises(ValueError):
                controller.exchange("ARM_CANCEL", CODE)
            self.assertEqual(fixture.commands, [])
            self.assertTrue(fixture.closed)


class BatchTests(unittest.TestCase):
    def test_prebuilt_run_uses_owned_manifest_and_removes_it_even_on_failure(self):
        # Only orchestration substitutes; not a cryptographic/simulator test.
        for exit_code in [0, 1]:
            with tempfile.TemporaryDirectory(prefix="lantern-batch-test-") as directory:
                root = Path(directory)
                template = root / "original.xctestrun"
                template.write_bytes(plistlib.dumps({"LanternBootstrapInteropTests": {}}))
                server = Mock()
                server.token = "a" * 32
                server.server_address = ("127.0.0.1", 1234)
                context = Mock()
                context.__enter__ = Mock(return_value=server)
                context.__exit__ = Mock(return_value=False)
                worker = Mock()
                worker.is_alive.return_value = False
                controller = Mock()
                controller.failure = None
                controller.phase = "COMPLETE"
                child = Mock()
                child.wait.return_value = exit_code
                child.poll.return_value = exit_code
                observed = []

                def spawn(command, **kwargs):
                    manifest = Path(command[command.index("-xctestrun") + 1])
                    self.assertTrue(manifest.exists())
                    self.assertEqual(manifest.parent, template.parent)
                    self.assertNotEqual(manifest, template)
                    configured = plistlib.loads(manifest.read_bytes())
                    self.assertEqual(configured["LanternBootstrapInteropTests"]["EnvironmentVariables"]
                                     ["LANTERN_INTEROP_CONTROL"], "127.0.0.1:1234:" + server.token)
                    self.assertEqual(command[-1], "test-without-building")
                    self.assertIn("-only-testing:LanternBootstrapInteropTests/BootstrapInteropTests/" +
                                  interop.SCENARIOS["cancel"], command)
                    observed.append(manifest)
                    return child

                with patch.object(interop, "ControlServer", return_value=context), \
                     patch.object(interop, "Controller", return_value=controller), \
                     patch.object(interop.threading, "Thread", return_value=worker), \
                     patch.object(interop.subprocess, "Popen", side_effect=spawn), patch("builtins.print"):
                    if exit_code:
                        with self.assertRaises(RuntimeError):
                            interop.run_scenario(root, "simulator-id", "cancel", template)
                    else:
                        interop.run_scenario(root, "simulator-id", "cancel", template)
                self.assertFalse(observed[0].exists())
                self.assertTrue(template.exists())
                server.shutdown.assert_called_once_with()
                controller.close.assert_called_once_with()

    def test_all_scenarios_prepare_once_and_keep_separate_runs(self):
        prepare = Mock(return_value="compiled-manifest")
        run = Mock()
        interop.run_batch(list(interop.SCENARIOS), prepare, run)
        prepare.assert_called_once_with()
        self.assertEqual([call.args for call in run.call_args_list],
                         [(scenario, "compiled-manifest") for scenario in ["success", "mismatch", "cancel"]])

    def test_failed_build_or_scenario_is_never_hidden_or_retried(self):
        prepare = Mock(side_effect=RuntimeError("Test build failed"))
        run = Mock()
        with self.assertRaises(RuntimeError):
            interop.run_batch(list(interop.SCENARIOS), prepare, run)
        run.assert_not_called()
        prepare = Mock(return_value="manifest")
        run = Mock(side_effect=[None, RuntimeError("Test mismatch failed")])
        with self.assertRaises(RuntimeError):
            interop.run_batch(list(interop.SCENARIOS), prepare, run)
        self.assertEqual(run.call_count, 2)
        prepare.assert_called_once_with()

    def test_test_manifest_control_environment_changes_only_expected_target(self):
        for document in [
            {"LanternBootstrapInteropTests": {"EnvironmentVariables": {"KEEP": "yes"}, "TestHostPath": "__TESTROOT__/App"},
             "__xctestrun_metadata__": {"FormatVersion": 1}},
            {"TestConfigurations": [{"TestTargets": [{"BlueprintName": "LanternBootstrapInteropTests",
                                                       "EnvironmentVariables": {"KEEP": "yes"}, "TestHostPath": "__TESTROOT__/App"}]}],
             "__xctestrun_metadata__": {"FormatVersion": 2}},
        ]:
            template = Mock()
            template.read_bytes.return_value = plistlib.dumps(document)
            endpoint = "127.0.0.1:1234:" + "a" * 32
            configured = plistlib.loads(interop.configured_test_run(template, endpoint))
            target = (configured.get("LanternBootstrapInteropTests") or
                      configured["TestConfigurations"][0]["TestTargets"][0])
            self.assertEqual(target["EnvironmentVariables"], {"KEEP": "yes", "LANTERN_INTEROP_CONTROL": endpoint})
            self.assertEqual(target["TestHostPath"], "__TESTROOT__/App")
            self.assertNotIn("LANTERN_INTEROP_CONTROL", str(document))  # Template untouched.

    def test_missing_disabled_or_ambiguous_bootstrap_manifest_fails(self):
        for document in [{"OtherTests": {}}, {"LanternBootstrapInteropTests": {"IsEnabled": False}},
                         {"TestConfigurations": [{"TestTargets": [{"BlueprintName": "LanternBootstrapInteropTests"}]},
                                                 {"TestTargets": [{"BlueprintName": "LanternBootstrapInteropTests"}]}]}]:
            template = Mock()
            template.read_bytes.return_value = plistlib.dumps(document)
            with self.assertRaises(RuntimeError):
                interop.configured_test_run(template, "endpoint")


class ProcessTests(unittest.TestCase):
    def launch(self, script):
        fixture = interop.FixtureProcess([sys.executable, "-u", "-c", script], Path(__file__).parent)
        self.addCleanup(fixture.close)
        return fixture

    def test_real_subprocess_line_io_exit_and_reader_cleanup(self):
        fixture = self.launch("import sys; print('LISTENING'); print(sys.stdin.readline().strip()); print('READY')")
        self.assertEqual(fixture.event(5), "LISTENING")
        fixture.send("CONFIRM")
        self.assertEqual(fixture.event(5), "CONFIRM")
        self.assertEqual(fixture.event(5), "READY")
        fixture.finish()
        fixture.close()
        self.assertFalse(fixture.reader.is_alive())
        self.assertTrue(fixture.process.stdin.closed)
        self.assertTrue(fixture.process.stdout.closed)

    def test_oversize_non_ascii_and_unexpected_extra_stdout_fail(self):
        for script in ["print('a' * 257)", "print(chr(233))", "print('a\\nb\\nc\\nd')"]:
            fixture = self.launch(script)
            fixture.process.wait(timeout=5)
            fixture.reader.join(timeout=5)
            with self.assertRaises(RuntimeError):
                fixture.finish()

    def test_hanging_process_is_terminated_and_reader_joined(self):
        fixture = self.launch("import time; print('WAITING'); time.sleep(60)")
        self.assertEqual(fixture.event(5), "WAITING")
        fixture.close()
        self.assertIsNotNone(fixture.process.poll())
        self.assertFalse(fixture.reader.is_alive())

    def test_expected_exit_one_must_be_explicit_and_other_exits_still_fail(self):
        fixture = self.launch("import sys; print('REJECTED COMPARISON'); sys.exit(1)")
        self.assertEqual(fixture.event(5), "REJECTED COMPARISON")
        with self.assertRaises(RuntimeError):
            fixture.finish()
        fixture.finish(expected_exit=1)
        other = self.launch("import sys; print('REJECTED COMPARISON'); sys.exit(2)")
        self.assertEqual(other.event(5), "REJECTED COMPARISON")
        with self.assertRaises(RuntimeError):
            other.finish(expected_exit=1)


class ServerTests(unittest.TestCase):
    def test_loopback_token_and_bounded_ascii_before_controller(self):
        controller = interop.Controller(lambda pin: self.fail("Invalid request must not launch fixture"))
        with interop.ControlServer(controller) as server:
            self.assertEqual(server.server_address[0], "127.0.0.1")
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                requests = [b"wrong SELECT " + PIN.encode() + b"\n", b"x" * 257,
                            server.token.encode() + b" SELECT \xff\n"]
                for request in requests:
                    with socket.create_connection(server.server_address, timeout=5) as client:
                        client.sendall(request)
                        with client.makefile("rb") as response:
                            self.assertEqual(response.readline(257), b"ERROR\n")
                self.assertIsNone(controller.failure)
            finally:
                server.shutdown()
                worker.join(timeout=5)
            self.assertFalse(worker.is_alive())

    def test_valid_control_request_reaches_controller(self):
        fixture = FakeFixture()
        controller = interop.Controller(lambda pin: fixture)
        self.addCleanup(controller.close)
        with interop.ControlServer(controller) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                with socket.create_connection(server.server_address, timeout=5) as client:
                    client.sendall((server.token + " SELECT " + PIN + "\n").encode())
                    with client.makefile("rb") as response:
                        self.assertEqual(response.readline(257).decode(), ENDPOINT + "\n")
                self.assertEqual(controller.phase, "COMPARE")
            finally:
                server.shutdown()
                worker.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
