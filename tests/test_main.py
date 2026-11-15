import unittest
from unittest import mock

import main
from tests.helpers import TempDatabaseTestCase

IP_RANGE = "192.168.1.0/24"
DEVICE = {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01", "vendor": "V"}


class RunRoundTests(TempDatabaseTestCase):
    """run_round with the network and notifications replaced by fakes."""

    def setUp(self):
        super().setUp()
        self.devices = [DEVICE]
        self.ports = []
        self.alerts = []
        self.port_scans = []

        def fake_scan_ports(ip):
            self.port_scans.append(ip)
            return self.ports

        for name, value in {
            "scan": lambda ip_range: self.devices,
            "scan_device": fake_scan_ports,
            "send_notification": lambda title, message: self.alerts.append((title, message)),
            "last_port_scan": {},
        }.items():
            patcher = mock.patch.object(main, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_silent_first_round_does_not_alert(self):
        main.run_round(IP_RANGE, silent=True)
        self.assertEqual(self.alerts, [])

    def test_new_device_triggers_alert(self):
        main.run_round(IP_RANGE, silent=False)
        self.assertEqual(len(self.alerts), 1)
        self.assertIn("New device", self.alerts[0][0])

    def test_known_device_does_not_alert_again(self):
        main.run_round(IP_RANGE, silent=False)
        main.run_round(IP_RANGE, silent=False)
        self.assertEqual(len(self.alerts), 1)

    def test_new_port_alert_only_after_baseline(self):
        self.ports = [(22, "ssh")]
        main.run_round(IP_RANGE, silent=True)  # baseline scan
        self.assertEqual(self.alerts, [])

        self.ports = [(22, "ssh"), (23, "telnet")]
        with mock.patch.object(main, "PORT_RESCAN_INTERVAL", 0):  # rescan right away
            main.run_round(IP_RANGE, silent=False)

        self.assertEqual(len(self.alerts), 1)
        self.assertIn("23/telnet", self.alerts[0][1])
        self.assertIn("risky", self.alerts[0][1])

    def test_trusted_device_mutes_ordinary_port_alerts_but_not_risky_ones(self):
        import db
        self.ports = [(22, "ssh")]
        main.run_round(IP_RANGE, silent=True)
        db.update_device(DEVICE["mac"], "NAS", True)
        self.ports = [(22, "ssh"), (8080, "http-alt")]
        with mock.patch.object(main, "PORT_RESCAN_INTERVAL", 0), mock.patch("builtins.print"):
            main.run_round(IP_RANGE, silent=False)
        self.assertEqual(self.alerts, [], "ordinary port on a trusted device: logged, not pushed")
        self.ports = [(22, "ssh"), (8080, "http-alt"), (23, "telnet")]
        with mock.patch.object(main, "PORT_RESCAN_INTERVAL", 0), mock.patch("builtins.print"):
            main.run_round(IP_RANGE, silent=False)
        self.assertEqual(len(self.alerts), 1)
        self.assertIn("23/telnet", self.alerts[0][1])
        events = [e for e in db.get_events() if e["kind"] == "port_opened"]
        self.assertEqual(len(events), 2, "both ports are in the event log")

    def test_ports_not_rescanned_before_interval(self):
        main.run_round(IP_RANGE, silent=True)
        main.run_round(IP_RANGE, silent=True)
        self.assertEqual(len(self.port_scans), 1)


if __name__ == "__main__":
    unittest.main()


class RawPermissionTest(unittest.TestCase):
    """main.py asks the kernel for a raw socket instead of checking for uid 0, so the
    Docker image can run it as a normal user with only CAP_NET_RAW."""

    def test_permission_error_means_no(self):
        with mock.patch("socket.socket", side_effect=PermissionError):
            self.assertFalse(main.can_send_raw_packets())

    def test_a_raw_socket_means_yes(self):
        fake = mock.MagicMock()
        with mock.patch("socket.socket", return_value=fake) as sock:
            self.assertTrue(main.can_send_raw_packets())
        sock.assert_called_once()
        fake.close.assert_called_once()

    def test_refuses_to_start_without_it(self):
        with mock.patch.object(main, "can_send_raw_packets", return_value=False), \
                mock.patch.object(main, "create_tables") as tables, \
                mock.patch("sys.stderr"):
            self.assertEqual(main.main(["--once"]), 1)
        tables.assert_not_called()


class JanusEngineTest(unittest.TestCase):
    """The optional Janus engine, with a fake janus executable."""

    def setUp(self):
        import os
        import stat
        import tempfile
        import portscan
        self.portscan = portscan
        portscan._janus_failed = False
        self.dir = tempfile.mkdtemp()
        self.bin = os.path.join(self.dir, "janus")
        self.args = os.path.join(self.dir, "args")
        report = (
            '{"scanner":"janus","hosts":[{"ip":"192.0.2.5","open_ports":['
            '{"port":2222,"service":"unknown","detected":{"service":"ssh","product":"OpenSSH","version":"9.6p1",'
            '"info":"Ubuntu-3ubuntu13"}},'
            '{"port":80,"service":"http","detected":{"service":"http","product":"nginx","version":"1.27.0\\u001b[31m"}},'
            '{"port":99999},"junk"]}]}'
        )
        with open(self.bin, "w") as f:
            f.write(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {self.args}\ncat <<'JSON'\n{report}\nJSON\n")
        os.chmod(self.bin, os.stat(self.bin).st_mode | stat.S_IEXEC)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir)
        self.portscan._janus_failed = False

    def env(self, **values):
        return mock.patch.dict("os.environ", {f"LYNCEUS_{k}": v for k, v in values.items()})

    def test_janus_results_with_versions(self):
        with self.env(JANUS=self.bin):
            got = self.portscan.scan_device("192.0.2.5", ports=[22, 80, 2222])
        self.assertEqual(got[0], (80, "http", "nginx 1.27.0?[31m"))   # escape codes neutralised
        self.assertEqual(got[1], (2222, "ssh", "OpenSSH 9.6p1 (Ubuntu-3ubuntu13)"))
        with open(self.args) as f:
            argv = f.read().split()
        self.assertEqual(argv[:4], ["-t", "192.0.2.5", "-p", "22,80,2222"])
        self.assertIn("--sv", argv)

    def test_only_an_ip_reaches_the_command_line(self):
        with self.assertRaises(ValueError):
            self.portscan.scan_ports_janus("192.0.2.5; rm -rf /", self.bin)

    def test_builtin_when_disabled_or_broken(self):
        builtin = [(22, "ssh")]
        with self.env(JANUS=self.bin, ENGINE="builtin"), \
                mock.patch.object(self.portscan, "scan_ports", return_value=builtin):
            self.assertEqual(self.portscan.scan_device("192.0.2.5"), [(22, "ssh", "")])
        with open(self.bin, "w") as f:
            f.write("#!/bin/sh\necho boom >&2\nexit 1\n")
        with self.env(JANUS=self.bin), mock.patch.object(self.portscan, "scan_ports", return_value=builtin), \
                mock.patch("builtins.print"):
            self.assertEqual(self.portscan.scan_device("192.0.2.5"), [(22, "ssh", "")])
            self.assertTrue(self.portscan._janus_failed, "fell back for the rest of the run")


class VersionColumnTest(TempDatabaseTestCase):
    def test_versions_are_stored_and_old_tuples_still_work(self):
        import db
        db.save_ports("aa:bb:cc:dd:ee:ff", [(22, "ssh", "OpenSSH 9.6p1"), (80, "http")], ip="192.0.2.5")
        ports = db.get_all_ports()["aa:bb:cc:dd:ee:ff"]
        self.assertEqual([(p["port"], p["version"]) for p in ports], [(22, "OpenSSH 9.6p1"), (80, "")])
