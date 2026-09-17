"""Regressions for the collector/Rspamd/upgrade integration defects.

Each test here corresponds to a defect found by reading the code rather than
by running it, so they are written to fail loudly if the behaviour returns.
"""

import json
import os
import types
from pathlib import Path

from helpers import FIXTURES, MailutTestCase

from mailut import collector
from mailut import scopes as scope_store
from mailut.config import Config
from mailut.mailu import ENV_BRIDGE_GATEWAYS, ENV_SMTP_LOG, Mailu
from mailut.util import MailutError, classify_bind_address


class _CollectArgs:
    verbose = False
    once = True
    no_log_poll = False
    allow_remote = False


class _FakeServer:
    """Stands in for the HTTP listener in tests about the startup guards.

    Guard tests must not be able to reach serve_forever: if a guard regresses,
    the test should fail in milliseconds, not block the suite forever waiting
    on a socket. It also lets them use addresses that do not exist on the test
    host, such as the documented 172.17.0.1.
    """

    instances: list = []

    def __init__(self, address, ingestor, max_body_bytes, token=None):
        self.address = address
        self.token = token
        _FakeServer.instances.append(self)

    def serve_forever(self, poll_interval=0.5):
        return None

    def server_close(self):
        return None


def _no_listener(test):
    """Replace the collector's server for the duration of one test."""
    _FakeServer.instances = []
    real = collector._Server
    collector._Server = _FakeServer
    test.addCleanup(setattr, collector, "_Server", real)
    return _FakeServer.instances


class BindAddressTests(MailutTestCase):
    """The collector must permit the documented Docker-bridge setup.

    Binding to the bridge gateway is how the antispam container reaches the
    host; refusing it made docs/install.md's own instructions unusable, because
    mailut-audit.service runs `audit collect` with no --allow-remote.

    But "private" is NOT the same as "Docker-local": a host's LAN or VPC
    address is private too, and binding the port to it exposes it to every
    machine on that network. Nor is "some Docker network has this gateway"
    enough -- a macvlan gateway is typically the real upstream router, and an
    unrelated project's bridge is not reachable from Mailu at all. Safety means
    the gateway of a bridge network the antispam container is attached to.
    """

    def setUp(self):
        super().setUp()
        # No Docker in the test environment: state explicitly what it would
        # report, so each case is deterministic.
        os.environ[ENV_BRIDGE_GATEWAYS] = "172.17.0.1,172.18.0.1"
        self.addCleanup(os.environ.pop, ENV_BRIDGE_GATEWAYS, None)

    def test_classification(self):
        for address, expected in (
            ("127.0.0.1", "loopback"),
            ("::1", "loopback"),
            ("localhost", "loopback"),
            ("172.17.0.1", "private"),
            ("192.168.1.10", "private"),
            ("10.1.2.3", "private"),
            ("0.0.0.0", "wildcard"),
            ("::", "wildcard"),
            ("", "wildcard"),
            ("8.8.8.8", "public"),
            ("mail.example.com", "unknown"),
        ):
            self.assertEqual(classify_bind_address(address), expected, address)

    def _collect(self, bind, **overrides):
        """Run cmd_collect far enough to exercise the bind guard.

        `once` is False because the guard only applies when an HTTP listener
        will be opened; the run stops at the token check, which is what these
        tests use as the "got past the bind guard" marker.
        """
        import logging

        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        path = self.tmp / "bind.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n"
            f"[collector]\nbind = {bind}\nport = 18999\ningest_smtp_logs = false\n"
            f"allow_unauthenticated = true\n",
            encoding="utf-8",
        )
        args = _CollectArgs()
        args.once = False
        for key, value in overrides.items():
            setattr(args, key, value)
        _no_listener(self)
        return collector.cmd_collect(args, Config.load(path))

    def test_bridge_gateway_bind_is_accepted(self):
        """The documented Linux setup must not refuse to start."""
        self.assertEqual(self._collect("172.17.0.1"), 0)

    def test_any_attached_bridge_gateway_is_accepted_not_just_docker0(self):
        self.assertEqual(self._collect("172.18.0.1"), 0)

    def test_loopback_bind_is_accepted(self):
        self.assertEqual(self._collect("127.0.0.1"), 0)

    def test_lan_address_is_refused_even_though_it_is_private(self):
        """The regression: RFC 1918 was treated as proof of being host-local."""
        for address in ("192.168.1.20", "10.0.1.15", "172.20.10.5"):
            with self.assertRaises(MailutError, msg=address) as caught:
                self._collect(address)
            self.assertIn("refusing to bind", str(caught.exception))
            self.assertIn("not the gateway of a Docker bridge network", str(caught.exception))

    def test_unverifiable_address_is_refused(self):
        """If Docker cannot be queried, we must not assume the address is safe."""
        os.environ.pop(ENV_BRIDGE_GATEWAYS, None)
        with self.assertRaises(MailutError) as caught:
            self._collect("192.168.1.20")
        self.assertIn("refusing to bind", str(caught.exception))

    def test_assessment_reports_the_reason(self):
        from mailut import collector as collector_mod
        from mailut.config import Config

        path = self.tmp / "assess.conf"
        for address, category, safe in (
            ("127.0.0.1", "loopback", True),
            ("172.17.0.1", "bridge-gateway", True),
            ("192.168.1.20", "unverified", False),
            ("0.0.0.0", "wildcard", False),
            ("8.8.8.8", "public", False),
        ):
            path.write_text(
                f"[storage]\nstate_dir = {self.state_dir}\n[collector]\nbind = {address}\n",
                encoding="utf-8",
            )
            verdict = collector_mod.assess_bind(Config.load(path))
            self.assertEqual(verdict["category"], category, address)
            self.assertEqual(verdict["safe"], safe, address)

    def test_wildcard_bind_is_refused(self):
        with self.assertRaises(MailutError) as caught:
            self._collect("0.0.0.0")
        self.assertIn("refusing to bind", str(caught.exception))

    def test_public_bind_is_refused(self):
        with self.assertRaises(MailutError) as caught:
            self._collect("8.8.8.8")
        self.assertIn("refusing to bind", str(caught.exception))

    def test_allow_remote_overrides_the_refusal(self):
        self.assertEqual(self._collect("0.0.0.0", allow_remote=True), 0)
        self.assertEqual(self._collect("192.168.1.20", allow_remote=True), 0)

    def test_the_shipped_exporter_and_docs_agree(self):
        """The example URL and the documented bind must be the same address."""
        from helpers import ROOT

        snippet = (ROOT / "share" / "rspamd" / "mailut-exporter.conf").read_text()
        install_doc = (ROOT / "docs" / "install.md").read_text()
        self.assertIn("172.17.0.1:8765", snippet)
        self.assertIn("bind = 172.17.0.1", install_doc)
        self.assertIn("172.17.0.1:8765", install_doc)
        # And the collector must actually start on that address.  Being
        # private is not what makes it acceptable -- it is acceptable because
        # Docker reports it as a bridge gateway, which this fixture says it is.
        self.assertEqual(self._collect("172.17.0.1"), 0)


class IPv6Tests(MailutTestCase):
    """An IPv6 bind must actually work, not merely pass the safety check.

    assess_bind() approves IPv6 loopback and IPv6 bridge gateways, but
    ThreadingHTTPServer creates an AF_INET socket, so binding one used to fail
    at the socket; and every URL was built as host:port, which is unparseable
    for an IPv6 literal -- it needs [host]:port.
    """

    def _conf(self, bind, port=18993):
        path = self.tmp / "v6.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n"
            f"[collector]\nbind = {bind}\nport = {port}\nallow_unauthenticated = true\n",
            encoding="utf-8")
        return Config.load(path)

    def test_url_host_brackets_ipv6_literals(self):
        from mailut.util import url_host

        self.assertEqual(url_host("::1"), "[::1]")
        self.assertEqual(url_host("fd00::1"), "[fd00::1]")
        self.assertEqual(url_host("127.0.0.1"), "127.0.0.1")
        self.assertEqual(url_host("host.docker.internal"), "host.docker.internal")
        self.assertEqual(url_host("[::1]"), "[::1]")

    def test_addresses_compare_by_value_not_by_spelling(self):
        from mailut.util import same_address

        self.assertTrue(same_address("fd00::1", "fd00:0:0:0:0:0:0:1"))
        self.assertTrue(same_address("127.0.0.1", "127.0.0.1"))
        self.assertFalse(same_address("fd00::1", "fd00::2"))
        self.assertFalse(same_address("example.com", "example.com"))

    def test_a_wildcard_bind_probes_loopback_of_the_right_family(self):
        self.assertEqual(collector.local_host_for("0.0.0.0"), "127.0.0.1")
        self.assertEqual(collector.local_host_for("::"), "::1")
        self.assertEqual(collector.local_host_for("fd00::1"), "fd00::1")

    def test_an_ipv6_gateway_is_recognised_however_it_is_written(self):
        os.environ[ENV_BRIDGE_GATEWAYS] = "fd00:0:0:0:0:0:0:1"
        self.addCleanup(os.environ.pop, ENV_BRIDGE_GATEWAYS, None)
        verdict = collector.assess_bind(self._conf("fd00::1"))
        self.assertEqual(verdict["category"], "bridge-gateway")
        self.assertTrue(verdict["safe"])

    def _family_for(self, address):
        """The socket family _Server picks, without needing that family to work.

        Many CI containers have no IPv6 at all, so this intercepts the socket
        creation rather than binding: what matters is that the family is chosen
        before the socket is made, which is the bug being guarded against.
        """
        import socketserver

        captured = {}
        real_init = socketserver.TCPServer.__init__

        def fake_init(self, server_address, handler, bind_and_activate=True):
            captured["family"] = self.address_family
            self.server_address = server_address

        socketserver.TCPServer.__init__ = fake_init
        self.addCleanup(setattr, socketserver.TCPServer, "__init__", real_init)
        ingestor = collector.Ingestor(self._conf("127.0.0.1"))
        self.addCleanup(ingestor.close)
        collector._Server((address, 18993), ingestor, 1048576, None)
        return captured["family"]

    def test_an_ipv6_bind_selects_an_ipv6_socket(self):
        import socket

        self.assertEqual(self._family_for("::1"), socket.AF_INET6)
        self.assertEqual(self._family_for("fd00::1"), socket.AF_INET6)

    def test_an_ipv4_bind_still_selects_ipv4(self):
        import socket

        self.assertEqual(self._family_for("127.0.0.1"), socket.AF_INET)
        self.assertEqual(self._family_for("172.17.0.1"), socket.AF_INET)

    def test_an_ipv6_collector_answers(self):
        """End to end: bind, then reach it at a URL built from that address."""
        import threading
        import urllib.request

        from mailut.util import url_host

        config = self._conf("::1")
        ingestor = collector.Ingestor(config)
        self.addCleanup(ingestor.close)
        try:
            server = collector._Server(("::1", 0), ingestor, 1048576, None)
        except OSError as exc:  # pragma: no cover - host without IPv6
            self.skipTest(f"no IPv6 on this host: {exc}")
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)

        port = server.server_address[1]
        url = f"http://{url_host('::1')}:{port}/health"
        self.assertIn("[::1]", url)
        with urllib.request.urlopen(url, timeout=10) as response:
            self.assertEqual(json.loads(response.read().decode())["status"], "ok")

    def test_the_doctor_probe_brackets_an_ipv6_exporter_url(self):
        from mailut import status

        override = self.compose_dir / "overrides" / "rspamd"
        override.mkdir(parents=True)
        (override / "mailut-exporter.conf").write_text(
            'metadata_exporter { rules { mailut { url = "http://[fd00::1]:18765/rspamd"; } } }',
            encoding="utf-8")
        path = self.tmp / "v6doctor.conf"
        path.write_text(
            f"[mailu]\ncompose_dir = {self.compose_dir}\ncompose_command = /bin/false\n"
            f"[storage]\nstate_dir = {self.state_dir}\n"
            f"[collector]\nbind = fd00::1\nport = 18765\nallow_unauthenticated = true\n",
            encoding="utf-8")
        os.environ[ENV_BRIDGE_GATEWAYS] = "fd00::1"
        self.addCleanup(os.environ.pop, ENV_BRIDGE_GATEWAYS, None)

        probed = []
        real = Mailu.probe_url_from_service
        Mailu.probe_url_from_service = lambda self, service, url, **kw: (
            probed.append(url), (True, "ok"))[1]
        self.addCleanup(setattr, Mailu, "probe_url_from_service", real)

        checks = {c["check"]: c for c in status.collect_checks(Config.load(path))}
        self.assertEqual(checks["rspamd exporter"]["status"], "ok",
                         checks["rspamd exporter"]["detail"])
        self.assertEqual(probed, ["http://[fd00::1]:18765/health"])


class BridgeGatewayDiscoveryTests(MailutTestCase):
    """Only bridge networks attached to antispam may authorise a bind address.

    The first version of this rule collected the gateway of *every* Docker
    network on the machine. Two things are wrong with that:

      * Driver. Docker's macvlan and ipvlan drivers attach containers straight
        to the physical network, and the configured gateway is normally the
        real upstream router (Docker's own documentation uses examples such as
        ``--gateway=192.168.32.254``). Docker also does not install the
        packet-filtering rules for them that it installs for bridge networks.
        Treating such a gateway as host-local is exactly backwards.
      * Attachment. The gateway of an unrelated Docker project is not reachable
        from the antispam container, so approving it yields a collector that
        Rspamd can never post to.
    """

    def _mailu(self, inspect_output, networks=("mailu_default",)):
        config = Config.load(self._conf())
        mailu = Mailu(config)
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return types.SimpleNamespace(returncode=0, stdout=inspect_output, stderr="")

        mailu.service_networks = lambda service: (set(networks), None)
        import mailut.mailu as mailu_mod

        real = mailu_mod.subprocess.run
        mailu_mod.subprocess.run = fake_run
        self.addCleanup(setattr, mailu_mod.subprocess, "run", real)
        return mailu, calls

    def _conf(self):
        path = self.tmp / "gw.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n[collector]\nbind = 127.0.0.1\n",
            encoding="utf-8",
        )
        return path

    def setUp(self):
        super().setUp()
        os.environ.pop(ENV_BRIDGE_GATEWAYS, None)

    def test_bridge_gateways_are_collected(self):
        mailu, _ = self._mailu("bridge 172.18.0.1\n")
        gateways, error = mailu.service_bridge_gateways("antispam")
        self.assertIsNone(error)
        self.assertEqual(gateways, {"172.18.0.1"})

    def test_macvlan_gateway_is_ignored(self):
        """A macvlan gateway is usually the LAN router, not a host-local address."""
        mailu, _ = self._mailu("macvlan 192.168.32.254\n")
        gateways, error = mailu.service_bridge_gateways("antispam")
        self.assertIsNone(error)
        self.assertEqual(gateways, set())

    def test_ipvlan_and_overlay_gateways_are_ignored(self):
        mailu, _ = self._mailu("ipvlan 192.168.40.1\noverlay 10.10.0.1\n")
        gateways, _ = mailu.service_bridge_gateways("antispam")
        self.assertEqual(gateways, set())

    def test_only_the_bridge_survives_a_mixed_listing(self):
        mailu, _ = self._mailu("macvlan 192.168.32.254\nbridge 172.18.0.1\n")
        gateways, _ = mailu.service_bridge_gateways("antispam")
        self.assertEqual(gateways, {"172.18.0.1"})

    def test_only_attached_networks_are_inspected(self):
        """An unrelated project's bridge must never be queried, let alone trusted."""
        mailu, calls = self._mailu("bridge 172.18.0.1\n", networks=("mailu_default",))
        mailu.service_bridge_gateways("antispam")
        self.assertEqual(len(calls), 1)
        self.assertIn("mailu_default", calls[0])
        self.assertNotIn("some_other_project_default", calls[0])

    def test_a_macvlan_lan_gateway_does_not_authorise_a_bind(self):
        """End to end: the exact shape of the reported defect."""
        import logging

        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        path = self.tmp / "macvlan.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n"
            f"[collector]\nbind = 192.168.32.254\nport = 18997\ningest_smtp_logs = false\n",
            encoding="utf-8",
        )
        config = Config.load(path)
        mailu = Mailu(config)
        mailu.service_networks = lambda service: ({"lan"}, None)
        import mailut.mailu as mailu_mod

        real = mailu_mod.subprocess.run
        mailu_mod.subprocess.run = lambda argv, **kw: types.SimpleNamespace(
            returncode=0, stdout="macvlan 192.168.32.254\n", stderr="")
        self.addCleanup(setattr, mailu_mod.subprocess, "run", real)

        verdict = collector.assess_bind(config, mailu)
        self.assertFalse(verdict["safe"])
        self.assertIn("bridge network", verdict["detail"])

    def test_discovery_failure_is_an_error_not_an_empty_answer(self):
        """"Cannot ask Docker" must not be reported as "no such gateway"."""
        config = Config.load(self._conf())
        mailu = Mailu(config)
        mailu.service_networks = lambda service: (set(), "no running container for the antispam service")
        gateways, error = mailu.service_bridge_gateways("antispam")
        self.assertEqual(gateways, set())
        self.assertIn("no running container", error)


class CollectorAuthTests(MailutTestCase):
    """Ingestion must be authenticated, so evidence cannot be fabricated.

    Reaching the right bridge network is a network-layer restriction: any other
    container on it could still POST invented audit records. For a store whose
    whole purpose is forensic evidence, that is the wrong default.
    """

    def _conf(self, token_file=None, **extra):
        path = self.tmp / "auth.conf"
        body = f"[storage]\nstate_dir = {self.state_dir}\n[collector]\nbind = 127.0.0.1\n"
        if token_file is not None:
            body += f"token_file = {token_file}\n"
        for key, value in extra.items():
            body += f"{key} = {value}\n"
        path.write_text(body, encoding="utf-8")
        return Config.load(path)

    def _token_file(self, content, mode=0o600):
        path = self.tmp / "collector.token"
        path.write_text(content, encoding="utf-8")
        path.chmod(mode)
        return path

    # -- reading the token ---------------------------------------------------
    def test_authentication_is_on_by_default(self):
        """The regression: an unset token_file used to mean "accept anything".

        A default installation must not have an open ingestion endpoint just
        because nobody filled in a setting.

        Only that it refuses is asserted here: with no token_file set this
        resolves to the real /etc/mailut/collector.token, and the exact error
        depends on whether that path is absent or merely unreadable by the user
        running the tests. The wording is asserted below, on a path we own.
        """
        with self.assertRaises(MailutError):
            collector.read_token(self._conf())

    def test_opting_out_is_explicit(self):
        self.assertIsNone(collector.read_token(self._conf(allow_unauthenticated="true")))

    def test_the_default_token_path_is_under_the_config_directory(self):
        from mailut import release

        config = self._conf()
        self.assertEqual(
            config.token_file,
            Path(release.layout()["confdir"]) / "collector.token",
        )

    def test_token_is_read(self):
        path = self._token_file("a" * 64)
        self.assertEqual(collector.read_token(self._conf(path)), "a" * 64)

    def test_a_world_readable_token_is_refused(self):
        """A secret any local account can read is not a secret."""
        path = self._token_file("a" * 64, mode=0o644)
        with self.assertRaises(MailutError) as caught:
            collector.read_token(self._conf(path))
        self.assertIn("readable by other accounts", str(caught.exception))

    def test_a_group_readable_token_is_refused(self):
        path = self._token_file("a" * 64, mode=0o640)
        with self.assertRaises(MailutError):
            collector.read_token(self._conf(path))

    def test_an_empty_token_is_refused(self):
        path = self._token_file("\n")
        with self.assertRaises(MailutError) as caught:
            collector.read_token(self._conf(path))
        self.assertIn("empty", str(caught.exception))

    def test_a_short_token_is_refused(self):
        path = self._token_file("hunter2")
        with self.assertRaises(MailutError) as caught:
            collector.read_token(self._conf(path))
        self.assertIn("at least", str(caught.exception))

    def test_a_missing_token_file_is_an_error_not_an_open_endpoint(self):
        with self.assertRaises(MailutError) as caught:
            collector.read_token(self._conf(self.tmp / "absent.token"))
        message = str(caught.exception)
        self.assertIn("no collector token", message)
        self.assertIn("mailut audit token generate", message)

    def test_token_file_must_be_absolute(self):
        path = self.tmp / "rel.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n"
            "[collector]\ntoken_file = collector.token\n", encoding="utf-8")
        with self.assertRaises(MailutError) as caught:
            Config.load(path)
        self.assertIn("absolute", str(caught.exception))

    def test_collect_refuses_to_start_with_an_unusable_token_file(self):
        """Failing closed: never fall back to accepting everything."""
        import logging

        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        path = self._token_file("a" * 64, mode=0o644)
        args = _CollectArgs()
        args.once = False
        started = _no_listener(self)
        with self.assertRaises(MailutError):
            collector.cmd_collect(args, self._conf(path, port=18996, ingest_smtp_logs="false"))
        self.assertEqual(started, [], "the listener must never be created")

    def test_collect_refuses_to_start_with_no_token_at_all(self):
        """The regression: a default install used to serve without a token."""
        import logging

        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        args = _CollectArgs()
        args.once = False
        started = _no_listener(self)
        config = self._conf(self.tmp / "absent.token", port=18995, ingest_smtp_logs="false")
        with self.assertRaises(MailutError) as caught:
            collector.cmd_collect(args, config)
        self.assertIn("no collector token", str(caught.exception))
        self.assertEqual(started, [], "the listener must never be created")

    def test_an_unconfigured_install_refuses_too(self):
        """No token_file line at all: the default path, not "no auth"."""
        import logging

        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        args = _CollectArgs()
        args.once = False
        started = _no_listener(self)
        path = self.tmp / "bare.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n"
            f"[collector]\nbind = 127.0.0.1\nport = 18994\ningest_smtp_logs = false\n",
            encoding="utf-8")
        with self.assertRaises(MailutError):
            collector.cmd_collect(args, Config.load(path))
        self.assertEqual(started, [])

    # -- reading the Authorization header ------------------------------------
    def test_bearer_scheme(self):
        self.assertEqual(collector.presented_token("Bearer sekrit"), "sekrit")

    def test_basic_scheme_carries_the_token_as_the_password(self):
        """What Rspamd's metadata_exporter can actually send.

        Its http backend builds the header from the rule's user/password and
        offers no way to set an arbitrary one, so Basic is the only scheme it
        can speak. The username is not a secret.
        """
        import base64

        header = "Basic " + base64.b64encode(b"mailut:sekrit").decode()
        self.assertEqual(collector.presented_token(header), "sekrit")

    def test_a_password_may_contain_a_colon(self):
        import base64

        header = "Basic " + base64.b64encode(b"mailut:a:b:c").decode()
        self.assertEqual(collector.presented_token(header), "a:b:c")

    def test_schemes_are_case_insensitive(self):
        self.assertEqual(collector.presented_token("bearer sekrit"), "sekrit")

    def test_unusable_headers_yield_no_token(self):
        for header in (None, "", "Bearer", "Bearer   ", "Digest xyz",
                       "Basic !!!not-base64!!!", "Basic " + "bm9jb2xvbg=="):
            self.assertIsNone(collector.presented_token(header), repr(header))

    # -- the endpoint itself -------------------------------------------------
    def _serve(self, token):
        import logging
        import threading

        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        ingestor = collector.Ingestor(self._conf())
        self.addCleanup(ingestor.close)
        server = collector._Server(("127.0.0.1", 0), ingestor, 1048576, token)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                                  daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def _post(self, base, headers=None):
        import urllib.error
        import urllib.request

        payload = json.dumps({"timestamp": 1758000000, "from": "a@example.net",
                              "rcpt": ["b@example.com"], "action": "reject"}).encode()
        request = urllib.request.Request(f"{base}/rspamd", data=payload,
                                         headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def test_ingestion_without_a_token_is_rejected(self):
        base = self._serve("s" * 32)
        self.assertEqual(self._post(base), 401)

    def test_ingestion_with_a_wrong_token_is_rejected(self):
        base = self._serve("s" * 32)
        self.assertEqual(self._post(base, {"Authorization": "Bearer wrong"}), 401)

    def test_ingestion_with_the_bearer_token_is_accepted(self):
        base = self._serve("s" * 32)
        self.assertEqual(self._post(base, {"Authorization": "Bearer " + "s" * 32}), 200)

    def test_ingestion_with_basic_credentials_is_accepted(self):
        import base64

        base = self._serve("s" * 32)
        header = "Basic " + base64.b64encode(b"mailut:" + b"s" * 32).decode()
        self.assertEqual(self._post(base, {"Authorization": header}), 200)

    def test_ingestion_is_open_when_no_token_is_configured(self):
        base = self._serve(None)
        self.assertEqual(self._post(base), 200)

    def test_a_rejected_post_stores_nothing(self):
        scope_store.upsert_scope(
            self.db(), scope_type="all", value="*", mode="include", level="metadata",
            retention_days=30, message_retention_days=None,
        )
        base = self._serve("s" * 32)
        self.assertEqual(self._post(base), 401)
        count = self.db().execute("SELECT count(*) AS n FROM audit_events").fetchone()["n"]
        self.assertEqual(count, 0)

    def test_health_stays_open_so_wiring_can_be_checked(self):
        import urllib.request

        base = self._serve("s" * 32)
        with urllib.request.urlopen(f"{base}/health", timeout=10) as response:
            payload = json.loads(response.read().decode())
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["auth"])

    def test_health_withholds_counters_from_unauthenticated_callers(self):
        import urllib.request

        base = self._serve("s" * 32)
        with urllib.request.urlopen(f"{base}/health", timeout=10) as response:
            self.assertNotIn("stats", json.loads(response.read().decode()))
        request = urllib.request.Request(
            f"{base}/health", headers={"Authorization": "Bearer " + "s" * 32})
        with urllib.request.urlopen(request, timeout=10) as response:
            self.assertIn("stats", json.loads(response.read().decode()))

    def test_the_shipped_exporter_snippet_sends_credentials(self):
        from helpers import ROOT

        snippet = (ROOT / "share" / "rspamd" / "mailut-exporter.conf").read_text()
        self.assertIn("user = ", snippet)
        self.assertIn("password = ", snippet)


class TokenCommandTests(MailutTestCase):
    """`mailut audit token generate` must be the easy path.

    Authentication is only secure-by-default if creating a token is one
    command; otherwise the documented `umask 077 && openssl rand` incantation
    is what gets skipped, and allow_unauthenticated is what gets set.
    """

    class _Args:
        force = False
        if_missing = False

    def _conf(self):
        path = self.tmp / "token.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n"
            f"[collector]\ntoken_file = {self.tmp / 'sub' / 'collector.token'}\n",
            encoding="utf-8")
        return Config.load(path)

    def _generate(self, **overrides):
        from mailut import tokencmd

        args = self._Args()
        for key, value in overrides.items():
            setattr(args, key, value)
        config = self._conf()
        return tokencmd.cmd_generate(args, config), config

    def test_generate_creates_a_usable_token(self):
        code, config = self._generate()
        self.assertEqual(code, 0)
        self.assertEqual(collector.read_token(config), config.token_file.read_text().strip())

    def test_the_token_is_private_from_the_start(self):
        _, config = self._generate()
        self.assertEqual(config.token_file.stat().st_mode & 0o777, 0o600)

    def test_the_parent_directory_is_created(self):
        _, config = self._generate()
        self.assertTrue(config.token_file.parent.is_dir())

    def test_tokens_are_random(self):
        _, config = self._generate()
        first = config.token_file.read_text()
        self._generate(force=True)
        self.assertNotEqual(first, config.token_file.read_text())

    def test_an_existing_token_is_never_replaced_silently(self):
        from mailut.util import UsageError

        _, config = self._generate()
        original = config.token_file.read_text()
        with self.assertRaises(UsageError) as caught:
            self._generate()
        self.assertIn("already exists", str(caught.exception))
        self.assertEqual(config.token_file.read_text(), original)

    def test_if_missing_leaves_an_existing_token_alone(self):
        """What `make enable` runs: never disturb a working installation."""
        _, config = self._generate()
        original = config.token_file.read_text()
        code, _ = self._generate(if_missing=True)
        self.assertEqual(code, 0)
        self.assertEqual(config.token_file.read_text(), original)

    def test_if_missing_creates_one_when_absent(self):
        code, config = self._generate(if_missing=True)
        self.assertEqual(code, 0)
        self.assertTrue(config.token_file.exists())

    def test_force_replaces_and_keeps_the_mode(self):
        _, config = self._generate()
        config.token_file.chmod(0o644)
        self._generate(force=True)
        self.assertEqual(config.token_file.stat().st_mode & 0o777, 0o600)
        collector.read_token(config)  # must not raise

    def test_show_prints_the_token(self):
        import contextlib
        import io

        from mailut import tokencmd

        _, config = self._generate()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            tokencmd.cmd_show(self._Args(), config)
        self.assertEqual(buffer.getvalue().strip(), config.token_file.read_text().strip())

    def test_show_without_a_token_explains_how_to_make_one(self):
        from mailut import tokencmd

        with self.assertRaises(MailutError) as caught:
            tokencmd.cmd_show(self._Args(), self._conf())
        self.assertIn("mailut audit token generate", str(caught.exception))

    def test_the_generated_token_is_accepted_over_http(self):
        """The whole loop: generate, serve, authenticate."""
        import base64
        import logging
        import threading
        import urllib.error
        import urllib.request

        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        _, config = self._generate()
        token = collector.read_token(config)
        ingestor = collector.Ingestor(config)
        self.addCleanup(ingestor.close)
        server = collector._Server(("127.0.0.1", 0), ingestor, 1048576, token)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)

        base = f"http://127.0.0.1:{server.server_address[1]}/rspamd"
        payload = json.dumps({"timestamp": 1758000000, "from": "a@example.net",
                              "rcpt": ["b@example.com"], "action": "reject"}).encode()

        def post(headers):
            request = urllib.request.Request(base, data=payload, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    return response.status
            except urllib.error.HTTPError as exc:
                return exc.code

        self.assertEqual(post({}), 401)
        header = "Basic " + base64.b64encode(f"mailut:{token}".encode()).decode()
        self.assertEqual(post({"Authorization": header}), 200)


class CollectOnceTests(MailutTestCase):
    """`--once` must poll exactly once and exit, not start a looping thread."""

    def setUp(self):
        super().setUp()
        import logging

        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        scope_store.upsert_scope(
            self.db(), scope_type="all", value="*", mode="include", level="metadata",
            retention_days=30, message_retention_days=None,
        )
        os.environ[ENV_SMTP_LOG] = str(FIXTURES / "smtp-inbound.log")
        self.addCleanup(os.environ.pop, ENV_SMTP_LOG, None)

    def test_once_polls_exactly_one_time(self):
        calls = []
        real_poll = collector.LogPoller.poll_once

        def counting_poll(self):
            calls.append(1)
            return real_poll(self)

        collector.LogPoller.poll_once = counting_poll
        self.addCleanup(setattr, collector.LogPoller, "poll_once", real_poll)

        args = _CollectArgs()
        # A short interval would have let the old implementation poll many
        # times inside its 30-second join().
        path = self.tmp / "once.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n"
            f"[collector]\nport = 18998\nlog_poll_seconds = 1\n",
            encoding="utf-8",
        )
        self.assertEqual(collector.cmd_collect(args, Config.load(path)), 0)
        self.assertEqual(len(calls), 1, f"expected one poll, got {len(calls)}")

    def test_once_returns_promptly(self):
        import time

        args = _CollectArgs()
        started = time.monotonic()
        self.assertEqual(collector.cmd_collect(args, self.config()), 0)
        elapsed = time.monotonic() - started
        # The old implementation joined a daemon thread for up to 30 seconds.
        self.assertLess(elapsed, 10, f"--once took {elapsed:.1f}s")

    def test_once_actually_ingests(self):
        collector.cmd_collect(_CollectArgs(), self.config())
        stored = self.db().execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"]
        self.assertGreaterEqual(stored, 5)

    def test_once_with_log_polling_disabled_does_nothing(self):
        args = _CollectArgs()
        args.no_log_poll = True
        self.assertEqual(collector.cmd_collect(args, self.config()), 0)
        stored = self.db().execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"]
        self.assertEqual(stored, 0)

    # -- --once must not be blocked by HTTP-only prerequisites ---------------
    #
    # It opens no socket, so neither the bind assessment nor the token is
    # relevant to it. Failing here would make the diagnostic command unusable
    # exactly when things are broken and it is most wanted.

    def _once(self, extra):
        path = self.tmp / "onceguard.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n[collector]\nport = 18994\n{extra}",
            encoding="utf-8",
        )
        return collector.cmd_collect(_CollectArgs(), Config.load(path))

    def test_once_works_without_a_token(self):
        self.assertEqual(self._once(f"token_file = {self.tmp / 'absent.token'}\n"), 0)
        stored = self.db().execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"]
        self.assertGreaterEqual(stored, 5)

    def test_once_works_with_an_unusable_token_file(self):
        token = self.tmp / "bad.token"
        token.write_text("a" * 64, encoding="utf-8")
        token.chmod(0o644)
        self.assertEqual(self._once(f"token_file = {token}\n"), 0)

    def test_once_works_when_the_bind_address_cannot_be_verified(self):
        """Docker down, antispam stopped: reading the smtp log still works."""
        os.environ.pop(ENV_BRIDGE_GATEWAYS, None)
        self.assertEqual(self._once("bind = 192.168.1.20\n"), 0)

    def test_once_works_with_a_bind_address_that_would_be_refused(self):
        self.assertEqual(self._once("bind = 8.8.8.8\n"), 0)

    def test_once_never_asks_docker_about_networks(self):
        """Not just tolerated -- the discovery must not even be attempted."""
        calls = []
        real = Mailu.service_bridge_gateways
        Mailu.service_bridge_gateways = lambda self, service: (calls.append(service), (set(), None))[1]
        self.addCleanup(setattr, Mailu, "service_bridge_gateways", real)
        self.assertEqual(self._once("bind = 172.17.0.1\n"), 0)
        self.assertEqual(calls, [])


class DoctorAuthTests(MailutTestCase):
    """doctor must report the authentication state, including a wrong password.

    The reachability probe cannot catch a credential mismatch: /health is open,
    so it answers happily while every real export is rejected with 401 and the
    audit trail quietly stays empty.
    """

    def _setup(self, *, token=None, exporter_password=..., url="http://172.17.0.1:18765/rspamd",
               allow_unauthenticated=False):
        override = self.compose_dir / "overrides" / "rspamd"
        override.mkdir(parents=True, exist_ok=True)
        rule = f'url = "{url}";'
        if exporter_password is not ...:
            rule += f' user = "mailut"; password = "{exporter_password}";'
        (override / "mailut-exporter.conf").write_text(
            "metadata_exporter { rules { mailut { " + rule + " } } }", encoding="utf-8")
        body = (
            f"[mailu]\ncompose_dir = {self.compose_dir}\ncompose_command = /bin/false\n"
            f"[storage]\nstate_dir = {self.state_dir}\n"
            f"[collector]\nbind = 172.17.0.1\nport = 18765\n"
        )
        if token is not None:
            token_path = self.tmp / "collector.token"
            token_path.write_text(token, encoding="utf-8")
            token_path.chmod(0o600)
            body += f"token_file = {token_path}\n"
        else:
            body += f"token_file = {self.tmp / 'absent.token'}\n"
        if allow_unauthenticated:
            body += "allow_unauthenticated = true\n"
        path = self.tmp / "doctorauth.conf"
        path.write_text(body, encoding="utf-8")
        os.environ[ENV_BRIDGE_GATEWAYS] = "172.17.0.1"
        self.addCleanup(os.environ.pop, ENV_BRIDGE_GATEWAYS, None)

        from mailut import status

        return {c["check"]: c for c in status.collect_checks(Config.load(path))}

    def test_a_missing_token_is_a_failure_not_a_warning(self):
        """Authentication is the default, so its absence is a broken install."""
        checks = self._setup(exporter_password=...)
        self.assertEqual(checks["collector token"]["status"], "fail")
        self.assertIn("no collector token", checks["collector token"]["detail"])

    def test_opting_out_is_a_warning(self):
        checks = self._setup(exporter_password=..., allow_unauthenticated=True)
        self.assertEqual(checks["collector token"]["status"], "warn")
        self.assertIn("fabricated", checks["collector token"]["detail"])

    def test_a_configured_token_is_reported_ok(self):
        checks = self._setup(token="t" * 32, exporter_password="t" * 32)
        self.assertEqual(checks["collector token"]["status"], "ok")

    def test_an_unreadable_token_file_fails(self):
        checks = self._setup(exporter_password=...)
        path = self.tmp / "bad.conf"
        path.write_text(
            f"[mailu]\ncompose_dir = {self.compose_dir}\ncompose_command = /bin/false\n"
            f"[storage]\nstate_dir = {self.state_dir}\n"
            f"[collector]\ntoken_file = {self.tmp / 'nonexistent.token'}\n",
            encoding="utf-8")
        from mailut import status

        checks = {c["check"]: c for c in status.collect_checks(Config.load(path))}
        self.assertEqual(checks["collector token"]["status"], "fail")

    def test_matching_credentials_are_reported_ok(self):
        checks = self._setup(token="t" * 32, exporter_password="t" * 32)
        self.assertEqual(checks["rspamd exporter auth"]["status"], "ok")

    def test_a_wrong_exporter_password_fails(self):
        """What the open /health endpoint can never tell you."""
        checks = self._setup(token="t" * 32, exporter_password="w" * 32)
        self.assertEqual(checks["rspamd exporter auth"]["status"], "fail")
        self.assertIn("401", checks["rspamd exporter auth"]["detail"])

    def test_a_missing_exporter_password_fails_when_a_token_is_required(self):
        checks = self._setup(token="t" * 32, exporter_password=...)
        self.assertEqual(checks["rspamd exporter auth"]["status"], "fail")
        self.assertIn("no credentials", checks["rspamd exporter auth"]["detail"])

    def test_the_secret_is_never_printed(self):
        secret = "t" * 32
        checks = self._setup(token=secret, exporter_password="w" * 32)
        for check in checks.values():
            self.assertNotIn(secret, check["detail"])
            self.assertNotIn("w" * 32, check["detail"])

    def test_an_exporter_password_without_a_host_token_is_flagged(self):
        checks = self._setup(exporter_password="t" * 32, allow_unauthenticated=True)
        self.assertEqual(checks["rspamd exporter auth"]["status"], "warn")


class RspamdDoctorTests(MailutTestCase):
    """doctor must check the real wiring, not that our own example exists."""

    def checks(self):
        from mailut import status

        return {c["check"]: c for c in status.collect_checks(self.config())}

    def test_missing_override_is_reported(self):
        check = self.checks()["rspamd exporter"]
        self.assertEqual(check["status"], "warn")
        self.assertIn("not be collected", check["detail"])

    def test_unrelated_override_does_not_count_as_configured(self):
        override = self.compose_dir / "overrides" / "rspamd"
        override.mkdir(parents=True)
        (override / "other.conf").write_text("# some unrelated tuning\n", encoding="utf-8")
        check = self.checks()["rspamd exporter"]
        self.assertEqual(check["status"], "warn")

    def matching_config(self, address="172.17.0.1"):
        """A config whose bind agrees with the exporter URL used below."""
        path = self.tmp / "matching.conf"
        path.write_text(
            f"[mailu]\ncompose_dir = {self.compose_dir}\ncompose_command = /bin/false\n"
            f"[storage]\nstate_dir = {self.state_dir}\n"
            f"[collector]\nbind = {address}\nport = 18765\n",
            encoding="utf-8",
        )
        return Config.load(path)

    def test_exporter_targeting_the_collector_is_recognised(self):
        from mailut import status

        override = self.compose_dir / "overrides" / "rspamd"
        override.mkdir(parents=True)
        (override / "mailut-exporter.conf").write_text(
            'metadata_exporter { rules { mailut { url = "http://172.17.0.1:18765/rspamd"; } } }',
            encoding="utf-8",
        )
        os.environ[ENV_BRIDGE_GATEWAYS] = "172.17.0.1"
        self.addCleanup(os.environ.pop, ENV_BRIDGE_GATEWAYS, None)
        checks = {c["check"]: c for c in status.collect_checks(self.matching_config())}
        self.assertEqual(checks["rspamd exporter"]["status"], "ok",
                         checks["rspamd exporter"]["detail"])
        self.assertEqual(checks["collector bind"]["status"], "ok",
                         checks["collector bind"]["detail"])

    def test_exporter_pointing_at_a_different_host_is_flagged(self):
        """The regression: any file containing ':<port>' counted as configured.

        bind = 172.17.0.1 with an exporter posting to 172.18.0.1:<port> was
        reported OK, because the check only looked for the port substring and
        the reachability probe tested the configured bind rather than the URL
        the exporter actually uses.
        """
        override = self.compose_dir / "overrides" / "rspamd"
        override.mkdir(parents=True)
        (override / "mailut-exporter.conf").write_text(
            'metadata_exporter { rules { mailut { url = "http://172.18.0.1:18765/rspamd"; } } }',
            encoding="utf-8",
        )
        check = self.checks()["rspamd exporter"]
        self.assertEqual(check["status"], "warn", check["detail"])
        self.assertIn("172.18.0.1", check["detail"])
        self.assertIn("bound to", check["detail"])

    def test_the_probe_targets_the_exporter_url_not_the_configured_bind(self):
        override = self.compose_dir / "overrides" / "rspamd"
        override.mkdir(parents=True)
        (override / "mailut-exporter.conf").write_text(
            'metadata_exporter { rules { mailut { url = "http://172.18.0.1:18765/rspamd"; } } }',
            encoding="utf-8",
        )
        probed = []
        real = Mailu.probe_url_from_service

        def capture(self, service, url, **kwargs):
            probed.append(url)
            return None, "stubbed"

        Mailu.probe_url_from_service = capture
        self.addCleanup(setattr, Mailu, "probe_url_from_service", real)
        self.checks()
        self.assertEqual(len(probed), 1)
        # The exporter's own host and port, with the health path substituted.
        self.assertEqual(probed[0], "http://172.18.0.1:18765/health")

    def test_a_wildcard_bind_accepts_any_exporter_host(self):
        path = self.tmp / "wild.conf"
        path.write_text(
            f"[mailu]\ncompose_dir = {self.compose_dir}\ncompose_command = /bin/false\n"
            f"[storage]\nstate_dir = {self.state_dir}\n"
            "[collector]\nbind = 0.0.0.0\nport = 18765\n",
            encoding="utf-8",
        )
        override = self.compose_dir / "overrides" / "rspamd"
        override.mkdir(parents=True)
        (override / "mailut-exporter.conf").write_text(
            'metadata_exporter { rules { mailut { url = "http://172.18.0.1:18765/rspamd"; } } }',
            encoding="utf-8",
        )
        from mailut import status

        checks = {c["check"]: c for c in status.collect_checks(Config.load(path))}
        self.assertEqual(checks["rspamd exporter"]["status"], "ok", checks["rspamd exporter"]["detail"])

    def test_exporter_on_the_wrong_port_is_not_accepted(self):
        override = self.compose_dir / "overrides" / "rspamd"
        override.mkdir(parents=True)
        (override / "mailut-exporter.conf").write_text(
            'metadata_exporter { rules { mailut { url = "http://172.17.0.1:9999/rspamd"; } } }',
            encoding="utf-8",
        )
        self.assertEqual(self.checks()["rspamd exporter"]["status"], "warn")

    def test_reachability_failure_is_never_reported_as_success(self):
        """A compose command that cannot exec must not look like a passing check."""
        check = self.checks()["rspamd -> collector"]
        self.assertEqual(check["status"], "warn")
        self.assertIn("not verified", check["detail"])

    def test_antispam_service_setting_is_used(self):
        """It was configured and documented but read nowhere."""
        mailu = Mailu(self.config())
        self.assertEqual(mailu.antispam_service, "antispam")
        self.assertTrue(str(mailu.rspamd_override_dir).endswith("overrides/rspamd"))


class ProbeTests(MailutTestCase):
    def test_probe_distinguishes_unreachable_from_unverifiable(self):
        mailu = Mailu(self.config())

        def fake_exec(service, args, stdin=None, timeout=120):
            return types.SimpleNamespace(returncode=0, stdout="MAILUT_NO_CLIENT\n", stderr="")

        mailu.exec_service = fake_exec
        reachable, detail = mailu.probe_url_from_service("antispam", "http://127.0.0.1:1/health")
        self.assertIsNone(reachable)
        self.assertIn("no curl or wget", detail)

        def fake_ok(service, args, stdin=None, timeout=120):
            return types.SimpleNamespace(returncode=0, stdout="MAILUT_OK\n", stderr="")

        mailu.exec_service = fake_ok
        self.assertEqual(mailu.probe_url_from_service("antispam", "http://x/health")[0], True)

        def fake_fail(service, args, stdin=None, timeout=120):
            return types.SimpleNamespace(returncode=1, stdout="", stderr="connection refused\n")

        mailu.exec_service = fake_fail
        reachable, detail = mailu.probe_url_from_service("antispam", "http://x/health")
        self.assertIs(reachable, False)
        self.assertIn("connection refused", detail)


class DegradedScopeTests(MailutTestCase):
    """A scope asking for more than the host permits must not look healthy."""

    def setUp(self):
        super().setUp()
        scope_store.upsert_scope(
            self.db(), scope_type="domain", value="example.com", mode="include",
            level="headers", retention_days=30, message_retention_days=None,
        )

    def tightened_config(self):
        path = self.tmp / "tight.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n"
            "[audit]\nallow_headers = false\n",
            encoding="utf-8",
        )
        return path

    def test_scopes_shows_the_effective_level(self):
        proc = self.run_cli("--config", str(self.tightened_config()), "audit", "scopes", expect=0)
        self.assertIn("metadata (asked headers)", proc.stdout)
        self.assertIn("collecting metadata only", proc.stderr)

    def test_scopes_json_exposes_the_effective_level(self):
        proc = self.run_cli(
            "--config", str(self.tightened_config()), "audit", "scopes", "--json", expect=0
        )
        record = json.loads(proc.stdout)[0]
        self.assertEqual(record["level"], "headers")
        self.assertEqual(record["effective_level"], "metadata")

    def test_doctor_warns_about_degraded_scopes(self):
        from mailut import status

        checks = {c["check"]: c for c in status.collect_checks(Config.load(self.tightened_config()))}
        self.assertEqual(checks["scope levels"]["status"], "warn")
        self.assertIn("example.com", checks["scope levels"]["detail"])

    def test_scopes_test_reports_the_effective_level(self):
        """--test must agree with the listing, not report the requested level."""
        proc = self.run_cli(
            "--config", str(self.tightened_config()),
            "audit", "scopes", "--test", "user@example.com", expect=0,
        )
        self.assertIn("metadata (asked headers)", proc.stdout)
        self.assertNotIn("level headers,", proc.stdout)

    def test_scopes_test_json_exposes_the_effective_level(self):
        proc = self.run_cli(
            "--config", str(self.tightened_config()),
            "audit", "scopes", "--test", "user@example.com", "--json", expect=0,
        )
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["collected"])
        self.assertEqual(payload["scope"]["level"], "headers")
        self.assertEqual(payload["effective_level"], "metadata")

    def test_listing_and_test_agree(self):
        conf = str(self.tightened_config())
        listing = self.run_cli("--config", conf, "audit", "scopes", expect=0).stdout
        tested = self.run_cli(
            "--config", conf, "audit", "scopes", "--test", "user@example.com", expect=0
        ).stdout
        for output in (listing, tested):
            self.assertIn("metadata (asked headers)", output)

    def test_test_reports_a_plain_level_when_nothing_is_degraded(self):
        proc = self.run_cli(
            "audit", "scopes", "--test", "user@example.com", expect=0
        )
        self.assertIn("level headers,", proc.stdout)
        self.assertNotIn("asked", proc.stdout)

    def test_no_warning_when_the_level_is_permitted(self):
        from mailut import status

        checks = {c["check"]: c for c in status.collect_checks(self.config())}
        self.assertEqual(checks["scope levels"]["status"], "ok")
        proc = self.run_cli("audit", "scopes", expect=0)
        self.assertNotIn("asked", proc.stdout)


class VersionJsonTests(MailutTestCase):
    def test_version_json_reports_the_schema_version(self):
        from mailut import migrations

        proc = self.run_cli("version", "--json", expect=0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema_version"], migrations.LATEST)
        self.assertIn("version", payload)
        self.assertIn("installed", payload)
