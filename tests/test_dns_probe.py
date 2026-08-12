import json
import math
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import dns_probe
import dns_analyze

REMOTE_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "remote"

SIGNED_A_ANSWER = """
; <<>> DiG 9.10.6 <<>> +dnssec +time=2 +tries=2 A signed.example
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4242
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
;; QUESTION SECTION:
;signed.example.\t\t\tIN\tA

;; ANSWER SECTION:
signed.example.\t\t300\tIN\tA\t192.0.2.10
signed.example.\t\t300\tIN\tRRSIG\tA 13 2 300 20260901000000 20260801000000 34505 signed.example. Zm9vYmFy

;; Query time: 21 msec
"""

DS_ANSWER = """
; <<>> DiG 9.10.6 <<>> +dnssec +time=2 +tries=2 DS signed.example
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4243
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
;; QUESTION SECTION:
;signed.example.\t\t\tIN\tDS

;; ANSWER SECTION:
signed.example.\t\t3600\tIN\tDS\t34505 13 2 0123456789ABCDEF0123456789ABCDEF
"""

TRACE_OUTPUT = """
; <<>> DiG 9.10.6 <<>> +trace +time=2 +tries=2 A www.example.com
;; global options: +cmd
.\t\t\t86400\tIN\tNS\ta.root-servers.net.
.\t\t\t86400\tIN\tNS\tb.root-servers.net.
;; Received 525 bytes from 192.0.2.53#53(192.0.2.53) in 13 ms

com.\t\t\t172800\tIN\tNS\ta.gtld-servers.net.
a.gtld-servers.net.\t172800\tIN\tA\t192.5.6.30
;; Received 1170 bytes from 198.41.0.4#53(a.root-servers.net) in 20 ms

example.com.\t\t172800\tIN\tNS\tns1.example.com.
ns1.example.com.\t172800\tIN\tA\t192.0.2.10
;; Received 733 bytes from 192.5.6.30#53(a.gtld-servers.net) in 31 ms

www.example.com.\t300\tIN\tA\t192.0.2.80
;; Received 76 bytes from 192.0.2.10#53(ns1.example.com) in 27 ms
"""

NXDOMAIN_TRACE_OUTPUT = """
; <<>> DiG 9.10.6 <<>> +trace +time=2 +tries=2 A printer.local
;; global options: +cmd
.\t\t\t351447\tIN\tNS\ta.root-servers.net.
.\t\t\t351447\tIN\tNS\th.root-servers.net.
;; Received 823 bytes from 192.0.2.53#53(192.0.2.53) in 7 ms

loans.\t\t\t86400\tIN\tNSEC\tlocker. NS DS RRSIG NSEC
.\t\t\t86400\tIN\tNSEC\taaa. NS SOA RRSIG NSEC DNSKEY TYPE63
;; Received 1071 bytes from 198.97.190.53#53(h.root-servers.net) in 96 ms
"""


def dnssec_probe(identifier, status, dnssec=None, resolver="system"):
    """One signature-layer probe carrying only the fields the verdict reads."""
    return {
        "id": identifier,
        "layer": "dnssec",
        "role": "recursive",
        "status": status,
        "resolver": resolver,
        "qname": "signed.example",
        "dnssec": dict(dnssec or {}),
    }


class _RecordingRequester:
    """Stands in for the network so no test ever reaches a real service."""

    def __init__(self, responses=None):
        self.calls = []
        self.responses = list(responses or [])

    def __call__(self, method, url, payload=None):
        self.calls.append({"method": method, "url": url, "payload": payload})
        if not self.responses:
            raise AssertionError("requester called more times than the test expected")
        return self.responses.pop(0)


class TargetTests(unittest.TestCase):
    def test_normalize_url_extracts_hostname_and_rejects_path_data(self):
        result = dns_probe.normalize_target("https://Example.COM/path?q=secret")
        self.assertEqual(result["hostname"], "example.com")
        self.assertNotIn("secret", json.dumps(result))

    def test_normalize_target_rejects_shell_metacharacters(self):
        with self.assertRaises(ValueError):
            dns_probe.normalize_target("example.com;uname -a")

    def test_record_type_validator_accepts_health_check_types(self):
        self.assertEqual(dns_probe._cli_record_type("a"), "A")
        self.assertEqual(dns_probe._cli_record_type("aaaa"), "AAAA")
        self.assertEqual(dns_probe._cli_record_type("ns"), "NS")
        self.assertEqual(dns_probe._cli_record_type("soa"), "SOA")

    def test_normalize_ipv4_literal(self):
        self.assertEqual(dns_probe.normalize_target("192.0.2.1")["ip"], "192.0.2.1")

    def test_normalize_bracketed_ipv6_url(self):
        result = dns_probe.normalize_target("https://[2001:db8::1]/status")
        self.assertEqual(result["ip"], "2001:db8::1")
        self.assertTrue(result["is_url"])

    def test_normalize_target_rejects_brackets_outside_ipv6_authority(self):
        with self.assertRaises(ValueError):
            dns_probe.normalize_target("https://example.com/path[unsafe]")

    def test_normalize_target_rejects_malformed_ipv6_url_port(self):
        with self.assertRaises(ValueError):
            dns_probe.normalize_target("https://[2001:db8::1]:not-a-port/status")

    def test_normalize_idn_uses_ascii_hostname(self):
        self.assertEqual(
            dns_probe.normalize_target("例子.测试")["hostname"],
            "xn--fsqu00a.xn--0zwm56d",
        )

    def test_normalize_target_rejects_url_credentials(self):
        with self.assertRaises(ValueError):
            dns_probe.normalize_target("https://user:password@example.com")

    def test_normalize_target_unwraps_a_markdown_link(self):
        # A target pasted from chat is routinely auto-linked, and the brackets used to
        # trip the unsafe-character check before the hostname was ever looked at.
        result = dns_probe.normalize_target("[www.example.com](https://www.example.com/path)")
        self.assertEqual(result["hostname"], "www.example.com")
        self.assertTrue(result["is_url"])

    def test_normalize_target_still_rejects_a_link_with_trailing_text(self):
        with self.assertRaises(ValueError):
            dns_probe.normalize_target("[a](https://b.example) 看看这个")


class CapabilityTests(unittest.TestCase):
    def test_windows_capabilities_prefer_nslookup(self):
        caps = dns_probe.detect_capabilities(
            "Windows",
            lambda name: "C:\\Windows\\System32\\nslookup.exe" if name == "nslookup" else None,
        )
        self.assertTrue(caps["nslookup"])
        self.assertFalse(caps["dig"])


class PlanTests(unittest.TestCase):
    def test_health_check_plan_repeats_each_record_type_over_udp_and_tcp(self):
        plan = dns_probe.build_probe_plan(
            dns_probe.normalize_target("example.com"),
            {"dig": True},
            options={
                "record_types": ["A", "AAAA", "NS", "SOA"],
                "samples": 2,
            },
        )

        self.assertEqual(len(plan), 16)
        self.assertEqual({entry["qtype"] for entry in plan}, {"A", "AAAA", "NS", "SOA"})
        self.assertEqual({entry["sample"] for entry in plan}, {1, 2})
        self.assertEqual(len({entry["id"] for entry in plan}), len(plan))
        for record_type in ("A", "AAAA", "NS", "SOA"):
            for sample in (1, 2):
                transports = {
                    entry["transport"]
                    for entry in plan
                    if entry["qtype"] == record_type and entry["sample"] == sample
                }
                self.assertEqual(transports, {"udp", "tcp"})

    def test_baseline_plan_counts_each_layer_separately(self):
        plan = dns_probe.build_probe_plan(
            dns_probe.normalize_target("www.example.com"),
            {"dig": True},
            options={
                "record_types": ["A", "AAAA", "NS", "SOA"],
                "samples": 2,
                "layers": ["local", "dnssec", "public", "trace", "authoritative"],
            },
        )

        counted = {}
        for entry in plan:
            counted[entry["layer"]] = counted.get(entry["layer"], 0) + 1
        # 16 local queries (4 types x 2 samples x UDP/TCP), 4 signature queries here plus
        # one pair at a validating resolver, 2 queries at each of 3 public resolvers, and
        # a single delegation walk. The authoritative layer needs nameserver addresses
        # that only the local layer can supply, so it is planned during collection.
        self.assertEqual(counted, {"local": 16, "dnssec": 6, "public": 6, "trace": 1})
        self.assertEqual(len({entry["id"] for entry in plan}), len(plan))
        self.assertEqual({entry["role"] for entry in plan if entry["layer"] == "trace"}, {"trace"})
        self.assertEqual(
            {entry["resolver"] for entry in plan if entry["layer"] == "public"},
            set(dns_probe._PUBLIC_RESOLVERS),
        )
        for entry in plan:
            dns_probe._validate_probe_argv(entry["argv"])

    def test_probe_plan_contains_only_allowlisted_executables(self):
        capabilities = {"dig": True, "nslookup": True, "host": False}
        plan = dns_probe.build_probe_plan({"hostname": "example.com"}, capabilities)
        self.assertTrue(plan)
        self.assertTrue(all(item["argv"][0] in {"dig", "nslookup"} for item in plan))

    def test_a_mapping_that_names_no_probe_tool_is_a_mis_passed_argument(self):
        # Options in the capabilities slot used to yield an empty plan, which reads as
        # "nothing to probe" instead of a wrong call.
        with self.assertRaises(ValueError):
            dns_probe.build_probe_plan(
                {"hostname": "example.com", "ip": None}, {"baseline": True},
            )

    def test_every_tool_absent_is_still_a_valid_capabilities_mapping(self):
        plan = dns_probe.build_probe_plan({"hostname": "example.com", "ip": None}, {})
        self.assertEqual(plan, [])

    def test_probe_plan_is_deterministic_and_keeps_resolver_as_argv_item(self):
        target = {"hostname": "example.com", "ip": None}
        capabilities = {"dig": True, "kdig": True, "nslookup": True, "host": True,
                        "resolvectl": True, "getent": True, "powershell": False}
        options = {"resolver": "1.1.1.1"}
        plan = dns_probe.build_probe_plan(target, capabilities, options)
        self.assertEqual(plan, dns_probe.build_probe_plan(target, capabilities, options))
        self.assertTrue(all(
            {"id", "purpose", "argv", "transport", "resolver", "qtype", "sample",
             "layer", "role"} <= set(item)
            and set(item) <= {"id", "purpose", "argv", "transport", "resolver", "qtype",
                              "sample", "layer", "role", "qname", "timeout_s"}
            for item in plan
        ))
        self.assertTrue(all(
            any("1.1.1.1" in argument for argument in item["argv"])
            for item in plan if item["resolver"] == "1.1.1.1"
        ))
        self.assertTrue(any(item["argv"][0] == "resolvectl" for item in plan))
        self.assertTrue(any(item["argv"][0] == "getent" for item in plan))


class ExecutionTests(unittest.TestCase):
    def test_run_probe_accepts_allowlisted_non_a_health_query(self):
        def fake_runner(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

        result = dns_probe.run_probe(
            ["dig", "+time=2", "+tries=2", "AAAA", "example.com"],
            timeout_s=1,
            runner=fake_runner,
        )

        self.assertEqual(result["returncode"], 0)

    def test_run_probe_records_timeout(self):
        def fake_runner(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

        result = dns_probe.run_probe(["dig", "example.com"], runner=fake_runner)

        self.assertTrue(result["timed_out"])
        self.assertIsNone(result["returncode"])
        self.assertFalse(result["output_truncated"])
        self.assertEqual(result["parser_status"], "not_parsed")

    def test_run_probe_rejects_executable_outside_allowlist(self):
        with self.assertRaises(ValueError):
            dns_probe.run_probe(["sh", "-c", "echo unsafe"])

    def test_run_probe_rejects_destructive_powershell_arguments(self):
        with self.assertRaises(ValueError):
            dns_probe.run_probe(["powershell", "-Command", "Remove-Item x"])

    def test_run_probe_rejects_dangerous_dig_option(self):
        with self.assertRaises(ValueError):
            dns_probe.run_probe(["dig", "+trace", "example.com"])

    def test_run_probe_rejects_non_finite_timeout(self):
        for timeout_s in (math.nan, math.inf, -math.inf):
            with self.subTest(timeout_s=timeout_s):
                with self.assertRaises(ValueError):
                    dns_probe.run_probe(["dig", "example.com"], timeout_s=timeout_s)

    def test_run_probe_caps_each_output_stream_by_encoded_byte_length(self):
        def fake_runner(*args, **kwargs):
            self.assertFalse(kwargs["shell"])
            self.assertTrue(kwargs["capture_output"])
            self.assertTrue(kwargs["text"])
            return subprocess.CompletedProcess(args[0], 0, stdout="abcdef", stderr="uvwxyz")

        result = dns_probe.run_probe(
            ["dig", "example.com"], max_output_bytes=4, runner=fake_runner
        )

        self.assertEqual(result["stdout"], "abcd")
        self.assertEqual(result["stderr"], "uvwx")
        self.assertTrue(result["output_truncated"])

    def test_run_probe_records_start_timestamp(self):
        def fake_runner(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        result = dns_probe.run_probe(["dig", "example.com"], runner=fake_runner)

        self.assertIn("started_at", result)
        self.assertRegex(result["started_at"], r"^\d{4}-\d{2}-\d{2}T.*Z$")


class EvidenceTests(unittest.TestCase):
    def test_collection_preserves_non_a_qtype_and_sampling_scope(self):
        def fake_runner(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        evidence = dns_probe.collect_evidence(
            "example.com",
            {
                "capabilities": {"dig": True},
                "record_types": ["AAAA"],
                "samples": 1,
            },
            runner=fake_runner,
        )

        self.assertEqual([probe["qtype"] for probe in evidence["probes"]], ["AAAA", "AAAA"])
        self.assertEqual(evidence["collection_scope"]["record_types"], ["AAAA"])
        self.assertEqual(evidence["collection_scope"]["samples"], 1)

    def test_missing_tools_health_scope_generates_manual_commands_for_each_type(self):
        evidence = dns_probe.collect_evidence(
            "example.com",
            {
                "capabilities": {},
                "record_types": ["A", "AAAA", "NS", "SOA"],
                "samples": 2,
            },
        )

        commands = [item.get("manual_command", "") for item in evidence["skipped"]]
        for record_type in ("A", "AAAA", "NS", "SOA"):
            self.assertTrue(
                any(" {0} ".format(record_type) in " " + command + " " for command in commands),
                record_type,
            )

    def test_collect_evidence_includes_environment_safety_and_manual_fallbacks(self):
        def fake_runner(argv, **kwargs):
            if argv == ["dig", "-v"]:
                return subprocess.CompletedProcess(argv, 0, stdout="dig 9.18.1\n", stderr="")
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout=(
                    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"
                    ";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n"
                    ";; QUESTION SECTION:\n;printer.local. IN A\n"
                    ";; ANSWER SECTION:\nprinter.local. 60 IN A 203.0.113.7\n"
                ),
                stderr="",
            )

        evidence = dns_probe.collect_evidence(
            "printer.local",
            {
                "capabilities": {"dig": True},
                "region": "cn-north-1",
                "deadline_s": 10,
            },
            runner=fake_runner,
        )

        self.assertEqual(evidence["schema_version"], "1.0")
        self.assertEqual(evidence["environment"]["region"], "cn-north-1")
        self.assertEqual(evidence["probes"][0]["parsed"]["addresses"], ["203.0.113.7"])
        self.assertEqual(evidence["probes"][0]["parser_status"], "parsed")
        self.assertTrue(any(item["id"] == "internal_name_exposure" for item in evidence["safety"]))
        self.assertTrue(any("manual_command" in item for item in evidence["skipped"]))

    def test_collect_evidence_rejects_non_finite_deadline(self):
        for deadline_s in (math.nan, math.inf, -math.inf):
            with self.subTest(deadline_s=deadline_s):
                with self.assertRaises(ValueError):
                    dns_probe.collect_evidence("example.com", {"deadline_s": deadline_s})

    def test_collect_evidence_marks_unstarted_probes_when_deadline_has_elapsed(self):
        def fake_runner(*args, **kwargs):
            self.fail("runner must not be called after an elapsed deadline")

        evidence = dns_probe.collect_evidence(
            "example.com",
            {"capabilities": {"dig": True}, "deadline_s": 0},
            runner=fake_runner,
        )

        self.assertEqual(evidence["probes"], [])
        self.assertTrue(any(item["reason"] == "total deadline elapsed" for item in evidence["skipped"]))
        self.assertTrue(all("resolver" in item for item in evidence["skipped"]))
        self.assertEqual(evidence["resolvers"], ["system"])

    def test_collect_evidence_has_stable_collection_fields(self):
        evidence = dns_probe.collect_evidence(
            "example.com",
            {"capabilities": {}, "deadline_s": 0},
            runner=lambda *args, **kwargs: self.fail("no subprocess expected"),
        )

        self.assertIn("collected_at", evidence)
        self.assertRegex(evidence["collected_at"], r"^\d{4}-\d{2}-\d{2}T.*Z$")
        self.assertEqual(evidence.get("findings"), [])
        self.assertEqual(evidence.get("redaction"), {"status": "pending"})

    def test_powershell_only_capability_emits_reviewed_windows_fallback(self):
        def fake_runner(argv, **kwargs):
            self.fail("PowerShell must not execute automatically")

        evidence = dns_probe.collect_evidence(
            "example.com",
            {"capabilities": {"powershell": True}, "deadline_s": 5},
            runner=fake_runner,
        )

        fallback = next(
            (item for item in evidence["skipped"] if "Resolve-DnsName" in item.get("manual_command", "")),
            None,
        )
        self.assertIsNotNone(fallback)
        self.assertEqual(
            fallback["manual_command"],
            "Resolve-DnsName -Name 'example.com' -Type A -DnsOnly",
        )
        self.assertIn("user-executed only after review", fallback["reason"])


class BundleTests(unittest.TestCase):
    def test_write_bundle_creates_expected_files_and_redacts_all_artifacts(self):
        evidence = {
            "schema_version": "1.0",
            "probes": [{
                "id": "dig_udp",
                "argv": [
                    "dig", "--token", "supersecret",
                    "https://example.com/check?api_key=supersecret#supersecret",
                ],
                "stdout": "password=supersecret",
                "stderr": "https://example.com/?token=supersecret#supersecret",
                "timed_out": False,
            }],
            "findings": [],
            "safety": [],
            "credentials": {"api_key": "supersecret"},
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = dns_probe.write_bundle(evidence, Path(directory))

            self.assertTrue(Path(paths["json"]).exists())
            self.assertTrue(Path(paths["markdown"]).exists())
            self.assertTrue(Path(paths["commands"]).exists())
            self.assertTrue(Path(paths["raw_summary"]).exists())
            for artifact in paths.values():
                self.assertNotIn("supersecret", Path(artifact).read_text(encoding="utf-8"))
            self.assertEqual(
                json.loads(Path(paths["commands"]).read_text(encoding="utf-8"))[0]["argv"],
                ["dig", "--token", "[REDACTED]", "https://example.com/check?[REDACTED]#[REDACTED]"],
            )

    def test_write_bundle_leaves_the_readable_report_name_to_the_analyzer(self):
        evidence = {"schema_version": "1.0", "probes": [], "safety": []}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "dns-debug-report.md"
            report.write_text("# DNS 诊断报告\n", encoding="utf-8")

            paths = dns_probe.write_bundle(evidence, root)

            self.assertEqual(Path(paths["markdown"]).name, "collection-summary.md")
            self.assertEqual(report.read_text(encoding="utf-8"), "# DNS 诊断报告\n")

    def test_write_bundle_rejects_preexisting_symlink_paths(self):
        evidence = {"schema_version": "1.0", "probes": [], "safety": []}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            try:
                (root / "raw").symlink_to(outside, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are not available on this platform")

            with self.assertRaises(ValueError):
                dns_probe.write_bundle(evidence, root)

            (root / "raw").unlink()
            (root / "dns-debug-report.json").symlink_to(outside / "redirected.json")
            with self.assertRaises(ValueError):
                dns_probe.write_bundle(evidence, root)

    def test_write_bundle_redacts_embedded_url_query_data(self):
        evidence = {
            "schema_version": "1.0",
            "probes": [{
                "id": "dig_udp",
                "stdout": "request failed: https://example.com/path?session=abc",
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = dns_probe.write_bundle(evidence, Path(directory))
            contents = Path(paths["json"]).read_text(encoding="utf-8")

        self.assertNotIn("session=abc", contents)
        self.assertIn("request failed: https://example.com/path?[REDACTED]", contents)

    def test_write_bundle_preserves_malformed_url_like_text(self):
        evidence = {
            "schema_version": "1.0",
            "probes": [{"id": "dig_udp", "stdout": "http://["}],
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = dns_probe.write_bundle(evidence, Path(directory))
            contents = Path(paths["json"]).read_text(encoding="utf-8")

        self.assertIn("http://[", contents)

    def test_write_bundle_marks_serialized_evidence_as_redacted(self):
        evidence = {
            "schema_version": "1.0",
            "redaction": {"status": "pending"},
            "probes": [],
            "safety": [],
            "findings": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = dns_probe.write_bundle(evidence, Path(directory))
            serialized = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))

        self.assertEqual(serialized["redaction"], {"status": "applied"})


class ArgvTemplateTests(unittest.TestCase):
    """The allowlist matches whole shapes, so a near miss has to stay rejected."""

    def accepts(self, argv):
        self.assertEqual(dns_probe._validate_probe_argv(argv), argv)

    def rejects(self, argv):
        with self.assertRaises(ValueError):
            dns_probe._validate_probe_argv(argv)

    def test_signature_queries_are_accepted_in_their_exact_form(self):
        self.accepts(["dig", "+dnssec", "+time=2", "+tries=2", "A", "example.com"])
        self.accepts(["dig", "+dnssec", "+time=2", "+tries=2", "A", "example.com", "@8.8.8.8"])
        self.accepts(["dig", "+dnssec", "+time=2", "+tries=2", "DS", "example.com"])
        self.accepts(["dig", "+dnssec", "+time=2", "+tries=2", "DNSKEY", "example.com"])
        self.accepts(["dig", "+dnssec", "+cd", "+time=2", "+tries=2", "A", "example.com"])
        self.accepts(
            ["dig", "+dnssec", "+cd", "+time=2", "+tries=2", "A", "example.com", "@8.8.8.8"]
        )

    def test_signature_queries_reject_added_or_reordered_options(self):
        self.rejects(["dig", "+dnssec", "+time=2", "+tries=2", "+tcp", "A", "example.com"])
        self.rejects(["dig", "+time=2", "+tries=2", "+dnssec", "A", "example.com"])
        self.rejects(["dig", "+cd", "+dnssec", "+time=2", "+tries=2", "A", "example.com"])
        self.rejects(["dig", "+dnssec", "+time=2", "+tries=2", "MX", "example.com"])

    def test_authoritative_query_requires_a_server_address(self):
        self.accepts(
            ["dig", "+norecurse", "+time=2", "+tries=2", "A", "example.com", "@192.0.2.10"]
        )
        self.accepts(
            ["dig", "+norecurse", "+time=2", "+tries=2", "NS", "example.com", "@192.0.2.10"]
        )
        # Without a named server the query says nothing about the zone's own answer.
        self.rejects(["dig", "+norecurse", "+time=2", "+tries=2", "A", "example.com"])
        self.rejects(
            ["dig", "+norecurse", "+time=2", "+tries=2", "A", "example.com", "@ns1.example.com"]
        )

    def test_trace_is_accepted_only_in_its_exact_form_without_a_server(self):
        self.accepts(["dig", "+trace", "+time=2", "+tries=2", "A", "example.com"])
        # A trace always starts at the root servers, so pinning one is meaningless.
        self.rejects(["dig", "+trace", "+time=2", "+tries=2", "A", "example.com", "@8.8.8.8"])
        self.rejects(["dig", "+trace", "+time=2", "+tries=1", "A", "example.com"])
        self.rejects(["dig", "+trace", "+dnssec", "+time=2", "+tries=2", "A", "example.com"])


class DnssecEvidenceTests(unittest.TestCase):
    def test_signed_answer_records_the_checked_flag_and_the_signature(self):
        parsed = dns_probe._parse_dig_output(SIGNED_A_ANSWER, "signed.example", "A")

        self.assertEqual(parsed["status"], "NOERROR")
        self.assertEqual(parsed["addresses"], ["192.0.2.10"])
        self.assertTrue(parsed["dnssec"]["requested"])
        self.assertTrue(parsed["dnssec"]["ad_flag"])
        self.assertTrue(parsed["dnssec"]["rrsig_present"])
        self.assertFalse(parsed["dnssec"]["cd_flag"])

    def test_parent_answer_records_the_registered_key_fingerprint(self):
        parsed = dns_probe._parse_dig_output(DS_ANSWER, "signed.example", "DS")

        self.assertEqual(
            parsed["dnssec"]["ds_records"],
            [{"key_tag": 34505, "algorithm": 13, "digest_type": 2}],
        )

    def test_answer_without_signatures_requested_says_nothing_about_dnssec(self):
        plain = SIGNED_A_ANSWER.replace("flags: do; udp: 1232", "udp: 1232").replace(
            "signed.example.\t\t300\tIN\tRRSIG\tA 13 2 300 20260901000000 "
            "20260801000000 34505 signed.example. Zm9vYmFy\n",
            "",
        )

        self.assertNotIn("dnssec", dns_probe._parse_dig_output(plain, "signed.example", "A"))

    def test_registered_key_and_checked_answer_read_as_signed(self):
        assessment = dns_probe._dnssec_assessment([
            dnssec_probe("dig_dnssec_a", "NOERROR", {"ad_flag": True, "rrsig_present": True}),
            dnssec_probe("dig_dnssec_cd_a", "NOERROR"),
            dnssec_probe("dig_dnssec_ds", "NOERROR", {"ds_records": [
                {"key_tag": 34505, "algorithm": 13, "digest_type": 2}
            ]}),
            dnssec_probe("dig_dnssec_dnskey", "NOERROR", {"dnskey_records": [
                {"key_tag": 34505, "algorithm": 13, "key_signing_key": True}
            ]}),
        ])

        self.assertEqual(assessment["validation"], "secure")
        self.assertEqual(assessment["matched_key_tags"], [34505])
        self.assertTrue(assessment["ds_present"])

    def test_parent_without_a_registered_key_reads_as_unsigned(self):
        assessment = dns_probe._dnssec_assessment([
            dnssec_probe("dig_dnssec_a", "NOERROR", {"ad_flag": False}),
            dnssec_probe("dig_dnssec_cd_a", "NOERROR"),
            dnssec_probe("dig_dnssec_ds", "NOERROR"),
            dnssec_probe("dig_dnssec_dnskey", "NOERROR"),
        ])

        # Unsigned is the domain owner's choice, so it must not read as a fault.
        self.assertEqual(assessment["validation"], "insecure")
        self.assertFalse(assessment["ds_present"])

    def test_failure_that_disappears_with_checking_disabled_reads_as_broken(self):
        probes = [
            dnssec_probe("dig_dnssec_a", "SERVFAIL"),
            dnssec_probe("dig_dnssec_cd_a", "NOERROR"),
            dnssec_probe("dig_dnssec_ds", "NOERROR", {"ds_records": [{"key_tag": 34505}]}),
            dnssec_probe("dig_dnssec_dnskey", "NOERROR"),
        ]

        assessment = dns_probe._dnssec_assessment(probes)

        self.assertEqual(assessment["validation"], "bogus")
        # The verdict is written back onto the probes, which is what the analyzer reads.
        self.assertEqual(
            {probe["dnssec"]["validation"] for probe in probes}, {"bogus"}
        )

    def test_broken_signature_reaches_the_analyzer_verdict(self):
        probes = [
            dnssec_probe("dig_dnssec_a", "SERVFAIL"),
            dnssec_probe("dig_dnssec_cd_a", "NOERROR"),
            dnssec_probe("dig_dnssec_ds", "NOERROR", {"ds_records": [{"key_tag": 34505}]}),
            dnssec_probe("dig_dnssec_dnskey", "NOERROR"),
        ]
        dns_probe._dnssec_assessment(probes)

        findings = dns_analyze.classify_evidence({
            "target": {"hostname": "signed.example", "ip": None, "is_url": False},
            "environment": {"region": None},
            "probes": [dict(probe, executed=True, transport="udp") for probe in probes],
        })

        finding = next(
            item for item in findings if item["category"] == "dnssec_validation_failure"
        )
        self.assertEqual(finding["status"], "confirmed")
        self.assertIn("dig_dnssec_a", finding["supporting_probe_ids"])

    def test_missing_checked_flag_stays_undecided_instead_of_guessing(self):
        for name, probes in (
            ("resolver did not mark the answer", [
                dnssec_probe("dig_dnssec_a", "NOERROR", {"ad_flag": False}),
                dnssec_probe("dig_dnssec_cd_a", "NOERROR"),
                dnssec_probe("dig_dnssec_ds", "NOERROR", {"ds_records": [{"key_tag": 34505}]}),
                dnssec_probe("dig_dnssec_dnskey", "NOERROR"),
            ]),
            ("parent query never answered", [
                dnssec_probe("dig_dnssec_a", "NOERROR", {"ad_flag": False}),
                dnssec_probe("dig_dnssec_cd_a", "NOERROR"),
                dnssec_probe("dig_dnssec_ds", "SERVFAIL"),
                dnssec_probe("dig_dnssec_dnskey", "SERVFAIL"),
            ]),
        ):
            with self.subTest(case=name):
                assessment = dns_probe._dnssec_assessment(probes)
                self.assertEqual(assessment["validation"], "indeterminate")
                self.assertTrue(assessment["reason"])

    def test_validating_public_resolver_can_decide_what_the_local_one_cannot(self):
        assessment = dns_probe._dnssec_assessment([
            dnssec_probe("dig_dnssec_a", "NOERROR", {"ad_flag": False}),
            dnssec_probe("dig_dnssec_cd_a", "NOERROR"),
            dnssec_probe("dig_dnssec_ds", "NOERROR", {"ds_records": [{"key_tag": 34505}]}),
            dnssec_probe("dig_dnssec_dnskey", "NOERROR"),
            dnssec_probe(
                "dig_dnssec_validating_a", "NOERROR", {"ad_flag": True}, "8.8.8.8"
            ),
            dnssec_probe("dig_dnssec_validating_cd_a", "NOERROR", None, "8.8.8.8"),
        ])

        self.assertEqual(assessment["validation"], "secure")
        self.assertEqual(assessment["validating_resolver"], "8.8.8.8")
        self.assertIn("8.8.8.8", assessment["reason"])

    def test_no_signature_layer_produces_no_verdict_at_all(self):
        self.assertIsNone(dns_probe._dnssec_assessment([
            {"id": "dig_udp", "layer": "local", "status": "NOERROR"}
        ]))


class TraceParsingTests(unittest.TestCase):
    def test_trace_output_becomes_ordered_hops_from_the_root_down(self):
        parsed = dns_probe._parse_dig_trace_output(TRACE_OUTPUT, "www.example.com", "A")

        self.assertEqual(parsed["hop_count"], 4)
        self.assertEqual(
            parsed["delegation_chain"], [".", "com", "example.com", "www.example.com"]
        )
        self.assertEqual(parsed["hops"][0]["zone"], ".")
        self.assertEqual(parsed["hops"][1]["from_server"], "a.root-servers.net")
        self.assertEqual(parsed["hops"][1]["from_address"], "198.41.0.4")
        self.assertEqual(parsed["hops"][2]["nameservers"], ["ns1.example.com"])
        self.assertEqual(parsed["hops"][2]["glue"], {"ns1.example.com": "192.0.2.10"})
        self.assertEqual(parsed["hops"][3]["rtt_ms"], 27)
        self.assertEqual([answer["data"] for answer in parsed["answers"]], ["192.0.2.80"])
        self.assertEqual(parsed["status"], "NOERROR")

    def test_trace_without_any_referral_block_is_left_unparsed(self):
        self.assertIsNone(
            dns_probe._parse_dig_trace_output(
                ";; connection timed out; no servers could be reached\n",
                "www.example.com",
                "A",
            )
        )

    def test_a_proof_of_nonexistence_is_not_read_as_a_delegation(self):
        # The root proves .local does not exist with NSEC records whose owner name is the
        # neighbouring name in sort order. That name is not a zone the walk reached.
        parsed = dns_probe._parse_dig_trace_output(NXDOMAIN_TRACE_OUTPUT, "printer.local", "A")

        self.assertEqual(parsed["hop_count"], 2)
        self.assertEqual(parsed["delegation_chain"], ["."])
        self.assertIsNone(parsed["hops"][1]["zone"])
        self.assertFalse(parsed["hops"][1]["referral"])
        self.assertTrue(parsed["hops"][0]["referral"])
        self.assertNotIn("status", parsed)


class AuthoritativeLayerTests(unittest.TestCase):
    def test_nameservers_and_glue_already_seen_become_direct_queries(self):
        discovery = dns_probe._observed_nameservers([{
            "id": "dig_trace",
            "layer": "trace",
            "qtype": "A",
            "hops": [
                {"zone": "com", "nameservers": ["a.gtld-servers.net"], "glue": {}},
                {
                    "zone": "example.com",
                    "nameservers": ["ns1.example.com", "ns2.example.com"],
                    "glue": {
                        "ns1.example.com": "192.0.2.10",
                        "ns2.example.com": "192.0.2.11",
                    },
                },
            ],
        }], "www.example.com")

        self.assertEqual(discovery["zone"], "example.com")
        self.assertEqual(discovery["nameservers"], ["ns1.example.com", "ns2.example.com"])

        entries = dns_probe._authoritative_layer_entries(
            "www.example.com",
            [
                {"name": name, "address": discovery["glue"][name]}
                for name in discovery["nameservers"]
            ],
            discovery["zone"],
        )

        self.assertEqual(
            entries[0]["argv"],
            ["dig", "+norecurse", "+time=2", "+tries=2", "A", "www.example.com", "@192.0.2.10"],
        )
        self.assertEqual({entry["layer"] for entry in entries}, {"authoritative"})
        # The role travels with the plan; the analyzer compares resolver answers against
        # authoritative ones and cannot infer which is which after the fact.
        self.assertEqual(
            [entry["role"] for entry in entries],
            ["authoritative", "authoritative", "child_authority"],
        )
        for entry in entries:
            dns_probe._validate_probe_argv(entry["argv"])

    def test_layer_is_skipped_with_a_reason_when_no_nameserver_was_seen(self):
        outcome = dns_probe._authoritative_layer(
            "www.example.com", [], None, {}, 1.0, {}, 0.0, 1024,
            lambda *args, **kwargs: None, {}, None,
        )

        self.assertEqual(outcome["plan"], [])
        self.assertEqual(outcome["probes"], [])
        self.assertEqual(len(outcome["skipped"]), 1)
        self.assertEqual(outcome["skipped"][0]["layer"], "authoritative")
        self.assertIn("no nameserver names were observed", outcome["skipped"][0]["reason"])


class ConcurrencyTests(unittest.TestCase):
    def _entries(self, count):
        return [
            dns_probe._entry(
                "dig_udp_{0}".format(index),
                "Query A records over UDP",
                ["dig", "+time=2", "+tries=2", "A", "example.com",
                 "@192.0.2.{0}".format(index)],
                "udp", "192.0.2.{0}".format(index),
            )
            for index in range(1, count + 1)
        ]

    def test_results_follow_plan_order_no_matter_which_probe_answers_first(self):
        entries = self._entries(6)

        def slow_runner(argv, **kwargs):
            # The last planned probe answers first, so ordering cannot come from timing.
            position = int(argv[-1].rsplit(".", 1)[1])
            time.sleep(0.01 * (len(entries) - position))
            return subprocess.CompletedProcess(argv, 0, stdout=argv[-1], stderr="")

        results = dns_probe._run_probe_batch(
            entries, 1.0, {"local": time.monotonic() + 5}, time.monotonic() + 5,
            1024, slow_runner, {}, threading.Lock(),
        )

        self.assertEqual(
            [result["stdout"] for result in results],
            [entry["argv"][-1] for entry in entries],
        )

    def test_one_resolver_never_receives_more_than_two_queries_at_once(self):
        entries = [
            dns_probe._entry(
                "dig_udp_sample_{0}".format(index),
                "Query A records over UDP",
                ["dig", "+time=2", "+tries=2", "A", "example.com", "@192.0.2.10"],
                "udp", "192.0.2.10", "A", index,
            )
            for index in range(1, 7)
        ]
        lock = threading.Lock()
        state = {"live": 0, "peak": 0}

        def counting_runner(argv, **kwargs):
            with lock:
                state["live"] += 1
                state["peak"] = max(state["peak"], state["live"])
            time.sleep(0.02)
            with lock:
                state["live"] -= 1
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        dns_probe._run_probe_batch(
            entries, 1.0, {"local": time.monotonic() + 5}, time.monotonic() + 5,
            1024, counting_runner, {}, threading.Lock(),
        )

        # Concurrency is bounded per resolver address so the run cannot look like a
        # load test against someone else's server.
        self.assertEqual(state["peak"], dns_probe._MAX_PARALLEL_PER_RESOLVER)

    def test_each_layer_holds_its_own_deadline(self):
        start = 1000.0
        deadlines = dns_probe._layer_deadlines(
            list(dns_probe._BASELINE_LAYERS), start, start + 90.0
        )

        self.assertEqual(set(deadlines), set(dns_probe._BASELINE_LAYERS))
        for layer, value in deadlines.items():
            self.assertEqual(value, start + dns_probe._LAYER_BUDGET_S[layer])
            self.assertLessEqual(value, start + 90.0)
        # A single-layer run is not carved up; it may use the whole budget.
        self.assertEqual(
            dns_probe._layer_deadlines(["local"], start, start + 20.0),
            {"local": start + 20.0},
        )

    def test_an_exhausted_layer_leaves_other_layers_their_budget(self):
        spent = time.monotonic() - 1
        alive = time.monotonic() + 5
        entries = [
            dns_probe._entry(
                "dig_dnssec_a", "Ask for A records with signatures requested",
                ["dig", "+dnssec", "+time=2", "+tries=2", "A", "example.com"],
                "udp", "system", "A", 1, "dnssec",
            ),
            dns_probe._entry(
                "dig_udp", "Query A records over UDP",
                ["dig", "+time=2", "+tries=2", "A", "example.com"], "udp", "system",
            ),
        ]

        results = dns_probe._run_probe_batch(
            entries, 1.0, {"dnssec": spent, "local": alive}, alive, 1024,
            lambda argv, **kwargs: subprocess.CompletedProcess(
                argv, 0, stdout="ok", stderr=""
            ),
            {}, threading.Lock(),
        )

        self.assertIsNone(results[0])
        self.assertEqual(results[1]["stdout"], "ok")
        skipped = dns_probe._skip_entry(
            entries[0], dns_probe._budget_reason(entries[0], {"dnssec": spent}, alive)
        )
        self.assertEqual(skipped["reason"], "dnssec layer time budget elapsed")
        self.assertEqual(skipped["layer"], "dnssec")


class RemoteObservationTests(unittest.TestCase):
    def test_regions_accept_country_codes_and_drop_duplicates(self):
        self.assertEqual(dns_probe.normalize_regions("us, DE ,us"), ["US", "DE"])
        self.assertEqual(dns_probe.normalize_regions(["cn", "jp"]), ["CN", "JP"])
        self.assertEqual(dns_probe.normalize_regions(None), [])

    def test_regions_reject_non_country_codes_and_oversized_lists(self):
        with self.assertRaises(ValueError):
            dns_probe.normalize_regions("USA")
        with self.assertRaises(ValueError):
            dns_probe.normalize_regions("US,DE,FR,JP,CN")

    def test_request_body_carries_only_the_name_and_record_type(self):
        body = dns_probe.remote_measurement_request("www.example.com", "A", ["US", "DE"])

        self.assertEqual(body["target"], "www.example.com")
        self.assertEqual(body["measurementOptions"]["query"]["type"], "A")
        # Pinning the resolver is what makes two countries comparable at all.
        self.assertEqual(body["measurementOptions"]["resolver"], "8.8.8.8")
        self.assertEqual(
            body["locations"],
            [{"country": "US", "limit": 2}, {"country": "DE", "limit": 2}],
        )
        # Nothing observed locally may appear in the payload.
        serialized = json.dumps(body)
        for leaked in ("resolv.conf", "search", "172.31.", "10.", "stdout"):
            self.assertNotIn(leaked, serialized)

    def test_missing_acknowledgement_sends_nothing(self):
        requester = _RecordingRequester()
        result = dns_probe.fetch_remote_observations(
            {"hostname": "www.example.com", "ip": None},
            "A", ["US"], False, requester=requester,
        )

        self.assertEqual(requester.calls, [])
        self.assertEqual(result["observations"], [])
        self.assertIn("--acknowledge-remote-query", result["skipped"][0]["reason"])
        self.assertFalse(result["disclosure"]["sent"])
        self.assertEqual(result["disclosure"]["reason_code"], "not_acknowledged")

    def test_internal_name_is_refused_even_when_acknowledged(self):
        requester = _RecordingRequester()
        result = dns_probe.fetch_remote_observations(
            {"hostname": "printer.local", "ip": None},
            "A", ["US", "DE"], True, requester=requester,
        )

        # The acknowledgement covers public names only: an internal name in someone
        # else's logs cannot be recalled.
        self.assertEqual(requester.calls, [])
        self.assertEqual(result["observations"], [])
        self.assertIn("internal or private names", result["skipped"][0]["reason"])
        self.assertFalse(result["disclosure"]["sent"])
        self.assertIsNone(result["disclosure"]["endpoint"])
        # A stable code so the report states the real reason without parsing prose.
        self.assertEqual(result["disclosure"]["reason_code"], "internal_name")

    def test_successful_measurement_polls_until_finished(self):
        document = json.loads(
            (REMOTE_FIXTURES_DIR / "globalping-us-de.json").read_text(encoding="utf-8")
        )
        requester = _RecordingRequester([
            {"id": "abc123"},
            {"status": "in-progress"},
            document,
        ])
        slept = []
        result = dns_probe.fetch_remote_observations(
            {"hostname": "www.example.com", "ip": None},
            "A", ["US", "DE"], True,
            requester=requester, sleeper=slept.append, clock=lambda: 0.0,
        )

        self.assertEqual([call["method"] for call in requester.calls], ["POST", "GET", "GET"])
        self.assertEqual(requester.calls[1]["url"], requester.calls[2]["url"])
        self.assertEqual(slept, [dns_probe._REMOTE_POLL_INTERVAL_S])
        self.assertEqual(len(result["observations"]), 4)
        self.assertTrue(result["disclosure"]["sent"])
        self.assertEqual(result["disclosure"]["endpoint"], "api.globalping.io")
        self.assertEqual(result["disclosure"]["sent_fields"], ["queried name", "record type"])

    def test_polling_stops_at_the_budget_instead_of_hanging(self):
        clock = iter([0.0, 1.0, dns_probe._REMOTE_TOTAL_BUDGET_S + 1.0])
        requester = _RecordingRequester([
            {"id": "abc123"},
            {"status": "in-progress"},
            {"status": "in-progress"},
        ])
        result = dns_probe.fetch_remote_observations(
            {"hostname": "www.example.com", "ip": None},
            "A", ["US"], True,
            requester=requester, sleeper=lambda _: None, clock=lambda: next(clock),
        )

        self.assertEqual(result["observations"], [])
        self.assertIn("TimeoutError", result["skipped"][0]["reason"])
        # The name did reach the service before the timeout, so the disclosure says so.
        self.assertTrue(result["disclosure"]["sent"])

    def test_parser_yields_two_stable_records_per_country(self):
        document = json.loads(
            (REMOTE_FIXTURES_DIR / "globalping-us-de.json").read_text(encoding="utf-8")
        )
        parsed = dns_probe.parse_remote_measurement(document, "www.example.com", "A")

        by_country = {}
        for observation in parsed["observations"]:
            by_country.setdefault(observation["vantage"], []).append(observation)
        self.assertEqual(sorted(by_country), ["DE", "US"])
        self.assertEqual([len(items) for items in by_country.values()], [2, 2])
        for observation in parsed["observations"]:
            self.assertEqual(observation["resolver"], "8.8.8.8")
            self.assertEqual(observation["role"], "recursive")
            self.assertEqual(observation["layer"], "regional")
            self.assertEqual(observation["qtype"], "A")
            self.assertEqual(observation["status"], "NOERROR")
        self.assertEqual(len(set(item["id"] for item in parsed["observations"])), 4)
        # The probe that answered nothing is recorded as skipped, never silently dropped.
        self.assertEqual(len(parsed["skipped"]), 1)
        self.assertIn("DE", parsed["skipped"][0]["reason"])

    def test_parser_reports_an_unusable_response_instead_of_inventing_records(self):
        self.assertIn(
            "not an object",
            dns_probe.parse_remote_measurement("nope", "www.example.com", "A")["skipped"][0]["reason"],
        )
        self.assertIn(
            "no probe results",
            dns_probe.parse_remote_measurement({"results": []}, "www.example.com", "A")["skipped"][0]["reason"],
        )

    def test_requests_are_limited_to_the_disclosed_host(self):
        for url in (
            "https://example.com/v1/measurements",
            "http://api.globalping.io/v1/measurements",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                dns_probe._remote_https_json("GET", url)


class RemoteDisclosureTests(unittest.TestCase):
    def _evidence(self, options, remote_fetcher):
        def runner(argv, **kwargs):
            raise FileNotFoundError(argv[0])

        return dns_probe.collect_evidence(
            "www.example.com", options, runner=runner, remote_fetcher=remote_fetcher,
        )

    def test_disclosure_is_recorded_when_no_region_was_requested(self):
        calls = []

        def fetcher(*args, **kwargs):
            calls.append(args)
            raise AssertionError("no region was requested")

        evidence = self._evidence({"layers": ["local"]}, fetcher)
        entries = [item for item in evidence["safety"] if item["id"] == "remote_query_disclosure"]

        self.assertEqual(calls, [])
        self.assertEqual(len(entries), 1)
        self.assertFalse(entries[0]["sent"])
        self.assertNotIn("remote_observations", evidence)

    def test_remote_records_and_disclosure_reach_the_evidence_file(self):
        observation = {
            "id": "remote_us_1", "layer": "regional", "role": "recursive",
            "vantage": "US", "resolver": "8.8.8.8", "transport": "udp",
            "qname": "www.example.com", "qtype": "A", "status": "NOERROR",
            "answers": [{"name": "www.example.com.", "type": "A", "value": "192.0.2.10"}],
        }
        disclosure = {
            "id": "remote_query_disclosure", "status": "warning", "sent": True,
            "endpoint": "api.globalping.io", "regions": ["US"],
            "sent_fields": ["queried name", "record type"], "message": "sent",
        }

        def fetcher(target, record_type, regions, acknowledged, **kwargs):
            self.assertEqual(regions, ["US"])
            self.assertTrue(acknowledged)
            return {
                "observations": [observation],
                "skipped": [],
                "disclosure": disclosure,
            }

        evidence = self._evidence(
            {"layers": ["local"], "regions": "us", "acknowledge_remote_query": True},
            fetcher,
        )

        self.assertEqual(evidence["remote_observations"], [observation])
        self.assertIn(disclosure, evidence["safety"])
        self.assertEqual(evidence["analysis_scope"]["regions"], ["US"])
        self.assertIn("regional", evidence["analysis_scope"]["layers"])


if __name__ == "__main__":
    unittest.main()
