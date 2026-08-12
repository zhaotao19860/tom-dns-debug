import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import dns_analyze
import dns_probe


def dig_output(status="NOERROR", answer_lines=(), flags="qr rd ra", authority_lines=()):
    sections = [
        "; <<>> DiG 9.18.1 <<>> +time=2 +tries=2 A example.com",
        ";; global options: +cmd",
        ";; Got answer:",
        ";; ->>HEADER<<- opcode: QUERY, status: {0}, id: 1234".format(status),
        ";; flags: {0}; QUERY: 1, ANSWER: {1}, AUTHORITY: {2}, ADDITIONAL: 1".format(
            flags, len(answer_lines), len(authority_lines)
        ),
        "",
        ";; OPT PSEUDOSECTION:",
        "; EDNS: version: 0, flags:; udp: 1232",
        ";; QUESTION SECTION:",
        ";example.com.\t\tIN\tA",
        "",
        ";; ANSWER SECTION:",
        *answer_lines,
        "",
        ";; AUTHORITY SECTION:",
        *authority_lines,
        "",
        ";; Query time: 12 msec",
        ";; SERVER: 10.0.0.53#53(10.0.0.53) (UDP)",
        ";; WHEN: Tue Aug 11 12:00:00 CST 2026",
        ";; MSG SIZE  rcvd: 56",
    ]
    return "\n".join(sections) + "\n"


def collector_runner(udp_output, tcp_output=None):
    tcp_output = udp_output if tcp_output is None else tcp_output

    def run(argv, **kwargs):
        if argv == ["dig", "-v"]:
            return subprocess.CompletedProcess(argv, 0, stdout="DiG 9.18.1\n", stderr="")
        output = tcp_output if "+tcp" in argv else udp_output
        return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

    return run


def collect_dig(udp_output, tcp_output=None):
    preflight = {
        "resolver_configuration": {
            "status": "collected",
            "source": "/etc/resolv.conf",
            "resolver_addresses": ["10.0.0.53"],
            "search_domains": ["corp.example"],
            "routing_domains": [],
        },
        "interfaces": {"status": "collected", "source": "socket.if_nameindex", "names": ["en0"]},
        "network_type": {"status": "unknown"},
        "proxy_doh_hints": {"status": "unknown", "proxy_environment_present": False},
    }
    preflight_skips = [{
        "id": "preflight_network_type",
        "reason": "network type is not available from portable standard-library APIs",
        "manual_command": "ip route show default",
        "execution": "user-executed only after review",
    }]
    with mock.patch.object(
        dns_probe,
        "_collect_platform_preflight",
        return_value=(preflight, preflight_skips),
    ):
        return dns_probe.collect_evidence(
            "example.com",
            {"capabilities": {"dig": True}, "region": "local", "deadline_s": 10},
            runner=collector_runner(udp_output, tcp_output),
        )


class CollectorAnalyzerProtocolTests(unittest.TestCase):
    def test_success_preserves_protocol_facts_and_report_content(self):
        evidence = collect_dig(dig_output(answer_lines=(
            "example.com.\t300\tIN\tA\t93.184.216.34",
        )))

        udp = evidence["probes"][0]
        self.assertNotIn("+short", udp["argv"])
        self.assertEqual(udp["qname"], "example.com")
        self.assertEqual(udp["qtype"], "A")
        self.assertEqual(udp["status"], "NOERROR")
        self.assertEqual(udp["flags"], ["qr", "rd", "ra"])
        self.assertFalse(udp["tc"])
        self.assertEqual(udp["role"], "recursive")
        self.assertEqual(udp["resolver_addresses"], ["10.0.0.53"])
        self.assertEqual(udp["answers"], [{
            "name": "example.com.", "ttl": 300, "class": "IN",
            "type": "A", "data": "93.184.216.34",
        }])

        findings = dns_analyze.classify_evidence(evidence)
        self.assertNotIn("missing_record", {item["category"] for item in findings})
        report = dns_analyze.render_report(evidence, findings)
        self.assertIn("NOERROR", report)
        self.assertIn("93.184.216.34", report)
        # Probe identifiers belong in the JSON bundle, not in the readable body.
        self.assertNotIn("dig_udp", report)

    def test_nxdomain_flows_to_exact_analyzer_category_and_report(self):
        evidence = collect_dig(dig_output(
            status="NXDOMAIN",
            authority_lines=("example.com. 60 IN SOA ns1.example. hostmaster.example. 1 3600 600 86400 60",),
        ))

        findings = dns_analyze.classify_evidence(evidence)
        finding = next(item for item in findings if item["category"] == "name_not_found")
        self.assertEqual(finding["status"], "confirmed")
        self.assertEqual(finding["supporting_probe_ids"], ["dig_udp", "dig_tcp"])
        self.assertNotIn("missing_record", {item["category"] for item in findings})
        self.assertIn("NXDOMAIN", dns_analyze.render_report(evidence, findings))

    def test_nodata_flows_to_exact_analyzer_category_and_report(self):
        evidence = collect_dig(dig_output(
            authority_lines=("example.com. 60 IN SOA ns1.example. hostmaster.example. 1 3600 600 86400 60",),
        ))

        findings = dns_analyze.classify_evidence(evidence)
        finding = next(item for item in findings if item["category"] == "missing_record")
        self.assertEqual(finding["supporting_probe_ids"], ["dig_udp", "dig_tcp"])
        self.assertNotIn("name_not_found", {item["category"] for item in findings})
        report = dns_analyze.render_report(evidence, findings)
        self.assertIn("NOERROR", report)
        self.assertIn("A", report)

    def test_servfail_flows_to_exact_analyzer_category_and_report(self):
        evidence = collect_dig(dig_output(status="SERVFAIL"))

        findings = dns_analyze.classify_evidence(evidence)
        finding = next(item for item in findings if item["category"] == "resolver_failure")
        self.assertEqual(finding["supporting_probe_ids"], ["dig_udp", "dig_tcp"])
        self.assertIn("SERVFAIL", dns_analyze.render_report(evidence, findings))

    def test_timeout_is_observed_without_becoming_nodata(self):
        def runner(argv, **kwargs):
            if argv == ["dig", "-v"]:
                return subprocess.CompletedProcess(argv, 0, stdout="DiG 9.18.1\n", stderr="")
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        with mock.patch.object(
            dns_probe,
            "_collect_platform_preflight",
            return_value=({"resolver_configuration": {"resolver_addresses": []}}, []),
        ):
            evidence = dns_probe.collect_evidence(
                "example.com",
                {"capabilities": {"dig": True}, "region": "local", "deadline_s": 10},
                runner=runner,
            )

        findings = dns_analyze.classify_evidence(evidence)
        timeout = next(item for item in findings if item["category"] == "query_timeout")
        self.assertEqual(timeout["supporting_probe_ids"], ["dig_udp", "dig_tcp"])
        self.assertNotIn("missing_record", {item["category"] for item in findings})
        self.assertIn("timeout", dns_analyze.render_report(evidence, findings).lower())

    def test_udp_tcp_outputs_form_one_exact_comparable_cohort(self):
        udp = dig_output(answer_lines=("example.com. 30 IN A 203.0.113.10",))
        tcp = dig_output(answer_lines=("example.com. 30 IN A 198.51.100.20",))
        evidence = collect_dig(udp, tcp)

        finding = next(
            item for item in dns_analyze.classify_evidence(evidence)
            if item["category"] == "transport_answer_divergence"
        )
        self.assertEqual(finding["supporting_probe_ids"], ["dig_udp", "dig_tcp"])
        self.assertEqual(evidence["probes"][0]["qname"], evidence["probes"][1]["qname"])
        self.assertEqual(evidence["probes"][0]["qtype"], evidence["probes"][1]["qtype"])

    def test_nslookup_success_excludes_server_address_from_dns_answers(self):
        output = (
            "Server:\t\t10.0.0.53\n"
            "Address:\t10.0.0.53#53\n\n"
            "Non-authoritative answer:\n"
            "Name:\texample.com\n"
            "Address: 93.184.216.34\n"
        )

        def runner(argv, **kwargs):
            if argv == ["nslookup", "-version"]:
                return subprocess.CompletedProcess(argv, 0, stdout="nslookup 9.18.1\n", stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

        with mock.patch.object(
            dns_probe,
            "_collect_platform_preflight",
            return_value=({"resolver_configuration": {"resolver_addresses": ["10.0.0.53"]}}, []),
        ):
            evidence = dns_probe.collect_evidence(
                "example.com", {"capabilities": {"nslookup": True}, "deadline_s": 10}, runner=runner
            )

        probe = evidence["probes"][0]
        self.assertEqual(probe["status"], "NOERROR")
        self.assertEqual([item["data"] for item in probe["answers"]], ["93.184.216.34"])

    def test_nslookup_nxdomain_reaches_name_not_found_without_server_address(self):
        output = (
            "Server:\t\t10.0.0.53\nAddress:\t10.0.0.53#53\n\n"
            "** server can't find absent.example: NXDOMAIN\n"
        )

        def runner(argv, **kwargs):
            if argv == ["nslookup", "-version"]:
                return subprocess.CompletedProcess(argv, 0, stdout="nslookup 9.18.1\n", stderr="")
            return subprocess.CompletedProcess(argv, 1, stdout=output, stderr="")

        with mock.patch.object(
            dns_probe,
            "_collect_platform_preflight",
            return_value=({"resolver_configuration": {"resolver_addresses": ["10.0.0.53"]}}, []),
        ):
            evidence = dns_probe.collect_evidence(
                "absent.example", {"capabilities": {"nslookup": True}, "deadline_s": 10}, runner=runner
            )

        probe = evidence["probes"][0]
        self.assertEqual(probe["status"], "NXDOMAIN")
        self.assertEqual(probe["answers"], [])
        finding = next(item for item in dns_analyze.classify_evidence(evidence) if item["category"] == "name_not_found")
        self.assertEqual(finding["supporting_probe_ids"], ["nslookup_udp", "nslookup_tcp"])

    def test_host_no_record_reaches_nodata_even_with_nonzero_exit(self):
        def runner(argv, **kwargs):
            if argv == ["host", "-V"]:
                return subprocess.CompletedProcess(argv, 0, stdout="host 9.18.1\n", stderr="")
            return subprocess.CompletedProcess(
                argv, 1, stdout="example.com has no A record\n", stderr=""
            )

        with mock.patch.object(
            dns_probe,
            "_collect_platform_preflight",
            return_value=({"resolver_configuration": {"resolver_addresses": ["10.0.0.53"]}}, []),
        ):
            evidence = dns_probe.collect_evidence(
                "example.com", {"capabilities": {"host": True}, "deadline_s": 10}, runner=runner
            )

        probe = evidence["probes"][0]
        self.assertEqual(probe["status"], "NOERROR")
        self.assertEqual(probe["answers"], [])
        finding = next(item for item in dns_analyze.classify_evidence(evidence) if item["category"] == "missing_record")
        self.assertEqual(finding["supporting_probe_ids"], ["host_udp", "host_tcp"])


class EvidenceSemanticsTests(unittest.TestCase):
    def test_parsed_cname_edges_distinguish_multihop_chain_from_real_cycle(self):
        valid = dns_probe._parse_dig_output(dig_output(answer_lines=(
            "example.com. 60 IN CNAME edge.example.",
            "edge.example. 60 IN CNAME origin.example.",
            "origin.example. 60 IN A 192.0.2.10",
        )), "example.com", "A")
        cycle = dns_probe._parse_dig_output(dig_output(answer_lines=(
            "example.com. 60 IN CNAME edge.example.",
            "edge.example. 60 IN CNAME example.com.",
        )), "example.com", "A")
        self.assertIsNotNone(valid)
        self.assertIsNotNone(cycle)
        self.assertEqual(valid["cname_edges"], [
            {"owner": "example.com", "target": "edge.example"},
            {"owner": "edge.example", "target": "origin.example"},
        ])

        valid["id"] = "valid-chain"
        cycle["id"] = "real-cycle"
        valid_categories = {
            item["category"] for item in dns_analyze.classify_evidence({"observations": [valid]})
        }
        cycle_finding = next(
            item for item in dns_analyze.classify_evidence({"observations": [cycle]})
            if item["category"] == "cname_loop"
        )
        self.assertNotIn("cname_loop", valid_categories)
        self.assertEqual(cycle_finding["supporting_probe_ids"], ["real-cycle"])

    def test_report_renders_nonzero_returncode_as_run_failure(self):
        evidence = {"target": "example.com", "observations": [{
            "id": "dig-failed", "qname": "example.com", "qtype": "A",
            "resolver": "system", "transport": "udp", "role": "recursive",
            "returncode": 9, "timed_out": False, "error": None,
        }]}
        report = dns_analyze.render_report(
            evidence, dns_analyze.classify_evidence(evidence)
        )

        self.assertIn("`dig-failed`", report)
        self.assertIn("命令以退出码 9 结束，属于运行异常", report)
        self.assertNotIn("execution=", report)

    def test_capture_truncation_is_not_the_dns_tc_flag(self):
        def runner(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout="abcdef", stderr="uvwxyz")

        result = dns_probe.run_probe(["dig", "example.com"], max_output_bytes=4, runner=runner)
        self.assertTrue(result["output_truncated"])
        self.assertNotIn("truncated", result)
        findings = dns_analyze.classify_evidence({"observations": [{
            "id": "capture-only", "qname": "example.com", "qtype": "A",
            "transport": "udp", "resolver": "system", "role": "recursive",
            "status": "NOERROR", "answers": [], "output_truncated": True, "tc": False,
        }]})
        categories = {item["category"] for item in findings}
        self.assertNotIn("truncation_or_edns_issue", categories)
        self.assertNotIn("missing_record", categories)

    def test_regional_gate_rejects_observations_outside_close_window(self):
        observations = []
        for vantage, answer, hour in (("north", "192.0.2.1", 0), ("south", "198.51.100.1", 2)):
            for suffix, minute in (("a", 0), ("b", 1)):
                observations.append({
                    "id": "{0}-{1}".format(vantage, suffix),
                    "qname": "cdn.example", "qtype": "A", "vantage": vantage,
                    "resolver": "public", "transport": "udp", "role": "recursive",
                    "status": "NOERROR", "answers": [answer],
                    "observed_at": "2026-08-11T{0:02d}:{1:02d}:00Z".format(hour, minute),
                })

        matrix = dns_analyze.compare_regional_answers(observations)
        self.assertFalse(matrix["sufficient_for_regional_claim"])
        categories = {item["category"] for item in dns_analyze.classify_evidence({"observations": observations})}
        self.assertNotIn("regional_answer_divergence", categories)
        self.assertNotIn("geodns_behavior", categories)

    def test_temporally_comparable_divergence_keeps_geodns_unverified(self):
        observations = []
        for vantage, answer, base_minute in (("north", "192.0.2.1", 0), ("south", "198.51.100.1", 2)):
            for suffix, delta in (("a", 0), ("b", 1)):
                observations.append({
                    "id": "{0}-{1}".format(vantage, suffix),
                    "qname": "cdn.example", "qtype": "A", "vantage": vantage,
                    "resolver": "public", "transport": "udp", "role": "recursive",
                    "status": "NOERROR", "answers": [answer],
                    "observed_at": "2026-08-11T12:{0:02d}:00Z".format(base_minute + delta),
                })

        findings = dns_analyze.classify_evidence({"observations": observations})
        regional = next(item for item in findings if item["category"] == "regional_answer_divergence")
        geodns = next(item for item in findings if item["category"] == "geodns_behavior")
        self.assertEqual(regional["status"], "confirmed")
        self.assertEqual(geodns["status"], "unverified")
        self.assertTrue(dns_analyze.compare_regional_answers(observations)["sufficient_for_regional_claim"])

    def test_txt_normalization_preserves_case_and_chunk_order(self):
        result = dns_analyze.compare_regional_answers([
            {
                "id": "north", "qname": "txt.example", "qtype": "TXT",
                "vantage": "north", "resolver": "public", "transport": "udp", "role": "recursive",
                "answers": [{"type": "TXT", "data": ["\"CaseSensitive\"", "\"PartTwo\""]}],
            },
            {
                "id": "south", "qname": "txt.example", "qtype": "TXT",
                "vantage": "south", "resolver": "public", "transport": "udp", "role": "recursive",
                "answers": [{"type": "TXT", "data": ["\"casesensitive\"", "\"PartTwo\""]}],
            },
        ])

        north_answer = result["groups"][0]["observations"][0]["answers"][0]
        self.assertEqual(north_answer, ["TXT", "\"CaseSensitive\"", "\"PartTwo\""])
        self.assertIn("answers", result["divergent_fields"])


class PreflightVersionAndBundleTests(unittest.TestCase):
    def test_resolv_conf_parser_preserves_actual_resolver_and_search_traceability(self):
        result = dns_probe._parse_resolv_conf(
            "nameserver 10.0.0.53\nnameserver 2001:db8::53\nsearch corp.example svc.example\n"
        )
        self.assertEqual(result["resolver_addresses"], ["10.0.0.53", "2001:db8::53"])
        self.assertEqual(result["search_domains"], ["corp.example", "svc.example"])
        self.assertEqual(result["routing_domains"], [])

    def test_collector_preserves_structured_preflight_and_reviewed_skips(self):
        evidence = collect_dig(dig_output(answer_lines=("example.com. 30 IN A 93.184.216.34",)))

        self.assertEqual(
            evidence["environment"]["preflight"]["resolver_configuration"]["resolver_addresses"],
            ["10.0.0.53"],
        )
        skipped = next(item for item in evidence["skipped"] if item["id"] == "preflight_network_type")
        self.assertEqual(skipped["execution"], "user-executed only after review")
        self.assertEqual(skipped["manual_command"], "ip route show default")

    def test_preflight_skips_unknown_actual_resolver_and_routing_domains(self):
        file_handle = mock.mock_open(read_data=b"search corp.example\n")
        with mock.patch.object(dns_probe.Path, "open", file_handle), mock.patch.object(
            dns_probe.platform, "system", return_value="Linux"
        ), mock.patch.object(dns_probe.socket, "if_nameindex", return_value=[(1, "lo")]):
            preflight, skipped = dns_probe._collect_platform_preflight()

        self.assertEqual(
            preflight["resolver_configuration"]["resolver_addresses"], []
        )
        skipped_by_id = {item["id"]: item for item in skipped}
        self.assertIn("preflight_resolver_configuration", skipped_by_id)
        self.assertIn("preflight_routing_domains", skipped_by_id)
        self.assertEqual(
            skipped_by_id["preflight_resolver_configuration"]["manual_command"],
            "resolvectl status",
        )

    def test_failed_tool_version_command_records_unavailable_version(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 1, stdout="not a version\n", stderr="unsupported option")

        versions = dns_probe._tool_versions(
            {"dig": True}, runner, dns_probe.time.monotonic() + 5, 1024
        )
        self.assertIn(["dig", "-v"], calls)
        self.assertIsNone(versions["dig"]["version"])
        self.assertEqual(versions["dig"]["error"], "version command exited 1")

    def test_powershell_version_is_not_automatically_executed(self):
        versions = dns_probe._tool_versions(
            {"powershell": True},
            lambda *args, **kwargs: self.fail("PowerShell must not execute automatically"),
            dns_probe.time.monotonic() + 5,
            1024,
        )
        self.assertIsNone(versions["powershell"]["version"])
        self.assertEqual(versions["powershell"]["error"], "version probe unsupported")

    def test_placeholder_distinguishes_all_execution_states(self):
        evidence = {
            "schema_version": "1.0",
            "probes": [
                {"id": "timeout", "timed_out": True, "returncode": None, "error": "timeout"},
                {"id": "execution", "timed_out": False, "returncode": None, "error": "FileNotFoundError"},
                {"id": "failed", "timed_out": False, "returncode": 9, "error": None},
                {"id": "completed", "timed_out": False, "returncode": 0, "error": None},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = dns_probe.write_bundle(evidence, Path(directory))
            markdown = Path(paths["markdown"]).read_text(encoding="utf-8")

        self.assertIn("- timeout: timeout", markdown)
        self.assertIn("- execution: execution-error", markdown)
        self.assertIn("- failed: failed-exit", markdown)
        self.assertIn("- completed: completed", markdown)


if __name__ == "__main__":
    unittest.main()
