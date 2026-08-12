import json
import sys
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import dns_analyze


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def load_fixture(name):
    return json.loads((FIXTURES_DIR / (name + ".json")).read_text(encoding="utf-8"))


def successful_probe(identifier, transport, duration_ms=5):
    parsed = {
        "qname": "www.example.com",
        "qtype": "A",
        "status": "NOERROR",
        "answers": ["192.0.2.80"],
        "ttls": [120],
        "flags": ["qr", "rd", "ra"],
        "tc": False,
    }
    return {
        "id": identifier,
        "executed": True,
        "resolver": "system",
        "resolver_addresses": ["192.0.2.53"],
        "transport": transport,
        "duration_ms": duration_ms,
        **parsed,
        "parsed": parsed,
    }


class HealthyResolutionTests(unittest.TestCase):
    def test_matching_udp_and_tcp_success_is_confirmed_without_regional_noise(self):
        evidence = {
            "target": {"hostname": "www.example.com", "ip": None, "is_url": False},
            "environment": {"region": None},
            "probes": [successful_probe("dig_udp", "udp"), successful_probe("dig_tcp", "tcp")],
        }

        findings = dns_analyze.classify_evidence(evidence)

        successful = [item for item in findings if item["category"] == "resolution_succeeded"]
        self.assertEqual(len(successful), 1)
        self.assertEqual(successful[0]["status"], "confirmed")
        self.assertEqual(successful[0]["supporting_probe_ids"], ["dig_udp", "dig_tcp"])
        self.assertNotIn(
            "insufficient_regional_evidence",
            {item["category"] for item in findings},
        )

    def test_region_label_keeps_regional_evidence_gate_active(self):
        evidence = {
            "target": {"hostname": "www.example.com", "ip": None, "is_url": False},
            "environment": {"region": "north"},
            "probes": [successful_probe("dig_udp", "udp")],
        }

        categories = {item["category"] for item in dns_analyze.classify_evidence(evidence)}

        self.assertIn("insufficient_regional_evidence", categories)

    def test_report_uses_readable_target_and_plain_language_facts(self):
        evidence = {
            "target": {"hostname": "www.example.com", "ip": None, "is_url": False},
            "environment": {"region": None},
            "probes": [
                successful_probe("dig_udp", "udp", duration_ms=7),
                successful_probe("dig_tcp", "tcp", duration_ms=8),
            ],
        }

        report = dns_analyze.render_report(
            evidence,
            dns_analyze.classify_evidence(evidence),
            language="zh-CN",
        )

        self.assertIn("**域名**：www.example.com", report)
        self.assertNotIn('域名**：{"hostname"', report)
        self.assertIn("缓存时间", report)
        self.assertIn("应答耗时", report)
        self.assertIn("192.0.2.53", report)
        # The report is read by non-specialists, so no machine-shaped evidence dumps.
        for machine_shape in ("qname=", "answers=[[", "provenance:", "resolver=system",
                              "transport=udp", "ttls=", "duration_ms="):
            self.assertNotIn(machine_shape, report)
        self.assertNotIn("没有足够的可比地域样本", report)
        self.assertIn("若业务仍异常", report)


class FixtureClassificationTests(unittest.TestCase):
    def test_nxdomain_is_not_reported_as_nodata(self):
        findings = dns_analyze.classify_evidence(load_fixture("nxdomain"))
        self.assertTrue(any(f["category"] == "name_not_found" for f in findings))
        self.assertFalse(any(f["category"] == "missing_record" for f in findings))

    def test_nodata_is_reported_as_missing_record(self):
        findings = dns_analyze.classify_evidence(load_fixture("nodata"))
        self.assertTrue(any(f["category"] == "missing_record" for f in findings))
        self.assertFalse(any(f["category"] == "name_not_found" for f in findings))

    def test_servfail_and_refused_remain_distinct_protocol_results(self):
        findings = dns_analyze.classify_evidence(load_fixture("servfail"))
        self.assertTrue(any(f["category"] == "resolver_failure" for f in findings))
        self.assertTrue(any(f["category"] == "query_refused" for f in findings))

    def test_dnssec_bogus_has_explicit_validation_finding(self):
        findings = dns_analyze.classify_evidence(load_fixture("dnssec-bogus"))
        finding = next(f for f in findings if f["category"] == "dnssec_validation_failure")
        self.assertEqual(finding["status"], "confirmed")
        self.assertIn("dnssec-validating", finding["supporting_probe_ids"])

    def test_udp_injection_is_high_probability_not_confirmed(self):
        findings = dns_analyze.classify_evidence(load_fixture("udp-injection"))
        finding = next(f for f in findings if f["category"] == "suspected_dns_injection")
        self.assertEqual(finding["status"], "high_probability")
        self.assertNotEqual(finding["status"], "confirmed")

    def test_geodns_divergence_is_not_called_hijacking(self):
        evidence = load_fixture("geodns")
        findings = dns_analyze.classify_evidence(evidence)
        self.assertTrue(any(f["category"] == "regional_answer_divergence" for f in findings))
        self.assertFalse(any("hijack" in f["category"] and f["status"] == "confirmed" for f in findings))
        observations = [dict(item, qname=evidence["target"]) for item in evidence["observations"]]
        self.assertTrue(
            dns_analyze.compare_regional_answers(observations)["sufficient_for_regional_claim"]
        )

    def test_delegation_mismatch_is_kept_separate(self):
        findings = dns_analyze.classify_evidence(load_fixture("delegation-mismatch"))
        self.assertTrue(any(f["category"] == "delegation_inconsistency" for f in findings))

    def test_every_finding_has_the_stable_contract(self):
        required = {
            "category", "severity", "confidence", "status", "summary",
            "supporting_probe_ids", "contradictory_probe_ids", "next_checks",
        }
        for fixture in FIXTURES_DIR.glob("*.json"):
            with self.subTest(fixture=fixture.name):
                findings = dns_analyze.classify_evidence(
                    json.loads(fixture.read_text(encoding="utf-8"))
                )
                self.assertTrue(findings)
                self.assertTrue(all(set(finding) == required for finding in findings))
                self.assertTrue(all(
                    finding["status"] in {"confirmed", "high_probability", "unverified"}
                    for finding in findings
                ))


class RegionalTests(unittest.TestCase):
    def test_udp_only_divergence_is_high_probability_injection(self):
        evidence = {
            "target": "www.example",
            "observations": [
                {"vantage": "affected", "resolver": "isp", "transport": "udp", "role": "recursive", "record_type": "A", "status": "NOERROR", "answers": ["203.0.113.10"]},
                {"vantage": "affected", "resolver": "isp", "transport": "tcp", "role": "recursive", "record_type": "A", "status": "NOERROR", "answers": ["198.51.100.20"]},
                {"vantage": "control", "resolver": "public", "transport": "udp", "role": "recursive", "record_type": "A", "status": "NOERROR", "answers": ["198.51.100.20"]},
            ]
        }
        findings = dns_analyze.classify_evidence(evidence)
        self.assertTrue(any(f["status"] == "high_probability" and "injection" in f["category"] for f in findings))

    def test_one_vantage_point_cannot_confirm_regional_incident(self):
        evidence = {"observations": [{"vantage": "affected", "resolver": "local", "transport": "udp", "answers": ["203.0.113.10"]}]}
        findings = dns_analyze.classify_evidence(evidence)
        self.assertTrue(any(f["status"] == "unverified" for f in findings))

    def test_regional_matrix_requires_two_vantage_points(self):
        result = dns_analyze.compare_regional_answers([
            {"vantage": "one", "resolver": "local", "answers": ["192.0.2.1"]},
        ])
        self.assertFalse(result["sufficient_for_regional_claim"])

    def test_regional_matrix_normalizes_dns_values_and_exposes_dimensions(self):
        result = dns_analyze.compare_regional_answers([
            {
                "id": "north-a", "vantage": "North", "resolver": "PUBLIC",
                "transport": "UDP", "role": "recursive", "qname": "Example.COM.",
                "qtype": "a", "status": "noerror", "answers": ["CDN.EXAMPLE."],
                "ttls": ["60"], "observed_at": "2026-08-11T12:00:00Z",
            },
            {
                "id": "north-a-repeat", "vantage": "north", "resolver": "public",
                "transport": "udp", "role": "recursive", "qname": "example.com",
                "record_type": "A", "status": "NOERROR", "answers": ["cdn.example"],
                "ttls": [60], "observed_at": "2026-08-11T12:01:00Z",
            },
            {
                "id": "south-a", "vantage": "south", "resolver": "public",
                "transport": "udp", "role": "recursive", "qname": "example.com",
                "record_type": "A", "status": "NOERROR", "answers": ["cdn.example"],
                "ttls": [60], "observed_at": "2026-08-11T12:02:00Z",
            },
            {
                "id": "south-a-repeat", "vantage": "SOUTH", "resolver": "PUBLIC",
                "transport": "UDP", "role": "recursive", "qname": "EXAMPLE.COM.",
                "qtype": "a", "status": "noerror", "answers": ["CDN.EXAMPLE."],
                "ttls": ["60"], "observed_at": "2026-08-11T12:03:00Z",
            },
            {
                "id": "south-tcp", "vantage": "south", "resolver": "public",
                "transport": "tcp", "role": "recursive", "qname": "example.com",
                "qtype": "A", "status": "NOERROR", "answers": ["cdn.example"],
                "ttls": [60], "observed_at": "2026-08-11T12:04:00Z",
            },
        ])
        self.assertTrue(result["sufficient_for_regional_claim"])
        self.assertEqual(result["dimensions"]["vantage"], ["north", "south"])
        self.assertEqual(result["dimensions"]["transport"], ["tcp", "udp"])
        self.assertNotIn("answers", result["divergent_fields"])
        self.assertNotIn("status", result["divergent_fields"])

    def test_inconsistent_answers_inside_each_vantage_do_not_confirm_regional_divergence(self):
        evidence = {
            "observations": [
                {"id": "north-a", "vantage": "north", "resolver": "a", "answers": ["192.0.2.1"]},
                {"id": "north-b", "vantage": "north", "resolver": "b", "answers": ["198.51.100.1"]},
                {"id": "south-a", "vantage": "south", "resolver": "a", "answers": ["192.0.2.1"]},
                {"id": "south-b", "vantage": "south", "resolver": "b", "answers": ["198.51.100.1"]},
            ]
        }
        findings = dns_analyze.classify_evidence(evidence)
        self.assertFalse(any(
            f["category"] == "regional_answer_divergence" and f["status"] == "confirmed"
            for f in findings
        ))

    def test_a_and_aaaa_queries_do_not_create_regional_or_geodns_findings(self):
        evidence = {
            "observations": [
                {"id": "north-a-1", "qname": "cdn.example", "qtype": "A", "vantage": "north", "resolver": "public", "transport": "udp", "role": "recursive", "answers": ["192.0.2.1"]},
                {"id": "north-a-2", "qname": "CDN.EXAMPLE.", "qtype": "a", "vantage": "north", "resolver": "public", "transport": "udp", "role": "recursive", "answers": ["192.0.2.1"]},
                {"id": "south-aaaa-1", "qname": "cdn.example", "qtype": "AAAA", "vantage": "south", "resolver": "public", "transport": "udp", "role": "recursive", "answers": ["2001:db8::1"]},
                {"id": "south-aaaa-2", "qname": "cdn.example.", "qtype": "aaaa", "vantage": "south", "resolver": "public", "transport": "udp", "role": "recursive", "answers": ["2001:db8::1"]},
            ]
        }
        categories = {finding["category"] for finding in dns_analyze.classify_evidence(evidence)}
        self.assertNotIn("regional_answer_divergence", categories)
        self.assertNotIn("geodns_behavior", categories)
        self.assertNotIn(
            "answers",
            dns_analyze.compare_regional_answers(evidence["observations"])["divergent_fields"],
        )
        self.assertFalse(
            dns_analyze.compare_regional_answers(evidence["observations"])["sufficient_for_regional_claim"]
        )

    def test_different_qnames_do_not_create_regional_or_geodns_findings(self):
        evidence = {
            "observations": [
                {"id": "north-1", "qname": "one.example", "qtype": "A", "vantage": "north", "resolver": "public", "transport": "udp", "role": "recursive", "answers": ["192.0.2.1"]},
                {"id": "north-2", "qname": "ONE.EXAMPLE.", "qtype": "A", "vantage": "north", "resolver": "public", "transport": "udp", "role": "recursive", "answers": ["192.0.2.1"]},
                {"id": "south-1", "qname": "two.example", "qtype": "A", "vantage": "south", "resolver": "public", "transport": "udp", "role": "recursive", "answers": ["198.51.100.1"]},
                {"id": "south-2", "qname": "two.example.", "qtype": "A", "vantage": "south", "resolver": "public", "transport": "udp", "role": "recursive", "answers": ["198.51.100.1"]},
            ]
        }
        categories = {finding["category"] for finding in dns_analyze.classify_evidence(evidence)}
        self.assertNotIn("regional_answer_divergence", categories)
        self.assertNotIn("geodns_behavior", categories)
        self.assertFalse(
            dns_analyze.compare_regional_answers(evidence["observations"])["sufficient_for_regional_claim"]
        )

    def test_confounded_dimensions_do_not_create_regional_or_geodns_findings(self):
        evidence = {
            "observations": [
                {"id": "north-1", "qname": "cdn.example", "qtype": "A", "vantage": "north", "resolver": "public-a", "transport": "udp", "role": "recursive", "answers": ["192.0.2.1"]},
                {"id": "north-2", "qname": "cdn.example", "qtype": "A", "vantage": "north", "resolver": "public-a", "transport": "udp", "role": "recursive", "answers": ["192.0.2.1"]},
                {"id": "south-1", "qname": "cdn.example", "qtype": "A", "vantage": "south", "resolver": "public-b", "transport": "tcp", "role": "authoritative", "answers": ["198.51.100.1"]},
                {"id": "south-2", "qname": "cdn.example", "qtype": "A", "vantage": "south", "resolver": "public-b", "transport": "tcp", "role": "authoritative", "answers": ["198.51.100.1"]},
            ]
        }
        categories = {finding["category"] for finding in dns_analyze.classify_evidence(evidence)}
        self.assertNotIn("regional_answer_divergence", categories)
        self.assertNotIn("geodns_behavior", categories)
        self.assertNotIn(
            "answers",
            dns_analyze.compare_regional_answers(evidence["observations"])["divergent_fields"],
        )
        self.assertFalse(
            dns_analyze.compare_regional_answers(evidence["observations"])["sufficient_for_regional_claim"]
        )

    def test_one_sample_per_vantage_is_not_stable_regional_evidence(self):
        evidence = {
            "observations": [
                {"id": "north", "qname": "cdn.example", "qtype": "A", "vantage": "north", "resolver": "public", "transport": "udp", "role": "recursive", "answers": ["192.0.2.1"]},
                {"id": "south", "qname": "cdn.example", "qtype": "A", "vantage": "south", "resolver": "public", "transport": "udp", "role": "recursive", "answers": ["198.51.100.1"]},
            ]
        }
        findings = dns_analyze.classify_evidence(evidence)
        self.assertFalse(any(
            finding["category"] == "regional_answer_divergence"
            and finding["status"] == "confirmed"
            for finding in findings
        ))
        self.assertFalse(
            dns_analyze.compare_regional_answers(evidence["observations"])["sufficient_for_regional_claim"]
        )

    def test_duplicate_probe_ids_do_not_count_as_repeated_regional_samples(self):
        north = {"id": "north", "qname": "cdn.example", "qtype": "A", "vantage": "north", "resolver": "public", "transport": "udp", "role": "recursive", "answers": ["192.0.2.1"]}
        south = {"id": "south", "qname": "cdn.example", "qtype": "A", "vantage": "south", "resolver": "public", "transport": "udp", "role": "recursive", "answers": ["198.51.100.1"]}
        findings = dns_analyze.classify_evidence({
            "observations": [north, dict(north), south, dict(south)],
        })
        self.assertFalse(any(
            finding["category"] == "regional_answer_divergence"
            and finding["status"] == "confirmed"
            for finding in findings
        ))

    def test_remote_observations_join_local_probes_and_reach_the_report(self):
        # Two countries, two probes each, one pinned resolver: exactly what the
        # comparison needs before it will say anything about geography at all.
        remote = [
            {
                "id": "remote_{0}_{1}".format(country.lower(), index),
                "layer": "regional", "role": "recursive", "vantage": country,
                "resolver": "8.8.8.8", "transport": "udp", "qname": "www.example.com",
                "qtype": "A", "status": "NOERROR",
                "observed_at": "2026-08-12T04:0{0}:00Z".format(index),
                "answers": [{"name": "www.example.com.", "type": "A", "value": address}],
            }
            for country, address in (("US", "192.0.2.10"), ("DE", "198.51.100.10"))
            for index in (1, 2)
        ]
        evidence = {
            "target": {"hostname": "www.example.com", "ip": None, "is_url": False},
            "environment": {"region": None},
            "collected_at": "2026-08-12T04:00:00Z",
            "analysis_scope": {"regional": True},
            "probes": [successful_probe("dig_udp", "udp"), successful_probe("dig_tcp", "tcp")],
            "remote_observations": remote,
            "safety": [{
                "id": "remote_query_disclosure", "status": "warning", "sent": True,
                "endpoint": "api.globalping.io", "regions": ["US", "DE"],
                "sent_fields": ["queried name", "record type"],
                "message": "sent",
            }],
        }

        matrix = dns_analyze.compare_regional_answers(remote)
        self.assertTrue(matrix["sufficient_for_regional_claim"])
        self.assertEqual(matrix["dimensions"]["vantage"], ["de", "us"])
        self.assertIn("answers", matrix["divergent_fields"])

        findings = dns_analyze.classify_evidence(evidence)
        self.assertTrue(any(
            finding["category"] == "regional_answer_divergence"
            and finding["status"] == "confirmed"
            for finding in findings
        ))

        report = dns_analyze.render_report(evidence, findings, language="zh-CN")
        self.assertIn("**别的地区问到什么**", report)
        self.assertIn("| DE | 198.51.100.10 |", report)
        self.assertIn("| US | 192.0.2.10 |", report)
        # The row lists addresses, never the raw name/type/value triple.
        self.assertNotIn("www.example.com.、A", report)


class RegionalReportWordingTests(unittest.TestCase):
    def _regional_evidence(self, de_addresses):
        observations = []
        for country, addresses in (("cn", ["103.235.46.102"]), ("de", de_addresses)):
            for index in (1, 2):
                observations.append({
                    "id": "remote-{0}-{1}".format(country, index),
                    "qname": "www.example.com", "qtype": "A", "record_type": "A",
                    "resolver": "8.8.8.8", "transport": "udp", "role": "recursive",
                    "layer": "regional", "vantage": country, "status": "NOERROR",
                    "answers": [
                        ["www.example.com", "A", address] for address in addresses
                    ],
                })
        return {"target": "www.example.com", "observations": observations}

    def _report(self, evidence):
        return dns_analyze.render_report(
            evidence, dns_analyze.classify_evidence(evidence), language="zh-CN",
        )

    def test_agreeing_regions_are_summarized_as_agreeing(self):
        report = self._report(self._regional_evidence(["103.235.46.102"]))

        # The overview row and the caveat must both match what the table shows; a caveat
        # about differing answers would contradict a run where every region agreed.
        self.assertIn("CN、DE 问到的地址相同", report)
        self.assertIn("各地区答案一致只代表这几个观测点", report)
        self.assertNotIn("各地区之间答案不同", report)
        self.assertNotIn("观测点：cn", report)

    def test_differing_regions_keep_the_cdn_caveat(self):
        report = self._report(self._regional_evidence(["198.51.100.7"]))

        self.assertIn("CN、DE 问到的地址不完全相同", report)
        self.assertIn("各地区之间答案不同", report)

    def test_a_send_that_happened_is_named_in_the_privacy_section(self):
        evidence = self._regional_evidence(["103.235.46.102"])
        evidence["safety"] = [{
            "id": "remote_query_disclosure", "status": "warning", "sent": True,
            "endpoint": "api.globalping.io", "regions": ["cn", "de"],
            "record_type": "A", "sent_fields": ["queried name", "record type"],
            "message": "sent",
        }]

        report = self._report(evidence)

        # The section contract is that it states whether anything left the machine, so a
        # run that did send something must not be summarized as "nothing was sent".
        self.assertIn("api.globalping.io", report)
        self.assertIn("域名与记录类型（A）", report)
        self.assertNotIn("全程没有向任何人发送内容", report)

    def test_a_run_with_no_send_says_so_plainly(self):
        report = self._report(self._regional_evidence(["103.235.46.102"]))

        self.assertIn("全程没有向任何人发送内容", report)
        self.assertNotIn("api.globalping.io", report)

    def test_record_types_the_remote_comparison_skipped_are_named(self):
        evidence = self._regional_evidence(["103.235.46.102"])
        evidence["observations"].append({
            "id": "local-aaaa", "qname": "www.example.com", "qtype": "AAAA",
            "record_type": "AAAA", "resolver": "system", "transport": "udp",
            "role": "recursive", "layer": "local", "status": "NOERROR",
            "answers": [["www.example.com", "AAAA", "2001:db8::1"]],
        })

        report = self._report(evidence)

        # "Every region agrees" must not be read as agreement about a type nobody asked
        # the remote probes for.
        self.assertIn("异地观测只对比了IPv4 地址记录（A）", report)
        self.assertIn("IPv6 地址记录（AAAA）没有在别的地区比对过", report)


class ConservativeEvidenceTests(unittest.TestCase):
    def test_numeric_rcode_is_classified_as_explicit_protocol_status(self):
        findings = dns_analyze.classify_evidence({
            "observations": [{
                "id": "rcode-3", "vantage": "north", "resolver": "public",
                "transport": "udp", "rcode": 3, "record_type": "A", "answers": [],
            }],
        })
        self.assertTrue(any(f["category"] == "name_not_found" for f in findings))

    def test_authoritative_evidence_outweighs_one_recursive_observation(self):
        evidence = {
            "target": "www.example",
            "observations": [
                {"id": "recursive", "vantage": "north", "resolver": "isp", "role": "recursive", "record_type": "A", "status": "NOERROR", "answers": ["203.0.113.8"]},
                {"id": "authoritative", "vantage": "north", "resolver": "ns1", "role": "authoritative", "record_type": "A", "status": "NOERROR", "answers": ["198.51.100.9"]},
            ]
        }
        findings = dns_analyze.classify_evidence(evidence)
        finding = next(f for f in findings if f["category"] == "resolver_authoritative_divergence")
        self.assertEqual(finding["status"], "high_probability")
        self.assertIn("authoritative", finding["supporting_probe_ids"])
        self.assertFalse(any("hijack" in f["category"] and f["status"] == "confirmed" for f in findings))

    def test_cname_loop_and_edns_truncation_are_distinct(self):
        evidence = {
            "observations": [
                {"id": "loop", "vantage": "north", "resolver": "public", "status": "SERVFAIL", "cname_chain": ["a.example.", "b.example.", "a.example."]},
                {"id": "udp-tc", "vantage": "north", "resolver": "public", "transport": "udp", "status": "NOERROR", "tc": True, "edns": {"enabled": True}},
                {"id": "tcp-full", "vantage": "north", "resolver": "public", "transport": "tcp", "status": "NOERROR", "answers": ["192.0.2.5"]},
            ]
        }
        findings = dns_analyze.classify_evidence(evidence)
        self.assertTrue(any(f["category"] == "cname_loop" for f in findings))
        self.assertTrue(any(f["category"] == "truncation_or_edns_issue" for f in findings))

    def test_collect_evidence_probe_shape_is_consumed_without_mutation(self):
        evidence = {
            "environment": {"region": "cn-north"},
            "probes": [{
                "id": "dig_udp", "resolver": "system", "transport": "udp",
                "parser_status": "parsed", "parsed": {"addresses": ["192.0.2.44"]},
            }],
        }
        original = json.loads(json.dumps(evidence))
        findings = dns_analyze.classify_evidence(evidence)
        self.assertTrue(findings)
        self.assertEqual(evidence, original)

    def test_ttl_inside_structured_answers_participates_in_comparison(self):
        result = dns_analyze.compare_regional_answers([
            {
                "id": "ttl-60", "qname": "ttl.example", "qtype": "A",
                "vantage": "north", "resolver": "public", "transport": "udp",
                "role": "recursive", "answers": [{"type": "A", "data": "192.0.2.1", "ttl": 60}],
            },
            {
                "id": "ttl-30", "qname": "ttl.example", "qtype": "A",
                "vantage": "south", "resolver": "public", "transport": "udp",
                "role": "recursive", "answers": [{"type": "A", "data": "192.0.2.1", "ttl": 30}],
            },
        ])
        self.assertIn("ttls", result["divergent_fields"])
        self.assertNotIn("answers", result["divergent_fields"])

    def test_transport_comparison_ignores_different_query_identity(self):
        evidence = {
            "observations": [
                {"id": "udp", "qname": "one.example", "qtype": "A", "vantage": "north", "resolver": "public", "transport": "udp", "role": "recursive", "answers": ["192.0.2.1"]},
                {"id": "tcp", "qname": "two.example", "qtype": "AAAA", "vantage": "north", "resolver": "public", "transport": "tcp", "role": "recursive", "answers": ["2001:db8::1"]},
            ]
        }
        categories = {finding["category"] for finding in dns_analyze.classify_evidence(evidence)}
        self.assertNotIn("transport_answer_divergence", categories)
        self.assertNotIn("suspected_dns_injection", categories)

    def test_recursive_authoritative_comparison_ignores_different_queries(self):
        evidence = {
            "observations": [
                {"id": "recursive", "qname": "one.example", "qtype": "A", "vantage": "north", "resolver": "public", "role": "recursive", "answers": ["192.0.2.1"]},
                {"id": "authoritative", "qname": "two.example", "qtype": "AAAA", "vantage": "north", "resolver": "ns1", "role": "authoritative", "answers": ["2001:db8::1"]},
            ]
        }
        categories = {finding["category"] for finding in dns_analyze.classify_evidence(evidence)}
        self.assertNotIn("resolver_authoritative_divergence", categories)

    def test_delegation_comparison_ignores_different_zones(self):
        evidence = {
            "observations": [
                {"id": "parent", "qname": "one.example", "role": "parent_delegation", "nameservers": ["ns1.old.example"]},
                {"id": "child", "qname": "two.example", "role": "child_authority", "nameservers": ["ns1.new.example"]},
            ]
        }
        categories = {finding["category"] for finding in dns_analyze.classify_evidence(evidence)}
        self.assertNotIn("delegation_inconsistency", categories)

    def test_nxdomain_contradictions_are_scoped_to_same_query_with_target_fallback(self):
        evidence = {
            "target": "same.example",
            "observations": [
                {"id": "nx", "qtype": "A", "status": "NXDOMAIN", "answers": []},
                {"id": "same", "record_type": "A", "status": "NOERROR", "answers": ["192.0.2.1"]},
                {"id": "other-name", "qname": "other.example", "qtype": "A", "status": "NOERROR", "answers": ["192.0.2.2"]},
                {"id": "other-type", "qtype": "AAAA", "status": "NOERROR", "answers": ["2001:db8::1"]},
            ]
        }
        finding = next(f for f in dns_analyze.classify_evidence(evidence) if f["category"] == "name_not_found")
        self.assertEqual(finding["contradictory_probe_ids"], ["same"])

    def test_nodata_and_dnssec_contradictions_are_scoped_to_same_query(self):
        evidence = {
            "observations": [
                {"id": "nodata", "qname": "empty.example", "qtype": "AAAA", "record_type": "AAAA", "status": "NOERROR", "answers": []},
                {"id": "nx-other-type", "qname": "empty.example", "qtype": "A", "status": "NXDOMAIN", "answers": []},
                {"id": "data-same", "qname": "empty.example", "qtype": "AAAA", "status": "NOERROR", "answers": ["2001:db8::8"]},
                {"id": "bogus", "qname": "signed.example", "qtype": "A", "status": "SERVFAIL", "dnssec": {"validation": "bogus"}},
                {"id": "ok-same", "qname": "signed.example", "qtype": "A", "status": "NOERROR", "answers": ["192.0.2.3"]},
                {"id": "ok-other", "qname": "other.example", "qtype": "A", "status": "NOERROR", "answers": ["192.0.2.4"]},
            ]
        }
        findings = dns_analyze.classify_evidence(evidence)
        nodata = next(f for f in findings if f["category"] == "missing_record")
        dnssec = next(f for f in findings if f["category"] == "dnssec_validation_failure")
        self.assertEqual(nodata["contradictory_probe_ids"], ["data-same"])
        self.assertEqual(dnssec["contradictory_probe_ids"], ["ok-same"])

    def test_standalone_udp_truncation_yields_clue(self):
        findings = dns_analyze.classify_evidence({
            "target": "large.example",
            "observations": [{
                "id": "udp-tc", "qtype": "DNSKEY", "vantage": "north",
                "resolver": "public", "transport": "udp", "role": "recursive",
                "status": "NOERROR", "tc": True,
            }],
        })
        self.assertTrue(any(f["category"] == "truncation_or_edns_issue" for f in findings))


class PublicResolverComparisonTests(unittest.TestCase):
    def _resolver_answers(self, **by_resolver):
        return {
            "target": "www.example.com",
            "observations": [
                {
                    "id": "public-{0}".format(resolver.replace(".", "-")),
                    "qname": "www.example.com", "qtype": "A", "resolver": resolver,
                    "transport": "udp", "vantage": "local", "role": "recursive",
                    "layer": "public", "status": "NOERROR",
                    "answers": [["www.example.com", "A", address] for address in addresses],
                }
                for resolver, addresses in by_resolver.items()
            ],
        }

    def test_identical_answers_across_resolvers_are_reported_as_agreement(self):
        evidence = self._resolver_answers(**{
            "8.8.8.8": ["192.0.2.10"], "1.1.1.1": ["192.0.2.10"],
        })

        findings = dns_analyze.classify_evidence(evidence)

        finding = next(f for f in findings if f["category"] == "public_resolver_agreement")
        self.assertEqual(finding["status"], "confirmed")
        self.assertEqual(len(finding["supporting_probe_ids"]), 2)

    def test_differing_answers_stay_unverified_and_name_no_cause(self):
        evidence = self._resolver_answers(**{
            "8.8.8.8": ["192.0.2.10"], "1.1.1.1": ["198.51.100.20"],
        })

        finding = next(
            item for item in dns_analyze.classify_evidence(evidence)
            if item["category"] == "public_resolver_divergence"
        )

        # CDN and per-region answers differ by design, so a difference alone is a clue.
        self.assertEqual(finding["status"], "unverified")
        self.assertEqual(
            finding["next_checks"],
            ["直接询问权威服务器，看每台解析器的答案是否都在权威给出的地址集合内。"],
        )

    def test_resolver_rcode_differences_and_empty_answers_are_reported(self):
        evidence = {
            "target": "www.example.com",
            "observations": [
                {
                    "id": "nx-1", "qname": "www.example.com", "qtype": "A",
                    "resolver": "8.8.8.8", "transport": "udp", "role": "recursive",
                    "status": "NXDOMAIN", "answers": [],
                },
                {
                    "id": "nx-2", "qname": "www.example.com", "qtype": "A",
                    "resolver": "8.8.8.8", "transport": "udp", "role": "recursive",
                    "status": "NXDOMAIN", "answers": [],
                },
                {
                    "id": "ok-1", "qname": "www.example.com", "qtype": "A",
                    "resolver": "1.1.1.1", "transport": "udp", "role": "recursive",
                    "status": "NOERROR", "answers": [],
                },
                {
                    "id": "ok-2", "qname": "www.example.com", "qtype": "A",
                    "resolver": "1.1.1.1", "transport": "udp", "role": "recursive",
                    "status": "NOERROR", "answers": [],
                },
            ],
        }

        finding = next(
            item for item in dns_analyze.classify_evidence(evidence)
            if item["category"] == "public_resolver_divergence"
        )
        self.assertEqual(finding["status"], "unverified")
        self.assertEqual(
            finding["supporting_probe_ids"], ["nx-1", "nx-2", "ok-1", "ok-2"]
        )

    def test_udp_tcp_differences_are_not_called_resolver_divergence(self):
        evidence = {
            "target": "www.example.com",
            "observations": [
                {
                    "id": "udp", "qname": "www.example.com", "qtype": "A",
                    "resolver": "8.8.8.8", "transport": "udp", "role": "recursive",
                    "status": "NOERROR", "answers": ["192.0.2.1"],
                },
                {
                    "id": "tcp", "qname": "www.example.com", "qtype": "A",
                    "resolver": "1.1.1.1", "transport": "tcp", "role": "recursive",
                    "status": "SERVFAIL", "answers": [],
                },
            ],
        }

        categories = {
            finding["category"] for finding in dns_analyze.classify_evidence(evidence)
        }
        self.assertNotIn("public_resolver_divergence", categories)

    def test_next_check_does_not_repeat_an_authoritative_query_already_run(self):
        evidence = self._resolver_answers(**{
            "8.8.8.8": ["192.0.2.10"], "1.1.1.1": ["198.51.100.20"],
        })
        evidence["observations"].append({
            "id": "authoritative", "qname": "www.example.com", "qtype": "A",
            "resolver": "192.0.2.53", "transport": "udp", "vantage": "local",
            "role": "authoritative", "layer": "authoritative", "status": "NOERROR",
            "answers": [["www.example.com", "A", "192.0.2.10"]],
        })

        finding = next(
            item for item in dns_analyze.classify_evidence(evidence)
            if item["category"] == "public_resolver_divergence"
        )

        self.assertEqual(
            finding["next_checks"],
            ["对照本报告“直接问权威服务器”一节，确认各解析器给出的答案都在权威给出的范围内。"],
        )

    def test_alias_only_authority_points_at_the_name_that_decides_the_address(self):
        evidence = self._resolver_answers(**{
            "8.8.8.8": ["192.0.2.10"], "1.1.1.1": ["198.51.100.20"],
        })
        evidence["observations"].append({
            "id": "authoritative", "qname": "www.example.com", "qtype": "A",
            "resolver": "192.0.2.53", "transport": "udp", "vantage": "local",
            "role": "authoritative", "layer": "authoritative", "status": "NOERROR",
            "answers": [["www.example.com", "CNAME", "www.example.net."]],
            "cname_chain": ["www.example.com.", "www.example.net."],
        })

        finding = next(
            item for item in dns_analyze.classify_evidence(evidence)
            if item["category"] == "public_resolver_divergence"
        )

        self.assertEqual(finding["next_checks"], [
            "权威服务器只给出别名，最终地址由 www.example.net 决定；"
            "对它单独跑一次检查即可取得权威地址集合。"
        ])


class MissingNameAdviceTests(unittest.TestCase):
    def test_missing_name_asks_the_authority_only_when_it_was_not_asked_yet(self):
        recursive_only = {
            "observations": [{
                "id": "local", "qname": "gone.example", "qtype": "A", "role": "recursive",
                "resolver": "system", "status": "NXDOMAIN", "answers": [],
            }],
        }
        finding = next(
            item for item in dns_analyze.classify_evidence(recursive_only)
            if item["category"] == "name_not_found"
        )
        self.assertIn("向权威服务器复核", finding["next_checks"][0])

    def test_authoritative_nxdomain_replaces_the_advice_for_every_record_type(self):
        evidence = {
            "observations": [
                {"id": "local-a", "qname": "gone.example", "qtype": "A", "role": "recursive",
                 "resolver": "system", "status": "NXDOMAIN", "answers": []},
                {"id": "local-aaaa", "qname": "gone.example", "qtype": "AAAA", "role": "recursive",
                 "resolver": "system", "status": "NXDOMAIN", "answers": []},
                {"id": "authority", "qname": "gone.example", "qtype": "A", "role": "authoritative",
                 "resolver": "192.0.2.53", "status": "NXDOMAIN", "answers": []},
            ],
        }

        findings = [
            item for item in dns_analyze.classify_evidence(evidence)
            if item["category"] == "name_not_found"
        ]

        # NXDOMAIN is about the name, not one record type, so the AAAA group must not
        # suggest a query the authority already answered.
        self.assertEqual(len(findings), 2)
        for finding in findings:
            self.assertEqual(len(finding["next_checks"]), 1)
            self.assertIn("权威服务器本身也说这个名称不存在", finding["next_checks"][0])


class ResolverFailureAdviceTests(unittest.TestCase):
    def _servfail_evidence(self, authoritative_answers):
        observations = [{
            "id": "local", "qname": "signed.example", "qtype": "A", "role": "recursive",
            "resolver": "system", "transport": "udp", "layer": "dnssec",
            "status": "SERVFAIL", "answers": [], "dnssec": {"validation": "bogus"},
        }]
        if authoritative_answers:
            observations.append({
                "id": "authority", "qname": "signed.example", "qtype": "A",
                "role": "authoritative", "resolver": "192.0.2.53", "transport": "udp",
                "layer": "authoritative", "status": "NOERROR",
                "answers": [["signed.example", "A", "192.0.2.7"]],
            })
        return {"target": "signed.example", "observations": observations}

    def _failure(self, evidence):
        return next(
            item for item in dns_analyze.classify_evidence(evidence)
            if item["category"] == "resolver_failure"
        )

    def test_a_reachable_authority_plus_bogus_signature_names_the_real_cause(self):
        # Both dead ends the generic advice offers are already ruled out by the same
        # report: the authority answered, and the signature verdict is confirmed bogus.
        finding = self._failure(self._servfail_evidence(True))

        self.assertIn("签名校验没通过", finding["summary"])
        self.assertEqual(len(finding["next_checks"]), 1)
        self.assertIn("按签名校验那一条处理", finding["next_checks"][0])
        self.assertNotIn("可达", finding["next_checks"][0])

    def test_without_an_authoritative_answer_the_generic_advice_stands(self):
        finding = self._failure(self._servfail_evidence(False))

        self.assertIn("判断不出原因", finding["summary"])
        self.assertIn("确认权威服务器是否可达", finding["next_checks"][0])


class RedactionAndReportTests(unittest.TestCase):
    def test_redact_text_removes_url_query_fragment_and_likely_secrets(self):
        value = (
            "see https://user:pass@example.com/check?token=do-not-leak#private "
            "password=hunter2 api_key: abc123 harmless=value"
        )
        redacted = dns_analyze.redact_text(value)
        for secret in ("user:pass", "do-not-leak", "private", "hunter2", "abc123"):
            self.assertNotIn(secret, redacted)
        self.assertIn("harmless=value", redacted)

    def test_redact_text_masks_common_compound_secret_names(self):
        redacted = dns_analyze.redact_text(
            "client_secret=do-not-leak refresh-token: also-secret"
        )
        self.assertNotIn("do-not-leak", redacted)
        self.assertNotIn("also-secret", redacted)

    def test_redact_text_masks_multi_token_basic_authorization(self):
        redacted = dns_analyze.redact_text("authorization: Basic dXNlcjpwYXNz")
        self.assertNotIn("dXNlcjpwYXNz", redacted)

    def test_chinese_report_uses_new_sections_limits_anycast_and_redacts(self):
        evidence = load_fixture("udp-injection")
        evidence["target"] = "https://example.com/check?token=do-not-leak#private"
        report = dns_analyze.render_report(
            evidence, dns_analyze.classify_evidence(evidence), language="zh-CN"
        )
        for section in (
            "## 结论", "## 检查项一览", "## 解析链路图", "## 查到了什么", "## 问题出在哪",
            "## 没查到的部分", "## 分享前请注意", "## 接下来可以做什么",
        ):
            self.assertIn(section, report)
        # Probe identifiers are machine bookkeeping; the prose cites how many queries saw
        # the behaviour and points at the JSON for the raw records.
        self.assertNotIn("affected-udp", report)
        self.assertIn("次查询记录到这一现象", report)
        self.assertIn("完整原始数据见同目录 `dns-debug-report.json`", report)
        self.assertIn("Anycast", report)
        self.assertIn("近似", report)
        self.assertNotIn("do-not-leak", report)
        self.assertNotIn("private", report)

    def test_cause_section_is_absent_when_nothing_is_wrong(self):
        evidence = {
            "target": {"hostname": "www.example.com", "ip": None, "is_url": False},
            "environment": {"region": None},
            "probes": [
                successful_probe("dig_udp", "udp"),
                successful_probe("dig_tcp", "tcp"),
            ],
        }
        report = dns_analyze.render_report(
            evidence, dns_analyze.classify_evidence(evidence), language="zh-CN"
        )

        self.assertNotIn("## 问题出在哪", report)
        self.assertIn("✅", report)

    def test_non_chinese_report_language_is_rejected(self):
        with self.assertRaises(ValueError):
            dns_analyze.render_report({}, [], language="en-US")

    def _refused_remote_evidence(self, reason_code):
        return {
            "target": "printer.local",
            "safety": [{
                "id": "remote_query_disclosure", "sent": False,
                "regions": ["US", "DE"], "reason_code": reason_code,
            }],
            "observations": [{
                "id": "local", "qname": "printer.local", "qtype": "A", "role": "recursive",
                "resolver": "system", "status": "NXDOMAIN", "answers": [],
            }],
        }

    def test_a_refused_remote_layer_is_named_instead_of_offering_the_flag(self):
        evidence = self._refused_remote_evidence("internal_name")

        report = dns_analyze.render_report(
            evidence, dns_analyze.classify_evidence(evidence), language="zh-CN"
        )

        self.assertIn("目标是内网名称，已直接拒绝", report)
        self.assertNotIn("需要的话加 `--regions US,DE`", report)

    def test_a_remote_layer_nobody_asked_for_still_offers_the_flag(self):
        evidence = self._refused_remote_evidence("internal_name")
        evidence["safety"][0]["regions"] = []

        report = dns_analyze.render_report(
            evidence, dns_analyze.classify_evidence(evidence), language="zh-CN"
        )

        self.assertIn("需要的话加 `--regions US,DE`", report)

    def test_a_walk_that_never_reached_the_name_is_not_called_normal(self):
        evidence = {
            "target": "printer.local",
            "observations": [{
                "id": "trace", "qname": "printer.local", "qtype": "A", "role": "trace",
                "layer": "trace", "resolver": "system",
                "delegation_chain": ["."],
                "hops": [{"level": 1, "zone": ".", "referral": True}],
            }],
        }

        report = dns_analyze.render_report(
            evidence, dns_analyze.classify_evidence(evidence), language="zh-CN"
        )

        self.assertIn("根服务器没有给出下一级委派", report)
        self.assertNotIn("每一跳都正常应答", report)


def observation(identifier, **overrides):
    record = {
        "id": identifier,
        "qname": "www.example.com",
        "qtype": "A",
        "status": "NOERROR",
        "answers": ["192.0.2.80"],
        "ttls": [120],
        "resolver": "system",
        "transport": "udp",
        "role": "recursive",
        "layer": "local",
    }
    record.update(overrides)
    return record


class PrivateAnswerTests(unittest.TestCase):
    """An off-net resolver handing back an internal address says where the answer works."""

    def _findings(self, observations, target="www.example.com"):
        evidence = {"target": target, "observations": observations}
        return {
            item["category"]: item
            for item in dns_analyze.classify_evidence(evidence)
        }

    def test_a_public_resolver_answering_with_an_rfc1918_address_is_flagged(self):
        finding = self._findings([
            observation("public-bad", layer="public", resolver="8.8.8.8",
                        answers=["10.6.145.191"]),
        ])["private_address_answer"]

        self.assertEqual(finding["severity"], "low")
        self.assertEqual(finding["status"], "high_probability")
        self.assertIn("10.6.145.191", finding["summary"])
        self.assertIn("8.8.8.8", finding["summary"])
        self.assertEqual(finding["supporting_probe_ids"], ["public-bad"])

    def test_the_machines_own_resolver_answering_that_way_is_not_flagged(self):
        """Split-horizon DNS on the local network is the normal case, not a fault."""
        categories = self._findings([
            observation("local", answers=["10.6.145.191"]),
        ])

        self.assertNotIn("private_address_answer", categories)

    def test_documentation_addresses_are_not_called_internal(self):
        categories = self._findings([
            observation("public-a", layer="public", resolver="8.8.8.8",
                        answers=["192.0.2.80"]),
        ])

        self.assertNotIn("private_address_answer", categories)

    def test_an_internal_target_expects_an_internal_answer(self):
        categories = self._findings([
            observation("public-a", qname="printer.local", layer="public",
                        resolver="8.8.8.8", answers=["10.6.145.191"]),
        ], target="printer.local")

        self.assertNotIn("private_address_answer", categories)


class TopologyDiagramTests(unittest.TestCase):
    """The diagram answers one question: which hop should the reader look at."""

    def _report(self, observations, target="www.example.com"):
        evidence = {"target": target, "observations": observations}
        return dns_analyze.render_report(
            evidence, dns_analyze.classify_evidence(evidence), language="zh-CN"
        )

    def _diagram(self, report):
        body = report.split("## 解析链路图", 1)[1]
        return body.split("\n## ", 1)[0]

    def _nodes(self, report):
        """Just the fenced picture, so the legend's own glyphs are not mistaken for nodes."""
        return self._diagram(report).split("```")[1]

    def test_the_diagram_sits_between_the_layer_table_and_the_findings(self):
        report = self._report([
            observation("local-udp"),
            observation("local-tcp", transport="tcp"),
        ])

        self.assertLess(report.index("## 检查项一览"), report.index("## 解析链路图"))
        self.assertLess(report.index("## 解析链路图"), report.index("## 查到了什么"))

    def test_client_recursive_and_authoritative_hops_all_appear(self):
        report = self._report([
            observation("local-udp", resolver_addresses=["192.0.2.53"]),
            observation("public-a", layer="public", resolver="8.8.8.8"),
            observation("regional-us", layer="regional", resolver="8.8.8.8", vantage="US"),
            observation("trace", role="trace", layer="trace", status=None, answers=[],
                        resolver="root_servers", hops=[
                {"level": 1, "zone": ".", "nameservers": ["a.root-servers.net."], "rtt_ms": 8},
                {"level": 2, "zone": "com", "nameservers": ["a.gtld-servers.net."], "rtt_ms": 20},
                {"level": 3, "zone": "example.com", "nameservers": ["ns1.example.com."]},
            ]),
            observation("auth", role="authoritative", layer="authoritative",
                        resolver="192.0.2.10", transport="udp"),
        ])
        diagram = self._diagram(report)

        self.assertIn("[你的电脑]　查 www.example.com", diagram)
        self.assertIn("本机默认解析器（192.0.2.53）", diagram)
        self.assertIn("公共 DNS", diagram)
        self.assertIn("8.8.8.8", diagram)
        self.assertIn("别的地区的解析器（异地观测）", diagram)
        self.assertIn("根服务器", diagram)
        self.assertIn("com", diagram)
        self.assertIn("example.com", diagram)
        self.assertIn("192.0.2.10", diagram)
        self.assertIn("节点含义", diagram)

    def test_a_healthy_chain_marks_nothing_and_says_so(self):
        report = self._report([
            observation("local-udp"),
            observation("local-tcp", transport="tcp"),
            observation("auth", role="authoritative", layer="authoritative",
                        resolver="192.0.2.10"),
        ])
        diagram = self._diagram(report)

        self.assertNotIn("**要看的节点**", diagram)
        self.assertNotIn("❌", self._nodes(report))
        self.assertNotIn("⚠️", self._nodes(report))
        self.assertIn("没有发现异常节点", diagram)

    def test_a_public_resolver_answering_with_an_internal_address_is_the_marked_node(self):
        diagram = self._diagram(self._report([
            observation("local-udp"),
            observation("public-bad", layer="public", resolver="198.51.100.9",
                        answers=["10.6.145.191"]),
        ]))

        self.assertIn("198.51.100.9 ⚠️", diagram)
        self.assertIn("**要看的节点**", diagram)
        self.assertIn("- 198.51.100.9：10.6.145.191（内网地址，公网到不了）", diagram)
        self.assertNotIn("- 本机默认解析器", diagram)

    def test_a_resolver_that_never_answered_is_marked_broken(self):
        diagram = self._diagram(self._report([
            observation("local-udp"),
            observation("public-dead", layer="public", resolver="198.51.100.9",
                        status="SERVFAIL", answers=[]),
        ]))

        self.assertIn("198.51.100.9 ❌", diagram)
        self.assertIn("**要看的节点**", diagram)

    def test_differing_addresses_are_stated_in_words_not_painted_on_every_hop(self):
        """Two resolvers disagreeing is a set-level fact; marking both hides the real ones."""
        report = self._report([
            observation("local-udp"),
            observation("public-a", layer="public", resolver="8.8.8.8",
                        answers=["198.51.100.7"]),
        ])
        diagram = self._diagram(report)

        self.assertNotIn("❓", self._nodes(report))
        self.assertNotIn("⚠️", self._nodes(report))
        self.assertNotIn("**要看的节点**", diagram)
        self.assertIn("地址不完全相同", diagram)
        self.assertIn("不等于被篡改", diagram)

    def test_matching_addresses_leave_the_divergence_note_out(self):
        diagram = self._diagram(self._report([
            observation("local-udp"),
            observation("public-a", layer="public", resolver="8.8.8.8"),
        ]))

        self.assertNotIn("地址不完全相同", diagram)

    def test_an_unverified_hop_is_never_counted_among_the_healthy_ones(self):
        """A walk from the root that ends without an answer settled nothing."""
        diagram = self._diagram(self._report([
            observation("trace", role="trace", layer="trace", status=None, answers=[],
                        resolver="root_servers", hops=[
                {"level": 1, "zone": ".", "nameservers": ["a.root-servers.net."]},
                {"level": 2, "zone": "com", "nameservers": ["a.gtld-servers.net."]},
            ]),
        ]))

        self.assertIn("com ❓", diagram)
        self.assertIn("没有节点被判定为有问题", diagram)
        self.assertIn("还没能得出结论的节点：com", diagram)
        self.assertNotIn("没有发现异常节点", diagram)

    def test_a_layer_with_no_evidence_produces_no_diagram(self):
        report = dns_analyze.render_report(
            {"target": "www.example.com", "observations": []}, [], language="zh-CN"
        )

        self.assertNotIn("## 解析链路图", report)

    def test_tree_glyphs_indent_children_under_the_right_parent(self):
        block = dns_analyze._tree_block([["first", "child"], ["second"]])

        self.assertEqual(block, ["├─ first", "│  child", "└─ second"])


if __name__ == "__main__":
    unittest.main()
