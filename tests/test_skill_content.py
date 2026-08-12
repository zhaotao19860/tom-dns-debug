import re
import unittest
from pathlib import Path


SKILL_DIR = Path(__file__).resolve().parents[1]
SKILL_PATH = SKILL_DIR / "SKILL.md"


class SkillContentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SKILL_PATH.read_text(encoding="utf-8")
        cls.lower = cls.text.lower()

    def test_frontmatter_is_trigger_only_and_skill_is_concise(self):
        match = re.match(r"\A---\n(.*?)\n---\n", self.text, re.DOTALL)
        self.assertIsNotNone(match)
        fields = {}
        for line in match.group(1).splitlines():
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
        self.assertEqual(set(fields), {"name", "description"})
        self.assertEqual(fields["name"], "tom-dns-debug")
        self.assertTrue(fields["description"].startswith("Use when"))
        for workflow_word in ("collects", "runs probes", "analyzes", "renders", "workflow"):
            self.assertNotIn(workflow_word, fields["description"].lower())
        self.assertLess(len(self.text.splitlines()), 500)

    def test_main_skill_routes_heavy_contract_and_stays_under_word_budget(self):
        contract = SKILL_DIR / "references" / "evidence-and-report.md"

        self.assertTrue(contract.is_file())
        self.assertIn("references/evidence-and-report.md", self.text)
        # Raised from 900: the baseline layer table and the remote-observation
        # disclosure have to be readable in the main file, because a reader deciding
        # what this skill may send off the machine cannot be sent to a reference.
        self.assertLess(len(self.text.split()), 1100)

    def test_skill_documents_the_baseline_layers(self):
        for phrase in (
            "--baseline", "--dnssec", "--public-resolvers", "--trace",
            "--authoritative", "8.8.8.8", "180.76.76.76", "114.114.114.114",
            "delegation", "authoritative", "local resolver",
        ):
            self.assertIn(phrase, self.lower)

    def test_remote_observation_requires_both_switches_and_refuses_internal_names(self):
        for phrase in (
            "--regions", "--acknowledge-remote-query", "api.globalping.io",
            "only the queried name and record type",
            "never sends collected evidence",
            "refused even when acknowledged",
            "remote_query_disclosure",
        ):
            self.assertIn(phrase, self.lower)
        # The outbound exception is scoped to that one endpoint; the no-upload
        # promises stay verbatim.
        self.assertIn(
            "call vendor apis except the disclosed remote-observation endpoint",
            self.lower,
        )
        self.assertIn("no upload by the skill", self.lower)
        self.assertIn("never upload or send automatically", self.lower)

    def test_skill_has_trigger_safety_and_regional_handoff_sections(self):
        for phrase in (
            "read-only", "regional", "manual", "dns_probe.py", "dns_analyze.py",
            "no upload", "session notice", "automatic", "internal-name exposure",
            "public resolver", "authoritative", "stable", "comparable", "two vantage",
            "anycast", "approximate", "geodns", "not proof of hijacking",
            "evidence citation", "chinese report",
        ):
            self.assertIn(phrase, self.lower)

    def test_skill_forbids_privileged_or_mutating_diagnostics(self):
        for phrase in (
            "never use sudo", "never modify configuration", "never clear caches",
            "never restart services", "never capture packets", "protected logs",
        ):
            self.assertIn(phrase, self.lower)

    def test_automatic_execution_is_limited_to_script_allowlist(self):
        for phrase in (
            "automatic execution is limited to `collect_evidence` and argv accepted by `run_probe`",
            "unsupported commands are user-executed only after review",
        ):
            self.assertIn(phrase, self.lower)
        for name in (
            "dnssec-delegation.md", "transport-and-edns.md", "local-and-platform.md",
        ):
            text = (SKILL_DIR / "references" / name).read_text(encoding="utf-8").lower()
            self.assertIn("user-executed only after review", text)
            self.assertIn("must not execute", text)

    def test_session_notice_has_complete_scope_and_duration(self):
        for phrase in (
            "normalized target", "expected duration", "concrete query scope",
            "public resolvers are included or excluded", "output directory",
            "no configuration or system changes", "no automatic upload or transmission",
        ):
            self.assertIn(phrase, self.lower)

    def test_collector_receives_normalized_string_not_mapping(self):
        for snippet in (
            "raw_input =",
            "normalized = normalize_target(raw_input)",
            'probe_target = normalized["hostname"] or normalized["ip"]',
            "collect_evidence(probe_target, options)",
            "never pass the normalized mapping",
        ):
            self.assertIn(snippet.lower(), self.lower)

    def test_raw_input_is_discarded_immediately_after_normalization(self):
        for phrase in (
            "use raw input only as the immediate argument to `normalize_target`",
            "del raw_input",
            "retain only `probe_target` and non-sensitive normalized fields",
            "never store or repeat url-only material",
        ):
            self.assertIn(phrase, self.lower)
        self.assertNotIn("retain the raw input", self.lower)
        normalized_at = self.lower.index("normalized = normalize_target(raw_input)")
        discard_at = self.lower.index("del raw_input")
        target_at = self.lower.index('probe_target = normalized["hostname"] or normalized["ip"]')
        self.assertLess(normalized_at, discard_at)
        self.assertLess(discard_at, target_at)

    def test_missing_tools_and_no_terminal_use_user_run_fallback(self):
        for phrase in (
            "missing supported tools", "use the available supported fallback automatically",
            "if no supported tool exists", "user-run command sheet",
            "record every skipped reason", "do not install anything",
        ):
            self.assertIn(phrase, self.lower)

    def test_handoff_is_explicit_and_user_controlled(self):
        for phrase in (
            "after local privacy review", "the user may choose",
            "paste or share selected redacted content", "never upload or send automatically",
        ):
            self.assertIn(phrase, self.lower)

    def test_skill_routes_all_references_conditionally(self):
        routes = {
            "references/diagnosis-playbook.md": "load when status codes",
            "references/dnssec-delegation.md": "load when delegation",
            "references/transport-and-edns.md": "load when udp",
            "references/local-and-platform.md": "load when local",
        }
        for path, condition in routes.items():
            self.assertIn("[", self.text)
            self.assertIn(path, self.text)
            self.assertIn(condition, self.lower)
            self.assertTrue((SKILL_DIR / path).exists())

    def test_skill_names_real_script_interfaces_and_contracts(self):
        for phrase in (
            "normalize_target", "detect_capabilities", "build_probe_plan", "run_probe",
            "collect_evidence", "write_bundle", "compare_regional_answers",
            "classify_evidence", "render_report", "schema_version", "probes", "skipped",
            "safety", "supporting_probe_ids", "contradictory_probe_ids", "next_checks",
        ):
            self.assertIn(phrase.lower(), self.lower)

    def test_skill_documents_cli_and_preserves_module_and_manual_fallbacks(self):
        for phrase in (
            "python3 scripts/dns_probe.py --target",
            "--output-dir",
            "--record-type a",
            "--no-public-resolvers",
            "python3 scripts/dns_analyze.py --input",
            "--finalize-bundle",
            "dns-debug-report.md",
            "--acknowledge-internal-public-query",
            "importable module interfaces",
            "no terminal",
            "user-run command sheet",
        ):
            self.assertIn(phrase, self.lower)
        self.assertNotIn("scripts are python modules, not command-line programs", self.lower)
        self.assertNotIn("do not invent cli flags", self.lower)

    def test_skill_covers_required_dns_and_environment_dimensions(self):
        for phrase in (
            "linux", "macos", "windows", "bind", "unbound", "dnsmasq",
            "systemd-resolved", "coredns", "kubernetes", "nxdomain", "nodata",
            "servfail", "refused", "a/aaaa", "cname", "mx", "txt", "srv", "caa",
            "ptr", "ns", "soa", "ds", "dnskey", "rrsig", "glue", "lame",
            "dnssec", "udp", "tcp", "edns", "mtu", "ipv4", "ipv6", "vpn",
            "split dns", "doh", "multi-interface", "same evidence schema",
        ):
            self.assertIn(phrase, self.lower)

    def test_references_are_short_tables_and_contain_no_external_automation(self):
        for name in (
            "diagnosis-playbook.md", "dnssec-delegation.md",
            "transport-and-edns.md", "local-and-platform.md",
        ):
            text = (SKILL_DIR / "references" / name).read_text(encoding="utf-8")
            self.assertIn("|", text)
            self.assertIn("decision", text.lower())
            self.assertLess(len(text.splitlines()), 220)
            for forbidden in ("curl ", "wget ", "api key", "access token", "mcp server"):
                self.assertNotIn(forbidden, text.lower())


if __name__ == "__main__":
    unittest.main()
