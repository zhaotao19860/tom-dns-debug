import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_DIR = Path(__file__).resolve().parents[1]
PROBE = SKILL_DIR / "scripts" / "dns_probe.py"
ANALYZE = SKILL_DIR / "scripts" / "dns_analyze.py"
OPENAI_YAML = SKILL_DIR / "agents" / "openai.yaml"


def run_script(script, *arguments, env=None):
    return subprocess.run(
        [sys.executable, str(script), *map(str, arguments)],
        capture_output=True,
        text=True,
        timeout=15,
        env=env,
    )


class ProbeCliTests(unittest.TestCase):
    def test_probe_cli_help_is_available(self):
        result = run_script(PROBE, "--help")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--target", result.stdout)
        self.assertIn("--resolver", result.stdout)
        self.assertIn("--record-type", result.stdout)
        self.assertIn("--health-check", result.stdout)
        self.assertIn("--samples", result.stdout)
        self.assertIn("--no-public-resolvers", result.stdout)
        self.assertIn("--acknowledge-internal-public-query", result.stdout)
        self.assertIn("--baseline", result.stdout)
        self.assertIn("--dnssec", result.stdout)
        self.assertIn("--public-resolvers", result.stdout)
        self.assertIn("--trace", result.stdout)
        self.assertIn("--authoritative", result.stdout)
        self.assertIn("--regions", result.stdout)
        self.assertIn("--acknowledge-remote-query", result.stdout)

    def test_probe_cli_writes_degraded_bundle_without_external_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            env = dict(os.environ, PATH="")

            result = run_script(
                PROBE,
                "--target", "example.com",
                "--output-dir", output,
                "--region", "offline-test",
                "--resolver", "192.0.2.1",
                "--resolver", "2001:db8::53",
                "--record-type", "A",
                "--timeout", "1",
                "--no-public-resolvers",
                env=env,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            report_path = output / "dns-debug-report.json"
            self.assertTrue(report_path.is_file())
            evidence = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["environment"]["region"], "offline-test")
            self.assertEqual(evidence["record_type"], "A")
            self.assertEqual(evidence["resolvers"], ["192.0.2.1", "2001:db8::53"])
            self.assertEqual(evidence["probes"], [])
            self.assertTrue(evidence["skipped"])
            self.assertEqual(len({item["id"] for item in evidence["skipped"]}), len(evidence["skipped"]))

    def test_probe_cli_rejects_unsupported_record_type(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            result = run_script(
                PROBE,
                "--target", "example.com",
                "--output-dir", output,
                "--record-type", "MX",
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("record type", result.stderr.lower())
            self.assertFalse(output.exists())

    def test_probe_cli_rejects_invalid_resolver_before_probe_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "executed"
            fake_dig = root / "dig"
            fake_dig.write_text(
                "#!{0}\nfrom pathlib import Path\nPath({1!r}).write_text('ran')\n".format(
                    sys.executable, str(marker)
                ),
                encoding="utf-8",
            )
            fake_dig.chmod(0o755)
            result = run_script(
                PROBE,
                "--target", "example.com",
                "--output-dir", root / "bundle",
                "--resolver", "not-an-ip",
                env=dict(os.environ, PATH=str(root)),
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("ip literal", result.stderr.lower())
            self.assertFalse(marker.exists())

    def test_no_public_resolvers_rejects_public_resolver_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            result = run_script(
                PROBE,
                "--target", "example.com",
                "--output-dir", output,
                "--resolver", "1.1.1.1",
                "--no-public-resolvers",
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("public resolver", result.stderr.lower())
            self.assertFalse(output.exists())

    def test_probe_cli_rejects_remote_acknowledgement_without_regions(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            result = run_script(
                PROBE,
                "--target", "example.com",
                "--output-dir", output,
                "--acknowledge-remote-query",
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("--acknowledge-remote-query requires --regions", result.stderr)
            self.assertFalse(output.exists())

    def test_probe_cli_ignores_regions_without_the_remote_acknowledgement(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            result = run_script(
                PROBE,
                "--target", "example.com",
                "--output-dir", output,
                "--regions", "US,DE",
                "--no-public-resolvers",
                env=dict(os.environ, PATH=""),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("no name left this machine", result.stderr)
            evidence = json.loads(
                (output / "dns-debug-report.json").read_text(encoding="utf-8")
            )
            disclosure = next(
                item for item in evidence["safety"]
                if item["id"] == "remote_query_disclosure"
            )
            self.assertFalse(disclosure["sent"])
            self.assertNotIn("remote_observations", evidence)

    def test_probe_cli_refuses_remote_observation_for_an_internal_name(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            result = run_script(
                PROBE,
                "--target", "printer.local",
                "--output-dir", output,
                "--regions", "US",
                "--acknowledge-remote-query",
                "--no-public-resolvers",
                env=dict(os.environ, PATH=""),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("refused outright", result.stderr)
            evidence = json.loads(
                (output / "dns-debug-report.json").read_text(encoding="utf-8")
            )
            disclosure = next(
                item for item in evidence["safety"]
                if item["id"] == "remote_query_disclosure"
            )
            self.assertFalse(disclosure["sent"])
            self.assertTrue(any(
                "internal or private names" in item["reason"]
                for item in evidence["skipped"]
            ))

    def test_probe_cli_rejects_timeout_above_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            result = run_script(
                PROBE,
                "--target", "example.com",
                "--output-dir", output,
                "--timeout", "60",
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("timeout", result.stderr.lower())
            self.assertFalse(output.exists())

    def test_internal_target_public_resolver_requires_acknowledgement_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "executed"
            fake_dig = root / "dig"
            fake_dig.write_text(
                "#!{0}\nfrom pathlib import Path\nPath({1!r}).write_text('ran')\n".format(
                    sys.executable, str(marker)
                ),
                encoding="utf-8",
            )
            fake_dig.chmod(0o755)

            result = run_script(
                PROBE,
                "--target", "printer.local",
                "--output-dir", root / "bundle",
                "--resolver", "1.1.1.1",
                env=dict(os.environ, PATH=str(root)),
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("acknowledge", result.stderr.lower())
            self.assertFalse(marker.exists())

    def test_acknowledged_internal_public_query_warns_before_degraded_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            result = run_script(
                PROBE,
                "--target", "printer.local",
                "--output-dir", output,
                "--resolver", "1.1.1.1",
                "--acknowledge-internal-public-query",
                env=dict(os.environ, PATH=""),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("warning", result.stderr.lower())
            self.assertIn("disclose", result.stderr.lower())
            evidence = json.loads(
                (output / "dns-debug-report.json").read_text(encoding="utf-8")
            )
            warning = next(item for item in evidence["safety"] if item["id"] == "internal_name_exposure")
            self.assertEqual(warning["status"], "warning")


class AnalyzeCliTests(unittest.TestCase):
    def test_analyze_cli_help_is_available(self):
        result = run_script(ANALYZE, "--help")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--input", result.stdout)
        self.assertIn("--output", result.stdout)
        self.assertIn("--finalize-bundle", result.stdout)

    def test_analyze_cli_reads_json_and_writes_chinese_report_offline(self):
        evidence = {
            "schema_version": "1.0",
            "target": "missing.example",
            "observations": [{
                "id": "offline-nxdomain",
                "qname": "missing.example",
                "qtype": "A",
                "status": "NXDOMAIN",
                "answers": [],
                "resolver": "system",
                "transport": "udp",
                "vantage": "local",
                "role": "recursive",
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "evidence.json"
            output_path = Path(directory) / "analysis.md"
            original = json.dumps(evidence, indent=2) + "\n"
            input_path.write_text(original, encoding="utf-8")
            result = run_script(ANALYZE, "--input", input_path, "--output", output_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            report = output_path.read_text(encoding="utf-8")
            self.assertIn("# DNS \u8bca\u65ad\u62a5\u544a", report)
            self.assertIn("NXDOMAIN", report)
            # The readable report names no probe ids; it points at the JSON for them.
            self.assertNotIn("offline-nxdomain", report)
            self.assertIn("dns-debug-report.json", report)
            self.assertEqual(input_path.read_text(encoding="utf-8"), original)

    def test_analyze_cli_requires_existing_json_input(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            output = Path(directory) / "analysis.md"
            result = run_script(ANALYZE, "--input", missing, "--output", output)

            self.assertEqual(result.returncode, 2)
            self.assertIn("existing json", result.stderr.lower())
            self.assertFalse(output.exists())

    def test_analyze_cli_rejects_same_input_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "evidence.json"
            input_path.write_text("{}\n", encoding="utf-8")
            result = run_script(ANALYZE, "--input", input_path, "--output", input_path)

            self.assertEqual(result.returncode, 2)
            self.assertIn("different paths", result.stderr.lower())
            self.assertEqual(input_path.read_text(encoding="utf-8"), "{}\n")

    def test_two_cli_finalize_flow_keeps_canonical_bundle_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            probe_result = run_script(
                PROBE,
                "--target", "example.com",
                "--output-dir", bundle,
                "--no-public-resolvers",
                env=dict(os.environ, PATH=""),
            )
            self.assertEqual(probe_result.returncode, 0, probe_result.stderr)

            analyze_result = run_script(
                ANALYZE,
                "--input", bundle / "dns-debug-report.json",
                "--output", bundle / "dns-debug-report.md",
                "--finalize-bundle",
            )

            self.assertEqual(analyze_result.returncode, 0, analyze_result.stderr)
            evidence = json.loads(
                (bundle / "dns-debug-report.json").read_text(encoding="utf-8")
            )
            markdown = (bundle / "dns-debug-report.md").read_text(encoding="utf-8")
            self.assertTrue(evidence["findings"])
            self.assertIn("# DNS \u8bca\u65ad\u62a5\u544a", markdown)
            self.assertNotIn("# DNS Debug Report", markdown)
            self.assertTrue((bundle / "commands.json").is_file())
            self.assertTrue((bundle / "raw" / "summary.json").is_file())


class MetadataTests(unittest.TestCase):
    def test_openai_metadata_is_deterministic_and_dependency_free(self):
        expected = (
            "interface:\n"
            "  display_name: \"DNS Debug\"\n"
            "  short_description: \"Read-only DNS checks across resolver, DNSSEC, public DNS, delegation, and authoritative layers\"\n"
            "  default_prompt: \"Use $tom-dns-debug to check DNS health or diagnose failures, hijacking, poisoning, DNSSEC problems, and regional anomalies with bounded local evidence.\"\n"
        )

        self.assertEqual(OPENAI_YAML.read_text(encoding="utf-8"), expected)
        self.assertNotIn("dependencies:", expected)


if __name__ == "__main__":
    unittest.main()
