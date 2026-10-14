import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location("security_report", Path(__file__).parents[1] / "security_report.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReportTests(unittest.TestCase):
    def test_gitleaks_parser_fields_and_redaction(self):
        raw = [{"RuleID": "test-rule", "File": "fixture.txt", "StartLine": 3,
                "Commit": "a" * 40, "Secret": "source content must not survive",
                "Match": "source content must not survive", "Message": "private commit text",
                "Description": "untrusted free text", "Author": "private author"}]
        safe, count = module.transform("gitleaks", raw)
        self.assertEqual(count, 1)
        self.assertTrue(safe[0]["Description"])
        self.assertEqual(safe[0]["Secret"], "REDACTED")
        self.assertEqual(safe[0]["Match"], "REDACTED")
        self.assertEqual(safe[0]["Message"], "REDACTED")
        self.assertNotIn("must not survive", json.dumps(safe))
        self.assertNotIn("Author", safe[0])

    def test_gitleaks_rejects_null_and_missing_locations(self):
        for data in (None, [{}], {}):
            with self.assertRaises((ValueError, KeyError)):
                module.transform("gitleaks", data)

    def test_semgrep_does_not_hide_operational_errors(self):
        with self.assertRaises(ValueError):
            module.transform("semgrep", {"results": [], "errors": [{"type": "ParseError"}]})
        safe, count = module.transform("semgrep", {"results": [], "errors": []})
        self.assertEqual(count, 0)
        self.assertEqual(safe["results"], [])

    def test_semgrep_partial_warning_is_preserved(self):
        safe, count = module.transform("semgrep", {
            "results": [], "errors": [{
                "type": ["PartialParsing", []], "level": "warn", "path": "fixture.sh",
                "message": "untrusted source text",
            }],
        })
        self.assertEqual(count, 0)
        self.assertEqual(len(safe["errors"]), 1)
        self.assertNotIn("untrusted source text", json.dumps(safe))

    def test_trivy_preserves_counts_and_redacts_context(self):
        raw = {"SchemaVersion": 2, "ArtifactName": "test", "Results": [{
            "Secrets": [{"Match": "private content", "Code": {"Lines": []}}],
            "Misconfigurations": [{"CauseMetadata": {"Code": {"Lines": ["private content"]}}}],
            "Vulnerabilities": [{"VulnerabilityID": "CVE-0000-0000"}],
        }]}
        safe, count = module.transform("trivy", raw)
        self.assertEqual(count, 3)
        self.assertNotIn("private content", json.dumps(safe))

    def test_threagile_rejects_unrelated_json(self):
        for data in ({}, [{"title": "not a risks report"}]):
            with self.assertRaises(ValueError):
                module.transform("threagile", data)

    def test_zap_json_and_xml_exclude_evidence_and_url_credentials(self):
        raw = {"site": [{"@name": "http://backend:5000", "alerts": [{
            "pluginid": "1", "alert": "Test", "riskcode": "1", "desc": "Scanner description",
            "instances": [{"uri": "http://user:password@backend:5000/api?private=value#fragment",
                           "evidence": "private evidence", "requestbody": "private request"}],
        }]}]}
        safe, count = module.transform("zap", raw)
        self.assertEqual(count, 1)
        encoded = json.dumps(safe)
        for text in ("password", "private=value", "private evidence", "private request"):
            self.assertNotIn(text, encoded)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "zap.xml"
            module.zap_xml(safe, path)
            self.assertEqual(len(ET.parse(path).findall("site/alerts/alertitem")), 1)

    def test_collector_accepts_complete_run_and_rejects_hash_sha_and_run(self):
        import argparse
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha = "a" * 40
            contents = {
                "gitleaks": [],
                "semgrep": {"results": [], "errors": []},
                "trivy-high": {"SchemaVersion": 2, "ArtifactName": "test", "Results": []},
                "trivy-low": {"SchemaVersion": 2, "ArtifactName": "test", "Results": []},
                "threagile": [],
                "zap": {"site": []},
            }
            for key, content in contents.items():
                folder = root / ("tp18-" + key + "-" + sha)
                folder.mkdir()
                report = folder / "report.json"
                report.write_text(json.dumps(content))
                manifest = {
                    "tool": key.split("-")[0], "sha": sha, "run_id": "1",
                    "execution": "completed", "working_tree_dirty": False, "findings": 0,
                    "reports": [{"file": "report.json", "sha256": hashlib.sha256(report.read_bytes()).hexdigest()}],
                }
                (folder / "manifest.json").write_text(json.dumps(manifest))
            args = argparse.Namespace(source=str(root), destination=str(root / "output"))
            with patch.dict(os.environ, {"GITHUB_SHA": sha, "GITHUB_RUN_ID": "1"}, clear=True):
                module.collect(args)
                index = json.loads((root / "output/collection-index.json").read_text())
                self.assertEqual(len(index["reports"]), 6)
                manifest_path = root / ("tp18-gitleaks-" + sha) / "manifest.json"
                original = json.loads(manifest_path.read_text())
                for field, value in (("sha", "b" * 40), ("run_id", "2")):
                    changed = dict(original)
                    changed[field] = value
                    manifest_path.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):
                        module.collect(args)
                manifest_path.write_text(json.dumps(original))
                (manifest_path.parent / "report.json").write_text("modified")
                with self.assertRaises(ValueError):
                    module.collect(args)

    def test_missing_collection_fails_and_lists_missing_bundles(self):
        import argparse
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = argparse.Namespace(source=str(root / "missing"), destination=str(root / "output"))
            with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}, clear=True):
                with self.assertRaises(ValueError):
                    module.collect(args)
            index = json.loads((root / "output/collection-index.json").read_text())
            self.assertEqual(len(index["errors"]), 6)
            self.assertFalse(index["reports"])


if __name__ == "__main__":
    unittest.main()
