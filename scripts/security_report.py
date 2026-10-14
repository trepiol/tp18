#!/usr/bin/env python3
"""Validate and sanitize real scanner reports. Never invent missing reports."""
import argparse
import copy
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit
import xml.etree.ElementTree as ET

REDACTED = "REDACTED"
PARSERS = {
    "gitleaks": "Gitleaks Scan",
    "trivy": "Trivy Scan",
    "semgrep": "Semgrep JSON Report",
    "threagile": "Threagile risks report",
    "zap": "ZAP Scan",
}


def clean_url(value):
    parts = urlsplit(value)
    host = parts.hostname or ""
    if parts.port:
        host += ":" + str(parts.port)
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


def transform(tool, data):
    if tool == "gitleaks":
        if not isinstance(data, list):
            raise ValueError("Gitleaks report must be a list")
        safe = []
        for issue in data:
            for key in ("RuleID", "File", "StartLine"):
                if key not in issue:
                    raise ValueError("Missing Gitleaks location")
            commit = issue.get("Commit", "")
            if commit and not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise ValueError("Invalid commit metadata")
            safe.append({
                "Description": (
                    f"Secret detection rule {issue['RuleID']} at commit {commit or 'uncommitted'} "
                    f"range {issue['StartLine']}:{issue.get('StartColumn', 0)}-"
                    f"{issue.get('EndLine', issue['StartLine'])}:{issue.get('EndColumn', 0)}"
                ),
                "RuleID": issue["RuleID"],
                "File": issue["File"],
                "StartLine": int(issue["StartLine"]),
                "EndLine": int(issue.get("EndLine", issue["StartLine"])),
                "StartColumn": int(issue.get("StartColumn", 0)),
                "EndColumn": int(issue.get("EndColumn", 0)),
                "Commit": commit,
                "Fingerprint": issue.get("Fingerprint", ""),
                "Secret": REDACTED,
                "Match": REDACTED,
                "Message": REDACTED,
                "Tags": [],
            })
        return safe, len(safe)
    if tool == "semgrep":
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ValueError("Missing Semgrep results")
        warnings = []
        for error in data.get("errors") or []:
            kind = error.get("type")
            kind = kind[0] if isinstance(kind, list) else kind
            if error.get("level") != "warn" or kind != "PartialParsing":
                raise ValueError("Semgrep execution reported fatal errors")
            warnings.append({
                "type": "PartialParsing", "level": "warn",
                "path": error.get("path", ""),
                "message": "Nonfatal partial parsing warning; coverage is incomplete for this file.",
            })
        safe = []
        for issue in data["results"]:
            extra = issue["extra"]
            safe.append({
                "check_id": issue["check_id"], "path": issue["path"],
                "start": issue["start"], "end": issue["end"],
                "extra": {
                    "severity": extra["severity"],
                    "message": "Semgrep rule " + issue["check_id"],
                    "lines": REDACTED,
                    "metadata": {
                        key: extra.get("metadata", {})[key]
                        for key in ("cwe", "owasp", "references", "category")
                        if key in extra.get("metadata", {})
                    },
                    "fingerprint": extra.get("fingerprint", ""),
                },
            })
        return {"results": safe, "errors": warnings, "version": data.get("version")}, len(safe)
    if tool == "trivy":
        if not isinstance(data, dict) or data.get("SchemaVersion") != 2:
            raise ValueError("Unsupported Trivy schema")
        if not data.get("ArtifactName"):
            raise ValueError("Missing Trivy artifact identity")
        safe = copy.deepcopy(data)
        # ImageConfig can contain environment values, labels and build history.
        # Keep identity/OS metadata used by the parser, never the raw image config.
        if "Metadata" in safe:
            metadata = safe["Metadata"] or {}
            safe["Metadata"] = {
                key: metadata[key] for key in
                ("OS", "ImageID", "DiffIDs", "RepoTags", "RepoDigests", "Size")
                if key in metadata
            }
        count = 0
        for result in safe.get("Results") or []:
            for field in ("Vulnerabilities", "Misconfigurations", "Secrets"):
                items = result.get(field) or []
                if not isinstance(items, list):
                    raise ValueError("Invalid Trivy findings")
                count += len(items)
                for issue in items:
                    if field == "Secrets":
                        issue["Match"] = REDACTED
                        issue.pop("Code", None)
                    if field == "Misconfigurations":
                        issue["Message"] = REDACTED
                        issue.pop("Traces", None)
                        cause = issue.get("CauseMetadata") or {}
                        cause.pop("Code", None)
        return safe, count
    if tool == "threagile":
        if not isinstance(data, list):
            raise ValueError("Threagile risks.json must be a list")
        for issue in data:
            for field in ("category", "title", "severity", "synthetic_id", "exploitation_impact"):
                if field not in issue:
                    raise ValueError("Missing Threagile parser field")
        return data, len(data)
    if tool == "zap":
        if not isinstance(data, dict) or not isinstance(data.get("site"), list):
            raise ValueError("ZAP traditional JSON must contain site list")
        safe = {"@version": data.get("@version", ""), "site": []}
        count = 0
        for site in data["site"]:
            alerts = site.get("alerts")
            if not isinstance(alerts, list):
                raise ValueError("Missing ZAP alerts")
            new_site = {
                "@name": clean_url(site["@name"]),
                "@host": site.get("@host", "backend"),
                "@port": site.get("@port", "5000"),
                "@ssl": site.get("@ssl", "false"), "alerts": [],
            }
            for alert in alerts:
                clean = {key: alert[key] for key in (
                    "pluginid", "alert", "name", "riskcode", "confidence",
                    "desc", "solution", "reference", "cweid", "wascid",
                ) if key in alert}
                if not all(key in clean for key in ("pluginid", "riskcode", "desc")):
                    raise ValueError("Invalid ZAP alert")
                clean["instances"] = [{
                    "uri": clean_url(instance["uri"]),
                    "method": instance.get("method", "GET"),
                    "param": REDACTED, "attack": REDACTED, "evidence": REDACTED,
                } for instance in alert.get("instances", [])]
                new_site["alerts"].append(clean)
            count += len(alerts)
            safe["site"].append(new_site)
        return safe, count
    raise ValueError("Unknown scanner")


def zap_xml(data, path):
    root = ET.Element("OWASPZAPReport", {"version": str(data.get("@version", ""))})
    for site in data["site"]:
        node = ET.SubElement(root, "site", {
            key.lstrip("@"): str(value) for key, value in site.items() if key.startswith("@")
        })
        alerts = ET.SubElement(node, "alerts")
        for alert in site["alerts"]:
            item = ET.SubElement(alerts, "alertitem")
            for key, value in alert.items():
                if key != "instances":
                    ET.SubElement(item, key).text = str(value)
            instances = ET.SubElement(item, "instances")
            for instance in alert["instances"]:
                child = ET.SubElement(instances, "instance")
                for key, value in instance.items():
                    ET.SubElement(child, key).text = str(value)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def semgrep_sarif(data):
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Semgrep"}}, "results": [{
            "ruleId": issue["check_id"],
            "level": {"ERROR": "error", "WARNING": "warning", "INFO": "note"}[issue["extra"]["severity"]],
            "message": {"text": issue["extra"]["message"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": issue["path"]},
                "region": {"startLine": issue["start"]["line"]},
            }}],
        } for issue in data["results"]]}],
    }


def prepare(args):
    source, destination = Path(args.source), Path(args.destination)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "manifest.json").unlink(missing_ok=True)
    entries = []
    count = 0
    warning_count = 0
    for name in args.files:
        raw = source / name
        if Path(name).name != name or not raw.is_file() or raw.stat().st_size == 0:
            raise ValueError("Required report missing or empty")
        target = destination / name
        if raw.suffix == ".json":
            safe, findings = transform(args.tool, json.loads(raw.read_text()))
            if args.tool == "zap" and safe["@version"] != args.version:
                raise ValueError("ZAP version does not match pinned version")
            target.write_text(json.dumps(safe, indent=2) + "\n")
            count += findings
            if args.tool == "semgrep":
                warning_count += len(safe.get("errors", []))
            if args.tool == "zap":
                zap_xml(safe, destination / "zap-report.xml")
                (destination / "zap-report.html").write_text(
                    "<!doctype html><html><meta charset='utf-8'><title>ZAP safe summary</title>"
                    f"<h1>ZAP: {findings} alerts</h1><pre>{html.escape(json.dumps(safe, indent=2))}</pre></html>"
                )
            if args.tool == "semgrep":
                (destination / "semgrep.sarif").write_text(json.dumps(semgrep_sarif(safe)) + "\n")
        elif args.tool == "trivy" and raw.suffix == ".yaml":
            import yaml
            documents = list(yaml.safe_load_all(raw.read_text()))
            if not documents or any(
                isinstance(item, dict) and item.get("kind") == "Secret" for item in documents
            ):
                raise ValueError("Rendered YAML is empty or contains Secret objects")
            shutil.copyfile(raw, target)
        elif args.tool == "threagile" and raw.suffix in (".pdf", ".png"):
            shutil.copyfile(raw, target)
        else:
            raise ValueError("Unsupported report file")
    for path in sorted(destination.iterdir()):
        if path.is_file() and path.name != "manifest.json":
            entries.append({
                "file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size,
            })
    sha = os.environ.get("GITHUB_SHA") or subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True,
    ).strip()
    manifest = {
        "tool": args.tool, "version": args.version, "parser": PARSERS[args.tool],
        "sha": sha, "run_id": os.environ.get("GITHUB_RUN_ID"),
        "working_tree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"])),
        "execution": "completed", "findings": count, "warnings": warning_count,
        "reports": entries,
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"{args.tool}: validated {len(entries)} reports; findings={count}")


def collect(args):
    root, destination = Path(args.source), Path(args.destination)
    destination.mkdir(parents=True, exist_ok=True)
    expected = ["zap", "threagile", "semgrep", "trivy-high", "trivy-low", "gitleaks"]
    sha = os.environ["GITHUB_SHA"]
    found = {}
    failures = []
    for key in expected:
        folders = list(root.glob("tp18-" + key + "-" + sha))
        if len(folders) != 1:
            failures.append(key + ": artifact missing")
            continue
        folder = folders[0]
        try:
            manifest = json.loads((folder / "manifest.json").read_text())
            tool = key.split("-")[0]
            if manifest["tool"] != tool or manifest["sha"] != sha or manifest["execution"] != "completed":
                raise ValueError("Identity mismatch")
            if os.environ.get("GITHUB_RUN_ID") and manifest.get("run_id") != os.environ["GITHUB_RUN_ID"]:
                raise ValueError("Report from another workflow run")
            if manifest["working_tree_dirty"]:
                raise ValueError("Report from modified tracked source")
            if not manifest["reports"]:
                raise ValueError("No report files")
            json_count = 0
            for report in manifest["reports"]:
                if Path(report["file"]).name != report["file"]:
                    raise ValueError("Invalid report path")
                path = folder / report["file"]
                if hashlib.sha256(path.read_bytes()).hexdigest() != report["sha256"]:
                    raise ValueError("Checksum mismatch")
                if path.suffix == ".json":
                    _, count = transform(tool, json.loads(path.read_text()))
                    json_count += count
                elif path.suffix == ".xml":
                    ET.parse(path)
            if json_count != manifest["findings"]:
                raise ValueError("Finding count mismatch")
            found[key] = manifest
        except (KeyError, ValueError, OSError, TypeError, ET.ParseError):
            failures.append(key + ": report validation failed")
    index = {"sha": sha, "run_id": os.environ.get("GITHUB_RUN_ID"),
             "reports": found, "errors": failures,
             "jobs": json.loads(os.environ.get("TP18_JOB_RESULTS", "{}"))}
    (destination / "collection-index.json").write_text(json.dumps(index, indent=2) + "\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(f"### TP18 — Collection\n\nValidated bundles: **{len(found)}/6**.\n\n")
            for failure in failures:
                summary.write("- " + failure + "\n")
    print(f"Collection: {len(found)}/6 bundles; missing/invalid={len(failures)}")
    if failures:
        raise ValueError("Incomplete evidence collection")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("tool", choices=PARSERS)
    prepare_parser.add_argument("source")
    prepare_parser.add_argument("destination")
    prepare_parser.add_argument("--version", required=True)
    prepare_parser.add_argument("--files", nargs="+", required=True)
    collector = commands.add_parser("collect")
    collector.add_argument("source")
    collector.add_argument("destination")
    args = parser.parse_args()
    try:
        (prepare if args.command == "prepare" else collect)(args)
    except Exception:
        print("ERROR: required scanner output is absent, invalid or inconsistent. No empty fallback created.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
