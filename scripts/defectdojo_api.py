#!/usr/bin/env python3
"""TP18: verified bundles -> native DefectDojo API v2 imports/reimports.

No scanner thresholds, exception lists or findings are modified here.
Credentials are read from the environment or a private file, never logged.
"""
import argparse
from collections import Counter
from datetime import date, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import urllib.error
import urllib.parse
import urllib.request
import uuid

import security_report

PRODUCT_TYPE = "Aplicaciones Web DevSecOps"
PRODUCT = "Notes App"
ENGAGEMENT = "CI/CD Automated Security Audits"


class DojoError(Exception):
    """An operational failure whose message is safe to publish."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DojoError(f"Unexpected HTTP redirect ({code}); request stopped")


class Client:
    def __init__(self):
        self.base = os.environ.get("DEFECTDOJO_URL", "http://127.0.0.1:8080").rstrip("/")
        u = urllib.parse.urlsplit(self.base)
        if (u.username or u.password or u.query or u.fragment or u.path
                or u.scheme not in ("http", "https") or not u.hostname):
            raise DojoError("Invalid DefectDojo URL")
        if u.scheme == "http" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise DojoError("Plain HTTP allowed only on loopback; use verified TLS otherwise")
        self.token = os.environ.get("DEFECTDOJO_API_KEY", "")
        token_file = os.environ.get("DEFECTDOJO_TOKEN_FILE")
        if token_file:
            f = Path(token_file)
            if f.stat().st_mode & 0o077:
                raise DojoError("Token file must be private (mode 600)")
            self.token = f.read_text().strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,200}", self.token):
            raise DojoError("Missing or invalid private API token")
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, path, *, method="GET", data=None, fields=None, report=None):
        if not path.startswith("/api/v2/") or path.startswith("//"):
            raise DojoError("API path outside allowed origin")
        headers = {"Authorization": "Token " + self.token, "Accept": "application/json"}
        body = None
        if fields is not None:
            boundary = "tp18-" + uuid.uuid4().hex
            chunks = []
            for k, v in fields.items():
                chunks.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n').encode())
            if report is not None:
                filename = report.name
                chunks.extend([(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode(), report.read_bytes(), b"\r\n"])
            chunks.append(f"--{boundary}--\r\n".encode())
            body = b"".join(chunks)
            headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
        elif data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=180) as response:
                status = response.status
                payload = response.read(20 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as exc:
            # Do not log server bodies: they can echo credentials or raw report text.
            raise DojoError(f"HTTP {exc.code}: {method} {path.split('?')[0]}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise DojoError(f"Network failure: {method} {path.split('?')[0]}") from None
        if len(payload) > 20 * 1024 * 1024:
            raise DojoError("API response exceeds configured size limit")
        try:
            result = json.loads(payload)
        except (ValueError, UnicodeError):
            raise DojoError(f"Invalid JSON response (HTTP {status})") from None
        return result, status

    def rows(self, endpoint, **filters):
        path = "/api/v2/" + endpoint + "/?" + urllib.parse.urlencode({"limit": 100, **filters})
        rows = []
        for _ in range(1000):
            result, _ = self.request(path)
            if not isinstance(result, dict) or not isinstance(result.get("results"), list):
                raise DojoError("Invalid paginated API response")
            rows.extend(result["results"])
            nxt = result.get("next")
            if not nxt:
                return rows
            if not nxt.startswith(self.base + "/api/v2/"):
                raise DojoError("Pagination outside trusted API origin")
            path = nxt[len(self.base):]
        raise DojoError("Pagination safety limit exceeded")

    def one(self, endpoint, name, *, create=None, **filters):
        matches = [r for r in self.rows(endpoint, **filters) if r.get("name") == name]
        if not matches and create is not None:
            result, status = self.request("/api/v2/" + endpoint + "/", method="POST", data=create)
            if status != 201 or not isinstance(result.get("id"), int):
                raise DojoError("Creation not confirmed by API")
            return result
        if len(matches) != 1:
            raise DojoError(f"Expected one exact {endpoint} object; found {len(matches)}")
        return matches[0]


def hierarchy(client, create):
    if create:
        pt = client.one("product_types", PRODUCT_TYPE, create={"name": PRODUCT_TYPE, "description": "Laboratorio DevSecOps TP18"})
        pt_id = pt["id"]
        p = client.one("products", PRODUCT, prod_type=pt_id, create={"name": PRODUCT, "prod_type": pt_id, "description": "Notes App Flask/PostgreSQL con Docker, Helm y Kubernetes. Auditorías OWASP ZAP, Threagile, Semgrep, Trivy y Gitleaks."})
    else:
        # The API-only account is a member of this Product, not the whole category.
        # Product-Type visibility would grant access to future unrelated products.
        expected_pt = os.environ.get("DEFECTDOJO_PRODUCT_TYPE_ID", "")
        if not expected_pt.isdecimal():
            raise DojoError("Set DEFECTDOJO_PRODUCT_TYPE_ID to the ID obtained during setup")
        pt_id = int(expected_pt)
        p = client.one("products", PRODUCT, prod_type=pt_id)
    e = client.one("engagements", ENGAGEMENT, product=p["id"], create={"name": ENGAGEMENT, "product": p["id"], "target_start": str(date.today()), "target_end": str(date.today() + timedelta(days=365)), "status": "In Progress", "engagement_type": "CI/CD", "deduplication_on_engagement": True} if create else None)
    if e["product"] != p["id"] or p["prod_type"] != pt_id:
        raise DojoError("Hierarchy identity mismatch")
    return {"product_type_id": pt_id, "product_id": p["id"], "engagement_id": e["id"]}


def snapshot(client, ids):
    tests = client.rows("tests", engagement=ids["engagement_id"])
    findings = []
    per_test = []
    for test in sorted(tests, key=lambda x: x["id"]):
        rows = client.rows("findings", test=test["id"])
        if any(f["test"] != test["id"] for f in rows):
            raise DojoError("Server did not scope findings to the requested Test")
        findings.extend(rows)
        per_test.append({"id": test["id"], "title": test["title"], "findings": len(rows), "active": sum(bool(f["active"]) for f in rows), "duplicates": sum(bool(f["duplicate"]) for f in rows), "severities": dict(Counter(f["severity"] for f in rows))})
    lifecycle = ("active", "verified", "false_p", "duplicate", "out_of_scope", "risk_accepted", "under_review", "under_defect_review", "is_mitigated")
    individual_states = {str(f["id"]): {"test": f["test"], "severity": f["severity"], **{key: f.get(key) for key in lifecycle}} for f in findings}
    state_hash = hashlib.sha256(json.dumps(individual_states, sort_keys=True).encode()).hexdigest()
    return {"finding_ids_and_states_sha256": state_hash, "risk_accepted": sum(bool(f.get("risk_accepted")) for f in findings), "severities": dict(Counter(f["severity"] for f in findings)), "tests": len(tests), "findings": len(findings), "active": sum(bool(f["active"]) for f in findings), "duplicates": sum(bool(f["duplicate"]) for f in findings), "states": dict(Counter(f"active={bool(f['active'])};duplicate={bool(f['duplicate'])};mitigated={bool(f.get('is_mitigated'))}" for f in findings)), "test_details": per_test}


def bundle_reports(args):
    if not re.fullmatch(r"[a-f0-9]{40}", args.sha) or not args.run_id.isdecimal():
        raise DojoError("Expected a full Git SHA and numeric Run ID")
    os.environ["GITHUB_SHA"] = args.sha
    os.environ["GITHUB_RUN_ID"] = args.run_id
    root = Path(args.bundles).resolve()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    security_report.collect(SimpleNamespace(source=str(root), destination=str(out)))
    specs = [("zap", "zap-report.xml", "ZAP Scan", "DAST"), ("threagile", "risks.json", "Threagile risks report", "Threat Modeling"), ("semgrep", "semgrep-results.json", "Semgrep JSON Report", "SAST"), ("gitleaks", "gitleaks-report.json", "Gitleaks Scan", "Git History")]
    for band, suffix in (("high", "blocking"), ("low", "report")):
        for kind, label in (("fs", "SCA"), ("image", "Container"), ("secrets", "Secrets"), ("config", "IaC")):
            specs.append(("trivy-" + band, f"trivy-{kind}-{suffix}.json", "Trivy Scan", label))
    reports = []
    for bundle, filename, parser, scope in specs:
        folder = root / f"tp18-{bundle}-{args.sha}"
        report = folder / filename
        if report.is_symlink() or report.resolve().parent != folder.resolve():
            raise DojoError("Report is outside the validated bundle")
        manifest = json.loads((folder / "manifest.json").read_text())
        entry = next((r for r in manifest["reports"] if r["file"] == filename), None)
        if not entry or hashlib.sha256(report.read_bytes()).hexdigest() != entry["sha256"]:
            raise DojoError("Requested scan report not present in validated manifest")
        reports.append({"title": f"TP18 {bundle} {scope}", "parser": parser, "path": report, "sha256": entry["sha256"], "service": f"tp18:{bundle}:{scope.replace(' ', '-')}"})
    return reports


def execute(args, client, ids):
    reports = bundle_reports(args)
    before = snapshot(client, ids)
    receipts, failed = [], False
    for report in reports:
        try:
            matches = [t for t in client.rows("tests", engagement=ids["engagement_id"]) if t["title"] == report["title"]]
            if len(matches) > 1:
                raise DojoError("Ambiguous existing Test title; import stopped")
            if args.command == "import" and matches:
                raise DojoError("Initial import requires an absent Test; use sync or reimport")
            if args.command == "reimport" and not matches:
                raise DojoError("Reimport requires an existing Test")
            endpoint = "reimport-scan" if matches else "import-scan"
            fields = {"scan_type": report["parser"], "engagement": ids["engagement_id"], "test_title": report["title"], "active": "true", "verified": "false", "minimum_severity": "Info", "close_old_findings": "false", "auto_create_context": "false", "commit_hash": args.sha, "build_id": args.run_id, "branch_tag": args.branch, "service": report["service"], "deduplication_execution_mode": "sync", "source_code_management_uri": "https://github.com/trepiol/tp18", "version": "run-"+args.run_id}
            if matches:
                fields["test"] = matches[0]["id"]
                fields["do_not_reactivate"] = "true"
            result, status = client.request("/api/v2/" + endpoint + "/", method="POST", fields=fields, report=report["path"])
            test_id = result.get("test_id", result.get("test"))
            if status != 201 or not isinstance(test_id, int) or result.get("engagement_id") != ids["engagement_id"] or not result.get("deduplication_complete"):
                raise DojoError("Import or synchronous deduplication was not confirmed")
            test, _ = client.request(f"/api/v2/tests/{test_id}/")
            if test["engagement"] != ids["engagement_id"] or test["title"] != report["title"] or test.get("commit_hash") != args.sha or str(test.get("build_id")) != args.run_id or (matches and test_id != matches[0]["id"]):
                raise DojoError("Imported Test identity mismatch")
            receipts.append({"title": report["title"], "parser": report["parser"], "operation": endpoint, "http_status": status, "test_id": test_id, "sha256": report["sha256"], "deduplication_complete": True, "statistics": result.get("statistics", {}), "success": True})
            print(f"OK {endpoint}: {report['title']}; HTTP {status}; Test {test_id}")
        except DojoError as exc:
            failed = True
            receipts.append({"title": report["title"], "success": False, "error": str(exc)})
            print(f"ERROR {report['title']}: {exc}", file=sys.stderr)
    after = snapshot(client, ids)
    result = {"sha": args.sha, "run_id": args.run_id, "run_url": "https://github.com/trepiol/tp18/actions/runs/"+args.run_id, "hierarchy": ids, "before": before, "after": after, "receipts": receipts, "success": not failed}
    if args.command == "reimport" and before != after:
        result["success"] = False
        result["error"] = "Reimport changed counts/states/Test IDs; inspect safely before proceeding"
        failed = True
    target = Path(args.output) / "defectdojo-result.json"
    target.write_text(json.dumps(result, indent=2)+"\n")
    print(f"DefectDojo: {sum(r['success'] for r in receipts)}/{len(reports)} reports; Tests={after['tests']}; Findings={after['findings']}; active={after['active']}; duplicates={after['duplicates']}")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(f"### TP18 DefectDojo\n\nReports imported: {sum(r['success'] for r in receipts)}/{len(reports)}. Tests: {after['tests']}. Findings: {after['findings']}. Active: {after['active']}. Duplicates: {after['duplicates']}.\n\n")
            for receipt in receipts:
                f.write(f"- {receipt['title']}: {'OK' if receipt['success'] else 'FAILED'}\n")
    if failed:
        raise DojoError("One or more imports or reimport invariants failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("setup", "check", "snapshot", "import", "reimport", "sync", "negative"))
    parser.add_argument("--bundles", default=".security-bundles")
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    parser.add_argument("--branch", default=os.environ.get("GITHUB_REF_NAME", "main"))
    parser.add_argument("--output", default=".security-collection/defectdojo")
    args = parser.parse_args()
    try:
        client = Client()
        if args.command == "negative":
            negative_ids = hierarchy(client, create=False)
            before = snapshot(client, negative_ids)
            try:
                client.request("/api/v2/import-scan/", method="POST", fields={"scan_type": "TP18 invalid parser"})
            except DojoError as exc:
                if str(exc) != "HTTP 400: POST /api/v2/import-scan/":
                    raise
                after = snapshot(client, negative_ids)
                if before != after:
                    raise DojoError("Invalid request changed the snapshot")
                Path(args.output).mkdir(parents=True, exist_ok=True)
                (Path(args.output) / "negative.json").write_text(json.dumps({"http_status": 400, "before": before, "after": after, "success": True}, indent=2)+"\n")
                print("OK controlled negative test: HTTP 400: POST /api/v2/import-scan/; Tests and Findings unchanged")
                return 0
            raise DojoError("Invalid request was unexpectedly accepted")
        ids = hierarchy(client, create=args.command == "setup")
        print(f"API authentication and hierarchy OK: Product Type {ids['product_type_id']}; Product {ids['product_id']}; Engagement {ids['engagement_id']}")
        if args.command == "snapshot":
            result = snapshot(client, ids)
            Path(args.output).mkdir(parents=True, exist_ok=True)
            (Path(args.output)/"snapshot.json").write_text(json.dumps(result, indent=2)+"\n")
            print(json.dumps(result, indent=2))
        elif args.command in ("import", "reimport", "sync"):
            execute(args, client, ids)
        return 0
    except (DojoError, OSError, ValueError, KeyError, StopIteration, TypeError) as exc:
        if isinstance(exc, DojoError):
            print("ERROR: " + str(exc), file=sys.stderr)
        else:
            print("ERROR: invalid local configuration, bundle or API response; no success assumed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
