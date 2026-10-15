#!/usr/bin/env python3
"""Assert TP18 graph, blocking policies and preservation of inherited app/config."""
import subprocess
from pathlib import Path
import yaml

workflow = yaml.safe_load(Path(".github/workflows/cicd.yml").read_text())
jobs = workflow["jobs"]
assert jobs["build-and-package"]["needs"] == ["test-integrated-app"]
assert jobs["trivy-andon-cord"]["needs"] == "build-and-package"
assert jobs["trivy-audit-report"]["needs"] == ["build-and-package", "trivy-andon-cord"]
assert jobs["trivy-audit-report"]["if"] == "${{ always() && needs.build-and-package.result == 'success' }}"
assert "needs" not in jobs["gitleaks-andon-cord"]
assert jobs["gitleaks-audit-report"]["needs"] == ["gitleaks-andon-cord"]
assert jobs["gitleaks-audit-report"]["if"] == "${{ always() }}"
assert "needs" not in jobs["threat-modeling"]
assert "needs" not in jobs["semgrep"]
assert jobs["zap-audit"]["needs"] == ["build-and-package"]
assert jobs["collect-security-reports"]["if"] == "${{ always() }}"
for job in ("trivy-andon-cord", "gitleaks-andon-cord"):
    assert not jobs[job].get("continue-on-error")
    for step in jobs[job]["steps"]:
        assert not step.get("continue-on-error")
        assert "|| true" not in step.get("run", "")
for step in jobs["trivy-andon-cord"]["steps"]:
    if step.get("uses", "").startswith("aquasecurity/trivy-action"):
        assert step["with"]["exit-code"] == "1"
        assert step["with"]["severity"] == "HIGH,CRITICAL"
for step in jobs["trivy-audit-report"]["steps"]:
    if step.get("uses", "").startswith("aquasecurity/trivy-action"):
        assert step["with"]["exit-code"] == "0"
dojo = jobs["defectdojo-import"]
assert dojo["needs"] == ["collect-security-reports", "test-security-reports"]
assert "always()" in dojo["if"]
assert "needs.collect-security-reports.result == 'success'" in dojo["if"]
assert "github.event_name != 'pull_request'" in dojo["if"]
assert "needs.trivy-andon-cord.result" not in dojo["if"]
assert "needs.gitleaks-andon-cord.result" not in dojo["if"]
assert dojo["environment"] == "tp18-defectdojo"
assert not dojo.get("continue-on-error")
assert all(not step.get("continue-on-error") and "|| true" not in step.get("run", "") for step in dojo["steps"])
assert "unittest discover -s scripts/tests -v" in jobs["test-security-reports"]["steps"][-1]["run"]
deploy = jobs["deploy-k8s-helm"]
required = ["build-and-package", "trivy-andon-cord", "trivy-audit-report",
            "gitleaks-andon-cord", "gitleaks-audit-report", "semgrep",
            "zap-audit", "threat-modeling", "collect-security-reports",
            "test-security-reports", "defectdojo-import"]
assert set(deploy["needs"]) == set(required)
assert "github.ref == 'refs/heads/main'" in deploy["if"]
for name in required:
    assert "needs." + name + ".result == 'success'" in deploy["if"]
base = yaml.safe_load(subprocess.check_output(
    ["git", "show", "7072a9b:.github/workflows/cicd.yml"], text=True,
))
for name in ("test-integrated-app", "build-and-package", "legacy-lint", "gitleaks-andon-cord"):
    assert jobs[name] == base["jobs"][name], name
assert deploy["steps"] == base["jobs"]["deploy-k8s-helm"]["steps"]
for path in (".gitleaks.toml", "devops-tp12/app/backend/requirements.txt",
             "devops-tp12/app/backend/requirements-dev.txt"):
    assert Path(path).read_bytes() == subprocess.check_output(["git", "show", "7072a9b:" + path])
assert not subprocess.check_output(["git", "diff", "7072a9b", "--",
                                   "devops-tp12/app", "devops-tp12/chart", "devops-tp12/values-prod.yaml"])
semgrep = yaml.safe_load(Path(".github/workflows/semgrep.yml").read_text())
gate = next(step for step in semgrep["jobs"]["semgrep-scan"]["steps"]
            if step.get("name") == "Guard estricto heredado")
assert "--severity=ERROR --error" in gate["run"] and not gate.get("continue-on-error")
assert "|| true" not in gate["run"]
for folder in ("devops-tp12", "security", "scripts", "docs"):
    assert not list(Path(folder).rglob(".git")), folder
print("TP18 graph, independent audits, blocking gates, application and deploy controls: OK")
