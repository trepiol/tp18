#!/usr/bin/env python3
"""Launch exactly one trusted TP18 importer job in a disposable JIT runner.
Requires explicit operator authorization, gh administrative credentials and Docker.
No host directories, SSH keys or Docker socket are mounted into the runner.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

REPO = "trepiol/tp18"
BRANCHES = ("main", "feature/tp18-defectdojo-final")


def api(path, method="GET", data=None):
    cmd = ["gh", "api", path, "--method", method]
    if data is not None:
        cmd += ["--input", "-"]
    p = subprocess.run(cmd, input=json.dumps(data) if data is not None else None,
                       text=True, capture_output=True, timeout=45)
    if p.returncode:
        raise RuntimeError("GitHub API operation failed: " + method + " " + path)
    return json.loads(p.stdout) if p.stdout.strip() else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    if not args.run_id.isdecimal() or not re.fullmatch(r"[0-9a-f]{40}", args.sha):
        raise RuntimeError("Invalid run identity")
    if shutil.disk_usage(".").free < 4 * 1024**3:
        raise RuntimeError("Less than 4 GiB disk reserve; increase storage")
    run = api(f"repos/{REPO}/actions/runs/{args.run_id}")
    if (run["head_sha"] != args.sha or run["head_branch"] not in BRANCHES
            or run["event"] not in ("push", "workflow_dispatch")
            or run["actor"]["login"] != "trepiol"
            or run.get("triggering_actor", {}).get("login") != "trepiol"
            or run["path"] != ".github/workflows/cicd.yml"
            or run["head_repository"]["full_name"] != REPO):
        raise RuntimeError("Refusing an untrusted workflow run")
    local_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if local_sha != args.sha or subprocess.check_output(["git", "status", "--porcelain"]):
        raise RuntimeError("Operator checkout must be clean and match the reviewed run SHA")
    policy = api(f"repos/{REPO}/actions/permissions/fork-pr-contributor-approval")
    if policy.get("approval_policy") != "all_external_contributors":
        raise RuntimeError("All external contributor workflows must require approval")
    # Reject competing self-hosted work before exposing the importer runner.
    for state in ("queued", "in_progress", "waiting"):
        runs = api(f"repos/{REPO}/actions/runs?status={state}&per_page=100")["workflow_runs"]
        for other in runs:
            jobs = api(f"repos/{REPO}/actions/runs/{other['id']}/jobs?per_page=100")["jobs"]
            for job in jobs:
                if "self-hosted" in job.get("labels", []) and job["status"] != "completed":
                    if str(other["id"]) != args.run_id or job["name"] != "Fase 3 — Importar y reimportar en DefectDojo":
                        raise RuntimeError("Competing self-hosted job found; runner stays offline")
    # Approve only the intended environment of this already reviewed owner run.
    pending = api(f"repos/{REPO}/actions/runs/{args.run_id}/pending_deployments")
    for item in pending:
        if item["environment"]["name"] != "tp18-defectdojo":
            raise RuntimeError("Unexpected pending environment")
        api(f"repos/{REPO}/actions/runs/{args.run_id}/pending_deployments", "POST", {
            "environment_ids": [item["environment"]["id"]], "state": "approved",
            "comment": "Ejecución TP18 del propietario, SHA revisado y runner efímero autorizado."})
    jobs = api(f"repos/{REPO}/actions/runs/{args.run_id}/jobs?per_page=100")["jobs"]
    intended = [j for j in jobs if j["name"] == "Fase 3 — Importar y reimportar en DefectDojo"]
    if len(intended) != 1 or intended[0]["status"] not in ("queued", "waiting", "pending"):
        raise RuntimeError("Expected one queued importer job")
    name = "tp18-dojo-" + args.run_id
    config = api(f"repos/{REPO}/actions/runners/generate-jitconfig", "POST", {
        "name": name, "runner_group_id": 1,
        "labels": ["self-hosted", "linux", "x64", "tp18-defectdojo"], "work_folder": "_work"})
    private = Path(".security-private/defectdojo")
    env_file = private / (name + ".env")
    env_file.write_text("JIT_CONFIG=" + config["encoded_jit_config"] + "\n")
    env_file.chmod(0o600)
    print(f"Trusted run {args.run_id}, SHA {args.sha}; ephemeral runner {name}", flush=True)
    try:
        with (private / (name + ".log")).open("w") as log:
            p = subprocess.run([
                "docker", "run", "--rm", "--name", name,
                "--network", "host", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--memory", "1g", "--cpus", "1.5", "--pids-limit", "256",
                "--env-file", str(env_file), "tp18-dojo-runner:validated",
                "bash", "-c", 'exec ./run.sh --jitconfig "$JIT_CONFIG"'],
                stdout=log, stderr=subprocess.STDOUT, timeout=1500)
        if p.returncode:
            raise RuntimeError("Ephemeral runner failed; private diagnostic retained")
    finally:
        env_file.unlink(missing_ok=True)
        subprocess.run(["docker", "stop", "--time", "10", name], capture_output=True, timeout=20)
        # Only remove our own registration if GitHub did not already remove it.
        for runner in api(f"repos/{REPO}/actions/runners?per_page=100")["runners"]:
            if runner["name"] == name:
                api(f"repos/{REPO}/actions/runners/{runner['id']}", "DELETE")
    print("Ephemeral runner finished and registration cleaned up.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print("ERROR: " + str(exc) if isinstance(exc, RuntimeError) else "ERROR: runner operation failed; no success assumed", file=sys.stderr)
        sys.exit(1)
