#!/usr/bin/env python3
"""Exercise official parser code with lightweight model stubs; no Dojo installed."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import types


class Finding:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.unsaved_endpoints = []
        self.unsaved_req_resp = []
        self.unsaved_locations = []
        self.unsaved_tags = []


class Endpoint:
    @classmethod
    def from_uri(cls, uri):
        obj = cls()
        obj.uri = uri
        return obj


def install_stubs():
    for name in ("dojo", "dojo.models", "dojo.location", "dojo.location.feature",
                 "dojo.tools", "dojo.tools.locations", "dojo.utils"):
        sys.modules[name] = types.ModuleType(name)
    sys.modules["dojo.models"].Finding = Finding
    sys.modules["dojo.models"].Endpoint = Endpoint
    sys.modules["dojo.location.feature"].locations_enabled = lambda: False
    sys.modules["dojo.tools.locations"].LocationData = object
    sys.modules["dojo.tools.locations"].split_image_reference = lambda value: {}
    sys.modules["dojo.utils"].parse_cvss_data = lambda value: {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", help="Directory with pinned official <tool>-parser.py")
    parser.add_argument("reports", help="Directory with actual report bundles")
    args = parser.parse_args()
    install_stubs()
    classes = {"gitleaks": "GitleaksParser", "threagile": "ThreagileParser",
               "semgrep": "SemgrepParser", "trivy": "TrivyParser", "zap": "ZapParser"}
    results = []
    for folder in sorted(Path(args.reports).iterdir()):
        if not folder.is_dir() or not (folder / "manifest.json").is_file():
            continue
        manifest = json.loads((folder / "manifest.json").read_text())
        tool = manifest["tool"]
        spec = importlib.util.spec_from_file_location(
            "official_" + tool, Path(args.source) / (tool + "-parser.py"),
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        scanner = getattr(module, classes[tool])()
        for report in manifest["reports"]:
            path = folder / report["file"]
            if tool == "zap" and path.suffix != ".xml":
                continue
            if tool != "zap" and path.suffix != ".json":
                continue
            with path.open() as stream:
                findings = scanner.get_findings(stream, None)
            results.append({"tool": tool, "file": path.name, "parser": scanner.get_scan_types(),
                            "parsed_findings": len(findings)})
    if not results:
        raise ValueError("No actual reports available")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
