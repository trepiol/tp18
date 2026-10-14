#!/usr/bin/env bash
set -euo pipefail
tool="${1:?Use: install-security-cli.sh gitleaks|trivy}"
case "$tool" in
  gitleaks) version="8.30.0"; repo="gitleaks/gitleaks"; archive="gitleaks_${version}_linux_x64.tar.gz"; checksum="gitleaks_${version}_checksums.txt" ;;
  trivy) version="0.74.0"; repo="aquasecurity/trivy"; archive="trivy_${version}_Linux-64bit.tar.gz"; checksum="trivy_${version}_checksums.txt" ;;
  *) echo "Herramienta no soportada." >&2; exit 2 ;;
esac
tool_dir="${RUNNER_TEMP:-$PWD/.security-tools}/tp18-$tool"
mkdir -p "$tool_dir"
cd "$tool_dir"
release="https://github.com/$repo/releases/download/v$version"
curl --fail --silent --show-error --location --retry 3 "$release/$archive" -o "$archive"
curl --fail --silent --show-error --location --retry 3 "$release/$checksum" -o "$checksum"
sha256sum --check --ignore-missing "$checksum"
tar -xzf "$archive" "$tool"
chmod 755 "$tool"
if [[ "$tool" == "gitleaks" ]]; then
  test "$(./gitleaks version)" = "$version"
else
  ./trivy --version | head -1 | grep -Fx "Version: $version"
fi
if [[ -n "${GITHUB_PATH:-}" ]]; then echo "$tool_dir" >> "$GITHUB_PATH"; fi
