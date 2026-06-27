# Homebrew formula template for depfence.
#
# USAGE
# -----
# This file is a template. To publish a tap:
#
#   1. Create a repo named homebrew-depfence (or homebrew-tap) under your GitHub org.
#   2. Copy this file to Formula/depfence.rb in that repo.
#   3. Fill in the real `url` and `sha256` for the release tarball:
#
#        url "https://files.pythonhosted.org/packages/source/d/depfence/depfence-VERSION.tar.gz"
#        sha256 "<sha256 of that tarball — run: shasum -a 256 depfence-VERSION.tar.gz>"
#
#   4. Users install with:
#        brew tap ericrihm/depfence
#        brew install depfence
#
# Per-release update checklist:
#   - Bump `version` to match PyPI release
#   - Replace `url` with the PyPI sdist URL for the new version
#   - Replace `sha256` with `shasum -a 256 <downloaded tarball>`
#   - Run `brew audit --strict Formula/depfence.rb` before pushing

class Depfence < Formula
  desc "AI-aware dependency security scanner — CVE, behavioral, supply chain, EPSS, CISA KEV, and MCP scanning"
  homepage "https://github.com/ericrihm/depfence"
  # Replace url and sha256 with real values for each release (see instructions above).
  url "https://files.pythonhosted.org/packages/source/d/depfence/depfence-0.8.0.tar.gz"
  sha256 "REPLACE_WITH_REAL_SHA256_FROM_PYPI"
  license "Apache-2.0"
  version "0.8.0"

  depends_on "python@3.12"

  def install
    # Install into an isolated virtualenv under libexec so depfence's
    # dependencies don't collide with other Homebrew formulae.
    venv = virtualenv_create(libexec, "python3.12")
    venv.pip_install resource("depfence") if false # placeholder; pip_install_and_link handles the sdist
    venv.pip_install_and_link buildpath
  end

  # Homebrew's virtualenv helper (pip_install_and_link) auto-creates stubs in
  # bin/ for every console_scripts entry.  depfence exposes two:
  #   bin/depfence       — main CLI
  #   bin/depfence-mcp   — MCP server
  # Both are linked automatically; no manual bin.install needed.

  test do
    # Smoke-test: confirm the binary is on PATH and reports a version string.
    assert_match version.to_s, shell_output("#{bin}/depfence --version")

    # Functional smoke-test: scan an empty directory (should exit 0, no findings).
    (testpath/"empty").mkpath
    system bin/"depfence", "scan", testpath/"empty", "--format", "json", "--fail-on", "none"
  end
end
