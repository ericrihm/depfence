"""Source-level release contracts for isolated worker images."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
DOCKERFILE = ROOT / "containers" / "Dockerfile"
ENTRYPOINT = ROOT / "containers" / "bin" / "depfence-worker-entrypoint"


class ContainerReleaseContracts(unittest.TestCase):
    def test_base_image_is_digest_pinned_and_targets_are_distinct(self) -> None:
        source = DOCKERFILE.read_text(encoding="utf-8")
        self.assertRegex(source, r"python:[^\s]+@sha256:[0-9a-f]{64}")
        self.assertEqual(re.findall(r"^FROM runtime AS (intake|static|render)$", source, re.M), [
            "intake", "static", "render",
        ])
        self.assertIn("USER 65532:65532", source)
        self.assertIn('ENTRYPOINT ["/usr/local/bin/depfence-worker-entrypoint"]', source)

    def test_dispatcher_is_an_allowlist_without_shell_evaluation(self) -> None:
        source = ENTRYPOINT.read_text(encoding="utf-8")
        self.assertIn("intake:depfence-sealed-git-resolve", source)
        self.assertIn("intake:depfence-sealed-git-acquire", source)
        self.assertIn("static:depfence-sealed-git-inventory", source)
        self.assertIn("static:depfence-sealed-git-analyze", source)
        self.assertIn("render:depfence-artifact-analyzer", source)
        self.assertNotIn("eval ", source)
        self.assertNotIn('sh -c', source)
        self.assertIn('exec "$command" "$@"', source)

    def test_analysis_profile_denies_network_creation(self) -> None:
        profile = json.loads(
            (ROOT / "containers" / "seccomp-analysis.json").read_text(encoding="utf-8")
        )
        self.assertEqual(profile["defaultAction"], "SCMP_ACT_ERRNO")
        allowed = {name for group in profile["syscalls"] for name in group["names"]}
        self.assertFalse({"socket", "connect", "bind", "listen"} & allowed)

    def test_release_attaches_supply_chain_evidence_and_signs_digest(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "publish-analysis-images.yml"
        ).read_text(encoding="utf-8")
        for required in (
            "--sbom true",
            "--provenance mode=max",
            "cosign sign --yes",
            "cosign verify",
            'containerimage.digest',
            "id-token: write",
        ):
            self.assertIn(required, workflow)
        self.assertNotRegex(workflow, r"uses:\s+[^\s]+@(v|main|master)(?:\s|$)")

    def test_acquisition_proxy_is_dual_homed_and_exact_host_allowlisted(self) -> None:
        compose = (ROOT / "containers" / "compose.acquisition.yml").read_text(
            encoding="utf-8"
        )
        squid = (ROOT / "containers" / "egress-proxy" / "squid.conf").read_text(
            encoding="utf-8"
        )
        self.assertIn("internal: true", compose)
        self.assertIn("acquisition:", compose)
        self.assertIn("proxy-egress:", compose)
        self.assertIn("DEPFENCE_PROXY_ALLOWLIST", compose)
        self.assertIn('dstdomain "/etc/squid/allowed-domains.txt"', squid)
        self.assertNotIn("dstdom_regex", squid)
        self.assertIn("http_access deny prohibited_ipv4", squid)
        self.assertIn("http_access deny prohibited_ipv6", squid)
        self.assertIn("runtime: runsc", compose)

    def test_disposable_vm_bootstrap_is_pinned_and_has_no_host_share(self) -> None:
        create = (ROOT / "tools" / "intake-vm" / "create.sh").read_text(
            encoding="utf-8"
        )
        start = (ROOT / "tools" / "intake-vm" / "start.sh").read_text(
            encoding="utf-8"
        )
        guest = (ROOT / "tools" / "intake-vm" / "bootstrap-guest.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('UBUNTU_RELEASE="20260814"', create)
        self.assertIn("D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81", create)
        self.assertIn("gpgv --keyring", create)
        self.assertIn("127.0.0.1:$SSH_PORT-:22", start)
        self.assertNotIn("virtfs", start)
        self.assertNotIn("9p", start)
        self.assertIn('COSIGN_VERSION="3.0.2"', guest)
        self.assertIn('UV_VERSION="0.12.5"', guest)
        self.assertGreaterEqual(len(re.findall(r'[0-9a-f]{64}', guest)), 2)
        self.assertIn("https://storage.googleapis.com/gvisor/releases release main", guest)

    def test_readiness_gate_requires_signatures_runsc_and_zero_orphans(self) -> None:
        source = (ROOT / "tools" / "intake-vm" / "readiness.sh").read_text(
            encoding="utf-8"
        )
        for required in (
            "cosign verify",
            "--runtime runsc",
            "intake doctor",
            "containment-canary.sh",
            "dev.depfence.purpose=sealed-intake",
            "dev.depfence.purpose=sealed-resolution",
            "READY_FOR_URL",
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()

