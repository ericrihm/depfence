"""Tests for depfence/parsers/go_sum.py (parse_go_sum and parse_go_mod)."""

from __future__ import annotations

from pathlib import Path

from depfence.core.models import PackageId
from depfence.parsers.go_sum import parse_go_mod, parse_go_sum

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

GO_SUM_BASIC = """\
github.com/pkg/errors v0.9.0 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt38=
github.com/pkg/errors v0.9.0/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl08=
golang.org/x/sync v0.3.0 h1:ftCYgMx6zT/asHUrPw8BLLscYtGznsLAnjq5RH9P66E=
golang.org/x/sync v0.3.0/go.mod h1:FU7BRWMLTJDbd2wh6sVrkAa1tFfmZQ5kX/vTovp/gjM=
github.com/stretchr/testify v1.8.3 h1:RP3t2pwF7cMEbC1dqtB6poj3niw/9gnV4Cjg5oW5Oiw=
github.com/stretchr/testify v1.8.3/go.mod h1:sz/lmYIOXD/1dqDmKjjqLyZ2RngseejIcXlSw2iwfAo=
"""

GO_SUM_ONLY_GO_MOD_LINES = """\
github.com/foo/bar v1.0.0/go.mod h1:aaa=
github.com/foo/bar v1.0.0 h1:bbb=
"""

GO_SUM_MALFORMED = """\
# this line is a comment and has no version
github.com/bad-no-hash-field

github.com/valid/pkg v2.0.0 h1:xyz=
not_a_module_at_all
"""

GO_SUM_EMPTY = ""

GO_SUM_PSEUDO_VERSION = """\
github.com/foo/bar v0.0.0-20230101120000-abcdef123456 h1:abc=
github.com/foo/bar v0.0.0-20230101120000-abcdef123456/go.mod h1:def=
"""

GO_MOD_BASIC = """\
module example.com/myapp

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/pkg/errors v0.9.0
\tgolang.org/x/sync v0.3.0 // indirect
)

require github.com/stretchr/testify v1.8.3
"""

GO_MOD_EMPTY_REQUIRE = """\
module example.com/empty

go 1.21

require (
)
"""

GO_MOD_NO_REQUIRE = """\
module example.com/minimal

go 1.21
"""

GO_MOD_WITH_COMMENTS = """\
module example.com/commented

go 1.21

require (
\t// this whole line is a comment
\tgithub.com/real/dep v1.0.0
)
"""

GO_MOD_WITH_GO_TOOLCHAIN = """\
module example.com/tool

go 1.21

require (
\tgo 1.21
\tgithub.com/real/dep v1.0.0
)
"""

GO_MOD_MULTI_BLOCK = """\
module example.com/multi

go 1.21

require (
\tgithub.com/pkg/a v1.0.0
\tgithub.com/pkg/b v2.0.0
)

require (
\tgithub.com/pkg/c v3.0.0 // indirect
)
"""


# ---------------------------------------------------------------------------
# Tests for parse_go_sum
# ---------------------------------------------------------------------------

class TestParseGoSumBasic:
    def test_correct_package_count(self, tmp_path: Path):
        f = tmp_path / "go.sum"
        f.write_text(GO_SUM_BASIC)
        packages = parse_go_sum(f)
        # 3 modules, each with hash + go.mod line => deduplicated to 3
        assert len(packages) == 3

    def test_ecosystem_is_go(self, tmp_path: Path):
        f = tmp_path / "go.sum"
        f.write_text(GO_SUM_BASIC)
        assert all(p.ecosystem == "go" for p in parse_go_sum(f))

    def test_names_extracted(self, tmp_path: Path):
        f = tmp_path / "go.sum"
        f.write_text(GO_SUM_BASIC)
        names = {p.name for p in parse_go_sum(f)}
        assert "github.com/pkg/errors" in names
        assert "golang.org/x/sync" in names
        assert "github.com/stretchr/testify" in names

    def test_versions_extracted(self, tmp_path: Path):
        f = tmp_path / "go.sum"
        f.write_text(GO_SUM_BASIC)
        by_name = {p.name: p for p in parse_go_sum(f)}
        assert by_name["github.com/pkg/errors"].version == "v0.9.0"
        assert by_name["golang.org/x/sync"].version == "v0.3.0"
        assert by_name["github.com/stretchr/testify"].version == "v1.8.3"

    def test_go_mod_suffix_stripped(self, tmp_path: Path):
        f = tmp_path / "go.sum"
        f.write_text(GO_SUM_BASIC)
        by_name = {p.name: p for p in parse_go_sum(f)}
        # None of the versions should contain "/go.mod"
        for pkg in by_name.values():
            assert "/go.mod" not in (pkg.version or "")

    def test_returns_package_id_instances(self, tmp_path: Path):
        f = tmp_path / "go.sum"
        f.write_text(GO_SUM_BASIC)
        assert all(isinstance(p, PackageId) for p in parse_go_sum(f))


class TestParseGoSumDeduplication:
    def test_hash_and_gomod_lines_collapsed(self, tmp_path: Path):
        content = (
            "github.com/foo/bar v1.0.0 h1:aaa=\n"
            "github.com/foo/bar v1.0.0/go.mod h1:bbb=\n"
        )
        f = tmp_path / "go.sum"
        f.write_text(content)
        packages = parse_go_sum(f)
        assert len(packages) == 1
        assert packages[0].name == "github.com/foo/bar"
        assert packages[0].version == "v1.0.0"

    def test_only_go_mod_line_still_parsed(self, tmp_path: Path):
        # go.mod line appears first; hash line deduplicates
        f = tmp_path / "go.sum"
        f.write_text(GO_SUM_ONLY_GO_MOD_LINES)
        packages = parse_go_sum(f)
        assert len(packages) == 1
        assert packages[0].version == "v1.0.0"

    def test_same_module_different_versions_not_deduplicated(self, tmp_path: Path):
        content = (
            "github.com/foo/bar v1.0.0 h1:aaa=\n"
            "github.com/foo/bar v2.0.0 h1:bbb=\n"
        )
        f = tmp_path / "go.sum"
        f.write_text(content)
        packages = parse_go_sum(f)
        assert len(packages) == 2
        versions = {p.version for p in packages}
        assert versions == {"v1.0.0", "v2.0.0"}


class TestParseGoSumEdgeCases:
    def test_empty_file_returns_empty_list(self, tmp_path: Path):
        f = tmp_path / "go.sum"
        f.write_text(GO_SUM_EMPTY)
        assert parse_go_sum(f) == []

    def test_malformed_lines_skipped(self, tmp_path: Path):
        f = tmp_path / "go.sum"
        f.write_text(GO_SUM_MALFORMED)
        packages = parse_go_sum(f)
        names = {p.name for p in packages}
        # Only github.com/valid/pkg should appear
        assert "github.com/valid/pkg" in names
        assert "github.com/bad-no-hash-field" not in names

    def test_blank_lines_skipped(self, tmp_path: Path):
        content = "\n\ngithub.com/foo/bar v1.0.0 h1:aaa=\n\n"
        f = tmp_path / "go.sum"
        f.write_text(content)
        packages = parse_go_sum(f)
        assert len(packages) == 1

    def test_pseudo_version_parsed(self, tmp_path: Path):
        f = tmp_path / "go.sum"
        f.write_text(GO_SUM_PSEUDO_VERSION)
        packages = parse_go_sum(f)
        assert len(packages) == 1
        assert "20230101" in packages[0].version


# ---------------------------------------------------------------------------
# Tests for parse_go_mod
# ---------------------------------------------------------------------------

class TestParseGoModBasic:
    def test_package_count(self, tmp_path: Path):
        f = tmp_path / "go.mod"
        f.write_text(GO_MOD_BASIC)
        packages = parse_go_mod(f)
        assert len(packages) == 4

    def test_ecosystem_is_go(self, tmp_path: Path):
        f = tmp_path / "go.mod"
        f.write_text(GO_MOD_BASIC)
        assert all(p.ecosystem == "go" for p in parse_go_mod(f))

    def test_names_extracted(self, tmp_path: Path):
        f = tmp_path / "go.mod"
        f.write_text(GO_MOD_BASIC)
        names = {p.name for p in parse_go_mod(f)}
        assert "github.com/gin-gonic/gin" in names
        assert "github.com/pkg/errors" in names
        assert "golang.org/x/sync" in names
        assert "github.com/stretchr/testify" in names

    def test_versions_extracted(self, tmp_path: Path):
        f = tmp_path / "go.mod"
        f.write_text(GO_MOD_BASIC)
        by_name = {p.name: p for p in parse_go_mod(f)}
        assert by_name["github.com/gin-gonic/gin"].version == "v1.9.1"
        assert by_name["golang.org/x/sync"].version == "v0.3.0"
        assert by_name["github.com/stretchr/testify"].version == "v1.8.3"

    def test_indirect_comment_stripped_from_version(self, tmp_path: Path):
        f = tmp_path / "go.mod"
        f.write_text(GO_MOD_BASIC)
        by_name = {p.name: p for p in parse_go_mod(f)}
        # "// indirect" must not bleed into the version string
        assert by_name["golang.org/x/sync"].version == "v0.3.0"


class TestParseGoModEdgeCases:
    def test_empty_require_block_returns_empty(self, tmp_path: Path):
        f = tmp_path / "go.mod"
        f.write_text(GO_MOD_EMPTY_REQUIRE)
        assert parse_go_mod(f) == []

    def test_no_require_directive_returns_empty(self, tmp_path: Path):
        f = tmp_path / "go.mod"
        f.write_text(GO_MOD_NO_REQUIRE)
        assert parse_go_mod(f) == []

    def test_comment_lines_inside_block_skipped(self, tmp_path: Path):
        f = tmp_path / "go.mod"
        f.write_text(GO_MOD_WITH_COMMENTS)
        packages = parse_go_mod(f)
        assert len(packages) == 1
        assert packages[0].name == "github.com/real/dep"

    def test_go_toolchain_entry_skipped(self, tmp_path: Path):
        f = tmp_path / "go.mod"
        f.write_text(GO_MOD_WITH_GO_TOOLCHAIN)
        packages = parse_go_mod(f)
        names = {p.name for p in packages}
        assert "go" not in names
        assert "github.com/real/dep" in names

    def test_multiple_require_blocks(self, tmp_path: Path):
        f = tmp_path / "go.mod"
        f.write_text(GO_MOD_MULTI_BLOCK)
        packages = parse_go_mod(f)
        names = {p.name for p in packages}
        assert "github.com/pkg/a" in names
        assert "github.com/pkg/b" in names
        assert "github.com/pkg/c" in names

    def test_deduplication_across_require_blocks(self, tmp_path: Path):
        content = """\
module example.com/dup

go 1.21

require github.com/foo/bar v1.0.0

require (
\tgithub.com/foo/bar v1.0.0
)
"""
        f = tmp_path / "go.mod"
        f.write_text(content)
        packages = parse_go_mod(f)
        foos = [p for p in packages if p.name == "github.com/foo/bar"]
        assert len(foos) == 1

    def test_returns_package_id_instances(self, tmp_path: Path):
        f = tmp_path / "go.mod"
        f.write_text(GO_MOD_BASIC)
        assert all(isinstance(p, PackageId) for p in parse_go_mod(f))
