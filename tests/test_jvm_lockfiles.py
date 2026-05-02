"""Tests for JVM lockfile parsers (Maven pom.xml, Gradle lockfile)."""

import tempfile
from pathlib import Path

import pytest

from depfence.parsers.jvm_lockfiles import (
    detect_jvm_lockfiles,
    parse_gradle_lockfile,
    parse_pom_xml,
)


class TestPomXml:
    def test_basic_dependencies(self):
        pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
            <version>31.1-jre</version>
        </dependency>
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>2.0.7</version>
        </dependency>
    </dependencies>
</project>"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(pom)
            f.flush()
            packages = parse_pom_xml(Path(f.name))
        assert len(packages) == 2
        assert packages[0].ecosystem == "maven"
        assert packages[0].name == "com.google.guava:guava"
        assert packages[0].version == "31.1-jre"

    def test_skips_test_scope(self):
        pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-core</artifactId>
            <version>2.14.2</version>
        </dependency>
    </dependencies>
</project>"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(pom)
            f.flush()
            packages = parse_pom_xml(Path(f.name))
        assert len(packages) == 1
        assert packages[0].name == "com.fasterxml.jackson.core:jackson-core"

    def test_skips_provided_scope(self):
        pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>javax.servlet-api</artifactId>
            <version>4.0.1</version>
            <scope>provided</scope>
        </dependency>
    </dependencies>
</project>"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(pom)
            f.flush()
            packages = parse_pom_xml(Path(f.name))
        assert len(packages) == 0

    def test_no_namespace(self):
        pom = """<?xml version="1.0"?>
<project>
    <dependencies>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-lang3</artifactId>
            <version>3.12.0</version>
        </dependency>
    </dependencies>
</project>"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(pom)
            f.flush()
            packages = parse_pom_xml(Path(f.name))
        assert len(packages) == 1
        assert packages[0].name == "org.apache.commons:commons-lang3"

    def test_dependency_management(self):
        pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework</groupId>
                <artifactId>spring-core</artifactId>
                <version>6.0.9</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(pom)
            f.flush()
            packages = parse_pom_xml(Path(f.name))
        assert len(packages) == 1
        assert packages[0].name == "org.springframework:spring-core"


class TestGradleLockfile:
    def test_basic_parsing(self):
        content = """# This is a Gradle generated file for dependency locking.
# Manual edits can mess things up - be careful.
com.fasterxml.jackson.core:jackson-core:2.14.2=compileClasspath,runtimeClasspath
com.google.guava:guava:31.1-jre=compileClasspath
org.slf4j:slf4j-api:2.0.7=runtimeClasspath
empty=
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".lockfile", delete=False) as f:
            f.write(content)
            f.flush()
            packages = parse_gradle_lockfile(Path(f.name))
        assert len(packages) == 3
        assert packages[0].ecosystem == "maven"
        assert packages[0].name == "com.fasterxml.jackson.core:jackson-core"
        assert packages[0].version == "2.14.2"

    def test_skips_comments_and_empty(self):
        content = """# Comment line
# Another comment

com.example:lib:1.0.0=compileClasspath
empty=
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".lockfile", delete=False) as f:
            f.write(content)
            f.flush()
            packages = parse_gradle_lockfile(Path(f.name))
        assert len(packages) == 1


class TestDetection:
    def test_detects_pom_xml(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "pom.xml").write_text("<project></project>")
            results = detect_jvm_lockfiles(p)
            assert any("pom.xml" in str(path) for _, path in results)

    def test_detects_gradle_lockfile(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "gradle.lockfile").write_text("empty=\n")
            results = detect_jvm_lockfiles(p)
            assert any("gradle.lockfile" in str(path) for _, path in results)
