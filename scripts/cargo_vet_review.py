#!/usr/bin/env python3
"""
Cargo Vet Review Assistant

Automates the cargo vet workflow by:
1. Parsing `cargo vet` output to identify unvetted dependencies
2. Fetching diffs from diff.rs or using local mode
3. Analyzing changes for security concerns (pattern matching + AI)
4. Providing educated suggestions about safety
5. Facilitating the certification process

Usage:
  python scripts/cargo_vet_review.py [--ai-provider gemini|claude] [--no-ai]
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityFinding:
    """A security-relevant finding in the diff."""
    category: str
    description: str
    risk: RiskLevel
    file_path: str = ""  # Relative path within the crate (e.g., "src/lib.rs")
    line_number: int = 0
    snippet: str = ""


@dataclass
class DiffAnalysis:
    """Analysis results for a crate diff."""
    crate_name: str
    old_version: str
    new_version: str
    diff_type: str  # "diff" or "inspect"
    lines_changed: int
    findings: list[SecurityFinding] = field(default_factory=list)
    raw_diff: str = ""
    recommendation: str = ""
    risk_score: RiskLevel = RiskLevel.LOW
    trust_suggestion: Optional[str] = None
    claude_analysis: Optional[str] = None  # AI-powered analysis


class DiffRsParser(HTMLParser):
    """Parse diff.rs HTML to extract the actual diff content."""
    def __init__(self):
        super().__init__()
        self.in_code = False
        self.in_pre = False
        self.diff_content = []
        self.current_file = ""

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "pre":
            self.in_pre = True
        elif tag == "code" and self.in_pre:
            self.in_code = True

    def handle_endtag(self, tag):
        if tag == "code":
            self.in_code = False
        elif tag == "pre":
            self.in_pre = False

    def handle_data(self, data):
        if self.in_code:
            self.diff_content.append(data)


class SecurityAnalyzer:
    """Analyzes diffs for security concerns."""

    # Patterns that indicate potential security issues
    UNSAFE_PATTERNS = [
        (r'\bunsafe\s*\{', "unsafe block", RiskLevel.HIGH),
        (r'\bunsafe\s+fn\b', "unsafe function", RiskLevel.HIGH),
        (r'\bunsafe\s+impl\b', "unsafe impl", RiskLevel.HIGH),
        (r'\bunsafe\s+trait\b', "unsafe trait", RiskLevel.HIGH),
    ]

    DANGEROUS_IMPORTS = [
        (r'use\s+std::process', "process execution import", RiskLevel.MEDIUM),
        (r'use\s+std::fs', "filesystem access import", RiskLevel.LOW),
        (r'use\s+std::net', "network access import", RiskLevel.MEDIUM),
        (r'use\s+std::os::unix::fs', "unix filesystem import", RiskLevel.MEDIUM),
        (r'use\s+libc::', "libc import", RiskLevel.MEDIUM),
        (r'use\s+nix::', "nix crate import", RiskLevel.MEDIUM),
        (r'std::mem::transmute', "transmute usage", RiskLevel.HIGH),
        (r'std::ptr::', "raw pointer operations", RiskLevel.HIGH),
    ]

    NETWORK_PATTERNS = [
        (r'https?://[^\s"\'>\)]+', "URL reference", RiskLevel.LOW),
        (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', "IP address", RiskLevel.MEDIUM),
        (r'TcpStream|UdpSocket|TcpListener', "network socket", RiskLevel.MEDIUM),
        (r'reqwest::|hyper::|curl::', "HTTP client", RiskLevel.MEDIUM),
    ]

    OBFUSCATION_PATTERNS = [
        (r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}', "long hex escape sequence", RiskLevel.HIGH),
        (r'base64::decode|from_base64', "base64 decoding", RiskLevel.MEDIUM),
        (r'(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', "possible base64 blob", RiskLevel.MEDIUM),
        (r'eval\s*\(', "eval-like construct", RiskLevel.CRITICAL),
        (r'from_utf8_unchecked', "unchecked UTF-8 conversion", RiskLevel.HIGH),
    ]

    BUILD_SCRIPT_PATTERNS = [
        (r'println!\s*\(\s*"cargo:', "build script directive", RiskLevel.LOW),
        (r'Command::new', "command execution in build", RiskLevel.HIGH),
        (r'cc::Build', "C compilation", RiskLevel.MEDIUM),
        (r'bindgen::', "FFI binding generation", RiskLevel.MEDIUM),
    ]

    CRYPTO_PATTERNS = [
        (r'rand::|random|OsRng|ThreadRng', "random number generation", RiskLevel.LOW),
        (r'sha[0-9]+::|md5::|blake[0-9]*::', "hash function", RiskLevel.LOW),
        (r'aes::|chacha::|cipher::', "encryption", RiskLevel.MEDIUM),
        (r'ring::|rustls::|openssl::', "crypto library", RiskLevel.LOW),
    ]

    PRIVILEGE_PATTERNS = [
        (r'setuid|setgid|seteuid|setegid', "privilege modification", RiskLevel.CRITICAL),
        (r'CAP_[A-Z_]+', "Linux capability", RiskLevel.HIGH),
        (r'chmod|chown|chgrp', "permission modification", RiskLevel.MEDIUM),
        (r'sudo|doas|pkexec', "privilege escalation command", RiskLevel.CRITICAL),
    ]

    ENV_PATTERNS = [
        (r'std::env::var|env!|option_env!', "environment variable access", RiskLevel.LOW),
        (r'std::env::set_var', "environment variable modification", RiskLevel.MEDIUM),
        (r'HOME|PATH|LD_PRELOAD|LD_LIBRARY_PATH', "sensitive env var", RiskLevel.MEDIUM),
    ]

    # Known trusted publishers (from cargo vet trust suggestions)
    TRUSTED_PUBLISHERS = {
        "dtolnay": "David Tolnay - prolific Rust maintainer",
        "djc": "Dirkjan Ochtman - Rust ecosystem contributor",
        "carllerche": "Carl Lerche - Tokio maintainer",
        "alexcrichton": "Alex Crichton - Rust/Cargo maintainer",
        "sfackler": "Steven Fackler - rust-postgres, rust-openssl",
        "BurntSushi": "Andrew Gallant - ripgrep, regex author",
    }

    # Known safe crates that are widely used
    WELL_KNOWN_CRATES = {
        "serde", "serde_json", "serde_derive", "tokio", "async-trait",
        "anyhow", "thiserror", "clap", "log", "env_logger", "tracing",
        "rand", "regex", "lazy_static", "once_cell", "parking_lot",
        "bytes", "futures", "pin-project", "syn", "quote", "proc-macro2",
        "chrono", "uuid", "url", "http", "hyper", "reqwest", "rustls",
        "ring", "tempfile", "walkdir", "glob", "libc", "cc", "pkg-config",
    }

    def __init__(self):
        self.all_patterns = [
            ("Unsafe Code", self.UNSAFE_PATTERNS),
            ("Dangerous Imports", self.DANGEROUS_IMPORTS),
            ("Network Operations", self.NETWORK_PATTERNS),
            ("Obfuscation/Encoding", self.OBFUSCATION_PATTERNS),
            ("Build Script", self.BUILD_SCRIPT_PATTERNS),
            ("Cryptography", self.CRYPTO_PATTERNS),
            ("Privilege Operations", self.PRIVILEGE_PATTERNS),
            ("Environment Access", self.ENV_PATTERNS),
        ]

    def _extract_relative_path(self, full_path: str, crate_name: str) -> str:
        """Extract the relative path within a crate from a full cache path.

        Converts paths like:
          home/user/.cache/cargo-vet/src/uzers-0.12.2/tests/groups.rs
        To:
          tests/groups.rs
        """
        # Try to find the crate directory pattern (crate-version/)
        # Pattern: anything ending with crate_name-version/
        pattern = rf'(?:^|/)({re.escape(crate_name)}-[^/]+)/(.+)$'
        match = re.search(pattern, full_path)
        if match:
            return match.group(2)

        # Fallback: just use the filename
        if '/' in full_path:
            # Try to get a reasonable relative path (last 2-3 components)
            parts = full_path.split('/')
            # Skip cache path components
            for i, part in enumerate(parts):
                if part == 'src' and i > 0 and 'cargo-vet' in parts[i-1]:
                    # Found cargo-vet cache, skip to crate contents
                    remaining = parts[i+1:]
                    if len(remaining) > 1:
                        return '/'.join(remaining[1:])  # Skip crate-version dir
            # Last resort: return last 2 path components
            return '/'.join(parts[-2:]) if len(parts) >= 2 else full_path
        return full_path

    def analyze_diff(self, diff_content: str, crate_name: str) -> list[SecurityFinding]:
        """Analyze diff content for security concerns."""
        findings = []

        # Only analyze added lines (lines starting with +)
        added_lines = []
        current_file = ""
        line_num = 0

        for line in diff_content.split('\n'):
            # Track current file
            if line.startswith('diff --git') or line.startswith('+++'):
                match = re.search(r'[ab]/(.+?)(?:\s|$)', line)
                if match:
                    current_file = match.group(1)
                    line_num = 0
                continue

            # Track line numbers from @@ markers
            if line.startswith('@@'):
                match = re.search(r'\+(\d+)', line)
                if match:
                    line_num = int(match.group(1))
                continue

            # Only analyze added lines
            if line.startswith('+') and not line.startswith('+++'):
                added_content = line[1:]  # Remove the leading +
                added_lines.append((current_file, line_num, added_content))
                line_num += 1
            elif not line.startswith('-'):
                line_num += 1

        # Check for build.rs changes
        build_rs_changes = any(f.endswith('build.rs') for f, _, _ in added_lines)
        if build_rs_changes:
            findings.append(SecurityFinding(
                category="Build Script",
                description="Changes to build.rs detected - review build-time behavior",
                risk=RiskLevel.MEDIUM,
                file_path="build.rs",
                line_number=0,
            ))

        # Check for Cargo.toml changes (new dependencies)
        cargo_changes = [(f, n, c) for f, n, c in added_lines if f.endswith('Cargo.toml')]
        for file_path, line_num, content in cargo_changes:
            # Look for new dependencies
            if re.search(r'^\s*\[.*dependencies', content) or re.search(r'^\s*\w+\s*=\s*["{]', content):
                if 'git' in content or 'path' in content:
                    rel_path = self._extract_relative_path(file_path, crate_name)
                    findings.append(SecurityFinding(
                        category="Dependencies",
                        description=f"New dependency with git/path source: {content.strip()}",
                        risk=RiskLevel.HIGH,
                        file_path=rel_path,
                        line_number=line_num,
                        snippet=content.strip(),
                    ))

        # Run pattern analysis on added lines
        for category, patterns in self.all_patterns:
            for file_path, line_num, content in added_lines:
                for pattern, desc, risk in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        # Skip well-known safe patterns
                        if self._is_false_positive(category, content, matches, crate_name):
                            continue

                        rel_path = self._extract_relative_path(file_path, crate_name)
                        findings.append(SecurityFinding(
                            category=category,
                            description=f"{desc}: {matches[0] if len(matches) == 1 else matches}",
                            risk=risk,
                            file_path=rel_path,
                            line_number=line_num,
                            snippet=content.strip()[:100],
                        ))

        return findings

    def _is_false_positive(self, category: str, content: str, matches: list, crate_name: str) -> bool:
        """Filter out known false positives."""
        # Documentation URLs are safe
        if category == "Network Operations":
            for match in matches:
                if isinstance(match, str):
                    if any(domain in match for domain in [
                        "docs.rs", "crates.io", "github.com", "rust-lang.org",
                        "mozilla.org", "apache.org", "spdx.org", "example.com",
                        "localhost", "127.0.0.1"
                    ]):
                        return True
                    # SPDX license identifiers
                    if "spdx.org/licenses" in match:
                        return True

        # Test code is lower risk
        if '/tests/' in content or '#[test]' in content or '#[cfg(test)]' in content:
            return True

        # Comments are informational
        if content.strip().startswith('//') or content.strip().startswith('/*'):
            return True

        return False

    def calculate_risk_score(self, findings: list[SecurityFinding]) -> RiskLevel:
        """Calculate overall risk score from findings."""
        if not findings:
            return RiskLevel.LOW

        risk_counts = {level: 0 for level in RiskLevel}
        for finding in findings:
            risk_counts[finding.risk] += 1

        if risk_counts[RiskLevel.CRITICAL] > 0:
            return RiskLevel.CRITICAL
        elif risk_counts[RiskLevel.HIGH] >= 3 or risk_counts[RiskLevel.HIGH] >= 1:
            return RiskLevel.HIGH
        elif risk_counts[RiskLevel.MEDIUM] >= 5:
            return RiskLevel.HIGH
        elif risk_counts[RiskLevel.MEDIUM] >= 2:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def generate_recommendation(self, analysis: DiffAnalysis) -> str:
        """Generate a recommendation based on analysis."""
        recommendations = []

        # Check if it's a well-known crate
        if analysis.crate_name in self.WELL_KNOWN_CRATES:
            recommendations.append(f"'{analysis.crate_name}' is a well-known, widely-used crate.")

        # Check trust suggestions
        if analysis.trust_suggestion:
            publisher = analysis.trust_suggestion
            if publisher in self.TRUSTED_PUBLISHERS:
                recommendations.append(
                    f"Publisher '{publisher}' is a trusted Rust ecosystem maintainer "
                    f"({self.TRUSTED_PUBLISHERS[publisher]}). Consider: cargo vet trust {analysis.crate_name} {publisher}"
                )

        # Size-based recommendations
        if analysis.lines_changed < 50:
            recommendations.append("Small diff - quick manual review recommended.")
        elif analysis.lines_changed < 200:
            recommendations.append("Moderate diff - focused review on highlighted concerns.")
        elif analysis.lines_changed < 1000:
            recommendations.append("Large diff - thorough review recommended, consider breaking into sessions.")
        else:
            recommendations.append("Very large diff - consider trusting publisher if reputable, or auditing incrementally.")

        # Risk-based recommendations
        if analysis.risk_score == RiskLevel.CRITICAL:
            recommendations.append("CRITICAL findings detected - MANUAL REVIEW REQUIRED before certifying.")
        elif analysis.risk_score == RiskLevel.HIGH:
            recommendations.append("High-risk patterns found - careful manual review recommended.")
        elif analysis.risk_score == RiskLevel.MEDIUM:
            recommendations.append("Some patterns of interest found - review the highlighted sections.")
        else:
            recommendations.append("No major concerns found - likely safe to certify after brief review.")

        # Specific finding recommendations
        unsafe_findings = [f for f in analysis.findings if "unsafe" in f.category.lower()]
        if unsafe_findings:
            recommendations.append(f"Found {len(unsafe_findings)} unsafe code additions - these require manual verification.")

        build_findings = [f for f in analysis.findings if "build" in f.category.lower()]
        if build_findings:
            recommendations.append("Build script changes detected - verify no malicious build-time behavior.")

        # Add diff URL for easy review
        if analysis.old_version:
            diff_url = f"https://diff.rs/{analysis.crate_name}/{analysis.old_version}/{analysis.new_version}"
            recommendations.append(f"Review diff: {diff_url}")
        else:
            crate_url = f"https://crates.io/crates/{analysis.crate_name}/{analysis.new_version}"
            recommendations.append(f"Review crate: {crate_url}")

        return "\n".join(f"  - {r}" for r in recommendations)


class CargoVetParser:
    """Parse cargo vet output to extract audit requirements."""

    @dataclass
    class AuditItem:
        command: str
        crate_name: str
        old_version: Optional[str]
        new_version: str
        publisher: str
        used_by: str
        audit_size: str
        trust_note: Optional[str] = None

    def parse_vet_output(self, output: str) -> list[AuditItem]:
        """Parse cargo vet output to get list of required audits."""
        items = []

        # Pattern for diff commands
        diff_pattern = re.compile(
            r'cargo vet diff (\S+) (\S+) (\S+)\s+'
            r'(\S+)\s+'  # Publisher
            r'(.+?)\s+'  # Used by
            r'(\d+ files? changed.+?)$',
            re.MULTILINE
        )

        # Pattern for inspect commands
        inspect_pattern = re.compile(
            r'cargo vet inspect (\S+) (\S+)\s+'
            r'(\S+)\s+'  # Publisher
            r'(.+?)\s+'  # Used by
            r'(\d+ lines?)$',
            re.MULTILINE
        )

        # Pattern for trust notes
        trust_pattern = re.compile(
            r'NOTE: this project trusts ([^(]+) \((\w+)\)'
        )

        for match in diff_pattern.finditer(output):
            crate, old_ver, new_ver, publisher, used_by, size = match.groups()

            # Check for trust note on next line
            trust_note = None
            pos = match.end()
            remaining = output[pos:pos+200]
            trust_match = trust_pattern.search(remaining)
            if trust_match and remaining.find('\n') > remaining.find('NOTE:'):
                trust_note = trust_match.group(2)

            items.append(self.AuditItem(
                command=f"cargo vet diff {crate} {old_ver} {new_ver}",
                crate_name=crate,
                old_version=old_ver,
                new_version=new_ver,
                publisher=publisher,
                used_by=used_by.strip(),
                audit_size=size,
                trust_note=trust_note,
            ))

        for match in inspect_pattern.finditer(output):
            crate, version, publisher, used_by, size = match.groups()

            trust_note = None
            pos = match.end()
            remaining = output[pos:pos+200]
            trust_match = trust_pattern.search(remaining)
            if trust_match and remaining.find('\n') > remaining.find('NOTE:'):
                trust_note = trust_match.group(2)

            items.append(self.AuditItem(
                command=f"cargo vet inspect {crate} {version}",
                crate_name=crate,
                old_version=None,
                new_version=version,
                publisher=publisher,
                used_by=used_by.strip(),
                audit_size=size,
                trust_note=trust_note,
            ))

        return items


class DiffFetcher:
    """Fetch diffs from diff.rs or locally via cargo vet."""

    def fetch_from_diff_rs(self, crate: str, old_ver: str, new_ver: str, verbose: bool = False) -> Optional[str]:
        """Fetch diff from diff.rs website."""
        url = f"https://diff.rs/{crate}/{old_ver}/{new_ver}/"

        try:
            if verbose:
                print(f"    Debug: Fetching from {url}")

            req = urllib.request.Request(url, headers={
                'User-Agent': 'cargo-vet-review/1.0 (security audit tool)',
                'Accept': 'text/html',
            })
            with urllib.request.urlopen(req, timeout=60) as response:
                html = response.read().decode('utf-8')

            if verbose:
                print(f"    Debug: Got {len(html)} bytes of HTML")

            # Parse HTML to extract diff
            parser = DiffRsParser()
            parser.feed(html)

            if verbose:
                print(f"    Debug: Parsed {len(parser.diff_content)} content blocks")

            if parser.diff_content:
                return '\n'.join(parser.diff_content)

            # If parsing failed, return None to fall back to local mode
            if verbose:
                print("    Debug: No content extracted from HTML")
            return None

        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            print(f"    Warning: Could not fetch from diff.rs: {e}")
            return None
        except Exception as e:
            print(f"    Warning: Error fetching from diff.rs: {e}")
            return None

    def fetch_local(self, crate: str, old_ver: Optional[str], new_ver: str, verbose: bool = False) -> Optional[str]:
        """Fetch diff using cargo vet's local mode."""
        try:
            if old_ver:
                cmd = ["cargo", "vet", "diff", crate, old_ver, new_ver, "--mode=local"]
                timeout = 60  # Diffs are usually fast
            else:
                cmd = ["cargo", "vet", "inspect", crate, new_ver, "--mode=local"]
                timeout = 180  # Full crate downloads can be slow

            if verbose:
                print(f"    Debug: Running command: {' '.join(cmd)}")

            # For inspect (new crate), first check if the cache already exists
            if not old_ver:
                cache_dir = Path.home() / ".cache" / "cargo-vet" / "src" / f"{crate}-{new_ver}"
                if cache_dir.exists():
                    if verbose:
                        print(f"    Debug: Cache already exists at {cache_dir}")
                    return self._generate_inspect_diff(cache_dir, crate, new_ver, verbose)

            # cargo vet inspect/diff --mode=local prompts "(press ENTER to inspect locally)"
            # and then opens an interactive shell. We need to:
            # 1. Send ENTER to proceed past the prompt
            # 2. Immediately send 'exit' to close the nested shell
            # 3. Read the source files directly from the cache
            result = subprocess.run(
                cmd,
                input="\nexit\n",  # ENTER to proceed, then exit the shell
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if verbose:
                print(f"    Debug: Command returned {result.returncode}")
                if result.stderr:
                    print(f"    Debug: stderr: {result.stderr[:200]}")

            # For 'inspect' command, the source is downloaded to ~/.cache/cargo-vet/src/{crate}-{version}/
            # We need to generate a diff-like output from the source files
            if not old_ver:
                cache_dir = Path.home() / ".cache" / "cargo-vet" / "src" / f"{crate}-{new_ver}"
                if cache_dir.exists():
                    if verbose:
                        print(f"    Debug: Reading source from {cache_dir}")
                    return self._generate_inspect_diff(cache_dir, crate, new_ver, verbose)
                else:
                    if verbose:
                        print(f"    Debug: Cache dir not found: {cache_dir}")
                    # Fall back to stdout if available
                    if result.stdout:
                        return result.stdout

            if result.returncode == 0:
                return result.stdout
            else:
                # cargo vet diff sometimes returns non-zero but still produces output
                if result.stdout:
                    return result.stdout
                print(f"    Warning: cargo vet command failed: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            print(f"    Warning: cargo vet command timed out ({timeout}s)")
            return None
        except FileNotFoundError:
            print("    Error: cargo-vet not found. Install with: cargo install cargo-vet")
            return None

    def _generate_inspect_diff(self, cache_dir: Path, crate: str, version: str, verbose: bool = False) -> str:
        """Generate a unified diff-like output for a full crate inspection.

        This creates output similar to what 'git diff' would show, treating all
        files as new additions. This allows the security analyzer to process
        the crate source using the same logic as version diffs.
        """
        diff_lines = []

        # Find all source files (prioritize important files)
        important_files = ['Cargo.toml', 'build.rs', 'src/lib.rs', 'src/main.rs']
        all_files = []

        for pattern in ['**/*.rs', '**/*.toml', '**/build.rs']:
            all_files.extend(cache_dir.glob(pattern))

        # Remove duplicates and sort (important files first)
        seen = set()
        sorted_files = []

        for important in important_files:
            full_path = cache_dir / important
            if full_path.exists() and full_path not in seen:
                sorted_files.append(full_path)
                seen.add(full_path)

        for f in sorted(all_files):
            if f not in seen and f.is_file():
                sorted_files.append(f)
                seen.add(f)

        if verbose:
            print(f"    Debug: Found {len(sorted_files)} source files")

        for file_path in sorted_files:
            try:
                rel_path = file_path.relative_to(cache_dir)
                content = file_path.read_text(encoding='utf-8', errors='replace')
                lines = content.split('\n')

                # Generate unified diff header (treating as new file)
                diff_lines.append(f"diff --git a/{rel_path} b/{rel_path}")
                diff_lines.append(f"new file mode 100644")
                diff_lines.append(f"--- /dev/null")
                diff_lines.append(f"+++ b/{rel_path}")
                diff_lines.append(f"@@ -0,0 +1,{len(lines)} @@")

                # Add all lines as additions
                for line in lines:
                    diff_lines.append(f"+{line}")
                diff_lines.append("")  # Empty line between files

            except Exception as e:
                if verbose:
                    print(f"    Debug: Could not read {file_path}: {e}")
                continue

        return '\n'.join(diff_lines)


class AIAnalyzer:
    """Use an AI provider's CLI to analyze diffs for security concerns."""

    SECURITY_REVIEW_PROMPT = """You are a security auditor reviewing Rust crate changes for the cargo-vet tool.
Your job is to analyze the following code changes and identify potential security concerns.

## Crate Information
- Crate: {crate_name}
- Version change: {version_info}
- Publisher: {publisher}
- This is a: {review_type}

## Review Criteria (safe-to-deploy)
This crate must not introduce a serious security vulnerability to production software exposed to untrusted input.

Focus on:
1. **Unsafe code blocks** - Are they sound? Could they cause memory corruption?
2. **External inputs** - Is user/network input properly validated?
3. **File system access** - Are paths properly sanitized? Any directory traversal risks?
4. **Network operations** - Any unexpected connections? Data exfiltration risks?
5. **Process execution** - Command injection risks? Unexpected shell commands?
6. **Cryptographic operations** - Are they using secure algorithms correctly?
7. **Build scripts (build.rs)** - Any suspicious build-time behavior?
8. **Obfuscation** - Any encoded strings, suspicious base64, or hidden behavior?
9. **Dependencies** - Any new dependencies added via git or path?
10. **Privilege operations** - Any setuid, capability, or permission changes?

## Code to Review
```
{code_content}
```

## Your Analysis
Provide a concise security analysis with:
1. **Summary** (1-2 sentences): Overall assessment
2. **Risk Level**: LOW / MEDIUM / HIGH / CRITICAL
3. **Key Findings**: List specific concerns (if any) with file:line references
4. **Recommendation**: Should this be certified? What needs manual review?

Keep your response focused and actionable. If the changes look safe, say so clearly.
"""

    FULL_CRATE_PROMPT = """You are a security auditor reviewing a NEW Rust crate for the cargo-vet tool.
This is a FULL CRATE REVIEW - the entire crate source is being added as a new dependency.

## Crate Information
- Crate: {crate_name}
- Version: {version}
- Publisher: {publisher}
- Lines of code: ~{line_count}

## Review Criteria (safe-to-deploy)
This crate must not introduce a serious security vulnerability to production software.

Since this is a full crate review, focus on:
1. **Purpose** - What does this crate do? Is it a well-known/reputable crate?
2. **Unsafe code** - Grep for `unsafe` - are the unsafe blocks justified and sound?
3. **Dependencies** - What other crates does it pull in?
4. **Build scripts** - Does build.rs do anything suspicious?
5. **Network/filesystem** - Does it make network calls or access files unexpectedly?
6. **Attack surface** - Where could malicious input cause problems?

## Crate Source (partial - showing key files)
```
{code_content}
```

## Your Analysis
Provide a concise security analysis with:
1. **Summary** (1-2 sentences): What this crate does and overall safety assessment
2. **Risk Level**: LOW / MEDIUM / HIGH / CRITICAL
3. **Key Findings**: Specific concerns or notable patterns
4. **Recommendation**: Safe to certify? Or needs deeper review?

Keep your response focused and actionable.
"""

    def __init__(self, provider: str, path: Optional[str] = None):
        self.provider = provider
        self.cli_path = path or provider
        self._cli_available = None

    def is_available(self) -> bool:
        """Check if the AI provider's CLI is available."""
        if self._cli_available is not None:
            return self._cli_available

        self._cli_available = shutil.which(self.cli_path) is not None
        return self._cli_available

    def analyze_diff(
        self,
        diff_content: str,
        crate_name: str,
        old_version: Optional[str],
        new_version: str,
        publisher: str,
        is_full_crate: bool = False,
        verbose: bool = False,
    ) -> Optional[str]:
        """Ask an AI to analyze the diff for security concerns."""
        if not self.is_available():
            if verbose:
                print(f"    Debug: {self.provider.capitalize()} CLI not found at '{self.cli_path}'")
            return None

        # Truncate very large diffs to avoid token limits
        max_content_size = 50000  # ~12k tokens
        if len(diff_content) > max_content_size:
            # For large diffs, include beginning and end with truncation notice
            half = max_content_size // 2
            diff_content = (
                diff_content[:half] +
                f"\n\n... [TRUNCATED - {len(diff_content) - max_content_size} chars omitted] ...\n\n" +
                diff_content[-half:]
            )

        if is_full_crate:
            prompt = self.FULL_CRATE_PROMPT.format(
                crate_name=crate_name,
                version=new_version,
                publisher=publisher,
                line_count=len(diff_content.split('\n')),
                code_content=diff_content,
            )
        else:
            version_info = f"{old_version} -> {new_version}" if old_version else new_version
            review_type = "version upgrade diff" if old_version else "new crate (full source)"

            prompt = self.SECURITY_REVIEW_PROMPT.format(
                crate_name=crate_name,
                version_info=version_info,
                publisher=publisher,
                review_type=review_type,
                code_content=diff_content,
            )

        # Write prompt to temp file
        prompt_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(prompt)
                prompt_file = f.name

            if verbose:
                print(f"    Debug: Prompt for {self.provider} written to {prompt_file} ({len(prompt)} chars)")

            if self.provider == 'claude':
                # Method 1: Use -p flag with prompt from file
                result = subprocess.run(
                    [self.cli_path, "-p", prompt, "--output-format", "text"],
                    capture_output=True, text=True, timeout=180,
                )
                if result.returncode == 0 and result.stdout and len(result.stdout.strip()) > 10:
                    return result.stdout.strip()
                # Method 2: Pipe prompt via stdin
                result = subprocess.run(
                    [self.cli_path, "--output-format", "text"],
                    input=prompt, capture_output=True, text=True, timeout=180,
                )
                if result.returncode == 0 and result.stdout and len(result.stdout.strip()) > 10:
                    return result.stdout.strip()
                # Method 3: Use --print flag
                result = subprocess.run(
                    [self.cli_path, "--print", prompt],
                    capture_output=True, text=True, timeout=180,
                )
                if result.returncode == 0 and result.stdout and len(result.stdout.strip()) > 10:
                    return result.stdout.strip()

            elif self.provider == 'gemini':
                # Assume gemini CLI is compatible with one of these patterns
                # Method 1: Use -p for prompt
                result = subprocess.run(
                    [self.cli_path, "-p", prompt],
                    capture_output=True, text=True, timeout=180,
                )
                if result.returncode == 0 and result.stdout and len(result.stdout.strip()) > 10:
                    return result.stdout.strip()
                # Method 2: Pipe prompt via stdin
                result = subprocess.run(
                    [self.cli_path],
                    input=prompt, capture_output=True, text=True, timeout=180,
                )
                if result.returncode == 0 and result.stdout and len(result.stdout.strip()) > 10:
                    return result.stdout.strip()


            # If all methods failed, print debug info
            print(f"    Warning: All {self.provider} invocation methods failed")
            if 'result' in locals() and result.stderr:
                print(f"    Last error: {result.stderr[:300]}")

            return None

        except subprocess.TimeoutExpired:
            print(f"    Warning: {self.provider.capitalize()} analysis timed out (180s)")
            return None
        except Exception as e:
            print(f"    Warning: {self.provider.capitalize()} analysis failed: {e}")
            import traceback
            if verbose:
                traceback.print_exc()
            return None
        finally:
            if prompt_file and os.path.exists(prompt_file):
                os.unlink(prompt_file)


def print_color(text: str, color: str):
    """Print colored text."""
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'reset': '\033[0m',
        'bold': '\033[1m',
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")


def generate_diff_url(crate_name: str, old_version: Optional[str], new_version: str) -> str:
    """Generate a diff.rs URL for reviewing changes.

    Note: File-specific URLs don't work reliably because browsers decode %2F
    in the URL bar, which breaks diff.rs links. So we only generate base URLs.

    For full crate reviews (no old_version), we use the same version twice
    which shows the entire crate as "new" code on diff.rs.

    Args:
        crate_name: Name of the crate
        old_version: Previous version (None for full crate review)
        new_version: New version being reviewed

    Returns:
        URL to diff.rs for reviewing
    """
    if old_version:
        return f"https://diff.rs/{crate_name}/{old_version}/{new_version}"
    else:
        # For full crate review, use same version twice to show all code as "new"
        return f"https://diff.rs/{crate_name}/{new_version}/{new_version}"


def print_finding(finding: SecurityFinding):
    """Print a security finding with appropriate coloring."""
    risk_colors = {
        RiskLevel.LOW: 'green',
        RiskLevel.MEDIUM: 'yellow',
        RiskLevel.HIGH: 'red',
        RiskLevel.CRITICAL: 'magenta',
    }
    color = risk_colors[finding.risk]
    risk_label = f"[{finding.risk.value.upper()}]"

    print_color(f"    {risk_label} {finding.category}: {finding.description}", color)

    # Show file and line location
    if finding.file_path:
        location = finding.file_path
        if finding.line_number > 0:
            location += f":{finding.line_number}"
        print(f"         Location: {location}")

    if finding.snippet:
        print(f"         Snippet: {finding.snippet[:80]}...")


def run_cargo_vet() -> str:
    """Run cargo vet and return output."""
    try:
        result = subprocess.run(
            ["cargo", "vet"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        # cargo vet returns non-zero when audits are needed
        return result.stdout + result.stderr
    except FileNotFoundError:
        print("Error: cargo-vet not found. Install with: cargo install cargo-vet")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("Error: cargo vet timed out")
        sys.exit(1)


def certify_crate(crate: str, version: str, notes: str = "") -> bool:
    """Run cargo vet certify for a crate."""
    try:
        cmd = ["cargo", "vet", "certify", crate, version]
        if notes:
            cmd.extend(["--notes", notes])

        # certify requires interactive input, so we need to handle that
        result = subprocess.run(
            cmd,
            timeout=30,
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Error during certification: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Automated cargo vet review assistant with AI-powered analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Interactive review with Gemini AI analysis
  %(prog)s --ai-provider claude # Use Claude AI instead
  %(prog)s --no-ai            # Review without AI (pattern matching only)
  %(prog)s --skip-large 5000  # Skip diffs larger than 5000 lines
  %(prog)s --dry-run          # Analyze without certifying
  %(prog)s --json             # Output analysis as JSON
  %(prog)s --crate uuid       # Only analyze a specific crate
        """,
    )
    parser.add_argument(
        "--skip-large",
        type=int,
        default=100000,
        help="Skip diffs larger than N lines (default: 100000)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Analyze only, don't offer to certify",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output analysis as JSON",
    )
    parser.add_argument(
        "--crate",
        type=str,
        help="Only analyze a specific crate",
    )
    parser.add_argument(
        "--ai-provider",
        type=str,
        default="gemini",
        choices=["gemini", "claude"],
        help="The AI provider to use for analysis (default: gemini)",
    )
    parser.add_argument(
        "--ai-provider-path",
        type=str,
        default=None,
        help="Path to the AI provider's CLI binary (e.g., /path/to/gemini)",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI analysis (use pattern matching only)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug output for troubleshooting",
    )

    args = parser.parse_args()

    print_color("Cargo Vet Review Assistant", "bold")
    print_color("=" * 60, "cyan")
    print()

    # Run cargo vet to get current status
    print("Running cargo vet to identify unvetted dependencies...")
    vet_output = run_cargo_vet()

    if "Vetting Failed" not in vet_output and "unvetted dependencies" not in vet_output:
        print_color("All dependencies are already vetted!", "green")
        return

    # Parse the output
    vet_parser = CargoVetParser()
    items = vet_parser.parse_vet_output(vet_output)

    if not items:
        print("Could not parse cargo vet output. Raw output:")
        print(vet_output)
        return

    # Filter if specific crate requested
    if args.crate:
        items = [i for i in items if i.crate_name == args.crate]
        if not items:
            print(f"Crate '{args.crate}' not found in unvetted list")
            return

    print(f"Found {len(items)} crates requiring audit")
    print()

    # Sort by audit size (smaller first)
    def size_key(item):
        match = re.search(r'(\d+)', item.audit_size)
        return int(match.group(1)) if match else 0

    items.sort(key=size_key)

    # Setup analyzers and fetcher
    analyzer = SecurityAnalyzer()
    ai_analyzer = None
    if not args.no_ai:
        ai_analyzer = AIAnalyzer(provider=args.ai_provider, path=args.ai_provider_path)
    fetcher = DiffFetcher()
    analyses = []

    # Check AI availability
    use_ai = ai_analyzer and ai_analyzer.is_available()
    if not args.no_ai:
        provider_name = args.ai_provider.capitalize()
        if use_ai:
            print_color(f"{provider_name} AI analysis: ENABLED", "green")
        else:
            cli_name = args.ai_provider_path or args.ai_provider
            print_color(f"{provider_name} AI analysis: NOT AVAILABLE (could not find '{cli_name}', install it or use --no-ai)", "yellow")
    print()

    for idx, item in enumerate(items, 1):
        is_full_crate = item.old_version is None
        review_type = "FULL CRATE REVIEW" if is_full_crate else "version upgrade"

        print_color(f"\n{'='*60}", "cyan")
        print_color(f"[{idx}/{len(items)}] {item.crate_name}", "bold")
        if is_full_crate:
            print_color(f"    NEW CRATE: {item.new_version}", "yellow")
        else:
            print(f"    Version: {item.old_version} -> {item.new_version}")
        print(f"    Publisher: {item.publisher}")
        print(f"    Used by: {item.used_by}")
        print(f"    Size: {item.audit_size}")
        print(f"    Type: {review_type}")

        # Show diff URL prominently
        diff_url = generate_diff_url(item.crate_name, item.old_version, item.new_version)
        print_color(f"    Review: {diff_url}", "cyan")

        if item.trust_note:
            print_color(f"    Trust suggestion: cargo vet trust {item.crate_name} {item.trust_note}", "cyan")
        print()

        # Extract line count from size
        size_match = re.search(r'(\d+)\s*(?:lines?|insertions?)', item.audit_size)
        line_count = int(size_match.group(1)) if size_match else 0

        if line_count > args.skip_large:
            print_color(f"    Skipping - diff too large ({line_count} lines > {args.skip_large})", "yellow")
            print(f"    Consider: cargo vet trust {item.crate_name} {item.trust_note or item.publisher}")
            continue

        # Fetch diff using cargo vet (gets ALL files, unlike diff.rs which only shows one)
        print("    Fetching source changes...")
        diff_content = fetcher.fetch_local(
            item.crate_name, item.old_version, item.new_version, verbose=args.verbose
        )

        if not diff_content:
            print_color("    Could not fetch source content", "red")
            continue

        # Pattern-based analysis
        print("    Running pattern-based security analysis...")
        findings = analyzer.analyze_diff(diff_content, item.crate_name)

        analysis = DiffAnalysis(
            crate_name=item.crate_name,
            old_version=item.old_version or "",
            new_version=item.new_version,
            diff_type="diff" if item.old_version else "inspect",
            lines_changed=line_count,
            findings=findings,
            raw_diff=diff_content[:5000] if args.json else "",
            trust_suggestion=item.trust_note,
        )
        analysis.risk_score = analyzer.calculate_risk_score(findings)
        analysis.recommendation = analyzer.generate_recommendation(analysis)

        # AI analysis
        if use_ai:
            print(f"    Requesting {args.ai_provider.capitalize()} AI analysis (this may take a moment)...")
            ai_result = ai_analyzer.analyze_diff(
                diff_content=diff_content,
                crate_name=item.crate_name,
                old_version=item.old_version,
                new_version=item.new_version,
                publisher=item.publisher,
                is_full_crate=is_full_crate,
                verbose=args.verbose,
            )
            analysis.claude_analysis = ai_result

        analyses.append(analysis)

        # Print results
        risk_colors = {
            RiskLevel.LOW: 'green',
            RiskLevel.MEDIUM: 'yellow',
            RiskLevel.HIGH: 'red',
            RiskLevel.CRITICAL: 'magenta',
        }

        print()
        print_color("-" * 50, "cyan")
        print_color("ANALYSIS RESULTS", "bold")
        print_color("-" * 50, "cyan")

        print_color(f"\n    Pattern Analysis Risk Level: {analysis.risk_score.value.upper()}", risk_colors[analysis.risk_score])

        if findings:
            print(f"\n    Pattern-Based Findings ({len(findings)}):")
            # Group findings by risk level
            for risk in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
                risk_findings = [f for f in findings if f.risk == risk]
                for finding in risk_findings[:5]:  # Limit output
                    print_finding(finding)
                if len(risk_findings) > 5:
                    print(f"         ... and {len(risk_findings) - 5} more {risk.value} findings")
        else:
            print_color("    No pattern-based concerns found in added code.", "green")

        # AI analysis output
        if analysis.claude_analysis:
            print()
            print_color("-" * 50, "magenta")
            print_color("AI ANALYSIS", "bold")
            print_color("-" * 50, "magenta")
            print()
            # Indent the response
            for line in analysis.claude_analysis.split('\n'):
                print(f"    {line}")
            print()

        print_color("-" * 50, "cyan")
        print_color("RECOMMENDATION", "bold")
        print_color("-" * 50, "cyan")
        print(analysis.recommendation)

        # Interactive certification (if not dry-run)
        if not args.dry_run and not args.json:
            print()
            print_color("-" * 50, "cyan")
            print_color("ACTIONS", "bold")
            print_color("-" * 50, "cyan")
            print("      [c] Certify this crate")
            print("      [v] View full diff in pager (less)")
            print("      [d] View diff inline (first 200 lines)")
            print("      [u] Show diff.rs URL")
            if item.trust_note:
                print(f"      [t] Trust publisher '{item.trust_note}'")
            if use_ai:
                print("      [a] Re-run AI analysis")
            if analysis.claude_analysis:
                print("      [r] Re-display AI analysis")
            print("      [s] Skip to next crate")
            print("      [q] Quit")

            while True:
                try:
                    choice = input("\n    Choice: ").strip().lower()
                except (KeyboardInterrupt, EOFError):
                    print("\n\nExiting...")
                    sys.exit(0)

                if choice == 'c':
                    print("    Opening cargo vet certify...")
                    certify_crate(item.crate_name, item.new_version)
                    break
                elif choice == 'v':
                    # Show diff in pager
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.diff', delete=False) as f:
                        f.write(diff_content)
                        temp_path = f.name
                    subprocess.run(["less", "-R", temp_path])
                    os.unlink(temp_path)
                elif choice == 'd':
                    # Show diff inline (first N lines)
                    print()
                    print_color("-" * 50, "cyan")
                    print_color("DIFF PREVIEW (first 200 lines)", "bold")
                    print_color("-" * 50, "cyan")
                    lines = diff_content.split('\n')[:200]
                    for line in lines:
                        if line.startswith('+') and not line.startswith('+++'):
                            print_color(f"    {line}", "green")
                        elif line.startswith('-') and not line.startswith('---'):
                            print_color(f"    {line}", "red")
                        elif line.startswith('@@'):
                            print_color(f"    {line}", "cyan")
                        else:
                            print(f"    {line}")
                    if len(diff_content.split('\n')) > 200:
                        print_color(f"\n    ... [{len(diff_content.split(chr(10))) - 200} more lines, use 'v' to view all]", "yellow")
                    print()
                elif choice == 'u':
                    # Show URL for manual access
                    if item.old_version:
                        url = f"https://diff.rs/{item.crate_name}/{item.old_version}/{item.new_version}/"
                    else:
                        url = f"https://crates.io/crates/{item.crate_name}/{item.new_version}"
                    print(f"\n    URL: {url}\n")
                elif choice == 't' and item.trust_note:
                    subprocess.run(["cargo", "vet", "trust", item.crate_name, item.trust_note])
                    break
                elif choice == 'a' and use_ai:
                    print("    Re-running AI analysis...")
                    ai_result = ai_analyzer.analyze_diff(
                        diff_content=diff_content,
                        crate_name=item.crate_name,
                        old_version=item.old_version,
                        new_version=item.new_version,
                        publisher=item.publisher,
                        is_full_crate=is_full_crate,
                        verbose=True,  # Always verbose on re-run for debugging
                    )
                    if ai_result:
                        analysis.claude_analysis = ai_result
                        print()
                        print_color("-" * 50, "magenta")
                        print_color("AI ANALYSIS (refreshed)", "bold")
                        print_color("-" * 50, "magenta")
                        print()
                        for line in ai_result.split('\n'):
                            print(f"    {line}")
                        print()
                    else:
                        print_color("    AI analysis failed", "red")
                elif choice == 'r' and analysis.claude_analysis:
                    print()
                    print_color("-" * 50, "magenta")
                    print_color("AI ANALYSIS", "bold")
                    print_color("-" * 50, "magenta")
                    print()
                    for line in analysis.claude_analysis.split('\n'):
                        print(f"    {line}")
                    print()
                elif choice == 's':
                    break
                elif choice == 'q':
                    print("\nExiting...")
                    sys.exit(0)
                else:
                    print("    Invalid choice, try again")

    # Output JSON if requested
    if args.json:
        output = []
        for a in analyses:
            output.append({
                "crate": a.crate_name,
                "old_version": a.old_version,
                "new_version": a.new_version,
                "diff_type": a.diff_type,
                "risk_score": a.risk_score.value,
                "lines_changed": a.lines_changed,
                "findings": [
                    {
                        "category": f.category,
                        "description": f.description,
                        "risk": f.risk.value,
                        "location": f.line_info,
                    }
                    for f in a.findings
                ],
                "recommendation": a.recommendation,
                "claude_analysis": a.claude_analysis,
            })
        print(json.dumps(output, indent=2))

    # Summary
    print()
    print_color("=" * 60, "cyan")
    print_color("SUMMARY", "bold")
    print_color("=" * 60, "cyan")
    print(f"  Total crates needing audit: {len(items)}")
    print(f"  Analyzed: {len(analyses)} crates")
    print(f"  Skipped: {len(items) - len(analyses)} crates (too large or fetch failed)")

    if use_ai:
        ai_analyzed = sum(1 for a in analyses if a.claude_analysis)
        print(f"  AI-analyzed: {ai_analyzed} crates")

    # Count full crate reviews vs diffs
    full_reviews = sum(1 for a in analyses if a.diff_type == "inspect")
    diff_reviews = sum(1 for a in analyses if a.diff_type == "diff")
    if full_reviews > 0:
        print(f"  Full crate reviews: {full_reviews}")
    if diff_reviews > 0:
        print(f"  Version upgrade diffs: {diff_reviews}")

    risk_counts = {level: 0 for level in RiskLevel}
    for a in analyses:
        risk_counts[a.risk_score] += 1

    print("\n  Risk distribution:")
    for risk in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
        count = risk_counts[risk]
        if count > 0:
            color = risk_colors[risk]
            print_color(f"    {risk.value.upper()}: {count}", color)

    # List any critical/high risk crates for quick reference
    high_risk = [a for a in analyses if a.risk_score in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
    if high_risk:
        print()
        print_color("  Crates requiring careful review:", "red")
        for a in high_risk:
            print(f"    - {a.crate_name} {a.new_version} [{a.risk_score.value.upper()}]")


if __name__ == "__main__":
    main()
