"""
Sentinel — Regex-based diff analyser.

Calculates a Signal-to-Noise Ratio for PR diffs WITHOUT tree-sitter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ── Regex patterns ──────────────────────────────────────────────────────────

# Lines considered "noise" (whitespace, comments, docstrings, blank)
_BLANK_RE = re.compile(r"^\s*$")
_COMMENT_RE = re.compile(
    r"^\s*(?:"
    r"#|"               # Python / Shell
    r"//|"              # C / JS / TS / Go / Rust
    r"/\*|\*/|"         # block comment delimiters
    r"\*\s|"            # block comment continuation
    r"--|"              # SQL / Haskell
    r";|"               # Lisp / Assembly
    r"<!--"             # HTML
    r")"
)
_DOCSTRING_RE = re.compile(r'^\s*(?:"""|\'\'\'|/\*\*)')
_IMPORT_RE = re.compile(
    r"^\s*(?:import\s|from\s.*import|require\(|#include|using\s|use\s)"
)
_TRIVIAL_WHITESPACE_RE = re.compile(r"^[+-]\s*$")

# Diff header patterns
_DIFF_FILE_RE = re.compile(r"^diff --git a/(.*) b/(.*)")
_HUNK_HEADER_RE = re.compile(r"^@@\s")
_ADDED_LINE_RE = re.compile(r"^\+(?!\+\+)")    # added line (not +++ header)
_REMOVED_LINE_RE = re.compile(r"^-(?!--)")      # removed line (not --- header)


# ── Data classes ────────────────────────────────────────────────────────────


@dataclass
class FileAnalysis:
    """Per-file breakdown of the analysis."""

    filename: str
    logic_lines: int = 0
    noise_lines: int = 0
    total_added: int = 0
    total_removed: int = 0


@dataclass
class AnalysisResult:
    """Aggregate result of diff analysis."""

    logic_lines: int = 0
    noise_lines: int = 0
    total_added: int = 0
    total_removed: int = 0
    signal_to_noise_ratio: float = 0.0
    is_low_effort: bool = False
    file_breakdown: list[FileAnalysis] = field(default_factory=list)

    # convenience flags
    is_docs_only: bool = False
    is_trivial_rename: bool = False


# ── Analyser ────────────────────────────────────────────────────────────────

_DOCS_EXTENSIONS = frozenset({
    ".md", ".txt", ".rst", ".adoc", ".rdoc",
    ".yml", ".yaml", ".json", ".toml",  # config / docs
})


class DiffAnalyzer:
    """Parse a unified diff and compute signal-to-noise metrics.

    Usage::

        analyzer = DiffAnalyzer(snr_threshold=0.10)
        result = analyzer.analyze(diff_text)
    """

    def __init__(self, snr_threshold: float = 0.10) -> None:
        self.snr_threshold = snr_threshold

    # ── internals ───────────────────────────────────────────────────────

    @staticmethod
    def _is_noise(line_content: str) -> bool:
        """Return True if *line_content* is noise (whitespace/comment/import)."""
        stripped = line_content.lstrip("+-")  # remove diff +/- prefix
        if _BLANK_RE.match(stripped):
            return True
        if _COMMENT_RE.match(stripped):
            return True
        if _DOCSTRING_RE.match(stripped):
            return True
        if _IMPORT_RE.match(stripped):
            return True
        return False

    @staticmethod
    def _is_docs_file(filename: str) -> bool:
        """Return True if the file is a documentation / config file."""
        lower = filename.lower()
        return any(lower.endswith(ext) for ext in _DOCS_EXTENSIONS)

    # ── public ──────────────────────────────────────────────────────────

    def analyze(self, diff_text: str) -> AnalysisResult:
        """Analyse a unified-diff string and return an :class:`AnalysisResult`."""
        result = AnalysisResult()
        current_file: FileAnalysis | None = None
        all_files_are_docs = True

        for line in diff_text.splitlines():
            # New file header
            m = _DIFF_FILE_RE.match(line)
            if m:
                if current_file:
                    result.file_breakdown.append(current_file)
                fname = m.group(2)
                current_file = FileAnalysis(filename=fname)
                if not self._is_docs_file(fname):
                    all_files_are_docs = False
                continue

            # Skip hunk headers and other meta lines
            if _HUNK_HEADER_RE.match(line) or line.startswith("+++") or line.startswith("---"):
                continue

            # Only care about added lines for effort scoring
            if _ADDED_LINE_RE.match(line):
                if current_file:
                    current_file.total_added += 1
                result.total_added += 1

                if self._is_noise(line):
                    result.noise_lines += 1
                    if current_file:
                        current_file.noise_lines += 1
                else:
                    result.logic_lines += 1
                    if current_file:
                        current_file.logic_lines += 1

            elif _REMOVED_LINE_RE.match(line):
                result.total_removed += 1
                if current_file:
                    current_file.total_removed += 1

        # Don't forget the last file
        if current_file:
            result.file_breakdown.append(current_file)

        # ── compute metrics ─────────────────────────────────────────────
        if result.total_added > 0:
            result.signal_to_noise_ratio = result.logic_lines / result.total_added
        else:
            result.signal_to_noise_ratio = 0.0

        result.is_low_effort = result.signal_to_noise_ratio < self.snr_threshold
        result.is_docs_only = all_files_are_docs and len(result.file_breakdown) > 0

        # Trivial rename: very few added lines and most are noise
        if result.total_added <= 3 and result.logic_lines <= 1:
            result.is_trivial_rename = True

        return result
