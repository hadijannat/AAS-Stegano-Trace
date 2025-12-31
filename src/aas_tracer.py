"""
aas_tracer.py - Forensic Watermark Extraction and Analysis

This module provides the "forensics" side of the AAS-Stegano-Trace system.
Given a potentially leaked AAS file, it extracts any embedded watermarks
and provides detailed analysis to identify the source of the leak.

Forensic Workflow:
    1. SCAN: Quick check if the file contains any watermarks
    2. EXTRACT: Deep traversal to find all watermark instances
    3. ANALYZE: Cross-reference findings and build confidence report
    4. REPORT: Generate human-readable forensic report

Evidence Handling:
    This module is designed with evidence integrity in mind. It never
    modifies the input data and provides complete audit trails of
    all findings. The reports include file checksums and timestamps
    suitable for legal documentation.

Example Investigation:
    >>> from aas_stegano_trace import AASTracer
    >>> tracer = AASTracer()
    >>> report = tracer.trace("leaked_motor_aas.json")
    >>> if report.watermarks_found:
    ...     print(f"LEAK IDENTIFIED: File was issued to {report.payloads}")
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set, Union

try:
    from .stegano_core import SteganoEngine, ZeroWidthCodec
except ImportError:
    from stegano_core import SteganoEngine, ZeroWidthCodec


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES FOR FORENSIC REPORTS
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class WatermarkFinding:
    """
    Records a single watermark extraction from the AAS structure.

    Each finding represents one location where a watermark was detected
    and successfully decoded. Multiple findings with the same payload
    provide stronger evidence of the file's origin.

    Attributes:
        payload: The decoded watermark content (e.g., "Supplier-B")
        location_path: JSON path where the watermark was found
        field_type: Category of field (description, property, etc.)
        visible_context: Surrounding visible text for context
        confidence: Extraction confidence (1.0 = fully decoded)
    """

    payload: str
    location_path: str
    field_type: str
    visible_context: str
    confidence: float = 1.0

    def __hash__(self):
        return hash((self.payload, self.location_path))


@dataclass
class TraceReport:
    """
    Comprehensive forensic analysis report for a suspected leaked AAS file.

    This report aggregates all watermark findings and provides the evidence
    needed to identify the source of a data leak. It includes file metadata,
    all discovered watermarks, and a confidence assessment.

    Attributes:
        file_path: Path to the analyzed file
        file_hash: SHA-256 hash of the file for evidence integrity
        scan_timestamp: When the forensic scan was performed
        watermarks_found: True if any watermarks were detected
        payloads: Set of unique decoded payloads (recipient identifiers)
        findings: Detailed list of all watermark locations
        total_watermarks: Total count of watermark instances found
        verdict: Human-readable summary of findings
    """

    file_path: str
    file_hash: str
    scan_timestamp: str
    watermarks_found: bool
    payloads: Set[str] = field(default_factory=set)
    findings: List[WatermarkFinding] = field(default_factory=list)
    total_watermarks: int = 0
    verdict: str = ""

    def forensic_summary(self) -> str:
        """
        Generate a formal forensic report suitable for documentation.

        This output format is designed to be included in legal documents
        or incident reports, with all relevant technical details.
        """
        lines = [
            "╔══════════════════════════════════════════════════════════════════╗",
            "║            FORENSIC WATERMARK ANALYSIS REPORT                    ║",
            "╠══════════════════════════════════════════════════════════════════╣",
            f"║  File:      {self.file_path[:50]:<50} ║",
            f"║  SHA-256:   {self.file_hash[:50]:<50} ║",
            f"║  Scan Time: {self.scan_timestamp:<50} ║",
            "╠══════════════════════════════════════════════════════════════════╣",
        ]

        if self.watermarks_found:
            lines.append("║  ⚠️  WATERMARKS DETECTED                                         ║")
            lines.append("╠══════════════════════════════════════════════════════════════════╣")
            lines.append("║  Identified Recipients:                                          ║")
            for payload in self.payloads:
                lines.append(f"║    → {payload:<56} ║")
            lines.append(f"║  Total Watermark Instances: {self.total_watermarks:<36} ║")
            lines.append("╠══════════════════════════════════════════════════════════════════╣")
            lines.append("║  VERDICT:                                                        ║")

            if len(self.payloads) == 1:
                recipient = list(self.payloads)[0]
                lines.append(f"║  This file was exclusively issued to: {recipient:<23} ║")
                lines.append("║  Evidence strength: HIGH (single consistent recipient)          ║")
            else:
                lines.append("║  Multiple recipients detected - possible file merge or          ║")
                lines.append("║  re-distribution chain. Further investigation recommended.      ║")
                lines.append("║  Evidence strength: MEDIUM (requires corroboration)             ║")
        else:
            lines.append("║  ✓ NO WATERMARKS DETECTED                                        ║")
            lines.append("╠══════════════════════════════════════════════════════════════════╣")
            lines.append("║  This file does not contain any detectable forensic watermarks.  ║")
            lines.append("║  This could mean:                                                ║")
            lines.append("║    • File was never watermarked (original source)                ║")
            lines.append("║    • Watermarks were deliberately stripped                       ║")
            lines.append("║    • File was re-created rather than copied                      ║")

        lines.append("╚══════════════════════════════════════════════════════════════════╝")

        return "\n".join(lines)

    def to_json(self) -> str:
        """Export report as JSON for programmatic processing."""
        return json.dumps(
            {
                "file_path": self.file_path,
                "file_hash": self.file_hash,
                "scan_timestamp": self.scan_timestamp,
                "watermarks_found": self.watermarks_found,
                "payloads": list(self.payloads),
                "total_watermarks": self.total_watermarks,
                "findings": [
                    {
                        "payload": f.payload,
                        "location_path": f.location_path,
                        "field_type": f.field_type,
                        "visible_context": f.visible_context[:100],
                        "confidence": f.confidence,
                    }
                    for f in self.findings
                ],
            },
            indent=2,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN TRACER CLASS
# ═══════════════════════════════════════════════════════════════════════════════


class AASTracer:
    """
    Forensic analysis engine for detecting and extracting AAS watermarks.

    This class provides comprehensive scanning capabilities to detect
    forensic watermarks in AAS files. It's designed to be used when
    investigating suspected data leaks or verifying file provenance.

    The tracer never modifies input data and produces detailed reports
    suitable for incident documentation and legal proceedings.

    Example:
        >>> tracer = AASTracer()
        >>>
        >>> # Quick check
        >>> if tracer.has_watermark("suspicious_file.json"):
        ...     print("Watermark detected!")
        >>>
        >>> # Full forensic analysis
        >>> report = tracer.trace("suspicious_file.json")
        >>> print(report.forensic_summary())
        >>>
        >>> # Save evidence
        >>> with open("forensic_report.json", "w") as f:
        ...     f.write(report.to_json())
    """

    def __init__(self, engine: SteganoEngine = None):
        """
        Initialize the forensic tracer.

        Args:
            engine: SteganoEngine instance for decoding. Uses default if None.
        """
        self._engine = engine or SteganoEngine()

    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────────────────────────

    def has_watermark(self, source: Union[str, Path, Dict]) -> bool:
        """
        Quick check if a file or data structure contains watermarks.

        This is a fast preliminary scan that doesn't perform full extraction.
        Use trace() for comprehensive forensic analysis.

        Args:
            source: File path (str/Path) or parsed AAS dict

        Returns:
            True if watermark markers are detected, False otherwise.
        """
        # Load data if path provided
        if isinstance(source, (str, Path)):
            try:
                with open(source, encoding="utf-8") as f:
                    content = f.read()
                    # Quick string check before parsing JSON
                    if ZeroWidthCodec.MARKER not in content:
                        return False
                    aas_data = json.loads(content)
            except Exception:
                return False
        else:
            aas_data = source

        # Recursive scan for markers
        return self._scan_for_markers(aas_data)

    def trace(self, source: Union[str, Path, Dict]) -> TraceReport:
        """
        Perform comprehensive forensic analysis on an AAS file.

        This method scans the entire AAS structure for watermarks,
        extracts all payloads, and generates a detailed forensic report.

        Args:
            source: File path (str/Path) or parsed AAS dict

        Returns:
            TraceReport with all findings and forensic analysis.

        Example:
            >>> report = tracer.trace("leaked_file.json")
            >>> if report.watermarks_found:
            ...     print(f"Leak source identified: {report.payloads}")
        """
        # Initialize report with metadata
        file_path = str(source) if isinstance(source, (str, Path)) else "<in-memory>"
        file_hash = ""
        raw_content = ""

        # Load data based on source type
        if isinstance(source, (str, Path)):
            try:
                with open(source, encoding="utf-8") as f:
                    raw_content = f.read()
                file_hash = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()
                aas_data = json.loads(raw_content)
            except FileNotFoundError:
                return TraceReport(
                    file_path=file_path,
                    file_hash="",
                    scan_timestamp=datetime.now().isoformat(),
                    watermarks_found=False,
                    verdict="ERROR: File not found",
                )
            except json.JSONDecodeError:
                return TraceReport(
                    file_path=file_path,
                    file_hash=file_hash,
                    scan_timestamp=datetime.now().isoformat(),
                    watermarks_found=False,
                    verdict="ERROR: Invalid JSON",
                )
        else:
            aas_data = source
            # Compute hash of the data structure
            json_str = json.dumps(aas_data, sort_keys=True)
            file_hash = hashlib.sha256(json_str.encode("utf-8")).hexdigest()

        # Create report structure
        report = TraceReport(
            file_path=file_path,
            file_hash=file_hash,
            scan_timestamp=datetime.now().isoformat(),
            watermarks_found=False,
        )

        # Perform deep extraction
        self._extract_watermarks(aas_data, "root", report)

        # Update report summary
        report.watermarks_found = len(report.findings) > 0
        report.total_watermarks = len(report.findings)

        if report.watermarks_found:
            if len(report.payloads) == 1:
                recipient = list(report.payloads)[0]
                report.verdict = f"File was issued to: {recipient}"
            else:
                report.verdict = f"Multiple recipients detected: {report.payloads}"
        else:
            report.verdict = "No forensic watermarks found"

        return report

    def extract_payloads(self, source: Union[str, Path, Dict]) -> List[str]:
        """
        Simple extraction of unique payload values from an AAS file.

        This is a convenience method that returns just the decoded
        recipient identifiers without the full forensic report.

        Args:
            source: File path or parsed AAS dict

        Returns:
            List of unique payload strings found in the file.
        """
        report = self.trace(source)
        return list(report.payloads)

    # ─────────────────────────────────────────────────────────────────────────
    # INTERNAL: Scanning and Extraction
    # ─────────────────────────────────────────────────────────────────────────

    def _scan_for_markers(self, node: Any) -> bool:
        """
        Quick recursive scan for watermark marker characters.

        This is a fast check that doesn't decode - just looks for
        the presence of zero-width characters.
        """
        if isinstance(node, str):
            return ZeroWidthCodec.MARKER in node
        elif isinstance(node, dict):
            return any(self._scan_for_markers(v) for v in node.values())
        elif isinstance(node, list):
            return any(self._scan_for_markers(item) for item in node)
        return False

    def _extract_watermarks(self, node: Any, path: str, report: TraceReport) -> None:
        """
        Recursively extract all watermarks from the AAS structure.

        This performs deep traversal similar to the injector, but
        focuses on extraction and evidence gathering rather than
        modification.
        """
        if isinstance(node, dict):
            # Check description fields
            self._extract_from_descriptions(node, path, report)

            # Check string properties
            self._extract_from_property(node, path, report)

            # Check multi-language properties
            self._extract_from_multilang(node, path, report)

            # Recurse into children
            for key, value in node.items():
                child_path = f"{path}.{key}"
                self._extract_watermarks(value, child_path, report)

        elif isinstance(node, list):
            for idx, item in enumerate(node):
                child_path = f"{path}[{idx}]"
                self._extract_watermarks(item, child_path, report)

    def _extract_from_descriptions(self, node: Dict, path: str, report: TraceReport) -> None:
        """Extract watermarks from description text fields."""
        if "description" not in node:
            return

        descriptions = node.get("description")
        if not isinstance(descriptions, list):
            return

        for idx, desc in enumerate(descriptions):
            if not isinstance(desc, dict):
                continue

            text_value = desc.get("text", "")
            if not text_value or not isinstance(text_value, str):
                continue

            result = self._engine.decode(text_value)
            if result.is_valid and result.payload:
                # Extract visible text (without the watermark)
                visible_text = self._engine.strip_watermark(text_value)

                finding = WatermarkFinding(
                    payload=result.payload,
                    location_path=f"{path}.description[{idx}].text",
                    field_type="description",
                    visible_context=visible_text[:50],
                    confidence=1.0,
                )
                report.findings.append(finding)
                report.payloads.add(result.payload)

    def _extract_from_property(self, node: Dict, path: str, report: TraceReport) -> None:
        """Extract watermarks from string Property values."""
        if node.get("modelType") != "Property":
            return
        if node.get("valueType") != "xs:string":
            return

        value = node.get("value")
        if not value or not isinstance(value, str):
            return

        result = self._engine.decode(value)
        if result.is_valid and result.payload:
            visible_text = self._engine.strip_watermark(value)

            finding = WatermarkFinding(
                payload=result.payload,
                location_path=f"{path}.value",
                field_type="string_property",
                visible_context=visible_text[:50],
                confidence=1.0,
            )
            report.findings.append(finding)
            report.payloads.add(result.payload)

    def _extract_from_multilang(self, node: Dict, path: str, report: TraceReport) -> None:
        """Extract watermarks from MultiLanguageProperty values."""
        if node.get("modelType") != "MultiLanguageProperty":
            return

        values = node.get("value")
        if not isinstance(values, list):
            return

        for idx, lang_string in enumerate(values):
            if not isinstance(lang_string, dict):
                continue

            text_value = lang_string.get("text", "")
            if not text_value or not isinstance(text_value, str):
                continue

            result = self._engine.decode(text_value)
            if result.is_valid and result.payload:
                visible_text = self._engine.strip_watermark(text_value)

                finding = WatermarkFinding(
                    payload=result.payload,
                    location_path=f"{path}.value[{idx}].text",
                    field_type="multi_lang_property",
                    visible_context=visible_text[:50],
                    confidence=1.0,
                )
                report.findings.append(finding)
                report.payloads.add(result.payload)
