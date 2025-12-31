"""
test_aas_stegano_trace.py - Comprehensive Test Suite

This test module provides thorough coverage of the AAS-Stegano-Trace system,
including unit tests for the steganography engine, integration tests for
AAS injection/extraction, and end-to-end workflow tests.

Run with: python -m pytest tests/ -v
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Import the modules under test
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aas_injector import AASInjector
from aas_tracer import AASTracer
from stegano_core import EncodeResult, SteganoEngine, ZeroWidthCodec

# ═══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def engine():
    """Provide a SteganoEngine instance for tests."""
    return SteganoEngine()


@pytest.fixture
def injector(engine):
    """Provide an AASInjector instance for tests."""
    return AASInjector(engine)


@pytest.fixture
def tracer(engine):
    """Provide an AASTracer instance for tests."""
    return AASTracer(engine)


@pytest.fixture
def sample_aas():
    """Provide a sample AAS structure for testing."""
    return {
        "assetAdministrationShells": [{"id": "urn:example:aas:test-001", "idShort": "TestAsset"}],
        "submodels": [
            {
                "idShort": "Nameplate",
                "description": [
                    {"language": "en", "text": "Nameplate information"},
                    {"language": "de", "text": "Typenschild Informationen"},
                ],
                "submodelElements": [
                    {
                        "idShort": "ManufacturerName",
                        "modelType": "Property",
                        "valueType": "xs:string",
                        "value": "Test Manufacturer GmbH",
                        "description": [{"language": "en", "text": "Name of manufacturer"}],
                    },
                    {
                        "idShort": "SerialNumber",
                        "modelType": "Property",
                        "valueType": "xs:string",
                        "value": "SN-12345",
                    },
                    {
                        "idShort": "MaxTemperature",
                        "modelType": "Property",
                        "valueType": "xs:double",
                        "value": 85.0,
                    },
                ],
            }
        ],
    }


@pytest.fixture
def temp_json_file(sample_aas):
    """Create a temporary JSON file with sample AAS data."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(sample_aas, f, indent=2)
        temp_path = f.name
    yield temp_path
    os.unlink(temp_path)


# ═══════════════════════════════════════════════════════════════════════════════
# ZERO-WIDTH CODEC TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestZeroWidthCodec:
    """Tests for the ZeroWidthCodec class."""

    def test_codec_constants_are_distinct(self):
        """Verify all codec characters are unique."""
        chars = [ZeroWidthCodec.ZERO, ZeroWidthCodec.ONE, ZeroWidthCodec.MARKER]
        assert len(chars) == len(set(chars)), "Codec characters must be unique"

    def test_codec_constants_are_invisible(self):
        """Verify codec characters have zero display width."""
        # These are known zero-width Unicode code points
        assert ZeroWidthCodec.ZERO == "\u200b"  # ZERO WIDTH SPACE
        assert ZeroWidthCodec.ONE == "\u200c"  # ZERO WIDTH NON-JOINER
        assert ZeroWidthCodec.MARKER == "\u200d"  # ZERO WIDTH JOINER

    def test_is_zero_width_detection(self):
        """Test the is_zero_width class method."""
        assert ZeroWidthCodec.is_zero_width("\u200b") is True
        assert ZeroWidthCodec.is_zero_width("\u200c") is True
        assert ZeroWidthCodec.is_zero_width("\u200d") is True
        assert ZeroWidthCodec.is_zero_width("A") is False
        assert ZeroWidthCodec.is_zero_width(" ") is False

    def test_contains_markers(self):
        """Test detection of zero-width chars in strings."""
        assert ZeroWidthCodec.contains_markers("Hello\u200bWorld") is True
        assert ZeroWidthCodec.contains_markers("Hello World") is False
        assert ZeroWidthCodec.contains_markers("") is False


# ═══════════════════════════════════════════════════════════════════════════════
# STEGANOGRAPHY ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestSteganoEngine:
    """Tests for the core steganography engine."""

    def test_encode_simple_string(self, engine):
        """Test encoding a simple ASCII string."""
        result = engine.encode("ABC")

        assert isinstance(result, EncodeResult)
        assert result.byte_length == 3
        assert result.bit_length == 24  # 3 bytes × 8 bits
        assert len(result.invisible_payload) == 26  # 24 bits + 2 markers
        assert result.checksum is not None

    def test_encode_decode_roundtrip(self, engine):
        """Verify encoding then decoding recovers original payload."""
        test_payloads = [
            "A",
            "Hello",
            "Supplier-ABC",
            "Company X - Contract #12345",
            "Unicode: äöü ñ",
            "Special: !@#$%^&*()",
        ]

        for payload in test_payloads:
            encoded = engine.encode(payload)
            decoded = engine.decode(encoded.invisible_payload)

            assert decoded.is_valid, f"Failed to decode: {payload}"
            assert decoded.payload == payload, f"Mismatch for: {payload}"

    def test_encode_empty_raises_error(self, engine):
        """Verify encoding empty string raises ValueError."""
        with pytest.raises(ValueError):
            engine.encode("")

        with pytest.raises(ValueError):
            engine.encode(None)

    def test_decode_no_markers(self, engine):
        """Test decoding text without watermark markers."""
        result = engine.decode("Plain text without watermarks")

        assert result.is_valid is False
        assert result.payload is None
        assert "delimiters" in result.error.lower()

    def test_decode_corrupted_single_marker(self, engine):
        """Test handling of corrupted watermark (only one marker)."""
        text = f"Text with only{ZeroWidthCodec.MARKER}one marker"
        result = engine.decode(text)

        assert result.is_valid is False

    def test_embed_positions(self, engine):
        """Test embedding watermark at different positions."""
        carrier = "Hello World"
        payload = "Secret"

        # Test end position (default)
        result_end = engine.embed(carrier, payload, position="end")
        assert result_end.startswith("Hello World")
        assert engine.decode(result_end).payload == payload

        # Test start position
        result_start = engine.embed(carrier, payload, position="start")
        assert result_start.endswith("Hello World")
        assert engine.decode(result_start).payload == payload

        # Test middle position
        result_mid = engine.embed(carrier, payload, position="middle")
        assert "Hello" in result_mid and "World" in result_mid
        assert engine.decode(result_mid).payload == payload

    def test_has_watermark(self, engine):
        """Test watermark presence detection."""
        clean = "No watermark here"
        marked = engine.embed("Some text", "Hidden")

        assert engine.has_watermark(clean) is False
        assert engine.has_watermark(marked) is True

    def test_strip_watermark(self, engine):
        """Test removal of watermark characters."""
        original = "Clean text"
        marked = engine.embed(original, "Hidden payload")
        stripped = engine.strip_watermark(marked)

        assert stripped == original
        assert engine.has_watermark(stripped) is False


# ═══════════════════════════════════════════════════════════════════════════════
# AAS INJECTOR TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestAASInjector:
    """Tests for the AAS-aware watermark injector."""

    def test_inject_into_descriptions(self, injector, sample_aas):
        """Test injection into description text fields."""
        report = injector.inject(sample_aas, "Test-Recipient")

        assert report.success
        assert report.total_injections > 0
        assert report.recipient_id == "Test-Recipient"

        # Verify description was modified
        desc_text = sample_aas["submodels"][0]["description"][0]["text"]
        assert ZeroWidthCodec.MARKER in desc_text

    def test_inject_into_string_properties(self, injector, sample_aas):
        """Test injection into Property values with xs:string type."""
        injector.inject(sample_aas, "PropTest")

        # Find the ManufacturerName property and check it was marked
        elements = sample_aas["submodels"][0]["submodelElements"]
        manufacturer = next(e for e in elements if e["idShort"] == "ManufacturerName")

        assert ZeroWidthCodec.MARKER in manufacturer["value"]

    def test_numeric_properties_unchanged(self, injector, sample_aas):
        """Verify numeric properties are NOT watermarked."""
        injector.inject(sample_aas, "NumericTest")

        # Find the MaxTemperature property (xs:double)
        elements = sample_aas["submodels"][0]["submodelElements"]
        temp_prop = next(e for e in elements if e["idShort"] == "MaxTemperature")

        # Value should remain a number, not modified
        assert temp_prop["value"] == 85.0

    def test_idempotent_injection(self, injector, sample_aas):
        """Verify re-injection doesn't create duplicate watermarks."""
        injector.inject(sample_aas, "First")
        report2 = injector.inject(sample_aas, "Second")

        # Second injection should skip already-marked fields
        assert report2.skipped_count > 0
        assert report2.total_injections == 0

    def test_injection_report_details(self, injector, sample_aas):
        """Test that injection report contains proper details."""
        report = injector.inject(sample_aas, "DetailTest")

        assert len(report.injection_points) == report.total_injections
        for ip in report.injection_points:
            assert ip.path is not None
            assert ip.original_value is not None
            assert ip.target_type is not None

    def test_inject_empty_aas(self, injector):
        """Test injection into AAS with no injectable fields."""
        empty_aas = {"assetAdministrationShells": [], "submodels": []}

        report = injector.inject(empty_aas, "EmptyTest")

        assert report.success is False
        assert report.total_injections == 0


# ═══════════════════════════════════════════════════════════════════════════════
# AAS TRACER TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestAASTracer:
    """Tests for the forensic watermark tracer."""

    def test_trace_unmarked_file(self, tracer, sample_aas):
        """Test tracing a file without watermarks."""
        report = tracer.trace(sample_aas)

        assert report.watermarks_found is False
        assert len(report.payloads) == 0
        assert report.total_watermarks == 0

    def test_trace_marked_file(self, tracer, injector, sample_aas):
        """Test tracing a file with watermarks."""
        # First inject
        injector.inject(sample_aas, "TraceTarget")

        # Then trace
        report = tracer.trace(sample_aas)

        assert report.watermarks_found is True
        assert "TraceTarget" in report.payloads
        assert report.total_watermarks > 0

    def test_trace_from_file_path(self, tracer, injector, temp_json_file):
        """Test tracing from a file path."""
        # Load, inject, and save
        with open(temp_json_file) as f:
            aas_data = json.load(f)

        injector.inject(aas_data, "FilePathTest")

        with open(temp_json_file, "w", encoding="utf-8") as f:
            json.dump(aas_data, f, ensure_ascii=False)

        # Trace from file path
        report = tracer.trace(temp_json_file)

        assert report.watermarks_found is True
        assert "FilePathTest" in report.payloads
        assert report.file_hash != ""

    def test_has_watermark_quick_check(self, tracer, injector, sample_aas):
        """Test quick watermark presence check."""
        assert tracer.has_watermark(sample_aas) is False

        injector.inject(sample_aas, "QuickCheck")

        assert tracer.has_watermark(sample_aas) is True

    def test_extract_payloads_convenience(self, tracer, injector, sample_aas):
        """Test the extract_payloads convenience method."""
        injector.inject(sample_aas, "ExtractTest")

        payloads = tracer.extract_payloads(sample_aas)

        assert "ExtractTest" in payloads

    def test_forensic_summary_format(self, tracer, injector, sample_aas):
        """Test that forensic summary is properly formatted."""
        injector.inject(sample_aas, "SummaryTest")
        report = tracer.trace(sample_aas)

        summary = report.forensic_summary()

        assert "FORENSIC WATERMARK ANALYSIS" in summary
        assert "SummaryTest" in summary
        assert "SHA-256" in summary


# ═══════════════════════════════════════════════════════════════════════════════
# END-TO-END WORKFLOW TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestEndToEndWorkflow:
    """Integration tests for complete workflows."""

    def test_full_inject_trace_workflow(self, sample_aas):
        """Test complete inject → save → load → trace workflow."""
        recipient = "E2E-Test-Company"

        # Step 1: Inject
        engine = SteganoEngine()
        injector = AASInjector(engine)
        inject_report = injector.inject(sample_aas, recipient)

        assert inject_report.success

        # Step 2: Simulate save/load (JSON roundtrip)
        json_str = json.dumps(sample_aas, ensure_ascii=False)
        loaded_aas = json.loads(json_str)

        # Step 3: Trace
        tracer = AASTracer(engine)
        trace_report = tracer.trace(loaded_aas)

        assert trace_report.watermarks_found
        assert recipient in trace_report.payloads

    def test_visual_integrity_preserved(self, sample_aas):
        """Verify that visible content is unchanged after watermarking."""
        # Capture original visible values
        original_value = sample_aas["submodels"][0]["submodelElements"][0]["value"]
        original_desc = sample_aas["submodels"][0]["description"][0]["text"]

        # Inject watermark
        engine = SteganoEngine()
        injector = AASInjector(engine)
        injector.inject(sample_aas, "VisualTest")

        # Get watermarked values
        marked_value = sample_aas["submodels"][0]["submodelElements"][0]["value"]
        marked_desc = sample_aas["submodels"][0]["description"][0]["text"]

        # Strip watermarks and compare
        assert engine.strip_watermark(marked_value) == original_value
        assert engine.strip_watermark(marked_desc) == original_desc

    def test_multiple_recipients_distinguishable(self, sample_aas):
        """Test that different recipients get unique watermarks."""
        import copy

        aas_for_a = copy.deepcopy(sample_aas)
        aas_for_b = copy.deepcopy(sample_aas)

        engine = SteganoEngine()
        injector = AASInjector(engine)
        tracer = AASTracer(engine)

        injector.inject(aas_for_a, "Recipient-A")
        injector.inject(aas_for_b, "Recipient-B")

        # Verify each traces to correct recipient
        report_a = tracer.trace(aas_for_a)
        report_b = tracer.trace(aas_for_b)

        assert "Recipient-A" in report_a.payloads
        assert "Recipient-B" not in report_a.payloads

        assert "Recipient-B" in report_b.payloads
        assert "Recipient-A" not in report_b.payloads


# ═══════════════════════════════════════════════════════════════════════════════
# RUN TESTS
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
