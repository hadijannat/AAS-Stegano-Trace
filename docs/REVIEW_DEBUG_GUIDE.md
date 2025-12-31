# Technical Review and Debugging Guide for AAS-Stegano-Trace

## Executive Summary
This guide explains how to review and debug the AAS-Stegano-Trace codebase. The system implements invisible forensic watermarking for Asset Administration Shell (AAS) JSON files using zero-width Unicode steganography. The design is intentionally layered so the core encoding logic can be audited and tested in isolation.

## 1) System Architecture Overview
- `src/stegano_core.py` is the dependency-free core (encoding/decoding).
- `src/aas_injector.py` and `src/aas_tracer.py` add AAS-aware traversal logic.
- `src/cli.py` provides the CLI and calls the injector/tracer.
- `src/__main__.py` exposes module execution via `python -m aas_stegano_trace ...`.
- Tests live in `tests/` and exercise unit, integration, and end-to-end flows.

Dependency flow is strictly downward: CLI -> injector/tracer -> core. The core does not depend on any higher layer.

## 2) Steganography Core (`stegano_core.py`)
### 2.1 Unicode Character Selection
The system uses three zero-width code points:
- U+200B (ZERO WIDTH SPACE) represents binary 0
- U+200C (ZERO WIDTH NON-JOINER) represents binary 1
- U+200D (ZERO WIDTH JOINER) is the delimiter

These are invisible in most renderers and preserved by JSON serializers when `ensure_ascii=False` is used.

### 2.2 ZeroWidthCodec Utilities
- `ZeroWidthCodec.is_zero_width(char)` returns True for the three code points.
- `ZeroWidthCodec.contains_markers(text)` scans for any zero-width characters.

### 2.3 Encoding Process
`SteganoEngine.encode(payload)` does:
1) UTF-8 encode the payload to bytes.
2) Convert each byte to an 8-bit binary string.
3) Map bits to zero-width characters.
4) Wrap with U+200D delimiters.

The result is an `EncodeResult` containing the invisible payload, bit length, byte length, and a short SHA-256 checksum.

### 2.4 Decoding Process
`SteganoEngine.decode(text)` does:
1) Locate delimiter markers.
2) Extract the zero-width region.
3) Map zero-width chars back to bits.
4) Validate bit length is a multiple of 8.
5) Decode UTF-8 bytes back to the payload.

If anything is invalid, `DecodeResult.is_valid` is False and `DecodeResult.error` explains why.

### 2.5 Debugging the Core
```python
from stegano_core import SteganoEngine

engine = SteganoEngine()
result = engine.encode("ABC")
print(result.bit_length)                # 24 (3 bytes * 8)
print(len(result.invisible_payload))    # 26 (24 + 2 markers)

decoded = engine.decode(result.invisible_payload)
assert decoded.payload == "ABC"
print(repr(result.invisible_payload[:10]))
```

## 3) AAS Injector (`aas_injector.py`)
### 3.1 Target Field Selection
The injector modifies only safe text fields:
- `description[].text` (LangString arrays)
- `Property` elements where `valueType == "xs:string"`
- `MultiLanguageProperty` values (`value[].text`)

### 3.2 Recursive Traversal
`_traverse_and_inject()` walks dicts and lists depth-first, tracking JSON paths. It calls the target-specific helpers at each dict node.

### 3.3 Idempotency
If a field already contains the delimiter (U+200D), it is skipped and counted in `skipped_count`.

### 3.4 InjectionReport
`InjectionReport` records:
- `recipient_id`
- `total_injections`
- `injection_points` (with JSON paths and original values)
- `skipped_count` and any `warnings`

### 3.5 Debugging the Injector
```python
report = injector.inject(aas_data, "Debug-Recipient")
for ip in report.injection_points:
    print(ip.path, ip.target_type, ip.original_value[:40])
```

## 4) AAS Tracer (`aas_tracer.py`)
### 4.1 Extraction Logic
The tracer mirrors injector traversal and decodes watermark candidates in the same field types. It never mutates the input.

### 4.2 WatermarkFinding and TraceReport
- `WatermarkFinding` includes payload, location path, field type, visible context, and confidence.
- `TraceReport` aggregates findings, unique payloads, file hash, and a formatted summary.

### 4.3 Debugging the Tracer
```python
result = tracer.trace(aas_data)
for finding in result.findings:
    print(finding.location_path, finding.payload)
```

## 5) CLI (`cli.py`)
### 5.1 Commands
- `inject`: watermark a JSON file and write a new output.
- `trace`: full forensic analysis (prints summary or JSON).
- `verify`: quick watermark presence check.
- `demo`: end-to-end demonstration.

### 5.2 Exit Codes
- `0`: success (or no watermark for trace/verify)
- `1`: error (missing file, bad JSON, or no injectable fields)
- `2`: watermark detected (trace/verify)

### 5.3 Critical Serialization Rule
All writes must use `ensure_ascii=False` and UTF-8 to preserve zero-width characters.

## 6) Tests (`tests/test_aas_stegano_trace.py`)
- Framework: pytest.
- Key suites cover the codec, engine, injector, tracer, and end-to-end flows.
- Run all tests:
  ```bash
  python -m pytest tests/ -v
  ```

## 7) Common Debugging Scenarios
### 7.1 Watermark Not Detected After Injection
- Confirm the file was saved with `ensure_ascii=False`.
- Check for UTF-8 bytes `E2 80 8B`, `E2 80 8C`, `E2 80 8D`.
- Verify `InjectionReport.total_injections > 0`.

### 7.2 Decode Returns Invalid Data
- Ensure the binary length is a multiple of 8.
- Check for missing or duplicated delimiters.
- Watch for malformed UTF-8 sequences in the decoded bytes.

### 7.3 Performance Issues
Traversal is linear in file size. Profile with:
```bash
python -m cProfile -s cumtime -m src.cli inject large.json "Recipient"
```

### 7.4 Character Encoding Mismatches
All file I/O should use UTF-8. If you suspect a different encoding, you can inspect bytes directly or use an external detector (for example, `chardet` requires a separate install).

## 8) Extending the System
### 8.1 New Injectable Field Types
Add a new `_inject_*` method and call it from `_traverse_and_inject`. Mirror the change with a `_extract_*` method in the tracer.

### 8.2 Alternative Encoding Schemes
Subclass `SteganoEngine` and override `encode`/`decode`. Pass the custom engine into `AASInjector` and `AASTracer`.

### 8.3 Adding Checksums
If you need corruption detection, append a checksum to the payload before encoding and validate it on decode.
