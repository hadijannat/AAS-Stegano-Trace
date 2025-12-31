# AAS-Stegano-Trace

## Invisible Forensic Watermarking for Asset Administration Shells

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Standard Library Only](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen.svg)](#installation)

**AAS-Stegano-Trace** enables data owners to embed imperceptible forensic fingerprints into Asset Administration Shell files. When proprietary AAS data is shared with partners and later surfaces in unauthorized locations, this tool identifies exactly who leaked it.

> *"Zero-Reveal proves facts without showing data. Stegano-Trace shares data and traces who leaks it."*  
> Together, they form a complete **Data Sovereignty** toolkit for Industry 4.0.

---

## The Research Problem

In modern manufacturing ecosystems, high-value digital assets are routinely shared across organizational boundaries:

- **Simulation Models** embedded in AAS files enable suppliers to optimize their processes
- **Operational Data** helps customers perform predictive maintenance
- **Configuration Parameters** allow integrators to commission equipment

Once an AAS file leaves your infrastructure, you lose control. If a supplier leaks your proprietary "Motor Efficiency Model" to a competitor, you have no way to prove **who** leaked it—digital files are normally identical copies with no provenance trail.

### The Research Question

> *"How can we embed an imperceptible, survivable forensic fingerprint into an Asset Administration Shell that identifies the leaking party without altering the data's functional behavior?"*

---

## The Solution: Zero-Width Steganography

**Steganography** is the art of hiding information in plain sight. Unlike encryption (which makes data unreadable), steganography makes data *invisible* while remaining perfectly functional.

This tool exploits **zero-width Unicode characters**—code points that exist in text strings but have no visual representation. We encode recipient identifiers into invisible bit sequences and inject them into AAS text fields.

### How It Works

```
┌──────────────────────────────────────────────────────────────────────┐
│  VISIBLE TO HUMANS:     "Max Rotation Speed"                         │
│  VISIBLE TO PARSERS:    "Max Rotation Speed"                         │
│  VISIBLE TO THIS TOOL:  "Max Rotation Speed" + [Hidden: "Supplier-B"]│
└──────────────────────────────────────────────────────────────────────┘
```

The encoding uses three Unicode characters from the "General Punctuation" block:

| Character | Unicode | Binary Meaning |
|-----------|---------|----------------|
| Zero Width Space | `U+200B` | Binary `0` |
| Zero Width Non-Joiner | `U+200C` | Binary `1` |
| Zero Width Joiner | `U+200D` | Delimiter (marks payload start/end) |

These characters are preserved by JSON serializers, text editors, and virtually all processing pipelines—but they occupy zero display width, making them invisible to casual inspection.

---

## Installation

**Zero external dependencies.** This project uses only Python's standard library.

```bash
# Clone the repository
git clone https://github.com/hadijannat/AAS-Stegano-Trace.git
cd AAS-Stegano-Trace

# Verify installation
python -m src.cli --help
```

For development with tests:

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## Quick Start

### 1. Watermark a File (Before Sharing)

You're about to send motor specifications to "SupplierX-Corp". Mark it first:

```bash
python -m src.cli inject examples/industrial_motor.json "SupplierX-Corp"
```

Output:
```
✓ Watermark injected into 12 field(s)
ℹ Output file: examples/industrial_motor_to_SupplierX_Corp.json
✓ File ready for distribution to: 'SupplierX-Corp'
```

### 2. Verify Invisibility

Open both files in any text editor. They look **identical**:
- Original: `examples/industrial_motor.json`
- Watermarked: `examples/industrial_motor_to_SupplierX_Corp.json`

The file size difference is negligible (a few bytes per watermarked field).

### 3. Investigate a Leak (Forensic Analysis)

Months later, your motor specifications appear on a competitor's system. You obtain the file and analyze it:

```bash
python -m src.cli trace leaked_motor_file.json
```

Output:
```
╔══════════════════════════════════════════════════════════════════╗
║            FORENSIC WATERMARK ANALYSIS REPORT                    ║
╠══════════════════════════════════════════════════════════════════╣
║  File:      leaked_motor_file.json                               ║
║  SHA-256:   3a7f2b9c...                                          ║
║  Scan Time: 2024-12-31T14:23:01                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚠️  WATERMARKS DETECTED                                         ║
╠══════════════════════════════════════════════════════════════════╣
║  Identified Recipients:                                          ║
║    → SupplierX-Corp                                              ║
║  Total Watermark Instances: 12                                   ║
╠══════════════════════════════════════════════════════════════════╣
║  VERDICT:                                                        ║
║  This file was exclusively issued to: SupplierX-Corp             ║
║  Evidence strength: HIGH (single consistent recipient)           ║
╚══════════════════════════════════════════════════════════════════╝
```

**You now have forensic evidence that the leak originated from SupplierX-Corp.**

---

## CLI Reference

### `inject` - Embed Watermark

```bash
python -m src.cli inject <file> <recipient> [options]

Arguments:
  file        Input AAS JSON file to watermark
  recipient   Identifier to embed (company name, contract ID, etc.)

Options:
  -o, --output PATH    Custom output file path
  -v, --verbose        Show detailed injection report
```

### `trace` - Forensic Analysis

```bash
python -m src.cli trace <file> [options]

Arguments:
  file        AAS JSON file to analyze

Options:
  --json      Output results as machine-readable JSON
```

### `verify` - Quick Check

```bash
python -m src.cli verify <file> [options]

Arguments:
  file        AAS JSON file to check

Options:
  -q, --quiet   Silent mode (exit code only)
```

### `demo` - Interactive Demonstration

```bash
python -m src.cli demo
```

Creates sample files and walks through the complete workflow.

---

## Python API

For integration into larger systems, use the Python API directly:

```python
from src import SteganoEngine, AASInjector, AASTracer
import json

# Load an AAS file
with open('my_asset.json', 'r') as f:
    aas_data = json.load(f)

# Initialize the toolchain
engine = SteganoEngine()
injector = AASInjector(engine)
tracer = AASTracer(engine)

# Inject watermark for a specific recipient
report = injector.inject(aas_data, "Partner-ABC")
print(f"Watermarked {report.total_injections} fields")

# CRITICAL: Use ensure_ascii=False when saving!
with open('my_asset_for_partner.json', 'w', encoding='utf-8') as f:
    json.dump(aas_data, f, indent=2, ensure_ascii=False)

# Later: Forensic analysis of suspected leak
trace_report = tracer.trace('suspected_leak.json')
if trace_report.watermarks_found:
    print(f"Leak source: {trace_report.payloads}")
```

---

## Architecture

```
aas-stegano-trace/
├── src/
│   ├── __init__.py          # Package exports
│   ├── stegano_core.py      # Zero-width encoding engine
│   ├── aas_injector.py      # AAS-aware watermark injection
│   ├── aas_tracer.py        # Forensic extraction & analysis
│   └── cli.py               # Command-line interface
├── tests/
│   └── test_aas_stegano_trace.py
├── examples/
│   ├── industrial_motor.json
│   └── minimal_aas.json
├── docs/
│   └── TECHNICAL_DETAILS.md
└── README.md
```

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `stegano_core.py` | Low-level binary encoding/decoding using zero-width Unicode |
| `aas_injector.py` | Traverses AAS structures, identifies injectable fields, embeds watermarks |
| `aas_tracer.py` | Scans AAS files for watermarks, generates forensic reports |
| `cli.py` | Professional command-line interface with colored output |

---

## Technical Details

### Which AAS Fields Are Watermarked?

The injector targets text fields that survive standard AAS processing:

1. **`description` arrays**: LangString objects with `text` fields
2. **`Property` elements**: Only those with `valueType: "xs:string"`
3. **`MultiLanguageProperty` elements**: LangString values

Numeric, boolean, and binary fields are **never** modified to avoid breaking simulations or calculations.

### Watermark Survivability

The watermark survives:
- ✅ JSON serialization/deserialization
- ✅ Pretty-printing and minification
- ✅ Copy/paste operations
- ✅ File compression (ZIP, GZIP)
- ✅ Most text editors and viewers

The watermark may be lost if:
- ❌ Text is manually retyped
- ❌ Values are programmatically overwritten
- ❌ A sophisticated attacker specifically strips zero-width characters

### Security Model

This is **forensic watermarking**, not encryption. The security relies on:

1. **Obscurity of presence**: Attackers don't think to check for invisible characters
2. **Defense in depth**: Watermarks are injected into multiple fields
3. **Deterrence**: Knowledge of watermarking discourages leaks

For sensitive data requiring cryptographic protection, pair this with **[Zero-Reveal-DPP](https://github.com/hadijannat/Zero-Reveal-DPP)**.

---

## Relationship to Zero-Reveal-DPP

This project complements the **Zero-Reveal-DPP** project:

| Aspect | Zero-Reveal-DPP | AAS-Stegano-Trace |
|--------|-----------------|-------------------|
| **Problem** | "How do I prove facts without revealing data?" | "How do I trace who leaked my data?" |
| **Technique** | Cryptography (Salted Merkle Trees) | Steganography (Zero-Width Unicode) |
| **When Used** | Before sharing | Before sharing |
| **Value** | Privacy-preserving verification | Accountability & deterrence |
| **Security** | Cryptographically secure | Security through obscurity |

Together, they provide a comprehensive **Data Sovereignty** toolkit:
1. Use **Zero-Reveal** to selectively prove compliance without exposing sensitive values
2. Use **Stegano-Trace** to watermark files before distribution for leak accountability

---

## Use Cases

### Supply Chain Data Sharing

Mark AAS files uniquely for each supplier. If proprietary data surfaces with competitors, trace the source.

### Catena-X / Manufacturing-X

Enable data sharing in automotive ecosystems while maintaining accountability for data exfiltration.

### Intellectual Property Protection

Protect simulation models, efficiency curves, and configuration data that represent significant R&D investment.

### Regulatory Evidence

Generate forensic reports suitable for legal proceedings when investigating IP theft.

---

## Limitations & Considerations

1. **Not encryption**: The encoding can be reversed by anyone who knows the algorithm
2. **Requires JSON integrity**: If JSON is re-serialized with `ensure_ascii=True`, watermarks may be escaped
3. **Text fields only**: Numeric/binary data cannot be watermarked
4. **Sophisticated attackers**: A determined attacker who knows about zero-width characters can strip them

---

## Contributing

Contributions are welcome! Areas of interest:

- Additional AAS element types (Blob metadata, Annotations)
- Alternative steganographic techniques (whitespace patterns, homoglyph substitution)
- Integration with AAS servers (BaSyx, AASX Server)
- Web-based demo interface

---

## Citation

If you use this work in academic research, please cite:

```bibtex
@software{aas_stegano_trace,
  author = {Jannat, Hadi},
  title = {AAS-Stegano-Trace: Invisible Forensic Watermarking for Asset Administration Shells},
  year = {2024},
  url = {https://github.com/hadijannat/AAS-Stegano-Trace},
  institution = {RWTH Aachen University, Chair of Information and Automation Systems}
}
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Author

**Hadi Jannat**  
Researcher, Chair of Information and Automation Systems for Process and Material Technology  
RWTH Aachen University

- GitHub: [@hadijannat](https://github.com/hadijannat)
- Related Project: [Zero-Reveal-DPP](https://github.com/hadijannat/Zero-Reveal-DPP)
