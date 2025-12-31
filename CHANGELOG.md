# Changelog

All notable changes to AAS-Stegano-Trace will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-31

### Added

Initial release of AAS-Stegano-Trace with complete forensic watermarking capabilities.

**Core Features:**
- Zero-width Unicode steganography engine for invisible binary encoding
- AAS-aware injection targeting description fields, string Properties, and MultiLanguageProperty elements
- Forensic tracer with comprehensive analysis and reporting
- Professional CLI with inject, trace, verify, and demo commands

**Technical Capabilities:**
- UTF-8 payload support for international recipient identifiers
- Idempotent injection (safe to re-run without duplicate watermarks)
- Defense-in-depth through multi-field watermarking
- Machine-readable JSON output for CI/CD integration

**Documentation:**
- Comprehensive README with research context and usage examples
- Technical documentation explaining the steganography approach
- Example AAS files for testing and demonstration
- Complete test suite with unit and integration tests

**Developer Experience:**
- Zero external dependencies (Python standard library only)
- Modern Python packaging with pyproject.toml
- GitHub Actions CI workflow for automated testing
- Type hints throughout the codebase

## [Unreleased]

### Planned

- Error correction codes for watermark resilience
- Web-based demonstration interface
- Integration with BaSyx AAS server
- Alternative steganographic techniques (whitespace, homoglyphs)
- Per-field unique payloads for granular leak detection
