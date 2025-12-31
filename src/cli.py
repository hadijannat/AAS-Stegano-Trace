#!/usr/bin/env python3
"""
cli.py - Command Line Interface for AAS-Stegano-Trace

This module provides a professional CLI for forensic watermarking operations
on Asset Administration Shell files. It supports three primary workflows:

    1. INJECT: Mark an AAS file with a recipient identifier before sharing
    2. TRACE:  Analyze a file to extract any embedded watermarks
    3. VERIFY: Quick check if a file contains watermarks

Usage Examples:
    # Mark a file for a specific recipient
    $ python -m aas_stegano_trace inject motor.json "Supplier-ABC"

    # Investigate a potentially leaked file
    $ python -m aas_stegano_trace trace leaked_file.json

    # Quick watermark presence check
    $ python -m aas_stegano_trace verify suspicious_file.json

The CLI is designed for both interactive use and CI/CD pipeline integration,
with appropriate exit codes and machine-readable output options.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Callable, cast

# Local imports (when run as module)
if TYPE_CHECKING:
    from .aas_injector import AASInjector
    from .aas_tracer import AASTracer
    from .stegano_core import SteganoEngine
else:
    try:
        from .aas_injector import AASInjector
        from .aas_tracer import AASTracer
        from .stegano_core import SteganoEngine
    except ImportError:
        # Direct script execution
        from aas_injector import AASInjector
        from aas_tracer import AASTracer
        from stegano_core import SteganoEngine


# ═══════════════════════════════════════════════════════════════════════════════
# CLI OUTPUT FORMATTING
# ═══════════════════════════════════════════════════════════════════════════════


class ConsoleOutput:
    """Handles formatted console output with optional color support."""

    # ANSI color codes (disabled if not TTY)
    COLORS_ENABLED = sys.stdout.isatty()

    RESET = "\033[0m" if COLORS_ENABLED else ""
    BOLD = "\033[1m" if COLORS_ENABLED else ""
    GREEN = "\033[92m" if COLORS_ENABLED else ""
    RED = "\033[91m" if COLORS_ENABLED else ""
    YELLOW = "\033[93m" if COLORS_ENABLED else ""
    BLUE = "\033[94m" if COLORS_ENABLED else ""
    CYAN = "\033[96m" if COLORS_ENABLED else ""

    @classmethod
    def banner(cls) -> None:
        """Print the application banner."""
        print(
            f"""
{cls.CYAN}╔═══════════════════════════════════════════════════════════════╗
║  {cls.BOLD}AAS-Stegano-Trace{cls.RESET}{cls.CYAN}                                           ║
║  Invisible Forensic Watermarking for Asset Administration Shells ║
║  Version 1.0.0 | MIT License                                     ║
╚═══════════════════════════════════════════════════════════════════╝{cls.RESET}
"""
        )

    @classmethod
    def success(cls, message: str) -> None:
        """Print a success message."""
        print(f"{cls.GREEN}✓ {message}{cls.RESET}")

    @classmethod
    def error(cls, message: str) -> None:
        """Print an error message."""
        print(f"{cls.RED}✗ {message}{cls.RESET}")

    @classmethod
    def warning(cls, message: str) -> None:
        """Print a warning message."""
        print(f"{cls.YELLOW}⚠ {message}{cls.RESET}")

    @classmethod
    def info(cls, message: str) -> None:
        """Print an info message."""
        print(f"{cls.BLUE}ℹ {message}{cls.RESET}")

    @classmethod
    def alert(cls, message: str) -> None:
        """Print an alert/detection message."""
        print(f"{cls.RED}{cls.BOLD}🚨 {message}{cls.RESET}")


# ═══════════════════════════════════════════════════════════════════════════════
# COMMAND HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════


def cmd_inject(args: argparse.Namespace) -> int:
    """
    Handle the 'inject' command - embed watermark into AAS file.

    This creates a new file with the forensic watermark embedded,
    ready to be distributed to the specified recipient.
    """
    ConsoleOutput.banner()

    input_path = Path(args.file)
    recipient = args.recipient

    # Validate input file exists
    if not input_path.exists():
        ConsoleOutput.error(f"File not found: {input_path}")
        return 1

    if input_path.suffix.lower() != ".json":
        ConsoleOutput.warning("File does not have .json extension - proceeding anyway")

    # Load the AAS file
    ConsoleOutput.info(f"Loading: {input_path}")
    try:
        with open(input_path, encoding="utf-8") as f:
            aas_data = json.load(f)
    except json.JSONDecodeError as e:
        ConsoleOutput.error(f"Invalid JSON: {e}")
        return 1
    except Exception as e:
        ConsoleOutput.error(f"Failed to read file: {e}")
        return 1

    # Perform injection
    ConsoleOutput.info(f"Injecting watermark for recipient: '{recipient}'")

    engine = SteganoEngine()
    injector = AASInjector(engine)
    report = injector.inject(aas_data, recipient)

    if not report.success:
        ConsoleOutput.error("No suitable text fields found for watermarking!")
        ConsoleOutput.info("The AAS file needs 'description' fields or string Properties.")
        return 1

    # Generate output filename
    if args.output:
        output_path = Path(args.output)
    else:
        # Create descriptive filename: original_to_recipient.json
        safe_recipient = "".join(c if c.isalnum() else "_" for c in recipient)
        output_path = input_path.with_stem(f"{input_path.stem}_to_{safe_recipient}")

    # Write the watermarked file
    # CRITICAL: ensure_ascii=False preserves Unicode zero-width characters!
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(aas_data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        ConsoleOutput.error(f"Failed to write output file: {e}")
        return 1

    # Success output
    print()  # Blank line
    ConsoleOutput.success(f"Watermark injected into {report.total_injections} field(s)")
    ConsoleOutput.info(f"Output file: {output_path}")

    if args.verbose:
        print()
        print(report.summary())

    print()
    ConsoleOutput.success(
        "File ready for distribution to: "
        + f"{ConsoleOutput.BOLD}'{recipient}'{ConsoleOutput.RESET}"
    )

    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    """
    Handle the 'trace' command - forensic analysis of suspected leak.

    This scans a file for embedded watermarks and generates a
    comprehensive forensic report.
    """
    ConsoleOutput.banner()

    input_path = Path(args.file)

    # Validate input file
    if not input_path.exists():
        ConsoleOutput.error(f"File not found: {input_path}")
        return 1

    # Perform forensic analysis
    ConsoleOutput.info(f"Scanning: {input_path}")
    print(f"   {ConsoleOutput.CYAN}Performing forensic watermark analysis...{ConsoleOutput.RESET}")
    print()

    tracer = AASTracer()
    report = tracer.trace(str(input_path))

    # Display results
    if args.json_output:
        # Machine-readable JSON output
        print(report.to_json())
    else:
        # Human-readable forensic report
        print(report.forensic_summary())

    print()

    # Summary with appropriate styling
    if report.watermarks_found:
        ConsoleOutput.alert("WATERMARK DETECTED!")
        issued_to = list(report.payloads)
        print(f"   This file was issued to: {ConsoleOutput.BOLD}{issued_to}{ConsoleOutput.RESET}")
        return 2  # Special exit code indicating watermark found
    else:
        ConsoleOutput.success("No forensic watermarks detected in this file.")
        return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """
    Handle the 'verify' command - quick watermark presence check.

    This is a fast check that returns a boolean result without
    full forensic analysis. Useful for batch processing.
    """
    input_path = Path(args.file)

    if not input_path.exists():
        if not args.quiet:
            ConsoleOutput.error(f"File not found: {input_path}")
        return 1

    tracer = AASTracer()
    has_watermark = tracer.has_watermark(str(input_path))

    if args.quiet:
        # Silent mode - just return exit code
        return 2 if has_watermark else 0
    else:
        if has_watermark:
            ConsoleOutput.alert(f"WATERMARK PRESENT: {input_path}")
            return 2
        else:
            ConsoleOutput.success(f"No watermark: {input_path}")
            return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """
    Handle the 'demo' command - run a demonstration of the full workflow.

    This creates sample files and demonstrates injection and tracing.
    """
    ConsoleOutput.banner()

    print(f"{ConsoleOutput.CYAN}═══ DEMONSTRATION MODE ═══{ConsoleOutput.RESET}")
    print()

    # Create sample AAS data
    sample_aas = {
        "assetAdministrationShells": [
            {"id": "urn:example:aas:motor-001", "idShort": "IndustrialMotor"}
        ],
        "submodels": [
            {
                "idShort": "Nameplate",
                "description": [{"language": "en", "text": "Motor identification data"}],
                "submodelElements": [
                    {
                        "idShort": "ManufacturerName",
                        "modelType": "Property",
                        "valueType": "xs:string",
                        "value": "ACME Motors GmbH",
                        "description": [{"language": "en", "text": "Name of the manufacturer"}],
                    },
                    {
                        "idShort": "SerialNumber",
                        "modelType": "Property",
                        "valueType": "xs:string",
                        "value": "SN-2024-00142",
                    },
                ],
            }
        ],
    }

    # Step 1: Save original
    original_file = Path("demo_motor_original.json")
    with open(original_file, "w", encoding="utf-8") as f:
        json.dump(sample_aas, f, indent=2, ensure_ascii=False)
    ConsoleOutput.info(f"Created sample AAS: {original_file}")

    # Step 2: Inject watermark
    recipient = "SupplierX-Corp"
    engine = SteganoEngine()
    injector = AASInjector(engine)
    report = injector.inject(sample_aas, recipient)

    watermarked_file = Path("demo_motor_watermarked.json")
    with open(watermarked_file, "w", encoding="utf-8") as f:
        json.dump(sample_aas, f, indent=2, ensure_ascii=False)

    ConsoleOutput.success(f"Watermarked {report.total_injections} fields for '{recipient}'")
    ConsoleOutput.info(f"Saved as: {watermarked_file}")
    print()

    # Step 3: Show the magic - files look identical!
    print(f"{ConsoleOutput.YELLOW}═══ THE MAGIC ═══{ConsoleOutput.RESET}")
    print("Open both files in a text editor - they look IDENTICAL!")
    print(f"  Original:    {original_file}")
    print(f"  Watermarked: {watermarked_file}")
    print()

    # Step 4: Trace the watermark
    print(f"{ConsoleOutput.YELLOW}═══ FORENSIC TRACE ═══{ConsoleOutput.RESET}")
    tracer = AASTracer()
    trace_report = tracer.trace(str(watermarked_file))
    print(trace_report.forensic_summary())

    return 0


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════


def main() -> int:
    """Run the CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="aas-stegano-trace",
        description="Invisible Forensic Watermarking for Asset Administration Shells",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s inject motor.json "Supplier-ABC"    Mark file for Supplier-ABC
  %(prog)s trace leaked_file.json              Analyze for watermarks
  %(prog)s verify *.json                       Quick batch check
  %(prog)s demo                                Run demonstration

For more information: https://github.com/hadijannat/AAS-Stegano-Trace
        """,
    )

    subparsers = parser.add_subparsers(
        dest="command", title="commands", description="Available operations"
    )

    # ─────────────────────────────────────────────────────────────────────────
    # INJECT command
    # ─────────────────────────────────────────────────────────────────────────
    inject_parser = subparsers.add_parser(
        "inject",
        help="Embed invisible watermark into AAS file",
        description="Mark an AAS JSON file with a forensic watermark identifying the recipient.",
    )
    inject_parser.add_argument("file", help="Input AAS JSON file to watermark")
    inject_parser.add_argument(
        "recipient", help="Recipient identifier to embed (e.g., company name, contract ID)"
    )
    inject_parser.add_argument(
        "-o", "--output", help="Output file path (default: <input>_to_<recipient>.json)"
    )
    inject_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed injection report"
    )
    inject_parser.set_defaults(func=cmd_inject)

    # ─────────────────────────────────────────────────────────────────────────
    # TRACE command
    # ─────────────────────────────────────────────────────────────────────────
    trace_parser = subparsers.add_parser(
        "trace",
        help="Extract and analyze watermarks (forensics)",
        description="Perform forensic analysis to detect and extract embedded watermarks.",
    )
    trace_parser.add_argument("file", help="AAS JSON file to analyze")
    trace_parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output results as JSON (machine-readable)",
    )
    trace_parser.set_defaults(func=cmd_trace)

    # ─────────────────────────────────────────────────────────────────────────
    # VERIFY command
    # ─────────────────────────────────────────────────────────────────────────
    verify_parser = subparsers.add_parser(
        "verify",
        help="Quick check for watermark presence",
        description="Fast check if file contains watermarks (no full analysis).",
    )
    verify_parser.add_argument("file", help="AAS JSON file to check")
    verify_parser.add_argument(
        "-q", "--quiet", action="store_true", help="Silent mode - only return exit code"
    )
    verify_parser.set_defaults(func=cmd_verify)

    # ─────────────────────────────────────────────────────────────────────────
    # DEMO command
    # ─────────────────────────────────────────────────────────────────────────
    demo_parser = subparsers.add_parser(
        "demo",
        help="Run interactive demonstration",
        description="Create sample files and demonstrate the full watermarking workflow.",
    )
    demo_parser.set_defaults(func=cmd_demo)

    # ─────────────────────────────────────────────────────────────────────────
    # Parse and execute
    # ─────────────────────────────────────────────────────────────────────────
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    try:
        func = cast(Callable[[argparse.Namespace], int], args.func)
        return func(args)
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        return 130
    except Exception as e:
        ConsoleOutput.error(f"Unexpected error: {e}")
        if os.environ.get("DEBUG"):
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
