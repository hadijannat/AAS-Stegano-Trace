"""
AAS-Stegano-Trace: Forensic Watermarking for Asset Administration Shells

This package provides invisible forensic fingerprinting for AAS files using 
Zero-Width Unicode Steganography. It enables data owners to embed imperceptible 
recipient identifiers that survive standard file handling but enable leak tracing.

Core Components:
    - stegano_core: Low-level zero-width encoding/decoding primitives
    - aas_injector: AAS-aware watermark injection traversal
    - aas_tracer: Forensic extraction and analysis
    - cli: Command-line interface for all operations

Example:
    >>> from aas_stegano_trace import SteganoEngine, AASInjector
    >>> engine = SteganoEngine()
    >>> injector = AASInjector(engine)
    >>> injector.inject(aas_data, "Supplier-B")

Author: Hadi Jannat (RWTH Aachen University - IAT)
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Hadi Jannat"
__email__ = "your.email@rwth-aachen.de"

from .stegano_core import SteganoEngine, ZeroWidthCodec
from .aas_injector import AASInjector, InjectionReport
from .aas_tracer import AASTracer, TraceReport

__all__ = [
    "SteganoEngine",
    "ZeroWidthCodec",
    "AASInjector",
    "InjectionReport",
    "AASTracer",
    "TraceReport",
]
