"""Compatibility wrapper package for AAS-Stegano-Trace."""

from src import (  # re-export public API
    SteganoEngine,
    ZeroWidthCodec,
    AASInjector,
    InjectionReport,
    AASTracer,
    TraceReport,
    __version__,
    __author__,
    __email__,
)

__all__ = [
    "SteganoEngine",
    "ZeroWidthCodec",
    "AASInjector",
    "InjectionReport",
    "AASTracer",
    "TraceReport",
]
