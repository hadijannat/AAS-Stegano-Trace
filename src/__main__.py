#!/usr/bin/env python3
"""
__main__.py - Module entry point for python -m execution

This allows the package to be run directly as:
    python -m aas_stegano_trace <command> [args]

Equivalent to:
    python -m aas_stegano_trace.cli <command> [args]
"""

from .cli import main

if __name__ == '__main__':
    exit(main())
