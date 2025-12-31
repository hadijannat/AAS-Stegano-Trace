"""
stegano_core.py - Zero-Width Unicode Steganography Engine

This module implements the fundamental steganographic operations using invisible
Unicode characters to encode binary data within plaintext strings. The technique
exploits the existence of "zero-width" Unicode code points that occupy no visual
space but are preserved in text processing pipelines.

Technical Background:
    Zero-width characters are Unicode code points designed for text rendering
    control (e.g., controlling ligature formation in Arabic script). Because
    they have no visual representation, they can be injected into strings
    without altering the perceived content. This module repurposes them as
    an invisible binary alphabet.

Encoding Scheme:
    ZERO_WIDTH_SPACE (U+200B)      → Binary '0'
    ZERO_WIDTH_NON_JOINER (U+200C) → Binary '1'
    ZERO_WIDTH_JOINER (U+200D)     → Delimiter (marks payload boundaries)

Security Note:
    This is forensic watermarking, not encryption. The encoding scheme is
    deterministic and reversible by anyone who knows the algorithm. The
    security model assumes that attackers won't think to check for invisible
    characters, not that they can't decode them if found.
"""

import hashlib
from dataclasses import dataclass
from typing import Optional

# ═══════════════════════════════════════════════════════════════════════════════
# UNICODE CODE POINTS FOR ZERO-WIDTH STEGANOGRAPHY
# ═══════════════════════════════════════════════════════════════════════════════


class ZeroWidthCodec:
    """
    Unicode code points used for invisible binary encoding.

    These characters are part of the "General Punctuation" Unicode block
    and are specifically designed to have zero display width. They are
    preserved by virtually all text processing systems including JSON
    serializers, making them ideal for steganographic embedding.

    Reference: Unicode Standard, Chapter 23.2 "Format Characters"
    """

    # Binary encoding characters
    ZERO: str = "\u200b"  # ZERO WIDTH SPACE - represents binary '0'
    ONE: str = "\u200c"  # ZERO WIDTH NON-JOINER - represents binary '1'

    # Delimiter character
    MARKER: str = "\u200d"  # ZERO WIDTH JOINER - payload boundary marker

    # Character set for detection
    ALL_CHARS: frozenset = frozenset({"\u200b", "\u200c", "\u200d"})

    @classmethod
    def is_zero_width(cls, char: str) -> bool:
        """Check if a character is a zero-width control character."""
        return char in cls.ALL_CHARS

    @classmethod
    def contains_markers(cls, text: str) -> bool:
        """Quick check if text contains any zero-width characters."""
        return any(c in cls.ALL_CHARS for c in text)


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES FOR STRUCTURED RESULTS
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class EncodeResult:
    """
    Result of encoding a payload into invisible characters.

    Attributes:
        invisible_payload: The encoded payload as invisible Unicode string
        bit_length: Number of binary bits in the encoding
        byte_length: Number of bytes in the original payload
        checksum: SHA-256 checksum of original payload (for integrity verification)
    """

    invisible_payload: str
    bit_length: int
    byte_length: int
    checksum: str

    def __len__(self) -> int:
        """Returns the number of invisible characters (includes markers)."""
        return len(self.invisible_payload)


@dataclass(frozen=True)
class DecodeResult:
    """
    Result of decoding invisible characters back to plaintext.

    Attributes:
        payload: The decoded plaintext payload
        bit_length: Number of binary bits that were decoded
        is_valid: Whether the decoding completed successfully
        error: Error message if decoding failed, None otherwise
    """

    payload: Optional[str]
    bit_length: int
    is_valid: bool
    error: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN STEGANOGRAPHY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════


class SteganoEngine:
    """
    Core engine for zero-width steganographic encoding and decoding.

    This class provides the fundamental operations for converting arbitrary
    text payloads into invisible Unicode sequences and back. It handles
    the binary conversion, character mapping, and delimiter management.

    The encoding process works as follows:
    1. Convert each character of the payload to its 8-bit ASCII/UTF-8 value
    2. Map each bit to a zero-width character (0→ZWSP, 1→ZWNJ)
    3. Wrap the bit sequence with ZWJ delimiters to mark boundaries

    Example:
        >>> engine = SteganoEngine()
        >>> encoded = engine.encode("ABC")
        >>> print(f"Encoded {encoded.byte_length} bytes into {len(encoded)} invisible chars")
        Encoded 3 bytes into 26 invisible chars

        >>> result = engine.decode(encoded.invisible_payload)
        >>> print(result.payload)
        ABC

    Thread Safety:
        This class is stateless and thread-safe. All methods are pure functions.
    """

    def __init__(self, codec: ZeroWidthCodec = None):
        """
        Initialize the steganography engine.

        Args:
            codec: Optional custom codec configuration. Uses default if None.
        """
        self._codec = codec or ZeroWidthCodec()

    # ─────────────────────────────────────────────────────────────────────────
    # ENCODING: Text → Invisible Unicode
    # ─────────────────────────────────────────────────────────────────────────

    def encode(self, payload: str) -> EncodeResult:
        """
        Encode a text payload into an invisible Unicode string.

        The encoding process converts the input string to a binary representation
        using 8-bit encoding per character, then maps each bit to a zero-width
        Unicode character. The result is wrapped with delimiter characters to
        enable reliable extraction later.

        Args:
            payload: The plaintext string to encode. Should be ASCII-compatible
                    for maximum compatibility, though UTF-8 is supported.

        Returns:
            EncodeResult containing the invisible payload and metadata.

        Raises:
            ValueError: If payload is empty or None.

        Example:
            >>> engine = SteganoEngine()
            >>> result = engine.encode("Supplier-B")
            >>> len(result.invisible_payload)  # Includes 2 markers + 80 bits
            82
        """
        if not payload:
            raise ValueError("Payload cannot be empty")

        # Step 1: Convert text to binary string representation
        # Each character becomes 8 binary digits (works for ASCII/Latin-1)
        # For full Unicode, we encode as UTF-8 bytes first
        payload_bytes = payload.encode("utf-8")
        binary_string = "".join(format(byte, "08b") for byte in payload_bytes)

        # Step 2: Map binary digits to invisible characters
        invisible_bits = []
        for bit in binary_string:
            if bit == "0":
                invisible_bits.append(ZeroWidthCodec.ZERO)
            else:
                invisible_bits.append(ZeroWidthCodec.ONE)

        # Step 3: Wrap with delimiter markers for reliable extraction
        # Format: [MARKER][encoded_bits][MARKER]
        invisible_payload = ZeroWidthCodec.MARKER + "".join(invisible_bits) + ZeroWidthCodec.MARKER

        # Step 4: Compute checksum for integrity verification
        checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

        return EncodeResult(
            invisible_payload=invisible_payload,
            bit_length=len(binary_string),
            byte_length=len(payload_bytes),
            checksum=checksum,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # DECODING: Invisible Unicode → Text
    # ─────────────────────────────────────────────────────────────────────────

    def decode(self, text: str) -> DecodeResult:
        """
        Extract and decode a hidden payload from text containing invisible characters.

        This method searches the input text for the delimiter markers and extracts
        the invisible binary sequence between them. It then converts this back to
        the original plaintext payload.

        Args:
            text: Any string that may contain an embedded invisible payload.
                 Can include visible characters (they are ignored during extraction).

        Returns:
            DecodeResult with the extracted payload and status information.
            If no valid payload is found, is_valid will be False.

        Example:
            >>> engine = SteganoEngine()
            >>> encoded = engine.encode("Test").invisible_payload
            >>> carrier = "Hello" + encoded + " World"  # Hidden in visible text
            >>> result = engine.decode(carrier)
            >>> result.payload
            'Test'
        """
        # Check for presence of delimiter markers
        if ZeroWidthCodec.MARKER not in text:
            return DecodeResult(
                payload=None,
                bit_length=0,
                is_valid=False,
                error="No watermark delimiters found in text",
            )

        try:
            # Find the payload boundaries (first and last markers)
            start_idx = text.find(ZeroWidthCodec.MARKER)
            end_idx = text.rfind(ZeroWidthCodec.MARKER)

            # Validate we have two distinct markers
            if start_idx == end_idx:
                return DecodeResult(
                    payload=None,
                    bit_length=0,
                    is_valid=False,
                    error="Only one delimiter found - payload corrupted",
                )

            # Extract the invisible bit sequence between markers
            encoded_region = text[start_idx + 1 : end_idx]

            # Convert invisible characters back to binary string
            binary_string = ""
            for char in encoded_region:
                if char == ZeroWidthCodec.ZERO:
                    binary_string += "0"
                elif char == ZeroWidthCodec.ONE:
                    binary_string += "1"
                # Ignore any non-zero-width characters that slipped in

            # Validate binary string length is multiple of 8
            if len(binary_string) % 8 != 0:
                return DecodeResult(
                    payload=None,
                    bit_length=len(binary_string),
                    is_valid=False,
                    error=f"Invalid bit length {len(binary_string)} (not multiple of 8)",
                )

            # Convert binary string back to bytes, then decode as UTF-8
            byte_chunks = [binary_string[i : i + 8] for i in range(0, len(binary_string), 8)]
            decoded_bytes = bytes([int(chunk, 2) for chunk in byte_chunks])
            decoded_payload = decoded_bytes.decode("utf-8")

            return DecodeResult(
                payload=decoded_payload, bit_length=len(binary_string), is_valid=True, error=None
            )

        except UnicodeDecodeError as e:
            return DecodeResult(
                payload=None, bit_length=0, is_valid=False, error=f"UTF-8 decode error: {e}"
            )
        except Exception as e:
            return DecodeResult(
                payload=None, bit_length=0, is_valid=False, error=f"Unexpected decode error: {e}"
            )

    # ─────────────────────────────────────────────────────────────────────────
    # UTILITY: Injection into carrier text
    # ─────────────────────────────────────────────────────────────────────────

    def embed(self, carrier: str, payload: str, position: str = "end") -> str:
        """
        Embed an invisible payload into a carrier string.

        This is a convenience method that encodes the payload and injects it
        into the carrier text at the specified position.

        Args:
            carrier: The visible text that will carry the hidden payload.
            payload: The secret message to hide.
            position: Where to inject - "start", "middle", or "end" (default).

        Returns:
            The carrier text with the invisible payload embedded.

        Example:
            >>> engine = SteganoEngine()
            >>> result = engine.embed("Motor Speed", "Supplier-X")
            >>> print(result)  # Looks identical to "Motor Speed"
            Motor Speed
            >>> engine.decode(result).payload
            'Supplier-X'
        """
        encoded = self.encode(payload)

        if position == "start":
            return encoded.invisible_payload + carrier
        elif position == "middle":
            mid = len(carrier) // 2
            return carrier[:mid] + encoded.invisible_payload + carrier[mid:]
        else:  # "end" is default
            return carrier + encoded.invisible_payload

    def has_watermark(self, text: str) -> bool:
        """
        Quick check if text contains a watermark (has valid delimiter markers).

        This is a fast preliminary check that doesn't attempt full decoding.
        Use decode() for complete extraction and validation.

        Args:
            text: String to check for watermark presence.

        Returns:
            True if the text contains watermark delimiters, False otherwise.
        """
        marker = ZeroWidthCodec.MARKER
        if marker not in text:
            return False

        # Check for at least two markers (start and end)
        first = text.find(marker)
        last = text.rfind(marker)
        return first != last

    def strip_watermark(self, text: str) -> str:
        """
        Remove all zero-width characters from text (including watermarks).

        This is useful for "cleaning" text that may contain watermarks,
        though note that this destroys the forensic evidence.

        Args:
            text: String potentially containing zero-width characters.

        Returns:
            Clean string with all zero-width characters removed.
        """
        return "".join(c for c in text if not ZeroWidthCodec.is_zero_width(c))
