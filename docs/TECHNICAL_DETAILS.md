# Technical Details: Zero-Width Steganography for AAS

This document provides an in-depth technical explanation of how AAS-Stegano-Trace embeds and extracts forensic watermarks using zero-width Unicode steganography.

## 1. Unicode Zero-Width Characters

### What Are Zero-Width Characters?

Unicode defines several "format characters" that influence text rendering but have no visual representation themselves. The most relevant for steganography are:

| Character | Code Point | Name | Primary Purpose |
|-----------|-----------|------|-----------------|
| ZWSP | U+200B | Zero Width Space | Word-break hints |
| ZWNJ | U+200C | Zero Width Non-Joiner | Prevent ligature formation |
| ZWJ | U+200D | Zero Width Joiner | Force ligature/emoji joining |

These characters were designed for typographic control in complex scripts (Arabic, Devanagari) and for emoji sequences. However, they have an interesting property that we exploit: they are preserved by virtually all text processing systems while remaining completely invisible to users.

### Why They Work for Steganography

The invisibility of zero-width characters makes them ideal for hiding information within the very structure of text itself. When you copy, paste, save, or load text containing these characters, they travel along silently. JSON serializers, text editors, and file systems all preserve them faithfully. The only way to detect them is to specifically look for them, either by examining the raw bytes of a file or by using character inspection tools.

## 2. Binary Encoding Scheme

### Mapping Bits to Characters

We establish a simple mapping from binary digits to zero-width characters:

```
Binary '0' → U+200B (Zero Width Space)
Binary '1' → U+200C (Zero Width Non-Joiner)
```

This gives us a two-symbol alphabet for representing arbitrary binary data. To mark the boundaries of our hidden payload, we use a third character as a delimiter:

```
Delimiter → U+200D (Zero Width Joiner)
```

### Encoding Process

To encode a text payload like "ABC", we proceed through these steps:

First, we convert each character to its binary representation. Standard ASCII/UTF-8 uses 8 bits per character:

```
'A' = 65 = 01000001
'B' = 66 = 01000010  
'C' = 67 = 01000011
```

Next, we concatenate these binary strings to form a continuous bit stream:

```
010000010100001001000011
```

Then we map each bit to its corresponding zero-width character. Let me represent them symbolically as `○` for U+200B (binary 0) and `●` for U+200C (binary 1):

```
○●○○○○○●○●○○○○●○○●○○○○●●
```

Finally, we wrap the sequence with our delimiter character (represented as `|`):

```
|○●○○○○○●○●○○○○●○○●○○○○●●|
```

The resulting string of 26 invisible characters can be appended to any visible text, creating a watermarked string that looks identical to the original but carries hidden information.

### Decoding Process

Decoding reverses this process. Given a watermarked string, we first locate the delimiter characters (U+200D) marking the payload boundaries. We extract the characters between the delimiters and convert each back to its binary value. After reassembling the bit stream into 8-bit chunks, we decode each chunk as a character.

## 3. AAS-Specific Injection Strategy

### Target Field Selection

Asset Administration Shells follow the IDTA metamodel specification. Not all fields are suitable for watermarking because some contain structured data that must remain pristine. We specifically target text fields that are designed for human-readable content, where additional invisible characters won't affect parsing or computation.

**Description Fields**: These are LangString arrays appearing throughout the AAS structure. Each LangString has a language code and a text field containing human-readable descriptions. These are ideal injection points because descriptions are meant for human consumption, parsers ignore their content, and they appear frequently throughout an AAS.

**String Properties**: Properties of type `xs:string` contain textual values that parsers treat as opaque strings. As long as the visible portion remains unchanged, the property functions correctly. However, we must be careful to only target Properties that are explicitly typed as strings, not those containing numeric or structured data.

**MultiLanguageProperty Elements**: Similar to descriptions, these contain arrays of LangStrings with language-specific text values. Each language variant receives the same watermark, providing redundancy.

### Fields We Never Touch

Numeric properties (xs:double, xs:integer, xs:float) are never modified because even invisible characters would cause parsing failures or corrupt calculations. Boolean fields, references, and semantic identifiers are similarly left untouched. The watermark must be invisible not just visually but functionally.

### Injection Placement

We append the watermark to the end of existing text rather than inserting it at the beginning or middle. This ensures that common operations like string comparison, prefix matching, or display truncation see the original content first. The watermark rides along at the end, surviving the journey through processing pipelines.

## 4. JSON Serialization Considerations

### The Critical ensure_ascii Parameter

When saving watermarked AAS data to JSON, you **must** use `ensure_ascii=False`:

```python
json.dump(aas_data, file, indent=2, ensure_ascii=False)
```

The reason for this requirement is that Python's JSON serializer, by default, escapes non-ASCII characters using \uXXXX notation. If `ensure_ascii=True` (the default), our zero-width characters become visible escape sequences like `\u200b\u200c\u200d`, which defeats the entire purpose of invisible watermarking.

With `ensure_ascii=False`, the Unicode characters are written directly to the output file in their UTF-8 representation. They remain invisible when the file is viewed normally but are preserved for later extraction.

### Character Encoding

Always use UTF-8 encoding when reading and writing AAS files. UTF-8 correctly represents all Unicode code points, including our zero-width characters, using a variable-length encoding scheme. The characters U+200B through U+200D are encoded as three-byte sequences in UTF-8, making them slightly larger than ASCII characters but still quite compact.

## 5. Security Analysis

### What This Tool Does Provide

This tool provides plausible deniability detection. If a leaked file contains your watermark, you have strong evidence that the leak originated from the party you issued that specific watermarked copy to. The watermark survives normal file handling operations, making it difficult to accidentally strip.

The approach also provides deterrence. If recipients know that files may be watermarked (even if they don't know the specifics), they may be more cautious about unauthorized sharing. The uncertainty creates a chilling effect on potential leakers.

### What This Tool Does Not Provide

This is not cryptographic security. A sophisticated attacker who knows about zero-width steganography could strip all such characters from a file using a simple script. The encoding algorithm is deterministic and reversible, providing no protection if the scheme is discovered.

The watermark also does not prove that the identified recipient actually performed the leak. It only proves that the file was derived from the copy issued to that recipient. The file could have been stolen from the recipient's systems, forwarded by an employee, or obtained through other means.

### Threat Model

The intended threat model assumes an attacker who does not specifically check for steganographic watermarks, makes copies of files through normal means (file copying, JSON re-serialization, email attachments), and may perform normal processing operations on the AAS data.

The watermark is vulnerable to attackers who know to check for zero-width characters and strip them, those who manually retype or recreate data rather than copying files, and those who programmatically regenerate AAS structures from extracted values.

## 6. Implementation Notes

### Idempotent Injection

The injector checks for existing watermark delimiters before injection. If a field already contains a watermark (indicated by the presence of U+200D), it is skipped. This prevents double-marking and allows safe re-injection attempts, which is important for workflows where files might be processed multiple times.

### Multiple Injection Points

The injector watermarks all suitable fields it finds rather than just one. This defense-in-depth approach means that even if some watermarks are accidentally or deliberately removed, others may survive. The forensic tracer searches comprehensively and reports all found watermarks, allowing confidence assessment based on the number of consistent findings.

### Payload Design

Watermark payloads should be designed with several considerations in mind. They should be unique per recipient so that each partner receives a distinguishable watermark. They should be meaningful for forensics, typically containing the recipient's name, contract ID, or issuance date. They should be reasonably compact because longer payloads mean more invisible characters and slightly larger files. And they should avoid special characters that might cause encoding issues.

A good payload format might be something like: `SupplierName-2024-ContractRef`

## 7. Future Directions

Several enhancements could strengthen this approach. Error correction codes could be added to the binary encoding to allow recovery from partial watermark corruption. Multiple encoding schemes could be employed so that different payload fragments use different steganographic techniques. Per-field unique payloads could identify not just the recipient but which specific field was extracted if only partial data leaks. Integration with blockchain or timestamping services could provide non-repudiable evidence of when watermarks were created.

These remain areas for future research and implementation.
