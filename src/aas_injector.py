"""
aas_injector.py - AAS-Aware Watermark Injection

This module provides intelligent traversal of Asset Administration Shell (AAS)
data structures to identify suitable injection points for forensic watermarks.
It understands the AAS metamodel and targets text fields that will survive
standard AAS processing pipelines.

Target Fields for Injection:
    1. Description fields: The 'description' array contains multilingual
       LangString entries with 'text' fields - ideal for watermarking.
    
    2. String Property values: SubmodelElements of type "Property" with
       valueType "xs:string" contain text values suitable for watermarking.
    
    3. MultiLanguageProperty: Similar to descriptions, these contain
       LangString arrays with text content.

Injection Strategy:
    The watermark is appended to the END of existing text to minimize
    disruption. This ensures that string comparisons, display truncation,
    and other operations see the original content first.

AAS Specification Reference:
    - IDTA-01001: Asset Administration Shell Metamodel
    - IDTA-01002: Asset Administration Shell Part 2 - API
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Optional
from enum import Enum
import copy

try:
    from .stegano_core import SteganoEngine, ZeroWidthCodec
except ImportError:
    from stegano_core import SteganoEngine, ZeroWidthCodec


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION AND DATA TYPES
# ═══════════════════════════════════════════════════════════════════════════════

class InjectionTarget(Enum):
    """Categories of AAS fields that can receive watermarks."""
    DESCRIPTION = "description"           # LangString in description arrays
    STRING_PROPERTY = "string_property"   # Property with xs:string valueType
    MULTI_LANG_PROPERTY = "multi_lang"    # MultiLanguageProperty values
    BLOB_CONTENT_TYPE = "blob_content"    # Blob contentType field (careful!)


@dataclass
class InjectionPoint:
    """
    Records a single location where a watermark was injected.
    
    This provides an audit trail of exactly where watermarks were placed,
    useful for debugging and for generating detailed injection reports.
    
    Attributes:
        path: JSON path to the injected field (e.g., "submodels[0].description[0].text")
        target_type: Category of the injection target
        original_value: The text value before injection
        field_key: The dictionary key that was modified
    """
    path: str
    target_type: InjectionTarget
    original_value: str
    field_key: str


@dataclass
class InjectionReport:
    """
    Comprehensive report of a watermark injection operation.
    
    This report provides full visibility into what was modified, enabling
    both verification and potential rollback of watermark operations.
    
    Attributes:
        recipient_id: The payload that was embedded (e.g., "Supplier-B")
        total_injections: Count of fields that received the watermark
        injection_points: Detailed list of each injection location
        skipped_count: Fields that were skipped (already watermarked, etc.)
        warnings: Non-fatal issues encountered during injection
        modified_data: Deep-copied AAS data when in_place=False, otherwise None
    """
    recipient_id: str
    total_injections: int
    injection_points: List[InjectionPoint] = field(default_factory=list)
    skipped_count: int = 0
    warnings: List[str] = field(default_factory=list)
    modified_data: Optional[Dict[str, Any]] = None
    
    @property
    def success(self) -> bool:
        """Returns True if at least one injection was successful."""
        return self.total_injections > 0
    
    def summary(self) -> str:
        """Human-readable summary of the injection operation."""
        lines = [
            f"═══════════════════════════════════════════════════════════",
            f"  Injection Report: '{self.recipient_id}'",
            f"═══════════════════════════════════════════════════════════",
            f"  ✓ Successfully watermarked: {self.total_injections} field(s)",
            f"  ○ Skipped (already marked):  {self.skipped_count} field(s)",
        ]
        
        if self.warnings:
            lines.append(f"  ⚠ Warnings: {len(self.warnings)}")
            for w in self.warnings[:3]:  # Show max 3 warnings
                lines.append(f"    - {w}")
        
        if self.injection_points:
            lines.append(f"\n  Injection Locations:")
            for ip in self.injection_points[:10]:  # Show max 10 locations
                short_path = ip.path[-50:] if len(ip.path) > 50 else ip.path
                lines.append(f"    • {ip.target_type.value}: ...{short_path}")
        
        lines.append(f"═══════════════════════════════════════════════════════════")
        return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN INJECTOR CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class AASInjector:
    """
    Intelligent watermark injection engine for Asset Administration Shells.
    
    This class implements the AAS-aware traversal logic needed to find and
    mark suitable text fields within an AAS structure. It respects the AAS
    metamodel and targets fields that are both useful for watermarking and
    unlikely to cause processing issues.
    
    Design Philosophy:
        - Non-destructive: Original data semantics are preserved
        - Idempotent: Re-injection is safe (duplicates are skipped)
        - Comprehensive: All suitable fields are marked (defense in depth)
        - Auditable: Every modification is recorded
    
    Example:
        >>> from aas_stegano_trace import SteganoEngine, AASInjector
        >>> import json
        >>> 
        >>> # Load an AAS file
        >>> with open('motor_aas.json', 'r') as f:
        ...     aas_data = json.load(f)
        >>> 
        >>> # Create injector and mark for specific recipient
        >>> engine = SteganoEngine()
        >>> injector = AASInjector(engine)
        >>> report = injector.inject(aas_data, "Supplier-XYZ")
        >>> 
        >>> print(report.summary())
        >>> 
        >>> # Save the watermarked AAS (CRITICAL: ensure_ascii=False!)
        >>> with open('motor_aas_supplier_xyz.json', 'w', encoding='utf-8') as f:
        ...     json.dump(aas_data, f, indent=2, ensure_ascii=False)
    
    Thread Safety:
        The inject() method modifies the input data in-place. For thread-safe
        operation, pass a deep copy of the AAS data.
    """
    
    def __init__(self, engine: SteganoEngine = None):
        """
        Initialize the AAS injector.
        
        Args:
            engine: SteganoEngine instance for encoding. Uses default if None.
        """
        self._engine = engine or SteganoEngine()
        
        # Configuration for which field types to target
        self._target_descriptions = True
        self._target_string_properties = True
        self._target_multilang_properties = True
    
    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────────────────────────
    
    def inject(
        self, 
        aas_data: Dict[str, Any], 
        recipient_id: str,
        in_place: bool = True
    ) -> InjectionReport:
        """
        Inject a forensic watermark throughout an AAS data structure.
        
        This method traverses the entire AAS structure and embeds the
        recipient_id into all suitable text fields. The watermark is
        invisible but can later be extracted to identify the recipient.
        
        Args:
            aas_data: Parsed AAS JSON structure (dict). Modified in-place
                     unless in_place=False.
            recipient_id: The identifier to embed. This will be recovered
                         during forensic analysis. Should be unique per
                         recipient (e.g., company name, contract ID).
            in_place: If True (default), modifies aas_data directly.
                     If False, works on a deep copy; the modified copy
                     is available as report.modified_data.
        
        Returns:
            InjectionReport with details of all modifications made.
        
        Raises:
            ValueError: If recipient_id is empty or aas_data is None.
        
        Note:
            When saving the result to JSON, you MUST use ensure_ascii=False
            to preserve the Unicode zero-width characters:
            
            json.dump(aas_data, f, indent=2, ensure_ascii=False)
        """
        if not recipient_id:
            raise ValueError("recipient_id cannot be empty")
        if aas_data is None:
            raise ValueError("aas_data cannot be None")
        
        # Work on copy if requested
        target_data = aas_data if in_place else copy.deepcopy(aas_data)
        
        # Initialize tracking for this injection run
        report = InjectionReport(recipient_id=recipient_id, total_injections=0)
        
        # Encode the payload once (will be reused for all injections)
        encoded = self._engine.encode(recipient_id)
        watermark = encoded.invisible_payload
        
        # Recursive traversal with path tracking
        self._traverse_and_inject(
            node=target_data,
            path="root",
            watermark=watermark,
            report=report
        )
        
        if not in_place:
            report.modified_data = target_data

        return report
    
    def configure(
        self,
        target_descriptions: bool = True,
        target_string_properties: bool = True,
        target_multilang_properties: bool = True
    ) -> 'AASInjector':
        """
        Configure which AAS field types should receive watermarks.
        
        This allows fine-grained control over injection targets. You might
        want to disable certain categories if they cause issues with
        specific AAS processing tools.
        
        Args:
            target_descriptions: Inject into description[].text fields
            target_string_properties: Inject into Property values (xs:string)
            target_multilang_properties: Inject into MultiLanguageProperty
        
        Returns:
            self (for method chaining)
        """
        self._target_descriptions = target_descriptions
        self._target_string_properties = target_string_properties
        self._target_multilang_properties = target_multilang_properties
        return self
    
    # ─────────────────────────────────────────────────────────────────────────
    # INTERNAL: Recursive Traversal
    # ─────────────────────────────────────────────────────────────────────────
    
    def _traverse_and_inject(
        self,
        node: Any,
        path: str,
        watermark: str,
        report: InjectionReport
    ) -> None:
        """
        Recursively traverse the AAS structure and inject watermarks.
        
        This method implements a depth-first traversal that understands
        the AAS data model structure. At each node, it checks for
        injectable fields and applies the watermark where appropriate.
        """
        if isinstance(node, dict):
            # Check for description array (common in AAS elements)
            if self._target_descriptions:
                self._inject_descriptions(node, path, watermark, report)
            
            # Check for Property with string value
            if self._target_string_properties:
                self._inject_string_property(node, path, watermark, report)
            
            # Check for MultiLanguageProperty
            if self._target_multilang_properties:
                self._inject_multilang_property(node, path, watermark, report)
            
            # Recurse into all child values
            for key, value in node.items():
                child_path = f"{path}.{key}"
                self._traverse_and_inject(value, child_path, watermark, report)
                
        elif isinstance(node, list):
            # Recurse into list elements with index tracking
            for idx, item in enumerate(node):
                child_path = f"{path}[{idx}]"
                self._traverse_and_inject(item, child_path, watermark, report)
    
    def _inject_descriptions(
        self,
        node: Dict,
        path: str,
        watermark: str,
        report: InjectionReport
    ) -> None:
        """
        Inject watermarks into AAS description fields.
        
        AAS elements can have a 'description' array containing LangString
        objects with 'language' and 'text' fields. We inject into each
        text field.
        
        Structure: { "description": [{"language": "en", "text": "..."}] }
        """
        if "description" not in node:
            return
        
        descriptions = node.get("description")
        if not isinstance(descriptions, list):
            return
        
        for idx, desc in enumerate(descriptions):
            if not isinstance(desc, dict):
                continue
            
            text_value = desc.get("text", "")
            if not text_value or not isinstance(text_value, str):
                continue
            
            # Skip if already watermarked
            if ZeroWidthCodec.MARKER in text_value:
                report.skipped_count += 1
                continue
            
            # Inject watermark at end of text
            desc["text"] = text_value + watermark
            
            # Record the injection
            injection_point = InjectionPoint(
                path=f"{path}.description[{idx}].text",
                target_type=InjectionTarget.DESCRIPTION,
                original_value=text_value,
                field_key="text"
            )
            report.injection_points.append(injection_point)
            report.total_injections += 1
    
    def _inject_string_property(
        self,
        node: Dict,
        path: str,
        watermark: str,
        report: InjectionReport
    ) -> None:
        """
        Inject watermarks into AAS Property elements with string values.
        
        Properties are SubmodelElements that hold typed values. We only
        target properties with valueType "xs:string" to avoid corrupting
        numerical or boolean data.
        
        Structure: {
            "modelType": "Property",
            "valueType": "xs:string",
            "value": "..."
        }
        """
        # Check if this is a string Property
        if node.get("modelType") != "Property":
            return
        if node.get("valueType") != "xs:string":
            return
        
        value = node.get("value")
        if not value or not isinstance(value, str):
            return
        
        # Skip if already watermarked
        if ZeroWidthCodec.MARKER in value:
            report.skipped_count += 1
            return
        
        # Inject watermark
        node["value"] = value + watermark
        
        # Record the injection
        injection_point = InjectionPoint(
            path=f"{path}.value",
            target_type=InjectionTarget.STRING_PROPERTY,
            original_value=value,
            field_key="value"
        )
        report.injection_points.append(injection_point)
        report.total_injections += 1
    
    def _inject_multilang_property(
        self,
        node: Dict,
        path: str,
        watermark: str,
        report: InjectionReport
    ) -> None:
        """
        Inject watermarks into MultiLanguageProperty elements.
        
        MultiLanguageProperty is similar to descriptions - it contains
        an array of LangStrings with language-specific values.
        
        Structure: {
            "modelType": "MultiLanguageProperty",
            "value": [{"language": "en", "text": "..."}]
        }
        """
        if node.get("modelType") != "MultiLanguageProperty":
            return
        
        values = node.get("value")
        if not isinstance(values, list):
            return
        
        for idx, lang_string in enumerate(values):
            if not isinstance(lang_string, dict):
                continue
            
            text_value = lang_string.get("text", "")
            if not text_value or not isinstance(text_value, str):
                continue
            
            # Skip if already watermarked
            if ZeroWidthCodec.MARKER in text_value:
                report.skipped_count += 1
                continue
            
            # Inject watermark
            lang_string["text"] = text_value + watermark
            
            # Record the injection
            injection_point = InjectionPoint(
                path=f"{path}.value[{idx}].text",
                target_type=InjectionTarget.MULTI_LANG_PROPERTY,
                original_value=text_value,
                field_key="text"
            )
            report.injection_points.append(injection_point)
            report.total_injections += 1
