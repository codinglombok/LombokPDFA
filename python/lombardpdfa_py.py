"""
LombokPDFA - Python Port (v0.9.0-alpha)
PDF/A compliance validator (ISO 19005 standard).
Supports PDF/A-1, PDF/A-2, PDF/A-3 validation.
Apache 2.0 License | Multi-language support
"""

import re
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from datetime import datetime


# ============================================================================
# PDFA CONSTANTS
# ============================================================================

class PDFALevel(Enum):
    """PDF/A compliance levels"""
    PDFA_1a = "PDF/A-1a"  # 2005, Level A (tagged)
    PDFA_1b = "PDF/A-1b"  # 2005, Level B (basic)
    PDFA_2a = "PDF/A-2a"  # 2011, Level A (enhanced)
    PDFA_2b = "PDF/A-2b"  # 2011, Level B
    PDFA_3a = "PDF/A-3a"  # 2012, Level A (packages)
    PDFA_3b = "PDF/A-3b"  # 2012, Level B


class ComplianceRule(Enum):
    """PDF/A compliance rules"""
    NO_UNCOMPRESSED_STREAMS = "no_uncompressed_streams"
    ALL_FONTS_EMBEDDED = "all_fonts_embedded"
    NO_JAVASCRIPT = "no_javascript"
    NO_FORMS = "no_forms"
    METADATA_REQUIRED = "metadata_required"
    COLORS_MUST_BE_CMYK_OR_GRAYSCALE = "colors_cmyk_grayscale"
    NO_EXTERNAL_REFERENCES = "no_external_refs"
    NO_TRANSPARENCY = "no_transparency"
    NO_3D_CONTENT = "no_3d_content"
    NO_EMBEDDED_MULTIMEDIA = "no_multimedia"
    TAGGED_DOCUMENT_REQUIRED = "tagged_document"
    LOGICAL_STRUCTURE_REQUIRED = "logical_structure"
    VALID_XMP_METADATA = "valid_xmp_metadata"


# ============================================================================
# PDF/A DATA STRUCTURES
# ============================================================================

@dataclass
class ComplianceIssue:
    """PDF/A compliance issue"""
    rule: ComplianceRule
    severity: str  # "error" or "warning"
    message: str
    location: Optional[str] = None  # e.g., "page 3, object 42"
    suggestion: Optional[str] = None


@dataclass
class FontInfo:
    """Font information"""
    name: str
    embedded: bool
    subset: bool
    type: str  # Type1, TrueType, CIDFont, etc.


@dataclass
class MetadataInfo:
    """PDF metadata"""
    title: Optional[str] = None
    author: Optional[str] = None
    subject: Optional[str] = None
    creator: Optional[str] = None
    producer: Optional[str] = None
    creation_date: Optional[str] = None
    modification_date: Optional[str] = None
    xmp_present: bool = False


@dataclass
class PDFAReport:
    """PDF/A compliance report"""
    file_name: str
    detected_level: Optional[PDFALevel] = None
    is_compliant: bool = False
    issues: List[ComplianceIssue] = None
    fonts: List[FontInfo] = None
    metadata: Optional[MetadataInfo] = None
    page_count: int = 0
    file_size: int = 0
    analysis_timestamp: str = ""
    
    def __post_init__(self):
        if self.issues is None:
            self.issues = []
        if self.fonts is None:
            self.fonts = []
    
    def add_issue(self, rule: ComplianceRule, severity: str, message: str,
                  location: str = None, suggestion: str = None):
        """Add a compliance issue"""
        self.issues.append(ComplianceIssue(
            rule=rule,
            severity=severity,
            message=message,
            location=location,
            suggestion=suggestion
        ))
    
    def error_count(self) -> int:
        """Count errors"""
        return sum(1 for issue in self.issues if issue.severity == "error")
    
    def warning_count(self) -> int:
        """Count warnings"""
        return sum(1 for issue in self.issues if issue.severity == "warning")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "fileName": self.file_name,
            "detectedLevel": self.detected_level.value if self.detected_level else None,
            "isCompliant": self.is_compliant,
            "errorCount": self.error_count(),
            "warningCount": self.warning_count(),
            "pageCount": self.page_count,
            "fileSize": self.file_size,
            "analysisTimestamp": self.analysis_timestamp,
            "issues": [
                {
                    "rule": issue.rule.value,
                    "severity": issue.severity,
                    "message": issue.message,
                    "location": issue.location,
                    "suggestion": issue.suggestion
                }
                for issue in self.issues
            ],
            "fonts": [
                {
                    "name": font.name,
                    "embedded": font.embedded,
                    "subset": font.subset,
                    "type": font.type
                }
                for font in self.fonts
            ],
            "metadata": {
                "title": self.metadata.title,
                "author": self.metadata.author,
                "subject": self.metadata.subject,
                "creator": self.metadata.creator,
                "producer": self.metadata.producer,
                "creationDate": self.metadata.creation_date,
                "modificationDate": self.metadata.modification_date,
                "xmpPresent": self.metadata.xmp_present
            } if self.metadata else None
        }
    
    def to_json(self) -> str:
        """Convert to JSON"""
        return json.dumps(self.to_dict(), indent=2, default=str)


# ============================================================================
# PDF ANALYZER
# ============================================================================

class PDFAnalyzer:
    """Analyzes PDF structure"""
    
    def __init__(self):
        self.content: Optional[bytes] = None
        self.offset: int = 0
    
    def parse_header(self) -> Optional[str]:
        """Parse PDF version from header"""
        if not self.content:
            return None
        
        # Look for %PDF-X.Y in first 1024 bytes
        header = self.content[:1024].decode('latin1', errors='ignore')
        match = re.search(r'%PDF-(\d\.\d)', header)
        
        if match:
            return match.group(1)
        return None
    
    def detect_pdf_a_declaration(self) -> Optional[PDFALevel]:
        """Detect PDF/A level from document metadata"""
        if not self.content:
            return None
        
        content_str = self.content.decode('latin1', errors='ignore')
        
        # Look for PDF/A identification in XMP metadata
        if 'PDF/A-1a' in content_str or 'pdfaid:conformance>a<' in content_str:
            return PDFALevel.PDFA_1a
        elif 'PDF/A-1b' in content_str or 'pdfaid:conformance>b<' in content_str:
            return PDFALevel.PDFA_1b
        elif 'PDF/A-2a' in content_str:
            return PDFALevel.PDFA_2a
        elif 'PDF/A-2b' in content_str:
            return PDFALevel.PDFA_2b
        elif 'PDF/A-3a' in content_str:
            return PDFALevel.PDFA_3a
        elif 'PDF/A-3b' in content_str:
            return PDFALevel.PDFA_3b
        
        return None
    
    def has_javascript(self) -> bool:
        """Check for JavaScript"""
        if not self.content:
            return False
        
        content_str = self.content.decode('latin1', errors='ignore')
        
        # Look for JavaScript patterns
        return ('/JavaScript' in content_str or 
                '/AA' in content_str or  # Additional Actions
                '/AcroForm' in content_str)
    
    def has_forms(self) -> bool:
        """Check for AcroForms"""
        if not self.content:
            return False
        
        content_str = self.content.decode('latin1', errors='ignore')
        return '/AcroForm' in content_str
    
    def has_external_references(self) -> bool:
        """Check for external references"""
        if not self.content:
            return False
        
        content_str = self.content.decode('latin1', errors='ignore')
        
        # Look for common external reference patterns
        return bool(re.search(r'/URI.*(?:http|ftp|file)', content_str, re.IGNORECASE))
    
    def has_transparency(self) -> bool:
        """Check for transparency effects"""
        if not self.content:
            return False
        
        content_str = self.content.decode('latin1', errors='ignore')
        
        # Look for transparency-related operators
        return bool(re.search(r'/ca |/CA |/SMask|/BM ', content_str))
    
    def has_3d_content(self) -> bool:
        """Check for 3D content"""
        if not self.content:
            return False
        
        content_str = self.content.decode('latin1', errors='ignore')
        return '/3D' in content_str or '/RichMedia' in content_str
    
    def has_embedded_multimedia(self) -> bool:
        """Check for embedded multimedia"""
        if not self.content:
            return False
        
        content_str = self.content.decode('latin1', errors='ignore')
        
        # Look for multimedia patterns
        return bool(re.search(r'/EmbeddedFile|/Launch|/Sound|/Movie', content_str))
    
    def extract_fonts(self) -> List[FontInfo]:
        """Extract font information"""
        if not self.content:
            return []
        
        fonts = []
        content_str = self.content.decode('latin1', errors='ignore')
        
        # Find font references
        font_pattern = r'/Font.*?<<(.*?)>>'
        for match in re.finditer(font_pattern, content_str, re.DOTALL):
            font_block = match.group(1)
            
            # Extract font name
            name_match = re.search(r'/BaseFont\s*/(\w+)', font_block)
            name = name_match.group(1) if name_match else "Unknown"
            
            # Check if embedded
            embedded = '/FontFile' in font_block
            
            # Check if subset
            subset = '+' in name
            
            # Detect font type
            font_type = "Type1"  # Default
            if '/TrueType' in font_block:
                font_type = "TrueType"
            elif '/CIDFont' in font_block:
                font_type = "CIDFont"
            
            fonts.append(FontInfo(
                name=name,
                embedded=embedded,
                subset=subset,
                type=font_type
            ))
        
        return fonts
    
    def extract_metadata(self) -> MetadataInfo:
        """Extract metadata"""
        if not self.content:
            return MetadataInfo()
        
        content_str = self.content.decode('latin1', errors='ignore')
        metadata = MetadataInfo()
        
        # Extract Info dictionary fields
        info_pattern = r'/Info.*?<<(.*?)>>'
        info_match = re.search(info_pattern, content_str, re.DOTALL)
        
        if info_match:
            info_block = info_match.group(1)
            
            # Extract title
            title_match = re.search(r'/Title\s*\((.*?)\)', info_block)
            if title_match:
                metadata.title = title_match.group(1)
            
            # Extract author
            author_match = re.search(r'/Author\s*\((.*?)\)', info_block)
            if author_match:
                metadata.author = author_match.group(1)
            
            # Extract subject
            subject_match = re.search(r'/Subject\s*\((.*?)\)', info_block)
            if subject_match:
                metadata.subject = subject_match.group(1)
            
            # Extract creator
            creator_match = re.search(r'/Creator\s*\((.*?)\)', info_block)
            if creator_match:
                metadata.creator = creator_match.group(1)
            
            # Extract producer
            producer_match = re.search(r'/Producer\s*\((.*?)\)', info_block)
            if producer_match:
                metadata.producer = producer_match.group(1)
        
        # Check for XMP metadata
        metadata.xmp_present = 'x:xmpmeta' in content_str or '<xmpmeta' in content_str
        
        return metadata
    
    def count_pages(self) -> int:
        """Count pages in PDF"""
        if not self.content:
            return 0
        
        content_str = self.content.decode('latin1', errors='ignore')
        
        # Look for /Pages catalog
        pages_match = re.search(r'/Pages.*?<<(.*?)>>', content_str, re.DOTALL)
        if pages_match:
            pages_block = pages_match.group(1)
            count_match = re.search(r'/Count\s+(\d+)', pages_block)
            if count_match:
                return int(count_match.group(1))
        
        return 0


# ============================================================================
# PDF/A VALIDATOR
# ============================================================================

class PDFAValidator:
    """Validates PDF/A compliance"""
    
    def __init__(self):
        self.analyzer = PDFAnalyzer()
    
    def validate(self, pdf_bytes: bytes, target_level: Optional[PDFALevel] = None) -> PDFAReport:
        """Validate PDF/A compliance"""
        report = PDFAReport(
            file_name="document.pdf",
            page_count=0,
            file_size=len(pdf_bytes),
            analysis_timestamp=datetime.now().isoformat()
        )
        
        # Set up analyzer
        self.analyzer.content = pdf_bytes
        
        # Check if it's a valid PDF
        pdf_version = self.analyzer.parse_header()
        if not pdf_version:
            report.add_issue(
                ComplianceRule.METADATA_REQUIRED,
                "error",
                "Not a valid PDF file",
                suggestion="Ensure file is a valid PDF document"
            )
            return report
        
        # Detect PDF/A level
        detected_level = self.analyzer.detect_pdf_a_declaration()
        report.detected_level = detected_level
        
        # Extract metadata
        report.metadata = self.analyzer.extract_metadata()
        report.page_count = self.analyzer.count_pages()
        
        # Extract fonts
        report.fonts = self.analyzer.extract_fonts()
        
        # Run compliance checks
        self._check_uncompressed_streams(report)
        self._check_fonts_embedded(report)
        self._check_no_javascript(report)
        self._check_no_forms(report)
        self._check_metadata(report)
        self._check_external_references(report)
        self._check_transparency(report)
        self._check_3d_content(report)
        self._check_multimedia(report)
        
        # Determine overall compliance
        error_count = report.error_count()
        report.is_compliant = error_count == 0
        
        return report
    
    def _check_uncompressed_streams(self, report: PDFAReport):
        """Check for uncompressed streams (not allowed in PDF/A)"""
        if not self.analyzer.content:
            return
        
        content_str = self.analyzer.content.decode('latin1', errors='ignore')
        
        # Look for stream objects without FlateDecode filter
        if 'stream' in content_str:
            # Simplified check - look for streams without /Filter
            unfiltered_streams = len(re.findall(r'stream\n(?!.*?/Filter)', content_str))
            if unfiltered_streams > 0:
                report.add_issue(
                    ComplianceRule.NO_UNCOMPRESSED_STREAMS,
                    "error",
                    f"Found {unfiltered_streams} uncompressed stream(s)",
                    suggestion="Compress all streams using FlateDecode or other supported filter"
                )
    
    def _check_fonts_embedded(self, report: PDFAReport):
        """Check that all fonts are embedded"""
        unembedded = [f for f in report.fonts if not f.embedded]
        if unembedded:
            font_names = ", ".join([f.name for f in unembedded])
            report.add_issue(
                ComplianceRule.ALL_FONTS_EMBEDDED,
                "error",
                f"Found unembedded fonts: {font_names}",
                suggestion="Embed all fonts in the PDF file"
            )
    
    def _check_no_javascript(self, report: PDFAReport):
        """Check for JavaScript"""
        if self.analyzer.has_javascript():
            report.add_issue(
                ComplianceRule.NO_JAVASCRIPT,
                "error",
                "PDF contains JavaScript",
                suggestion="Remove all JavaScript from the document"
            )
    
    def _check_no_forms(self, report: PDFAReport):
        """Check for AcroForms"""
        if self.analyzer.has_forms():
            report.add_issue(
                ComplianceRule.NO_FORMS,
                "warning",
                "PDF contains AcroForms",
                suggestion="Consider removing forms or using PDF/A-3 for form support"
            )
    
    def _check_metadata(self, report: PDFAReport):
        """Check for required metadata"""
        if not report.metadata or not report.metadata.xmp_present:
            report.add_issue(
                ComplianceRule.VALID_XMP_METADATA,
                "warning",
                "XMP metadata not found",
                suggestion="Add XMP metadata with PDF/A identification"
            )
    
    def _check_external_references(self, report: PDFAReport):
        """Check for external references"""
        if self.analyzer.has_external_references():
            report.add_issue(
                ComplianceRule.NO_EXTERNAL_REFERENCES,
                "error",
                "PDF contains external references (URLs, etc.)",
                suggestion="Remove or convert external references to internal links"
            )
    
    def _check_transparency(self, report: PDFAReport):
        """Check for transparency"""
        if self.analyzer.has_transparency():
            report.add_issue(
                ComplianceRule.NO_TRANSPARENCY,
                "warning",
                "PDF contains transparency effects",
                suggestion="Remove transparency or flatten images"
            )
    
    def _check_3d_content(self, report: PDFAReport):
        """Check for 3D content"""
        if self.analyzer.has_3d_content():
            report.add_issue(
                ComplianceRule.NO_3D_CONTENT,
                "error",
                "PDF contains 3D content",
                suggestion="Remove 3D content (not supported in PDF/A)"
            )
    
    def _check_multimedia(self, report: PDFAReport):
        """Check for embedded multimedia"""
        if self.analyzer.has_embedded_multimedia():
            report.add_issue(
                ComplianceRule.NO_EMBEDDED_MULTIMEDIA,
                "error",
                "PDF contains embedded multimedia",
                suggestion="Remove or extract multimedia content"
            )


# ============================================================================
# MAIN CLASS
# ============================================================================

class PDFA:
    """Main PDF/A validator class"""
    
    def __init__(self):
        self.validator = PDFAValidator()
        self.report: Optional[PDFAReport] = None
    
    def validate(self, pdf_source, target_level: Optional[PDFALevel] = None) -> 'PDFA':
        """Validate PDF/A compliance"""
        if isinstance(pdf_source, str):
            with open(pdf_source, 'rb') as f:
                pdf_bytes = f.read()
        else:
            pdf_bytes = pdf_source
        
        self.report = self.validator.validate(pdf_bytes, target_level)
        return self
    
    def getReport(self) -> Optional[PDFAReport]:
        """Get the validation report"""
        return self.report
    
    def isCompliant(self) -> bool:
        """Check if document is compliant"""
        if not self.report:
            return False
        return self.report.is_compliant
    
    def getErrors(self) -> List[ComplianceIssue]:
        """Get all errors"""
        if not self.report:
            return []
        return [issue for issue in self.report.issues if issue.severity == "error"]
    
    def getWarnings(self) -> List[ComplianceIssue]:
        """Get all warnings"""
        if not self.report:
            return []
        return [issue for issue in self.report.issues if issue.severity == "warning"]
    
    def getIssueCount(self) -> Tuple[int, int]:
        """Get error and warning counts"""
        if not self.report:
            return (0, 0)
        return (self.report.error_count(), self.report.warning_count())
    
    def getDetectedLevel(self) -> Optional[PDFALevel]:
        """Get detected PDF/A level"""
        if not self.report:
            return None
        return self.report.detected_level
    
    def toJSON(self) -> str:
        """Export report to JSON"""
        if not self.report:
            return "{}"
        return self.report.to_json()
    
    def toDict(self) -> Dict[str, Any]:
        """Export report to dictionary"""
        if not self.report:
            return {}
        return self.report.to_dict()
