"""
Test suite for LombokPDFA (Python port)
Comprehensive PDF/A compliance validation tests
"""

import pytest
from lombardpdfa_py import (
    PDFA, PDFAValidator, PDFAnalyzer, PDFAReport, PDFALevel,
    ComplianceRule, ComplianceIssue, FontInfo, MetadataInfo
)


# ============================================================================
# TEST FIXTURES
# ============================================================================

def create_minimal_pdf() -> bytes:
    """Create minimal valid PDF"""
    return b"""%%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT
/F1 12 Tf
100 700 Td
(Hello World) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000203 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
297
%%%%EOF"""


def create_pdf_with_javascript() -> bytes:
    """Create PDF with JavaScript"""
    return create_minimal_pdf() + b"\n/JavaScript (alert('test'))"


def create_pdf_with_unembedded_fonts() -> bytes:
    """Create PDF with unembedded fonts"""
    pdf = create_minimal_pdf()
    # Add reference to unembedded font
    return pdf + b"\n/Font << /F1 << /Type /Font >> >>"


def create_pdfa_compliant_pdf() -> bytes:
    """Create PDF/A compliant document"""
    return b"""%%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
203
%%%%EOF
x:xmpmeta PDF/A-1b"""


# ============================================================================
# TESTS
# ============================================================================

class TestComplianceIssue:
    """Tests for compliance issue representation"""
    
    def test_create_issue(self):
        issue = ComplianceIssue(
            rule=ComplianceRule.NO_JAVASCRIPT,
            severity="error",
            message="JavaScript detected",
            location="page 1",
            suggestion="Remove JavaScript"
        )
        assert issue.rule == ComplianceRule.NO_JAVASCRIPT
        assert issue.severity == "error"


class TestFontInfo:
    """Tests for font information"""
    
    def test_create_font_info(self):
        font = FontInfo(
            name="Arial",
            embedded=True,
            subset=False,
            type="TrueType"
        )
        assert font.name == "Arial"
        assert font.embedded is True
        assert font.type == "TrueType"


class TestMetadataInfo:
    """Tests for metadata information"""
    
    def test_create_metadata(self):
        metadata = MetadataInfo(
            title="Test Document",
            author="Test Author",
            xmp_present=True
        )
        assert metadata.title == "Test Document"
        assert metadata.author == "Test Author"
        assert metadata.xmp_present is True


class TestPDFAReport:
    """Tests for PDF/A report"""
    
    def test_create_report(self):
        report = PDFAReport(file_name="test.pdf")
        assert report.file_name == "test.pdf"
        assert report.is_compliant is False
        assert len(report.issues) == 0
    
    def test_add_issue(self):
        report = PDFAReport(file_name="test.pdf")
        report.add_issue(
            ComplianceRule.NO_JAVASCRIPT,
            "error",
            "JavaScript detected"
        )
        assert len(report.issues) == 1
        assert report.error_count() == 1
    
    def test_error_count(self):
        report = PDFAReport(file_name="test.pdf")
        report.add_issue(ComplianceRule.NO_JAVASCRIPT, "error", "Error 1")
        report.add_issue(ComplianceRule.NO_JAVASCRIPT, "error", "Error 2")
        assert report.error_count() == 2
    
    def test_warning_count(self):
        report = PDFAReport(file_name="test.pdf")
        report.add_issue(ComplianceRule.NO_FORMS, "warning", "Warning 1")
        assert report.warning_count() == 1
    
    def test_to_dict(self):
        report = PDFAReport(file_name="test.pdf", page_count=5, file_size=1000)
        report.add_issue(ComplianceRule.NO_JAVASCRIPT, "error", "JS detected")
        d = report.to_dict()
        
        assert d["fileName"] == "test.pdf"
        assert d["pageCount"] == 5
        assert d["fileSize"] == 1000
        assert len(d["issues"]) == 1
    
    def test_to_json(self):
        report = PDFAReport(file_name="test.pdf")
        json_str = report.to_json()
        
        assert "test.pdf" in json_str
        assert "{" in json_str


class TestPDFAnalyzer:
    """Tests for PDF analyzer"""
    
    def test_parse_header(self):
        pdf = create_minimal_pdf()
        analyzer = PDFAnalyzer()
        analyzer.content = pdf
        
        version = analyzer.parse_header()
        assert version == "1.4"
    
    def test_parse_header_invalid(self):
        analyzer = PDFAnalyzer()
        analyzer.content = b"Not a PDF"
        
        version = analyzer.parse_header()
        assert version is None
    
    def test_has_javascript_positive(self):
        analyzer = PDFAnalyzer()
        analyzer.content = create_pdf_with_javascript()
        
        assert analyzer.has_javascript() is True
    
    def test_has_javascript_negative(self):
        analyzer = PDFAnalyzer()
        analyzer.content = create_minimal_pdf()
        
        assert analyzer.has_javascript() is False
    
    def test_has_external_references_positive(self):
        analyzer = PDFAnalyzer()
        analyzer.content = b"%PDF-1.4\n/URI (http://example.com)\n%%EOF"
        
        assert analyzer.has_external_references() is True
    
    def test_has_external_references_negative_with_embedded_font(self):
        # Regression test: a regex precedence bug ("/URI.*http|ftp|file"
        # instead of "/URI.*(?:http|ftp|file)") previously matched the
        # bare word "file" anywhere - including inside "/FontFile2" for
        # a perfectly compliant embedded font - as an external reference.
        analyzer = PDFAnalyzer()
        analyzer.content = b"%PDF-1.4\n/FontFile2 5 0 R\n%%EOF"
        
        assert analyzer.has_external_references() is False
    
    def test_has_forms(self):
        analyzer = PDFAnalyzer()
        analyzer.content = b"/AcroForm <<>>"
        
        assert analyzer.has_forms() is True
    
    def test_has_transparency(self):
        analyzer = PDFAnalyzer()
        analyzer.content = b"/ca 0.5"
        
        assert analyzer.has_transparency() is True
    
    def test_has_3d_content(self):
        analyzer = PDFAnalyzer()
        analyzer.content = b"/3D <<"
        
        assert analyzer.has_3d_content() is True
    
    def test_has_multimedia(self):
        analyzer = PDFAnalyzer()
        analyzer.content = b"/Sound <<"
        
        assert analyzer.has_embedded_multimedia() is True
    
    def test_extract_fonts_empty(self):
        analyzer = PDFAnalyzer()
        analyzer.content = create_minimal_pdf()
        
        fonts = analyzer.extract_fonts()
        assert isinstance(fonts, list)
    
    def test_extract_metadata(self):
        analyzer = PDFAnalyzer()
        analyzer.content = create_minimal_pdf()
        
        metadata = analyzer.extract_metadata()
        assert isinstance(metadata, MetadataInfo)
    
    def test_count_pages(self):
        analyzer = PDFAnalyzer()
        analyzer.content = b"/Pages << /Count 3 >>"
        
        count = analyzer.count_pages()
        assert count == 3
    
    def test_detect_pdfa_1a(self):
        analyzer = PDFAnalyzer()
        analyzer.content = b"PDF/A-1a"
        
        level = analyzer.detect_pdf_a_declaration()
        assert level == PDFALevel.PDFA_1a
    
    def test_detect_pdfa_1b(self):
        analyzer = PDFAnalyzer()
        analyzer.content = b"PDF/A-1b"
        
        level = analyzer.detect_pdf_a_declaration()
        assert level == PDFALevel.PDFA_1b


class TestPDFAValidator:
    """Tests for PDF/A validator"""
    
    def test_create_validator(self):
        validator = PDFAValidator()
        assert validator.analyzer is not None
    
    def test_validate_minimal_pdf(self):
        pdf = create_minimal_pdf()
        validator = PDFAValidator()
        
        report = validator.validate(pdf)
        assert isinstance(report, PDFAReport)
    
    def test_validate_pdf_with_javascript(self):
        pdf = create_pdf_with_javascript()
        validator = PDFAValidator()
        
        report = validator.validate(pdf)
        # Should detect JavaScript issue
        errors = [i for i in report.issues if i.severity == "error"]
        assert len(errors) > 0
    
    def test_validate_pdfa_compliant(self):
        pdf = create_pdfa_compliant_pdf()
        validator = PDFAValidator()
        
        report = validator.validate(pdf)
        assert report.detected_level == PDFALevel.PDFA_1b


class TestPDFA:
    """Tests for main PDFA class"""
    
    def test_create_pdfa(self):
        pdfa = PDFA()
        assert pdfa.validator is not None
        assert pdfa.report is None
    
    def test_validate_pdf(self):
        pdf = create_minimal_pdf()
        pdfa = PDFA()
        
        result = pdfa.validate(pdf)
        assert result is pdfa  # Should return self for chaining
    
    def test_get_report(self):
        pdf = create_minimal_pdf()
        pdfa = PDFA()
        pdfa.validate(pdf)
        
        report = pdfa.getReport()
        assert isinstance(report, PDFAReport)
    
    def test_is_compliant_positive(self):
        pdf = create_pdfa_compliant_pdf()
        pdfa = PDFA()
        pdfa.validate(pdf)
        
        # Most compliant PDFs should pass basic checks
        assert isinstance(pdfa.isCompliant(), bool)
    
    def test_get_errors(self):
        pdf = create_pdf_with_javascript()
        pdfa = PDFA()
        pdfa.validate(pdf)
        
        errors = pdfa.getErrors()
        assert isinstance(errors, list)
    
    def test_get_warnings(self):
        pdf = create_minimal_pdf()
        pdfa = PDFA()
        pdfa.validate(pdf)
        
        warnings = pdfa.getWarnings()
        assert isinstance(warnings, list)
    
    def test_get_issue_count(self):
        pdf = create_pdf_with_javascript()
        pdfa = PDFA()
        pdfa.validate(pdf)
        
        error_count, warning_count = pdfa.getIssueCount()
        assert isinstance(error_count, int)
        assert isinstance(warning_count, int)
    
    def test_get_detected_level(self):
        pdf = create_pdfa_compliant_pdf()
        pdfa = PDFA()
        pdfa.validate(pdf)
        
        level = pdfa.getDetectedLevel()
        # Should be None or a valid PDFALevel
        assert level is None or isinstance(level, PDFALevel)
    
    def test_to_json(self):
        pdf = create_minimal_pdf()
        pdfa = PDFA()
        pdfa.validate(pdf)
        
        json_str = pdfa.toJSON()
        assert isinstance(json_str, str)
        assert "{" in json_str
    
    def test_to_dict(self):
        pdf = create_minimal_pdf()
        pdfa = PDFA()
        pdfa.validate(pdf)
        
        d = pdfa.toDict()
        assert isinstance(d, dict)


class TestComplianceRules:
    """Tests for compliance rule definitions"""
    
    def test_no_uncompressed_streams_rule(self):
        assert ComplianceRule.NO_UNCOMPRESSED_STREAMS.value == "no_uncompressed_streams"
    
    def test_all_fonts_embedded_rule(self):
        assert ComplianceRule.ALL_FONTS_EMBEDDED.value == "all_fonts_embedded"
    
    def test_no_javascript_rule(self):
        assert ComplianceRule.NO_JAVASCRIPT.value == "no_javascript"
    
    def test_no_forms_rule(self):
        assert ComplianceRule.NO_FORMS.value == "no_forms"


class TestPDFALevels:
    """Tests for PDF/A level definitions"""
    
    def test_pdfa_1a_level(self):
        assert PDFALevel.PDFA_1a.value == "PDF/A-1a"
    
    def test_pdfa_1b_level(self):
        assert PDFALevel.PDFA_1b.value == "PDF/A-1b"
    
    def test_pdfa_2a_level(self):
        assert PDFALevel.PDFA_2a.value == "PDF/A-2a"
    
    def test_pdfa_3b_level(self):
        assert PDFALevel.PDFA_3b.value == "PDF/A-3b"


class TestIntegration:
    """Integration tests"""
    
    def test_full_validation_workflow(self):
        pdf = create_minimal_pdf()
        pdfa = PDFA()
        
        # Validate
        pdfa.validate(pdf)
        
        # Check results
        report = pdfa.getReport()
        errors = pdfa.getErrors()
        warnings = pdfa.getWarnings()
        
        assert report is not None
        assert isinstance(errors, list)
        assert isinstance(warnings, list)
    
    def test_chainable_validate(self):
        pdf = create_minimal_pdf()
        
        report = PDFA().validate(pdf).getReport()
        assert isinstance(report, PDFAReport)
    
    def test_compliance_check_workflow(self):
        pdf = create_pdfa_compliant_pdf()
        pdfa = PDFA()
        
        pdfa.validate(pdf)
        
        # Get compliance status
        is_compliant = pdfa.isCompliant()
        level = pdfa.getDetectedLevel()
        
        assert isinstance(is_compliant, bool)
        assert level is None or isinstance(level, PDFALevel)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
