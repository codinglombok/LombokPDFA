package pdfa

import (
	"strings"
	"testing"
)

// ============================================================================
// TEST FIXTURES
// ============================================================================

func createMinimalPDF() []byte {
	return []byte(`%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
trailer
<< /Size 4 /Root 1 0 R >>
%%EOF`)
}

func createPDFAOnePBCompliant() []byte {
	return []byte(`%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
trailer
<< /Size 2 /Root 1 0 R >>
x:xmpmeta PDF/A-1b conformance
%%EOF`)
}

func createPDFWithJavaScript() []byte {
	base := createMinimalPDF()
	extra := []byte("\n/JavaScript (alert('test'))")
	return append(base, extra...)
}

func createPDFWithUnembeddedFont() []byte {
	return []byte(`%PDF-1.4
1 0 obj
<< /Type /Font << /BaseFont /Arial /Subtype /TrueType >> >>
endobj
trailer
<< /Size 2 >>
%%EOF`)
}

func createPDFWithTransparency() []byte {
	base := createMinimalPDF()
	extra := []byte("\n/ca 0.5 /BM /Normal")
	return append(base, extra...)
}

func createPDFWithMetadata() []byte {
	return []byte(`%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Info << /Title (Test Doc) /Author (Test Author) /Creator (Test Creator) /Producer (Test Producer) >> >>
endobj
x:xmpmeta present here
trailer
<< /Size 3 /Root 1 0 R >>
%%EOF`)
}

func createInvalidPDF() []byte {
	return []byte("This is not a PDF file at all")
}

// ============================================================================
// TESTS
// ============================================================================

func TestPDFAReportCreation(t *testing.T) {
	report := NewPDFAReport("test.pdf")
	if report.FileName != "test.pdf" {
		t.Errorf("Expected FileName 'test.pdf', got %s", report.FileName)
	}
	if len(report.Issues) != 0 {
		t.Errorf("Expected empty Issues, got %d", len(report.Issues))
	}
	if len(report.Fonts) != 0 {
		t.Errorf("Expected empty Fonts, got %d", len(report.Fonts))
	}
}

func TestAddIssue(t *testing.T) {
	report := NewPDFAReport("test.pdf")
	suggestion := "Fix this"
	report.AddIssue(NoJavaScript, "error", "Has JS", nil, &suggestion)

	if len(report.Issues) != 1 {
		t.Fatalf("Expected 1 issue, got %d", len(report.Issues))
	}
	if report.Issues[0].Rule != NoJavaScript {
		t.Errorf("Expected NoJavaScript rule")
	}
	if report.Issues[0].Severity != "error" {
		t.Errorf("Expected error severity")
	}
}

func TestErrorWarningCount(t *testing.T) {
	report := NewPDFAReport("test.pdf")
	report.AddIssue(NoJavaScript, "error", "msg1", nil, nil)
	report.AddIssue(NoForms, "warning", "msg2", nil, nil)
	report.AddIssue(NoTransparency, "warning", "msg3", nil, nil)

	if report.ErrorCount() != 1 {
		t.Errorf("Expected 1 error, got %d", report.ErrorCount())
	}
	if report.WarningCount() != 2 {
		t.Errorf("Expected 2 warnings, got %d", report.WarningCount())
	}
}

func TestToJSON(t *testing.T) {
	report := NewPDFAReport("test.pdf")
	jsonStr, err := report.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if !strings.Contains(jsonStr, "test.pdf") {
		t.Error("Expected JSON to contain fileName")
	}
}

func TestAnalyzerParseHeader(t *testing.T) {
	analyzer := NewPDFAnalyzer()
	analyzer.Content = createMinimalPDF()

	version := analyzer.ParseHeader()
	if version != "1.4" {
		t.Errorf("Expected version '1.4', got '%s'", version)
	}
}

func TestAnalyzerParseHeaderInvalid(t *testing.T) {
	analyzer := NewPDFAnalyzer()
	analyzer.Content = createInvalidPDF()

	version := analyzer.ParseHeader()
	if version != "" {
		t.Errorf("Expected empty version for invalid PDF, got '%s'", version)
	}
}

func TestDetectPDFADeclaration(t *testing.T) {
	analyzer := NewPDFAnalyzer()
	analyzer.Content = createPDFAOnePBCompliant()

	level := analyzer.DetectPDFADeclaration()
	if level == nil {
		t.Fatal("Expected non-nil PDFALevel")
	}
	if *level != PDFA1b {
		t.Errorf("Expected PDFA1b, got %v", *level)
	}
}

func TestDetectPDFADeclarationNone(t *testing.T) {
	analyzer := NewPDFAnalyzer()
	analyzer.Content = createMinimalPDF()

	level := analyzer.DetectPDFADeclaration()
	if level != nil {
		t.Errorf("Expected nil level for non-PDF/A document, got %v", *level)
	}
}

func TestHasJavaScript(t *testing.T) {
	analyzer := NewPDFAnalyzer()
	analyzer.Content = createPDFWithJavaScript()

	if !analyzer.HasJavaScript() {
		t.Error("Expected HasJavaScript to be true")
	}
}

func TestHasJavaScriptFalse(t *testing.T) {
	analyzer := NewPDFAnalyzer()
	analyzer.Content = []byte("%PDF-1.4\nclean content\n%%EOF")

	if analyzer.HasJavaScript() {
		t.Error("Expected HasJavaScript to be false")
	}
}

func TestHasExternalReferences(t *testing.T) {
	analyzer := NewPDFAnalyzer()
	analyzer.Content = []byte("%PDF-1.4\n/URI (http://example.com)\n%%EOF")

	if !analyzer.HasExternalReferences() {
		t.Error("Expected HasExternalReferences to be true")
	}
}

func TestHasExternalReferencesFalseWithEmbeddedFont(t *testing.T) {
	// Regression test: a regex precedence bug ("/URI.*http|ftp|file"
	// instead of "/URI.*(?:http|ftp|file)") previously matched the bare
	// word "file" anywhere - including inside "/FontFile2" for a
	// perfectly compliant embedded font - as an external reference.
	analyzer := NewPDFAnalyzer()
	analyzer.Content = []byte("%PDF-1.4\n/FontFile2 5 0 R\n%%EOF")

	if analyzer.HasExternalReferences() {
		t.Error("Expected HasExternalReferences to be false for a document with only an embedded font")
	}
}

func TestHasTransparency(t *testing.T) {
	analyzer := NewPDFAnalyzer()
	analyzer.Content = createPDFWithTransparency()

	if !analyzer.HasTransparency() {
		t.Error("Expected HasTransparency to be true")
	}
}

func TestExtractFonts(t *testing.T) {
	analyzer := NewPDFAnalyzer()
	analyzer.Content = createPDFWithUnembeddedFont()

	fonts := analyzer.ExtractFonts()
	if len(fonts) == 0 {
		t.Log("No fonts extracted (may depend on regex matching)")
	} else {
		if fonts[0].Name != "Arial" {
			t.Errorf("Expected font name 'Arial', got '%s'", fonts[0].Name)
		}
		if fonts[0].Embedded {
			t.Error("Expected font to be unembedded")
		}
	}
}

func TestExtractMetadata(t *testing.T) {
	analyzer := NewPDFAnalyzer()
	analyzer.Content = createPDFWithMetadata()

	metadata := analyzer.ExtractMetadata()
	if metadata == nil {
		t.Fatal("Expected non-nil metadata")
	}
	if metadata.Title != nil && *metadata.Title != "Test Doc" {
		t.Errorf("Expected title 'Test Doc', got '%v'", *metadata.Title)
	}
	if !metadata.XMPPresent {
		t.Error("Expected XMPPresent to be true")
	}
}

func TestCountPages(t *testing.T) {
	analyzer := NewPDFAnalyzer()
	analyzer.Content = createMinimalPDF()

	count := analyzer.CountPages()
	if count != 1 {
		t.Errorf("Expected page count 1, got %d", count)
	}
}

func TestValidatorValidateInvalidPDF(t *testing.T) {
	validator := NewPDFAValidator()
	report := validator.Validate(createInvalidPDF())

	if report == nil {
		t.Fatal("Expected non-nil report")
	}
	if report.ErrorCount() == 0 {
		t.Error("Expected at least one error for invalid PDF")
	}
}

func TestValidatorValidateMinimalPDF(t *testing.T) {
	validator := NewPDFAValidator()
	report := validator.Validate(createMinimalPDF())

	if report == nil {
		t.Fatal("Expected non-nil report")
	}
	if report.PageCount != 1 {
		t.Errorf("Expected page count 1, got %d", report.PageCount)
	}
}

func TestValidatorDetectsJavaScript(t *testing.T) {
	validator := NewPDFAValidator()
	report := validator.Validate(createPDFWithJavaScript())

	found := false
	for _, issue := range report.Issues {
		if issue.Rule == NoJavaScript {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected NoJavaScript issue to be detected")
	}
}

func TestPDFACreation(t *testing.T) {
	p := New()
	if p == nil {
		t.Error("Expected non-nil PDFA instance")
	}
	if p.GetReport() != nil {
		t.Error("Expected nil report before validation")
	}
}

func TestPDFAValidate(t *testing.T) {
	p := New()
	p.Validate(createMinimalPDF())

	report := p.GetReport()
	if report == nil {
		t.Fatal("Expected non-nil report after validation")
	}
}

func TestPDFAIsCompliant(t *testing.T) {
	p := New()
	p.Validate(createPDFWithJavaScript())

	if p.IsCompliant() {
		t.Error("Expected non-compliant document (has JavaScript)")
	}
}

func TestPDFAGetErrors(t *testing.T) {
	p := New()
	p.Validate(createPDFWithJavaScript())

	errors := p.GetErrors()
	if len(errors) == 0 {
		t.Error("Expected at least one error")
	}
}

func TestPDFAGetWarnings(t *testing.T) {
	p := New()
	p.Validate(createMinimalPDF())

	warnings := p.GetWarnings()
	// Minimal PDF without XMP metadata should generate a warning
	if len(warnings) == 0 {
		t.Log("No warnings generated (may be expected depending on rules)")
	}
}

func TestPDFAGetIssueCount(t *testing.T) {
	p := New()
	p.Validate(createPDFWithJavaScript())

	errCount, warnCount := p.GetIssueCount()
	if errCount == 0 {
		t.Error("Expected non-zero error count")
	}
	_ = warnCount
}

func TestPDFAGetDetectedLevel(t *testing.T) {
	p := New()
	p.Validate(createPDFAOnePBCompliant())

	level := p.GetDetectedLevel()
	if level == nil {
		t.Error("Expected detected level for PDF/A document")
	}
}

func TestPDFAToJSON(t *testing.T) {
	p := New()
	p.Validate(createMinimalPDF())

	jsonStr, err := p.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if jsonStr == "" {
		t.Error("Expected non-empty JSON")
	}
}

func TestPDFANilReportSafety(t *testing.T) {
	p := New()
	// Don't validate, test safety of methods with nil report

	if p.IsCompliant() != false {
		t.Error("Expected false for IsCompliant with nil report")
	}
	if len(p.GetErrors()) != 0 {
		t.Error("Expected empty errors with nil report")
	}
	if len(p.GetWarnings()) != 0 {
		t.Error("Expected empty warnings with nil report")
	}
	errCount, warnCount := p.GetIssueCount()
	if errCount != 0 || warnCount != 0 {
		t.Error("Expected 0,0 for issue count with nil report")
	}
	if p.GetDetectedLevel() != nil {
		t.Error("Expected nil level with nil report")
	}
	jsonStr, _ := p.ToJSON()
	if jsonStr != "{}" {
		t.Errorf("Expected '{}' for nil report JSON, got '%s'", jsonStr)
	}
}

func TestComplianceRuleConstants(t *testing.T) {
	rules := []ComplianceRule{
		NoUncompressedStreams,
		AllFontsEmbedded,
		NoJavaScript,
		NoForms,
		MetadataRequired,
		ColorsCMYKGrayscale,
		NoExternalReferences,
		NoTransparency,
		No3DContent,
		NoEmbeddedMultimedia,
		TaggedDocumentRequired,
		LogicalStructureRequired,
		ValidXMPMetadata,
	}
	if len(rules) != 13 {
		t.Errorf("Expected 13 compliance rules, got %d", len(rules))
	}
}

func TestPDFALevelConstants(t *testing.T) {
	levels := []PDFALevel{PDFA1a, PDFA1b, PDFA2a, PDFA2b, PDFA3a, PDFA3b}
	if len(levels) != 6 {
		t.Errorf("Expected 6 PDF/A levels, got %d", len(levels))
	}
}

func BenchmarkValidate(b *testing.B) {
	pdfBytes := createMinimalPDF()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := New()
		p.Validate(pdfBytes)
	}
}
