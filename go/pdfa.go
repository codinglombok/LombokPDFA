// Package pdfa implements LombokPDFA - Go Port (v0.9.0-alpha)
// PDF/A compliance validator (ISO 19005 standard).
// Supports PDF/A-1, PDF/A-2, PDF/A-3 validation.
// Apache 2.0 License | Multi-language support
package pdfa

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"
)

// ============================================================================
// PDFA CONSTANTS
// ============================================================================

// PDFALevel represents PDF/A compliance levels
type PDFALevel string

const (
	PDFA1a PDFALevel = "PDF/A-1a"
	PDFA1b PDFALevel = "PDF/A-1b"
	PDFA2a PDFALevel = "PDF/A-2a"
	PDFA2b PDFALevel = "PDF/A-2b"
	PDFA3a PDFALevel = "PDF/A-3a"
	PDFA3b PDFALevel = "PDF/A-3b"
)

// ComplianceRule represents PDF/A compliance rules
type ComplianceRule string

const (
	NoUncompressedStreams     ComplianceRule = "no_uncompressed_streams"
	AllFontsEmbedded          ComplianceRule = "all_fonts_embedded"
	NoJavaScript              ComplianceRule = "no_javascript"
	NoForms                   ComplianceRule = "no_forms"
	MetadataRequired          ComplianceRule = "metadata_required"
	ColorsCMYKGrayscale       ComplianceRule = "colors_cmyk_grayscale"
	NoExternalReferences      ComplianceRule = "no_external_refs"
	NoTransparency            ComplianceRule = "no_transparency"
	No3DContent               ComplianceRule = "no_3d_content"
	NoEmbeddedMultimedia      ComplianceRule = "no_multimedia"
	TaggedDocumentRequired    ComplianceRule = "tagged_document"
	LogicalStructureRequired  ComplianceRule = "logical_structure"
	ValidXMPMetadata          ComplianceRule = "valid_xmp_metadata"
)

// ============================================================================
// PDF/A DATA STRUCTURES
// ============================================================================

// ComplianceIssue represents a PDF/A compliance issue
type ComplianceIssue struct {
	Rule       ComplianceRule `json:"rule"`
	Severity   string         `json:"severity"` // "error" or "warning"
	Message    string         `json:"message"`
	Location   *string        `json:"location,omitempty"`
	Suggestion *string        `json:"suggestion,omitempty"`
}

// FontInfo holds font information
type FontInfo struct {
	Name     string `json:"name"`
	Embedded bool   `json:"embedded"`
	Subset   bool   `json:"subset"`
	Type     string `json:"type"` // Type1, TrueType, CIDFont, etc.
}

// MetadataInfo holds PDF metadata
type MetadataInfo struct {
	Title            *string `json:"title,omitempty"`
	Author           *string `json:"author,omitempty"`
	Subject          *string `json:"subject,omitempty"`
	Creator          *string `json:"creator,omitempty"`
	Producer         *string `json:"producer,omitempty"`
	CreationDate     *string `json:"creationDate,omitempty"`
	ModificationDate *string `json:"modificationDate,omitempty"`
	XMPPresent       bool    `json:"xmpPresent"`
}

// PDFAReport represents a PDF/A compliance report
type PDFAReport struct {
	FileName          string           `json:"fileName"`
	DetectedLevel     *PDFALevel       `json:"detectedLevel,omitempty"`
	IsCompliant       bool             `json:"isCompliant"`
	Issues            []ComplianceIssue `json:"issues"`
	Fonts             []FontInfo       `json:"fonts"`
	Metadata          *MetadataInfo    `json:"metadata,omitempty"`
	PageCount         int              `json:"pageCount"`
	FileSize          int              `json:"fileSize"`
	AnalysisTimestamp string           `json:"analysisTimestamp"`
}

// NewPDFAReport creates a new PDFAReport with defaults
func NewPDFAReport(fileName string) *PDFAReport {
	return &PDFAReport{
		FileName: fileName,
		Issues:   []ComplianceIssue{},
		Fonts:    []FontInfo{},
	}
}

// AddIssue adds a compliance issue to the report
func (r *PDFAReport) AddIssue(rule ComplianceRule, severity, message string, location, suggestion *string) {
	r.Issues = append(r.Issues, ComplianceIssue{
		Rule:       rule,
		Severity:   severity,
		Message:    message,
		Location:   location,
		Suggestion: suggestion,
	})
}

// ErrorCount returns the number of error-severity issues
func (r *PDFAReport) ErrorCount() int {
	count := 0
	for _, issue := range r.Issues {
		if issue.Severity == "error" {
			count++
		}
	}
	return count
}

// WarningCount returns the number of warning-severity issues
func (r *PDFAReport) WarningCount() int {
	count := 0
	for _, issue := range r.Issues {
		if issue.Severity == "warning" {
			count++
		}
	}
	return count
}

// ToJSON converts the report to a JSON string
func (r *PDFAReport) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ============================================================================
// PDF ANALYZER
// ============================================================================

// PDFAnalyzer analyzes PDF structure
type PDFAnalyzer struct {
	Content []byte
	Offset  int
}

// NewPDFAnalyzer creates a new PDFAnalyzer
func NewPDFAnalyzer() *PDFAnalyzer {
	return &PDFAnalyzer{}
}

var pdfVersionRe = regexp.MustCompile(`%PDF-(\d\.\d)`)

// ParseHeader parses the PDF version from the header
func (a *PDFAnalyzer) ParseHeader() string {
	if a.Content == nil {
		return ""
	}

	end := 1024
	if len(a.Content) < end {
		end = len(a.Content)
	}
	header := string(a.Content[:end])

	matches := pdfVersionRe.FindStringSubmatch(header)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// DetectPDFADeclaration detects PDF/A level from document metadata
func (a *PDFAnalyzer) DetectPDFADeclaration() *PDFALevel {
	if a.Content == nil {
		return nil
	}

	content := string(a.Content)

	levels := []struct {
		marker string
		level  PDFALevel
	}{
		{"PDF/A-1a", PDFA1a},
		{"pdfaid:conformance>a<", PDFA1a},
		{"PDF/A-1b", PDFA1b},
		{"pdfaid:conformance>b<", PDFA1b},
		{"PDF/A-2a", PDFA2a},
		{"PDF/A-2b", PDFA2b},
		{"PDF/A-3a", PDFA3a},
		{"PDF/A-3b", PDFA3b},
	}

	for _, l := range levels {
		if contains(content, l.marker) {
			level := l.level
			return &level
		}
	}

	return nil
}

// HasJavaScript checks for JavaScript
func (a *PDFAnalyzer) HasJavaScript() bool {
	if a.Content == nil {
		return false
	}
	content := string(a.Content)
	return contains(content, "/JavaScript") || contains(content, "/AA") || contains(content, "/AcroForm")
}

// HasForms checks for AcroForms
func (a *PDFAnalyzer) HasForms() bool {
	if a.Content == nil {
		return false
	}
	return contains(string(a.Content), "/AcroForm")
}

var externalRefRe = regexp.MustCompile(`(?i)/URI.*(?:http|ftp|file)`)

// HasExternalReferences checks for external references
func (a *PDFAnalyzer) HasExternalReferences() bool {
	if a.Content == nil {
		return false
	}
	return externalRefRe.MatchString(string(a.Content))
}

var transparencyRe = regexp.MustCompile(`/ca |/CA |/SMask|/BM `)

// HasTransparency checks for transparency effects
func (a *PDFAnalyzer) HasTransparency() bool {
	if a.Content == nil {
		return false
	}
	return transparencyRe.MatchString(string(a.Content))
}

// Has3DContent checks for 3D content
func (a *PDFAnalyzer) Has3DContent() bool {
	if a.Content == nil {
		return false
	}
	content := string(a.Content)
	return contains(content, "/3D") || contains(content, "/RichMedia")
}

var multimediaRe = regexp.MustCompile(`/EmbeddedFile|/Launch|/Sound|/Movie`)

// HasEmbeddedMultimedia checks for embedded multimedia
func (a *PDFAnalyzer) HasEmbeddedMultimedia() bool {
	if a.Content == nil {
		return false
	}
	return multimediaRe.MatchString(string(a.Content))
}

var fontBlockRe = regexp.MustCompile(`(?s)/Font.*?<<(.*?)>>`)
var fontNameRe = regexp.MustCompile(`/BaseFont\s*/(\w+)`)

// ExtractFonts extracts font information
func (a *PDFAnalyzer) ExtractFonts() []FontInfo {
	fonts := []FontInfo{}
	if a.Content == nil {
		return fonts
	}

	content := string(a.Content)
	matches := fontBlockRe.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		fontBlock := match[1]

		name := "Unknown"
		nameMatch := fontNameRe.FindStringSubmatch(fontBlock)
		if len(nameMatch) > 1 {
			name = nameMatch[1]
		}

		embedded := contains(fontBlock, "/FontFile")
		subset := contains(name, "+")

		fontType := "Type1"
		if contains(fontBlock, "/TrueType") {
			fontType = "TrueType"
		} else if contains(fontBlock, "/CIDFont") {
			fontType = "CIDFont"
		}

		fonts = append(fonts, FontInfo{
			Name:     name,
			Embedded: embedded,
			Subset:   subset,
			Type:     fontType,
		})
	}

	return fonts
}

var infoBlockRe = regexp.MustCompile(`(?s)/Info.*?<<(.*?)>>`)
var titleRe = regexp.MustCompile(`/Title\s*\((.*?)\)`)
var authorRe = regexp.MustCompile(`/Author\s*\((.*?)\)`)
var subjectRe = regexp.MustCompile(`/Subject\s*\((.*?)\)`)
var creatorRe = regexp.MustCompile(`/Creator\s*\((.*?)\)`)
var producerRe = regexp.MustCompile(`/Producer\s*\((.*?)\)`)

// ExtractMetadata extracts document metadata
func (a *PDFAnalyzer) ExtractMetadata() *MetadataInfo {
	metadata := &MetadataInfo{}
	if a.Content == nil {
		return metadata
	}

	content := string(a.Content)

	infoMatch := infoBlockRe.FindStringSubmatch(content)
	if len(infoMatch) > 1 {
		infoBlock := infoMatch[1]

		if m := titleRe.FindStringSubmatch(infoBlock); len(m) > 1 {
			metadata.Title = &m[1]
		}
		if m := authorRe.FindStringSubmatch(infoBlock); len(m) > 1 {
			metadata.Author = &m[1]
		}
		if m := subjectRe.FindStringSubmatch(infoBlock); len(m) > 1 {
			metadata.Subject = &m[1]
		}
		if m := creatorRe.FindStringSubmatch(infoBlock); len(m) > 1 {
			metadata.Creator = &m[1]
		}
		if m := producerRe.FindStringSubmatch(infoBlock); len(m) > 1 {
			metadata.Producer = &m[1]
		}
	}

	metadata.XMPPresent = contains(content, "x:xmpmeta") || contains(content, "<xmpmeta")

	return metadata
}

var pagesBlockRe = regexp.MustCompile(`(?s)/Pages.*?<<(.*?)>>`)
var countRe = regexp.MustCompile(`/Count\s+(\d+)`)

// CountPages counts pages in PDF
func (a *PDFAnalyzer) CountPages() int {
	if a.Content == nil {
		return 0
	}

	content := string(a.Content)
	pagesMatch := pagesBlockRe.FindStringSubmatch(content)
	if len(pagesMatch) > 1 {
		countMatch := countRe.FindStringSubmatch(pagesMatch[1])
		if len(countMatch) > 1 {
			var count int
			fmt.Sscanf(countMatch[1], "%d", &count)
			return count
		}
	}

	return 0
}

// contains is a simple substring helper (avoids importing strings twice in examples)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	n := len(substr)
	if n == 0 {
		return 0
	}
	for i := 0; i+n <= len(s); i++ {
		if s[i:i+n] == substr {
			return i
		}
	}
	return -1
}

// ============================================================================
// PDF/A VALIDATOR
// ============================================================================

// PDFAValidator validates PDF/A compliance
type PDFAValidator struct {
	Analyzer *PDFAnalyzer
}

// NewPDFAValidator creates a new PDFAValidator
func NewPDFAValidator() *PDFAValidator {
	return &PDFAValidator{
		Analyzer: NewPDFAnalyzer(),
	}
}

// Validate validates PDF/A compliance for the given bytes
func (v *PDFAValidator) Validate(pdfBytes []byte) *PDFAReport {
	report := NewPDFAReport("document.pdf")
	report.FileSize = len(pdfBytes)
	report.AnalysisTimestamp = time.Now().Format(time.RFC3339)

	v.Analyzer.Content = pdfBytes

	pdfVersion := v.Analyzer.ParseHeader()
	if pdfVersion == "" {
		suggestion := "Ensure file is a valid PDF document"
		report.AddIssue(MetadataRequired, "error", "Not a valid PDF file", nil, &suggestion)
		return report
	}

	report.DetectedLevel = v.Analyzer.DetectPDFADeclaration()
	report.Metadata = v.Analyzer.ExtractMetadata()
	report.PageCount = v.Analyzer.CountPages()
	report.Fonts = v.Analyzer.ExtractFonts()

	v.checkUncompressedStreams(report)
	v.checkFontsEmbedded(report)
	v.checkNoJavaScript(report)
	v.checkNoForms(report)
	v.checkMetadata(report)
	v.checkExternalReferences(report)
	v.checkTransparency(report)
	v.check3DContent(report)
	v.checkMultimedia(report)

	report.IsCompliant = report.ErrorCount() == 0

	return report
}

var streamNoFilterRe = regexp.MustCompile(`stream\n`)

func (v *PDFAValidator) checkUncompressedStreams(report *PDFAReport) {
	if v.Analyzer.Content == nil {
		return
	}
	content := string(v.Analyzer.Content)

	if contains(content, "stream") {
		matches := streamNoFilterRe.FindAllStringIndex(content, -1)
		unfiltered := 0
		for _, m := range matches {
			// crude check: no /Filter mention shortly before "stream"
			start := m[0] - 200
			if start < 0 {
				start = 0
			}
			snippet := content[start:m[0]]
			if !contains(snippet, "/Filter") {
				unfiltered++
			}
		}
		if unfiltered > 0 {
			suggestion := "Compress all streams using FlateDecode or other supported filter"
			msg := fmt.Sprintf("Found %d uncompressed stream(s)", unfiltered)
			report.AddIssue(NoUncompressedStreams, "error", msg, nil, &suggestion)
		}
	}
}

func (v *PDFAValidator) checkFontsEmbedded(report *PDFAReport) {
	var unembedded []string
	for _, f := range report.Fonts {
		if !f.Embedded {
			unembedded = append(unembedded, f.Name)
		}
	}
	if len(unembedded) > 0 {
		suggestion := "Embed all fonts in the PDF file"
		names := ""
		for i, n := range unembedded {
			if i > 0 {
				names += ", "
			}
			names += n
		}
		msg := fmt.Sprintf("Found unembedded fonts: %s", names)
		report.AddIssue(AllFontsEmbedded, "error", msg, nil, &suggestion)
	}
}

func (v *PDFAValidator) checkNoJavaScript(report *PDFAReport) {
	if v.Analyzer.HasJavaScript() {
		suggestion := "Remove all JavaScript from the document"
		report.AddIssue(NoJavaScript, "error", "PDF contains JavaScript", nil, &suggestion)
	}
}

func (v *PDFAValidator) checkNoForms(report *PDFAReport) {
	if v.Analyzer.HasForms() {
		suggestion := "Consider removing forms or using PDF/A-3 for form support"
		report.AddIssue(NoForms, "warning", "PDF contains AcroForms", nil, &suggestion)
	}
}

func (v *PDFAValidator) checkMetadata(report *PDFAReport) {
	if report.Metadata == nil || !report.Metadata.XMPPresent {
		suggestion := "Add XMP metadata with PDF/A identification"
		report.AddIssue(ValidXMPMetadata, "warning", "XMP metadata not found", nil, &suggestion)
	}
}

func (v *PDFAValidator) checkExternalReferences(report *PDFAReport) {
	if v.Analyzer.HasExternalReferences() {
		suggestion := "Remove or convert external references to internal links"
		report.AddIssue(NoExternalReferences, "error", "PDF contains external references (URLs, etc.)", nil, &suggestion)
	}
}

func (v *PDFAValidator) checkTransparency(report *PDFAReport) {
	if v.Analyzer.HasTransparency() {
		suggestion := "Remove transparency or flatten images"
		report.AddIssue(NoTransparency, "warning", "PDF contains transparency effects", nil, &suggestion)
	}
}

func (v *PDFAValidator) check3DContent(report *PDFAReport) {
	if v.Analyzer.Has3DContent() {
		suggestion := "Remove 3D content (not supported in PDF/A)"
		report.AddIssue(No3DContent, "error", "PDF contains 3D content", nil, &suggestion)
	}
}

func (v *PDFAValidator) checkMultimedia(report *PDFAReport) {
	if v.Analyzer.HasEmbeddedMultimedia() {
		suggestion := "Remove or extract multimedia content"
		report.AddIssue(NoEmbeddedMultimedia, "error", "PDF contains embedded multimedia", nil, &suggestion)
	}
}

// ============================================================================
// MAIN CLASS
// ============================================================================

// PDFA is the main PDF/A validator
type PDFA struct {
	validator *PDFAValidator
	report    *PDFAReport
}

// New creates a new PDFA instance
func New() *PDFA {
	return &PDFA{
		validator: NewPDFAValidator(),
	}
}

// Validate validates PDF/A compliance from bytes
func (p *PDFA) Validate(pdfBytes []byte) *PDFA {
	p.report = p.validator.Validate(pdfBytes)
	return p
}

// ValidateFile validates PDF/A compliance from a file path
func (p *PDFA) ValidateFile(path string) (*PDFA, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	p.report = p.validator.Validate(data)
	p.report.FileName = path
	return p, nil
}

// GetReport returns the validation report
func (p *PDFA) GetReport() *PDFAReport {
	return p.report
}

// IsCompliant checks if the document is compliant
func (p *PDFA) IsCompliant() bool {
	if p.report == nil {
		return false
	}
	return p.report.IsCompliant
}

// GetErrors returns all error-severity issues
func (p *PDFA) GetErrors() []ComplianceIssue {
	if p.report == nil {
		return []ComplianceIssue{}
	}
	var errors []ComplianceIssue
	for _, issue := range p.report.Issues {
		if issue.Severity == "error" {
			errors = append(errors, issue)
		}
	}
	return errors
}

// GetWarnings returns all warning-severity issues
func (p *PDFA) GetWarnings() []ComplianceIssue {
	if p.report == nil {
		return []ComplianceIssue{}
	}
	var warnings []ComplianceIssue
	for _, issue := range p.report.Issues {
		if issue.Severity == "warning" {
			warnings = append(warnings, issue)
		}
	}
	return warnings
}

// GetIssueCount returns error and warning counts
func (p *PDFA) GetIssueCount() (int, int) {
	if p.report == nil {
		return 0, 0
	}
	return p.report.ErrorCount(), p.report.WarningCount()
}

// GetDetectedLevel returns the detected PDF/A level
func (p *PDFA) GetDetectedLevel() *PDFALevel {
	if p.report == nil {
		return nil
	}
	return p.report.DetectedLevel
}

// ToJSON exports the report to JSON
func (p *PDFA) ToJSON() (string, error) {
	if p.report == nil {
		return "{}", nil
	}
	return p.report.ToJSON()
}
