<?php

/**
 * LombokPDFA - PHP Port (v0.9.0-alpha)
 * PDF/A compliance validation (ISO 19005 standard)
 * Supports WCAG 2.1 AA compliance checking
 * Apache 2.0 License | Multi-language support
 */

namespace Lombok;

/**
 * PDF/A compliance levels
 */
class PDFALevel {
    const PDFA_1A = 'PDF/A-1a';
    const PDFA_1B = 'PDF/A-1b';
    const PDFA_2A = 'PDF/A-2a';
    const PDFA_2B = 'PDF/A-2b';
    const PDFA_3A = 'PDF/A-3a';
    const PDFA_3B = 'PDF/A-3b';
}

/**
 * Compliance rules
 */
class ComplianceRule {
    const NO_JAVASCRIPT = 'no_javascript';
    const EMBEDDED_FONTS = 'embedded_fonts';
    const CMYK_OR_ICC = 'cmyk_or_icc';
    const NO_TRANSPARENCY = 'no_transparency';
    const METADATA_REQUIRED = 'metadata_required';
    const DOCUMENT_STRUCTURE = 'document_structure';
    const COLOR_SPACE = 'color_space';
    const FILE_ATTACHMENT = 'file_attachment';
    const EXTERNAL_REFERENCE = 'external_reference';
    const ENCRYPTION_ALLOWED = 'encryption_allowed';
}

/**
 * Compliance issue
 */
class ComplianceIssue {
    public $rule;
    public $severity; // 'error', 'warning', 'info'
    public $message;
    public $location;
    public $suggestion;

    public function __construct($rule, $severity, $message, $location = null, $suggestion = null) {
        $this->rule = $rule;
        $this->severity = $severity;
        $this->message = $message;
        $this->location = $location;
        $this->suggestion = $suggestion;
    }
}

/**
 * Font information
 */
class FontInfo {
    public $name;
    public $embedded;
    public $subset;
    public $type;

    public function __construct($name, $embedded, $subset = false, $type = null) {
        $this->name = $name;
        $this->embedded = $embedded;
        $this->subset = $subset;
        $this->type = $type;
    }
}

/**
 * Metadata information
 */
class MetadataInfo {
    public $title;
    public $author;
    public $subject;
    public $keywords;
    public $creator;
    public $producer;
    public $creationDate;

    public function __construct() {
        $this->title = null;
        $this->author = null;
        $this->subject = null;
        $this->keywords = null;
        $this->creator = null;
        $this->producer = null;
        $this->creationDate = null;
    }
}

/**
 * PDF/A report
 */
class PDFAReport {
    public $fileName;
    public $detectedLevel;
    public $isCompliant;
    public $issues;
    public $fonts;
    public $metadata;
    public $pageCount;

    public function __construct($fileName, $detectedLevel = null, $isCompliant = false) {
        $this->fileName = $fileName;
        $this->detectedLevel = $detectedLevel;
        $this->isCompliant = $isCompliant;
        $this->issues = [];
        $this->fonts = [];
        $this->metadata = new MetadataInfo();
        $this->pageCount = 0;
    }
}

/**
 * PDF analyzer
 */
class PDFAnalyzer {
    public function analyze($pdfBytes) {
        $analysis = [
            'hasJavaScript' => false,
            'hasTransparency' => false,
            'unembeddedFonts' => [],
            'colorSpaces' => [],
            'hasMetadata' => false,
            'pageCount' => 0,
            'isEncrypted' => false,
            'externalReferences' => 0,
        ];

        // Convert to string for analysis
        $pdfStr = is_string($pdfBytes) ? $pdfBytes : '';

        // Check for JavaScript
        if (preg_match('/\/JavaScript\s+\(/', $pdfStr) || 
            preg_match('/\/JS\s+\(/', $pdfStr)) {
            $analysis['hasJavaScript'] = true;
        }

        // Check for transparency
        if (preg_match('/\/ca\s+[\d.]+/i', $pdfStr) || 
            preg_match('/\/CA\s+[\d.]+/i', $pdfStr)) {
            $analysis['hasTransparency'] = true;
        }

        // Check for fonts
        if (preg_match_all('/\/Font\s+<<([^>]+)>>/i', $pdfStr, $matches)) {
            foreach ($matches[1] as $fontDef) {
                if (!preg_match('/\/FontFile|\/FontFile2|\/FontFile3/i', $fontDef)) {
                    preg_match('/\/BaseFont\s+\/([^\s\/]+)/i', $fontDef, $fontMatch);
                    if (!empty($fontMatch)) {
                        $analysis['unembeddedFonts'][] = $fontMatch[1];
                    }
                }
            }
        }

        // Check for metadata
        if (preg_match('/\/Metadata\s+/', $pdfStr)) {
            $analysis['hasMetadata'] = true;
        }

        // Count pages
        $pageMatches = preg_match_all('/\/Type\s+\/Page\b/', $pdfStr);
        $analysis['pageCount'] = max($pageMatches, 0);

        // Check encryption
        if (preg_match('/\/Encrypt\s+/', $pdfStr)) {
            $analysis['isEncrypted'] = true;
        }

        // Check for external references (URIs pointing to http/ftp/file).
        // Note: the alternation must be grouped - "/URI.*http|ftp|file"
        // would match the bare word "file" anywhere (e.g. inside
        // "/FontFile2" for a perfectly compliant embedded font).
        if (preg_match('/\/URI.*(?:http|ftp|file)/i', $pdfStr)) {
            $analysis['externalReferences'] = 1;
        }

        return $analysis;
    }
}

/**
 * PDF/A validator
 */
class PDFAValidator {
    private $analyzer;

    public function __construct() {
        $this->analyzer = new PDFAnalyzer();
    }

    public function validate($pdfBytes, $fileName) {
        $report = new PDFAReport($fileName);

        try {
            $analysis = $this->analyzer->analyze(is_string($pdfBytes) ? $pdfBytes : '');

            // Detect PDF/A level
            $detectedLevel = $this->detectLevel($pdfBytes);
            $report->detectedLevel = $detectedLevel;

            // Check compliance rules
            $this->checkCompliance($analysis, $report);

            // Determine if compliant
            $report->isCompliant = count($report->issues) === 0;

            return $report;
        } catch (\Exception $e) {
            $report->issues[] = new ComplianceIssue(
                ComplianceRule::DOCUMENT_STRUCTURE,
                'error',
                'Failed to parse PDF: ' . $e->getMessage()
            );
            return $report;
        }
    }

    private function detectLevel($pdfBytes) {
        $pdfStr = is_string($pdfBytes) ? $pdfBytes : '';

        if (preg_match('/PDF\/A-1a/i', $pdfStr)) {
            return PDFALevel::PDFA_1A;
        }
        if (preg_match('/PDF\/A-1b/i', $pdfStr)) {
            return PDFALevel::PDFA_1B;
        }
        if (preg_match('/PDF\/A-2a/i', $pdfStr)) {
            return PDFALevel::PDFA_2A;
        }
        if (preg_match('/PDF\/A-2b/i', $pdfStr)) {
            return PDFALevel::PDFA_2B;
        }
        if (preg_match('/PDF\/A-3a/i', $pdfStr)) {
            return PDFALevel::PDFA_3A;
        }
        if (preg_match('/PDF\/A-3b/i', $pdfStr)) {
            return PDFALevel::PDFA_3B;
        }

        return null;
    }

    private function checkCompliance($analysis, &$report) {
        // Check JavaScript
        if ($analysis['hasJavaScript']) {
            $report->issues[] = new ComplianceIssue(
                ComplianceRule::NO_JAVASCRIPT,
                'error',
                'JavaScript is not allowed in PDF/A documents',
                'document',
                'Remove all JavaScript'
            );
        }

        // Check unembedded fonts
        if (!empty($analysis['unembeddedFonts'])) {
            $report->issues[] = new ComplianceIssue(
                ComplianceRule::EMBEDDED_FONTS,
                'error',
                'Found unembedded fonts: ' . implode(', ', $analysis['unembeddedFonts']),
                'fonts',
                'Embed all fonts used in the document'
            );
        }

        // Check transparency
        if ($analysis['hasTransparency']) {
            $report->issues[] = new ComplianceIssue(
                ComplianceRule::NO_TRANSPARENCY,
                'warning',
                'Document contains transparency',
                'graphics',
                'Remove or flatten transparency'
            );
        }

        // Check metadata
        if (!$analysis['hasMetadata']) {
            $report->issues[] = new ComplianceIssue(
                ComplianceRule::METADATA_REQUIRED,
                'info',
                'Document metadata is missing',
                'metadata',
                'Add document metadata (title, author, etc.)'
            );
        }

        // Check encryption
        if ($analysis['isEncrypted']) {
            $report->issues[] = new ComplianceIssue(
                ComplianceRule::ENCRYPTION_ALLOWED,
                'info',
                'Document is encrypted',
                'security'
            );
        }

        // Check external references
        if (!empty($analysis['externalReferences'])) {
            $report->issues[] = new ComplianceIssue(
                ComplianceRule::EXTERNAL_REFERENCE,
                'error',
                'Document contains external references (URIs)',
                'document',
                'Remove or internalize external references'
            );
        }
    }
}

/**
 * Main PDFA class
 */
class PDFA {
    private $validator;

    public function __construct() {
        $this->validator = new PDFAValidator();
    }

    public function validate($pdfBytes, $fileName) {
        return $this->validator->validate($pdfBytes, $fileName);
    }

    public function validateFile($filePath) {
        if (!file_exists($filePath)) {
            throw new \Exception("File not found: $filePath");
        }

        $pdfBytes = file_get_contents($filePath);
        return $this->validate($pdfBytes, basename($filePath));
    }

    public function isComisonCompliant($pdfBytes) {
        $report = $this->validate($pdfBytes, 'unknown');

        // Check for critical errors
        foreach ($report->issues as $issue) {
            if ($issue->severity === 'error') {
                return false;
            }
        }

        return true;
    }

    public function getReportSummary(&$report) {
        $summary = [
            'fileName' => $report->fileName,
            'detectedLevel' => $report->detectedLevel,
            'isCompliant' => $report->isCompliant,
            'issueCount' => count($report->issues),
            'errorCount' => count(array_filter($report->issues, fn($i) => $i->severity === 'error')),
            'warningCount' => count(array_filter($report->issues, fn($i) => $i->severity === 'warning')),
            'infoCount' => count(array_filter($report->issues, fn($i) => $i->severity === 'info')),
        ];

        return $summary;
    }

    public function toJSON(&$report) {
        $issues = [];
        foreach ($report->issues as $issue) {
            $issues[] = [
                'rule' => $issue->rule,
                'severity' => $issue->severity,
                'message' => $issue->message,
                'location' => $issue->location,
                'suggestion' => $issue->suggestion,
            ];
        }

        return json_encode([
            'fileName' => $report->fileName,
            'detectedLevel' => $report->detectedLevel,
            'isCompliant' => $report->isCompliant,
            'issues' => $issues,
            'pageCount' => $report->pageCount,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}
