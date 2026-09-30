<?php
use Lombok\PDFA;
use Lombok\PDFALevel;
use PHPUnit\Framework\TestCase;

class LombokPDFATest extends TestCase {

    public function testDetectLevelPDFA1B() {
        $pdfa = new PDFA();
        $content = "%PDF-1.4\n/Type /Metadata\nPDF/A-1b\n%%EOF";
        $report = $pdfa->validate($content, 'test.pdf');
        $this->assertEquals(PDFALevel::PDFA_1B, $report->detectedLevel);
    }

    public function testDetectLevelNone() {
        $pdfa = new PDFA();
        $report = $pdfa->validate("%PDF-1.4\n%%EOF", 'test.pdf');
        $this->assertNull($report->detectedLevel);
    }

    public function testDetectsJavaScript() {
        $pdfa = new PDFA();
        $content = "%PDF-1.4\n/JavaScript (app.alert('hi'))\n%%EOF";
        $report = $pdfa->validate($content, 'test.pdf');
        $hasJsIssue = false;
        foreach ($report->issues as $issue) {
            if ($issue->rule === 'no_javascript') {
                $hasJsIssue = true;
            }
        }
        $this->assertTrue($hasJsIssue);
        $this->assertFalse($report->isCompliant);
    }

    public function testNoJavaScriptIsCompliantOnThatRule() {
        $pdfa = new PDFA();
        $content = "%PDF-1.4\n/Type /Metadata\nPDF/A-1b\n%%EOF";
        $report = $pdfa->validate($content, 'test.pdf');
        foreach ($report->issues as $issue) {
            $this->assertTrue($issue->rule !== 'no_javascript');
        }
    }

    public function testDetectsUnembeddedFonts() {
        $pdfa = new PDFA();
        $content = "%PDF-1.4\n/Font <</BaseFont /Arial /Type /Font>>\n%%EOF";
        $report = $pdfa->validate($content, 'test.pdf');
        $hasFontIssue = false;
        foreach ($report->issues as $issue) {
            if ($issue->rule === 'embedded_fonts') {
                $hasFontIssue = true;
                $this->assertStringContainsString('Arial', $issue->message);
            }
        }
        $this->assertTrue($hasFontIssue);
    }

    public function testEmbeddedFontDoesNotFlag() {
        $pdfa = new PDFA();
        $content = "%PDF-1.4\n/Font <</BaseFont /Arial /FontFile2 5 0 R>>\n%%EOF";
        $report = $pdfa->validate($content, 'test.pdf');
        foreach ($report->issues as $issue) {
            $this->assertTrue($issue->rule !== 'embedded_fonts');
        }
    }

    public function testDetectsTransparency() {
        $pdfa = new PDFA();
        $content = "%PDF-1.4\n/ca 0.5\n%%EOF";
        $report = $pdfa->validate($content, 'test.pdf');
        $hasTransparency = false;
        foreach ($report->issues as $issue) {
            if ($issue->rule === 'no_transparency') {
                $hasTransparency = true;
            }
        }
        $this->assertTrue($hasTransparency);
    }

    public function testDetectsMissingMetadata() {
        $pdfa = new PDFA();
        $report = $pdfa->validate("%PDF-1.4\n%%EOF", 'test.pdf');
        $hasMetadataIssue = false;
        foreach ($report->issues as $issue) {
            if ($issue->rule === 'metadata_required') {
                $hasMetadataIssue = true;
            }
        }
        $this->assertTrue($hasMetadataIssue);
    }

    public function testDetectsPresentMetadata() {
        $pdfa = new PDFA();
        $content = "%PDF-1.4\n/Metadata 5 0 R\n%%EOF";
        $report = $pdfa->validate($content, 'test.pdf');
        foreach ($report->issues as $issue) {
            $this->assertTrue($issue->rule !== 'metadata_required');
        }
    }

    public function testDetectsEncryption() {
        $pdfa = new PDFA();
        $content = "%PDF-1.4\n/Encrypt 5 0 R\n%%EOF";
        $report = $pdfa->validate($content, 'test.pdf');
        $hasEncryptIssue = false;
        foreach ($report->issues as $issue) {
            if ($issue->rule === 'encryption_allowed') {
                $hasEncryptIssue = true;
                $this->assertEquals('info', $issue->severity);
            }
        }
        $this->assertTrue($hasEncryptIssue);
    }

    public function testDetectsExternalReference() {
        $pdfa = new PDFA();
        $content = "%PDF-1.4\n/URI (http://example.com)\n%%EOF";
        $report = $pdfa->validate($content, 'test.pdf');
        $hasExternalRefIssue = false;
        foreach ($report->issues as $issue) {
            if ($issue->rule === 'external_reference') {
                $hasExternalRefIssue = true;
            }
        }
        $this->assertTrue($hasExternalRefIssue);
    }

    public function testEmbeddedFontDoesNotFalselyTriggerExternalReference() {
        // Regression test: a regex precedence bug ("/URI.*http|ftp|file"
        // instead of "/URI.*(?:http|ftp|file)") previously matched the
        // bare word "file" anywhere - including inside "/FontFile2" for
        // a perfectly compliant embedded font - as an external reference.
        $pdfa = new PDFA();
        $content = "%PDF-1.4\n/FontFile2 5 0 R\n%%EOF";
        $report = $pdfa->validate($content, 'test.pdf');
        foreach ($report->issues as $issue) {
            $this->assertTrue($issue->rule !== 'external_reference');
        }
    }

    public function testFullyCompliantDocument() {
        $pdfa = new PDFA();
        $content = "%PDF-1.4\nPDF/A-1b\n/Metadata 5 0 R\n%%EOF";
        $report = $pdfa->validate($content, 'clean.pdf');
        $this->assertTrue($report->isCompliant);
        $this->assertCount(0, $report->issues);
    }

    public function testIsComisonCompliantFalseOnError() {
        $pdfa = new PDFA();
        $content = "%PDF-1.4\n/JavaScript (bad)\n%%EOF";
        $this->assertFalse($pdfa->isComisonCompliant($content));
    }

    public function testIsComisonCompliantTrueWhenOnlyInfoIssues() {
        $pdfa = new PDFA();
        // Missing metadata is only an 'info' issue, not an error
        $content = "%PDF-1.4\nPDF/A-1b\n%%EOF";
        $this->assertTrue($pdfa->isComisonCompliant($content));
    }

    public function testGetReportSummary() {
        $pdfa = new PDFA();
        $content = "%PDF-1.4\n/JavaScript (bad)\n/ca 0.5\n%%EOF";
        $report = $pdfa->validate($content, 'test.pdf');
        $summary = $pdfa->getReportSummary($report);
        $this->assertEquals('test.pdf', $summary['fileName']);
        $this->assertEquals(1, $summary['errorCount']);
        $this->assertEquals(1, $summary['warningCount']);
    }

    public function testToJSON() {
        $pdfa = new PDFA();
        $content = "%PDF-1.4\n/JavaScript (bad)\n/Metadata 5 0 R\n%%EOF";
        $report = $pdfa->validate($content, 'test.pdf');
        $json = $pdfa->toJSON($report);
        $decoded = json_decode($json, true);
        $this->assertEquals('test.pdf', $decoded['fileName']);
        $this->assertCount(1, $decoded['issues']);
    }

    public function testValidateFile() {
        $tmpFile = tempnam(sys_get_temp_dir(), 'lombokpdfa_') . '.pdf';
        file_put_contents($tmpFile, "%PDF-1.4\nPDF/A-1b\n/Metadata 5 0 R\n%%EOF");
        try {
            $pdfa = new PDFA();
            $report = $pdfa->validateFile($tmpFile);
            $this->assertTrue($report->isCompliant);
            $this->assertEquals(basename($tmpFile), $report->fileName);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testValidateFileNotFoundThrows() {
        $pdfa = new PDFA();
        $threw = false;
        try {
            $pdfa->validateFile('/nonexistent/path/file.pdf');
        } catch (\Throwable $e) {
            $threw = true;
        }
        $this->assertTrue($threw);
    }
}
