/**
 * LombokPDFA - TypeScript Port (v0.9.0-alpha)
 * PDF/A compliance validator (ISO 19005 standard).
 * Supports PDF/A-1, PDF/A-2, PDF/A-3 validation.
 * Apache 2.0 License | Multi-language support
 */

// ============================================================================
// PDFA CONSTANTS
// ============================================================================

export enum PDFALevel {
  PDFA_1a = 'PDF/A-1a',
  PDFA_1b = 'PDF/A-1b',
  PDFA_2a = 'PDF/A-2a',
  PDFA_2b = 'PDF/A-2b',
  PDFA_3a = 'PDF/A-3a',
  PDFA_3b = 'PDF/A-3b',
}

export enum ComplianceRule {
  NO_UNCOMPRESSED_STREAMS = 'no_uncompressed_streams',
  ALL_FONTS_EMBEDDED = 'all_fonts_embedded',
  NO_JAVASCRIPT = 'no_javascript',
  NO_FORMS = 'no_forms',
  METADATA_REQUIRED = 'metadata_required',
  COLORS_CMYK_GRAYSCALE = 'colors_cmyk_grayscale',
  NO_EXTERNAL_REFERENCES = 'no_external_refs',
  NO_TRANSPARENCY = 'no_transparency',
  NO_3D_CONTENT = 'no_3d_content',
  NO_EMBEDDED_MULTIMEDIA = 'no_multimedia',
  TAGGED_DOCUMENT_REQUIRED = 'tagged_document',
  LOGICAL_STRUCTURE_REQUIRED = 'logical_structure',
  VALID_XMP_METADATA = 'valid_xmp_metadata',
}

// ============================================================================
// PDF/A DATA STRUCTURES
// ============================================================================

export interface ComplianceIssue {
  rule: ComplianceRule;
  severity: 'error' | 'warning';
  message: string;
  location?: string;
  suggestion?: string;
}

export interface FontInfo {
  name: string;
  embedded: boolean;
  subset: boolean;
  type: string; // Type1, TrueType, CIDFont, etc.
}

export interface MetadataInfo {
  title?: string;
  author?: string;
  subject?: string;
  creator?: string;
  producer?: string;
  creationDate?: string;
  modificationDate?: string;
  xmpPresent: boolean;
}

export class PDFAReport {
  fileName: string;
  detectedLevel: PDFALevel | null = null;
  isCompliant = false;
  issues: ComplianceIssue[] = [];
  fonts: FontInfo[] = [];
  metadata: MetadataInfo | null = null;
  pageCount = 0;
  fileSize = 0;
  analysisTimestamp = '';

  constructor(fileName: string) {
    this.fileName = fileName;
  }

  addIssue(
    rule: ComplianceRule,
    severity: 'error' | 'warning',
    message: string,
    location?: string,
    suggestion?: string
  ): void {
    this.issues.push({ rule, severity, message, location, suggestion });
  }

  errorCount(): number {
    return this.issues.filter((i) => i.severity === 'error').length;
  }

  warningCount(): number {
    return this.issues.filter((i) => i.severity === 'warning').length;
  }

  toDict(): Record<string, unknown> {
    return {
      fileName: this.fileName,
      detectedLevel: this.detectedLevel,
      isCompliant: this.isCompliant,
      errorCount: this.errorCount(),
      warningCount: this.warningCount(),
      pageCount: this.pageCount,
      fileSize: this.fileSize,
      analysisTimestamp: this.analysisTimestamp,
      issues: this.issues,
      fonts: this.fonts,
      metadata: this.metadata,
    };
  }

  toJSON(): string {
    return JSON.stringify(this.toDict(), null, 2);
  }
}

// ============================================================================
// PDF ANALYZER
// ============================================================================

export class PDFAnalyzer {
  content: Uint8Array | null = null;

  private toStr(): string {
    if (!this.content) return '';
    return Array.from(this.content)
      .map((b) => String.fromCharCode(b))
      .join('');
  }

  parseHeader(): string | null {
    if (!this.content) return null;
    const end = Math.min(1024, this.content.length);
    const header = Array.from(this.content.slice(0, end))
      .map((b) => String.fromCharCode(b))
      .join('');
    const match = header.match(/%PDF-(\d\.\d)/);
    return match ? match[1] : null;
  }

  detectPDFADeclaration(): PDFALevel | null {
    if (!this.content) return null;
    const content = this.toStr();

    if (content.includes('PDF/A-1a') || content.includes('pdfaid:conformance>a<')) {
      return PDFALevel.PDFA_1a;
    } else if (content.includes('PDF/A-1b') || content.includes('pdfaid:conformance>b<')) {
      return PDFALevel.PDFA_1b;
    } else if (content.includes('PDF/A-2a')) {
      return PDFALevel.PDFA_2a;
    } else if (content.includes('PDF/A-2b')) {
      return PDFALevel.PDFA_2b;
    } else if (content.includes('PDF/A-3a')) {
      return PDFALevel.PDFA_3a;
    } else if (content.includes('PDF/A-3b')) {
      return PDFALevel.PDFA_3b;
    }

    return null;
  }

  hasJavaScript(): boolean {
    if (!this.content) return false;
    const content = this.toStr();
    return (
      content.includes('/JavaScript') || content.includes('/AA') || content.includes('/AcroForm')
    );
  }

  hasForms(): boolean {
    if (!this.content) return false;
    return this.toStr().includes('/AcroForm');
  }

  hasExternalReferences(): boolean {
    if (!this.content) return false;
    return /\/URI.*(?:http|ftp|file)/i.test(this.toStr());
  }

  hasTransparency(): boolean {
    if (!this.content) return false;
    return /\/ca |\/CA |\/SMask|\/BM /.test(this.toStr());
  }

  has3DContent(): boolean {
    if (!this.content) return false;
    const content = this.toStr();
    return content.includes('/3D') || content.includes('/RichMedia');
  }

  hasEmbeddedMultimedia(): boolean {
    if (!this.content) return false;
    return /\/EmbeddedFile|\/Launch|\/Sound|\/Movie/.test(this.toStr());
  }

  extractFonts(): FontInfo[] {
    const fonts: FontInfo[] = [];
    if (!this.content) return fonts;

    const content = this.toStr();
    const fontPattern = /\/Font.*?<<(.*?)>>/gs;
    let match: RegExpExecArray | null;

    while ((match = fontPattern.exec(content)) !== null) {
      const fontBlock = match[1];

      const nameMatch = fontBlock.match(/\/BaseFont\s*\/(\w+)/);
      const name = nameMatch ? nameMatch[1] : 'Unknown';

      const embedded = fontBlock.includes('/FontFile');
      const subset = name.includes('+');

      let fontType = 'Type1';
      if (fontBlock.includes('/TrueType')) {
        fontType = 'TrueType';
      } else if (fontBlock.includes('/CIDFont')) {
        fontType = 'CIDFont';
      }

      fonts.push({ name, embedded, subset, type: fontType });
    }

    return fonts;
  }

  extractMetadata(): MetadataInfo {
    const metadata: MetadataInfo = { xmpPresent: false };
    if (!this.content) return metadata;

    const content = this.toStr();

    const infoMatch = content.match(/\/Info.*?<<(.*?)>>/s);
    if (infoMatch) {
      const infoBlock = infoMatch[1];

      const titleMatch = infoBlock.match(/\/Title\s*\((.*?)\)/);
      if (titleMatch) metadata.title = titleMatch[1];

      const authorMatch = infoBlock.match(/\/Author\s*\((.*?)\)/);
      if (authorMatch) metadata.author = authorMatch[1];

      const subjectMatch = infoBlock.match(/\/Subject\s*\((.*?)\)/);
      if (subjectMatch) metadata.subject = subjectMatch[1];

      const creatorMatch = infoBlock.match(/\/Creator\s*\((.*?)\)/);
      if (creatorMatch) metadata.creator = creatorMatch[1];

      const producerMatch = infoBlock.match(/\/Producer\s*\((.*?)\)/);
      if (producerMatch) metadata.producer = producerMatch[1];
    }

    metadata.xmpPresent = content.includes('x:xmpmeta') || content.includes('<xmpmeta');

    return metadata;
  }

  countPages(): number {
    if (!this.content) return 0;

    const content = this.toStr();
    const pagesMatch = content.match(/\/Pages.*?<<(.*?)>>/s);
    if (pagesMatch) {
      const countMatch = pagesMatch[1].match(/\/Count\s+(\d+)/);
      if (countMatch) {
        return parseInt(countMatch[1], 10);
      }
    }

    return 0;
  }
}

// ============================================================================
// PDF/A VALIDATOR
// ============================================================================

export class PDFAValidator {
  analyzer: PDFAnalyzer;

  constructor() {
    this.analyzer = new PDFAnalyzer();
  }

  validate(pdfBytes: Uint8Array): PDFAReport {
    const report = new PDFAReport('document.pdf');
    report.fileSize = pdfBytes.length;
    report.analysisTimestamp = new Date().toISOString();

    this.analyzer.content = pdfBytes;

    const pdfVersion = this.analyzer.parseHeader();
    if (!pdfVersion) {
      report.addIssue(
        ComplianceRule.METADATA_REQUIRED,
        'error',
        'Not a valid PDF file',
        undefined,
        'Ensure file is a valid PDF document'
      );
      return report;
    }

    report.detectedLevel = this.analyzer.detectPDFADeclaration();
    report.metadata = this.analyzer.extractMetadata();
    report.pageCount = this.analyzer.countPages();
    report.fonts = this.analyzer.extractFonts();

    this.checkUncompressedStreams(report);
    this.checkFontsEmbedded(report);
    this.checkNoJavaScript(report);
    this.checkNoForms(report);
    this.checkMetadata(report);
    this.checkExternalReferences(report);
    this.checkTransparency(report);
    this.check3DContent(report);
    this.checkMultimedia(report);

    report.isCompliant = report.errorCount() === 0;

    return report;
  }

  private checkUncompressedStreams(report: PDFAReport): void {
    if (!this.analyzer.content) return;
    const content = Array.from(this.analyzer.content)
      .map((b) => String.fromCharCode(b))
      .join('');

    if (content.includes('stream')) {
      const streamMatches = [...content.matchAll(/stream\n/g)];
      let unfiltered = 0;
      for (const m of streamMatches) {
        const idx = m.index ?? 0;
        const start = Math.max(0, idx - 200);
        const snippet = content.slice(start, idx);
        if (!snippet.includes('/Filter')) {
          unfiltered++;
        }
      }
      if (unfiltered > 0) {
        report.addIssue(
          ComplianceRule.NO_UNCOMPRESSED_STREAMS,
          'error',
          `Found ${unfiltered} uncompressed stream(s)`,
          undefined,
          'Compress all streams using FlateDecode or other supported filter'
        );
      }
    }
  }

  private checkFontsEmbedded(report: PDFAReport): void {
    const unembedded = report.fonts.filter((f) => !f.embedded);
    if (unembedded.length > 0) {
      const names = unembedded.map((f) => f.name).join(', ');
      report.addIssue(
        ComplianceRule.ALL_FONTS_EMBEDDED,
        'error',
        `Found unembedded fonts: ${names}`,
        undefined,
        'Embed all fonts in the PDF file'
      );
    }
  }

  private checkNoJavaScript(report: PDFAReport): void {
    if (this.analyzer.hasJavaScript()) {
      report.addIssue(
        ComplianceRule.NO_JAVASCRIPT,
        'error',
        'PDF contains JavaScript',
        undefined,
        'Remove all JavaScript from the document'
      );
    }
  }

  private checkNoForms(report: PDFAReport): void {
    if (this.analyzer.hasForms()) {
      report.addIssue(
        ComplianceRule.NO_FORMS,
        'warning',
        'PDF contains AcroForms',
        undefined,
        'Consider removing forms or using PDF/A-3 for form support'
      );
    }
  }

  private checkMetadata(report: PDFAReport): void {
    if (!report.metadata || !report.metadata.xmpPresent) {
      report.addIssue(
        ComplianceRule.VALID_XMP_METADATA,
        'warning',
        'XMP metadata not found',
        undefined,
        'Add XMP metadata with PDF/A identification'
      );
    }
  }

  private checkExternalReferences(report: PDFAReport): void {
    if (this.analyzer.hasExternalReferences()) {
      report.addIssue(
        ComplianceRule.NO_EXTERNAL_REFERENCES,
        'error',
        'PDF contains external references (URLs, etc.)',
        undefined,
        'Remove or convert external references to internal links'
      );
    }
  }

  private checkTransparency(report: PDFAReport): void {
    if (this.analyzer.hasTransparency()) {
      report.addIssue(
        ComplianceRule.NO_TRANSPARENCY,
        'warning',
        'PDF contains transparency effects',
        undefined,
        'Remove transparency or flatten images'
      );
    }
  }

  private check3DContent(report: PDFAReport): void {
    if (this.analyzer.has3DContent()) {
      report.addIssue(
        ComplianceRule.NO_3D_CONTENT,
        'error',
        'PDF contains 3D content',
        undefined,
        'Remove 3D content (not supported in PDF/A)'
      );
    }
  }

  private checkMultimedia(report: PDFAReport): void {
    if (this.analyzer.hasEmbeddedMultimedia()) {
      report.addIssue(
        ComplianceRule.NO_EMBEDDED_MULTIMEDIA,
        'error',
        'PDF contains embedded multimedia',
        undefined,
        'Remove or extract multimedia content'
      );
    }
  }
}

// ============================================================================
// MAIN CLASS
// ============================================================================

export class PDFA {
  private validator: PDFAValidator;
  private report: PDFAReport | null = null;

  constructor() {
    this.validator = new PDFAValidator();
  }

  validate(pdfBytes: Uint8Array): PDFA {
    this.report = this.validator.validate(pdfBytes);
    return this;
  }

  getReport(): PDFAReport | null {
    return this.report;
  }

  isCompliant(): boolean {
    if (!this.report) return false;
    return this.report.isCompliant;
  }

  getErrors(): ComplianceIssue[] {
    if (!this.report) return [];
    return this.report.issues.filter((i) => i.severity === 'error');
  }

  getWarnings(): ComplianceIssue[] {
    if (!this.report) return [];
    return this.report.issues.filter((i) => i.severity === 'warning');
  }

  getIssueCount(): [number, number] {
    if (!this.report) return [0, 0];
    return [this.report.errorCount(), this.report.warningCount()];
  }

  getDetectedLevel(): PDFALevel | null {
    if (!this.report) return null;
    return this.report.detectedLevel;
  }

  toJSON(): string {
    if (!this.report) return '{}';
    return this.report.toJSON();
  }

  toDict(): Record<string, unknown> {
    if (!this.report) return {};
    return this.report.toDict();
  }
}

export default PDFA;
