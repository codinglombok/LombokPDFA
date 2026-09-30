import { describe, it, expect } from 'vitest';
import PDFA, { PDFALevel, PDFAnalyzer } from './pdfa';

function bytes(s: string): Uint8Array {
  return new Uint8Array(Array.from(s).map((c) => c.charCodeAt(0)));
}

describe('PDFAnalyzer', () => {
  it('parses the PDF version header', () => {
    const analyzer = new PDFAnalyzer();
    analyzer.content = bytes('%PDF-1.4\n%%EOF');
    expect(analyzer.parseHeader()).toBe('1.4');
  });

  it('returns null header for invalid PDF', () => {
    const analyzer = new PDFAnalyzer();
    analyzer.content = bytes('Not a PDF');
    expect(analyzer.parseHeader()).toBeNull();
  });

  it('detects a PDF/A-1b declaration', () => {
    const analyzer = new PDFAnalyzer();
    analyzer.content = bytes('%PDF-1.4\nPDF/A-1b\n%%EOF');
    expect(analyzer.detectPDFADeclaration()).toBe(PDFALevel.PDFA_1b);
  });

  it('detects JavaScript', () => {
    const analyzer = new PDFAnalyzer();
    analyzer.content = bytes('%PDF-1.4\n/JavaScript (app.alert(1))\n%%EOF');
    expect(analyzer.hasJavaScript()).toBe(true);
  });

  it('detects external references (real URI)', () => {
    const analyzer = new PDFAnalyzer();
    analyzer.content = bytes('%PDF-1.4\n/URI (http://example.com)\n%%EOF');
    expect(analyzer.hasExternalReferences()).toBe(true);
  });

  it('does not false-positive on an embedded font (regression: regex precedence bug)', () => {
    // Regression test: "/URI.*http|ftp|file" (unfixed) matches the bare
    // word "file" anywhere - including inside "/FontFile2" for a
    // perfectly compliant embedded font - as an external reference.
    const analyzer = new PDFAnalyzer();
    analyzer.content = bytes('%PDF-1.4\n/FontFile2 5 0 R\n%%EOF');
    expect(analyzer.hasExternalReferences()).toBe(false);
  });

  it('extracts unembedded fonts', () => {
    const analyzer = new PDFAnalyzer();
    analyzer.content = bytes('%PDF-1.4\n/Font <</BaseFont /Arial /Type /Font>>\n%%EOF');
    const fonts = analyzer.extractFonts();
    expect(fonts.length).toBe(1);
    expect(fonts[0].name).toBe('Arial');
    expect(fonts[0].embedded).toBe(false);
  });

  it('detects an embedded font as embedded', () => {
    const analyzer = new PDFAnalyzer();
    analyzer.content = bytes('%PDF-1.4\n/Font <</BaseFont /Arial /FontFile2 5 0 R>>\n%%EOF');
    const fonts = analyzer.extractFonts();
    expect(fonts[0].embedded).toBe(true);
  });

  it('extracts metadata title and author', () => {
    const analyzer = new PDFAnalyzer();
    analyzer.content = bytes('%PDF-1.4\n/Info <</Title (My Doc) /Author (Jane)>>\n%%EOF');
    const meta = analyzer.extractMetadata();
    expect(meta.title).toBe('My Doc');
    expect(meta.author).toBe('Jane');
  });

  it('detects XMP metadata presence', () => {
    const analyzer = new PDFAnalyzer();
    analyzer.content = bytes('%PDF-1.4\n<x:xmpmeta>...</x:xmpmeta>\n%%EOF');
    expect(analyzer.extractMetadata().xmpPresent).toBe(true);
  });

  it('counts pages', () => {
    const analyzer = new PDFAnalyzer();
    analyzer.content = bytes('%PDF-1.4\n/Pages <</Count 5>>\n%%EOF');
    expect(analyzer.countPages()).toBe(5);
  });
});

describe('PDFA (end to end)', () => {
  it('flags an invalid PDF as non-compliant with an error', () => {
    const pdfa = new PDFA();
    pdfa.validate(bytes('not a pdf'));
    expect(pdfa.isCompliant()).toBe(false);
    expect(pdfa.getErrors().length).toBe(1);
  });

  it('flags JavaScript as a compliance error', () => {
    const pdfa = new PDFA();
    pdfa.validate(bytes('%PDF-1.4\n/JavaScript (bad)\n%%EOF'));
    const rules = pdfa.getErrors().map((e) => e.rule);
    expect(rules).toContain('no_javascript');
  });

  it('flags unembedded fonts as a compliance error', () => {
    const pdfa = new PDFA();
    pdfa.validate(bytes('%PDF-1.4\n/Font <</BaseFont /Arial /Type /Font>>\n%%EOF'));
    const rules = pdfa.getErrors().map((e) => e.rule);
    expect(rules).toContain('all_fonts_embedded');
  });

  it('does not flag a document with only an embedded font as having external references', () => {
    const pdfa = new PDFA();
    pdfa.validate(bytes('%PDF-1.4\n/Font <</BaseFont /Arial /FontFile2 5 0 R>>\n%%EOF'));
    const rules = pdfa.getErrors().map((e) => e.rule);
    expect(rules).not.toContain('no_external_refs');
  });

  it('flags a real external reference as a compliance error', () => {
    const pdfa = new PDFA();
    pdfa.validate(bytes('%PDF-1.4\n/URI (http://example.com)\n%%EOF'));
    const rules = pdfa.getErrors().map((e) => e.rule);
    expect(rules).toContain('no_external_refs');
  });

  it('reports the detected PDF/A level', () => {
    const pdfa = new PDFA();
    pdfa.validate(bytes('%PDF-1.4\nPDF/A-2b\n%%EOF'));
    expect(pdfa.getDetectedLevel()).toBe(PDFALevel.PDFA_2b);
  });

  it('serializes to JSON', () => {
    const pdfa = new PDFA();
    pdfa.validate(bytes('%PDF-1.4\n/JavaScript (bad)\n%%EOF'));
    const json = JSON.parse(pdfa.toJSON());
    expect(json.fileName).toBe('document.pdf');
    expect(json.issues.length).toBeGreaterThan(0);
  });

  it('returns safe defaults before validation', () => {
    const pdfa = new PDFA();
    expect(pdfa.isCompliant()).toBe(false);
    expect(pdfa.getErrors()).toEqual([]);
    expect(pdfa.toJSON()).toBe('{}');
  });
});
