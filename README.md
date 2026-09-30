# LombokPDFA

PDF/A archival format compliance library (ISO 19005).  
Part of the [Lombok Ecosystem](https://github.com/codinglombok).

## Features

- PDF/A-1b baseline archival with embedded fonts
- PDF/A-2b extended color management
- PDF/A-3b embedded file attachments
- Validation against ISO 19005-2/-3
- Zero external dependencies
- Multi-language: TypeScript, Python, PHP, Go

## Installation

```bash
npm install lombokpdfa          # TypeScript/JavaScript
pip install lombokpdfa          # Python
composer require codinglombok/lombokpdfa  # PHP
go get github.com/codinglombok/lombokpdfa # Go
```

## Quick Start (TypeScript)

```typescript
import { PDFA } from 'lombokpdfa'

const pdfa = await new PDFA(pdfBuffer)
  .convertTo('A-1b')
  .validateCompliance()
  .export()
```

## Use Cases

- Government document archival
- Tax/financial records (long-term storage)
- Legal document preservation
- Academic publications

## Project Structure

```
lombokpdfa/
├── typescript/     # TypeScript source + tests
├── python/         # Python port + tests
├── go/             # Go port + tests
├── php/            # PHP port + tests
├── package.json
├── LICENSE         # Apache 2.0
└── README.md
```

## License

Apache 2.0 — see [LICENSE](LICENSE)
