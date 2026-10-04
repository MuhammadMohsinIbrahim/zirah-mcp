# Changelog

All notable changes to Zirah are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Zirah uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may
change the CLI, the report formats and the data contract.

Rule pack versions (`YYYY.MM.N`) are recorded in every scan result and noted per release.

## [Unreleased]

### Security

- The LLM judge no longer sends secrets matched by zirah's D4 rules to the provider. Every
  request goes through one redaction step that providers cannot bypass: each such secret is
  replaced with `[REDACTED:<type>]`, and if redaction fails, nothing is sent. Secrets in
  formats the D4 rules do not recognize are not redacted. MCP config environment values and
  headers were never sent and still are not.

### Added

- PRIVACY.md states that the `ZIRAH_LLM` environment variable can select a cloud provider
  when `--llm` is not given.
- PRIVACY.md: Zirah collects no data and has no telemetry; with `--llm`, scanned manifest
  text goes only to the provider you choose.
- README: a "What `zirah discover` reads" section listing every config file per client.

### Fixed

- README quickstart and CONTRIBUTING: `cd zirah-mcp` after cloning (the repository was
  renamed).

### Changed

- `.env.example` says to set the variables in your environment; Zirah does not read a
  `.env` file.
- SPEC.md: 0.1.0 has shipped, the v0.1 coverage floor is 95%, and the CI checklist marks
  CodeQL and the coverage badge as planned. docs/PLAN.md notes that Dependabot was later
  removed.
- The PyPI summary and the PyPI README describe what Zirah ships today, a scanner; the
  trust registry is on the roadmap (v0.3), not part of 0.1.0.

## [0.1.0] - 2026-10-02

First release, v0.1: the offline CLI core.

### Added

- `zirah scan` for static manifest JSON files, stdio servers (`--allow-exec`, with a
  host-execution warning, time and size limits, and the whole process tree killed
  afterwards), and remote servers over Streamable HTTP or HTTP+SSE (`--transport`).
- In-house MCP client for MCP protocol versions 2024-11-05, 2025-03-26, 2025-06-18,
  2025-11-25 and 2026-07-28. It only negotiates and lists tools, prompts and resources; it
  never calls a tool.
- Detection modules with YAML rule packs:
  - **D1 tool poisoning**: invisible Unicode (zero-width, bidi, tag characters, variation
    selector runs), ANSI escapes and control characters, homoglyph-mixed names, hidden
    instructions, credential-file requests, covert forwarding, HTML/markdown smuggling, and
    text aimed at the scanner itself (`D1-SCANNER-EVASION`).
  - **D2 prompt injection** in prompts, resources and server instructions: instruction
    overrides, forged chat delimiters, jailbreaks, concealment, system prompt extraction,
    exfiltration (sensitive data, open destinations, destinations taken from tool output or
    fetched content), markdown image exfiltration, encoded instructions and scanner evasion.
  - **D3 tool shadowing** within one manifest.
  - **D4 secrets** in the manifest and target arguments, always redacted in output.
  - **D14 discover**: `zirah discover` lists MCP servers configured in Claude Desktop,
    Claude Code, Cursor, VS Code and Windsurf, read-only and offline, with an optional
    approved-servers list.
- `zirah scan --all` scans every discovered server into one `ScanSession`.
- Explainable trust score (0-100) and grade (A-F): every deducted point is listed against a
  finding.
- Reports: terminal, JSON, SARIF 2.1.0 (GitHub code scanning) and markdown.
- Optional LLM judge for D1-D3 (`--llm ollama|openai|anthropic`, default `none`); untrusted
  text is fenced as data.
- `examples/` with a harmless malicious demo server and a benign one (static and stdio).
- SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue and pull request templates.
- Published on PyPI as `zirah-mcp`; the import package and the command are `zirah`.
- Releases are built and published from GitHub Actions with PyPI trusted publishing
  (TestPyPI first), with PEP 740 attestations.

Rule pack: 2026.10.1.

[Unreleased]: https://github.com/MuhammadMohsinIbrahim/zirah-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MuhammadMohsinIbrahim/zirah-mcp/releases/tag/v0.1.0
