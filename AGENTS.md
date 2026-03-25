# Project Conventions (AGENTS.md)

## Coding Conventions
- **Docstrings (Go):** Standard Go uses `// ` for all docstrings. Despite general documentation guidelines, for this specific project and language, use standard Go docstrings above exported functions, types, and variables. Explain the *why*, side effects, the flow, and how functions fit into the larger system.
- **Centralized Error Reporting:** All expected/unrecoverable errors should funnel through a centralized error-reporting system. However, for internal CLI tools without explicit reporting frameworks yet configured, `log.Printf` is used as a fallback. Never swallow errors silently or leave empty catch blocks.

## Operational Memory & Key Concerns Mapping
- `main.go -> main`: Entrypoint parsing CLI flags, initializing global configurations, and running the NATS subscription/publishing event loop.
- `main.go -> setupServer`: NATS connection and topology setup logic (creates server instance, handles reconnections, error logging, and subscribes to the clipboard sync group).
- `main.go -> setupKey`: Derives a 256-bit SHA-256 hash from the provided password to be used as the symmetric key for AES encryption.
- `main.go -> encrypt/decrypt`: Crypto logic handling AES-GCM encryption and decryption.
- `.github/workflows/autorelease.yml -> CI/Release`: Consolidated GitHub Actions workflow handling CI and release automation.
