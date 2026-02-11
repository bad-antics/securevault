# SecureVault Wiki

Welcome to **SecureVault** — an encrypted credential vault for Julia with PBKDF2 key derivation, secure memory wiping, and audit logging.

## Navigation

- [[Getting Started]] — Installation and basic usage
- [[Architecture]] — Encryption design and security model
- [[API Reference]] — Julia API documentation
- [[Configuration]] — Vault settings
- [[Security Model]] — Threat model and guarantees

## Features

| Feature | Description |
|---------|-------------|
| 🔐 PBKDF2 | Key derivation with configurable iterations |
| 🧹 Memory Wipe | Secure zeroing of sensitive data |
| 📝 Audit Log | Tamper-evident access logging |
| 🗄️ Encrypted Store | AES-256-GCM at-rest encryption |
| 🔑 Key Rotation | Automated key rotation support |
