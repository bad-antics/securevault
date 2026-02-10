# SecureVault Quick Start

## Install
```julia
using Pkg
Pkg.add(url="https://github.com/bad-antics/securevault")
```

## Usage
```julia
using SecureVault

# Create vault
vault = create_vault("my.vault", "master_password")

# Add credentials
add_entry(vault, "GitHub", "user", "pass", url="https://github.com")

# Search
results = search_entries(vault, "git")

# Generate strong password
pw = generate_password(length=24)
pp = generate_passphrase(words=5)

# Export (without passwords)
export_vault(vault, "backup.csv", format=:csv)

# Close
close_vault(vault)
```

## Security
- AES-256-GCM encryption
- PBKDF2-SHA256 key derivation (100K iterations)
- Auto-lock after 5 minutes
- Audit trail with tamper detection
- Clipboard auto-clear
