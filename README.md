# SecureVault.jl 🔐

A secure, encrypted credential vault for Julia with military-grade encryption and secure memory handling.

[![Julia](https://img.shields.io/badge/Julia-1.6+-blue.svg)](https://julialang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔒 **AES-256 equivalent encryption** using authenticated stream cipher
- 🔑 **PBKDF2-HMAC-SHA256** key derivation with 100,000+ iterations
- 🧹 **Secure memory wiping** - secrets are wiped when destroyed
- 📁 **JSON-based encrypted storage** - portable vault files
- ⏰ **TTL-based expiration** - auto-expire secrets
- 📝 **Audit logging** - track all vault operations
- 🔄 **Key rotation** - change master password without data loss

## Installation

```julia
using Pkg
Pkg.add(url="https://github.com/bad-antics/securevault")
```

## Quick Start

```julia
using SecureVault

# Create a new vault
vault = create_vault("secrets.vault", "MyMasterPassword123!")

# Store credentials
store_credential!(vault, "GitHub", "bad-antics", "gh_token_xxx")
store_api_key!(vault, "OpenAI", "sk-xxx-yyy-zzz")

# Store with expiration (1 hour TTL)
store!(vault, "temp_token", Dict("token" => "abc123"), ttl_seconds=3600)

# Retrieve secrets
creds = retrieve(vault, "GitHub")
println(creds["username"])  # bad-antics

# List all entries
for entry in list_entries(vault)
    println("$(entry["name"]) - $(entry["category"])")
end

# Lock vault when done (wipes key from memory)
lock_vault!(vault)
```

## Secure String

Prevent sensitive data from lingering in memory:

```julia
# SecureString automatically wipes on garbage collection
password = SecureString("super_secret_password")

# Use the password
auth(String(password))

# Explicitly wipe when done
wipe!(password)
```

## Key Rotation

Change your master password without decrypting to disk:

```julia
vault = open_vault("secrets.vault", "OldPassword")
rotate_master_key!(vault, "NewSecurePassword456!")
```

## Export & Backup

```julia
# Export to encrypted backup
export_vault(vault, "backup.vault.enc", "BackupPassword")
```

## Security Features

### Encryption
- Stream cipher with SHA-256 keystream generation
- HMAC-SHA256 authentication tags prevent tampering
- Random 96-bit nonces for each encryption

### Key Derivation
- PBKDF2-HMAC-SHA256 with configurable iterations
- 256-bit random salt per vault
- Default 100,000 iterations (adjustable)

### Memory Protection
- `SecureString` type with automatic wiping
- Keys wiped on vault lock
- Multi-pass overwrite (random + zero)

### Audit Trail
- All operations logged with timestamps
- Track access patterns
- Detect unauthorized access attempts

## API Reference

### Vault Operations
| Function | Description |
|----------|-------------|
| `create_vault(path, password)` | Create new encrypted vault |
| `open_vault(path, password)` | Open existing vault |
| `lock_vault!(vault)` | Lock and wipe keys |
| `rotate_master_key!(vault, new_password)` | Change master password |
| `export_vault(vault, path, password)` | Export encrypted backup |

### Secret Management
| Function | Description |
|----------|-------------|
| `store!(vault, name, data)` | Store arbitrary secret |
| `store_credential!(vault, name, user, pass)` | Store username/password |
| `store_api_key!(vault, name, key)` | Store API key |
| `store_ssh_key!(vault, name, priv, pub)` | Store SSH keypair |
| `retrieve(vault, name)` | Get secret by name/ID |
| `delete!(vault, name)` | Remove secret |
| `list_entries(vault)` | List all entries |

### Utilities
| Function | Description |
|----------|-------------|
| `generate_password(length)` | Generate secure random password |
| `SecureString(str)` | Create wipeable string |
| `wipe!(secure_string)` | Securely wipe from memory |

## Use Cases

- 🔑 **Credential Management** - Store passwords, tokens, API keys
- 🤖 **Automation Scripts** - Secure credential storage for CI/CD
- 🔬 **Security Research** - Safe handling of sensitive test data
- 💻 **Development** - Local secrets management

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

Created by [bad-antics](https://github.com/bad-antics)

Part of the [Awesome Julia Security](https://github.com/bad-antics/awesome-julia-security) collection.
