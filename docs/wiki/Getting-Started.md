# Getting Started

## Installation

```julia
using Pkg
Pkg.add(url="https://github.com/bad-antics/securevault")
```

## Quick Start

```julia
using SecureVault

# Create a new vault
vault = Vault("~/.securevault", password="your-master-password")

# Store a credential
store!(vault, "github", username="bad-antics", password="secret123")

# Retrieve
cred = get(vault, "github")
println(cred.username)

# List entries
list(vault)

# Secure close (wipes memory)
close!(vault)
```

## Configuration

```julia
vault = Vault("~/.securevault",
    password = "master-pass",
    pbkdf2_iterations = 100_000,
    cipher = :aes256gcm,
    audit_log = true
)
```
