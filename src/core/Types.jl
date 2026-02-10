# Core types for SecureVault

@enum EntryCategory begin
    LOGIN
    CREDIT_CARD
    SECURE_NOTE
    SSH_KEY
    API_TOKEN
    WIFI_PASSWORD
    CRYPTO_WALLET
    IDENTITY
end

struct VaultEntry
    id::String
    title::String
    username::String
    password::String
    url::String
    notes::String
    category::EntryCategory
    tags::Vector{String}
    created::DateTime
    modified::DateTime
    accessed::DateTime
    favorite::Bool
    totp_secret::String
end

mutable struct Vault
    name::String
    filepath::String
    entries::Dict{String, VaultEntry}
    master_key::Vector{UInt8}
    salt::Vector{UInt8}
    locked::Bool
    created::DateTime
    modified::DateTime
    lock_timeout::Int  # seconds
    version::String
end

struct AuditEvent
    timestamp::DateTime
    action::String
    entry_id::String
    details::String
    checksum::String
end

struct VaultMetadata
    name::String
    version::String
    entry_count::Int
    created::DateTime
    modified::DateTime
    encryption::String
    kdf::String
end
