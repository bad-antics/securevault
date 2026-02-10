# Vault storage and persistence

function create_vault(filepath::String, password::String; name::String="MyVault", config::VaultConfig=DEFAULT_CONFIG)
    salt = generate_salt(config.salt_length)
    key = derive_key(password, salt, config=config)
    
    vault = Vault(
        name, filepath,
        Dict{String, VaultEntry}(),
        key, salt, false,
        now(), now(),
        config.lock_timeout, "2.0.0"
    )
    
    save_vault(vault)
    config.audit_enabled && log_event(vault, "VAULT_CREATED", "", "New vault: \$name")
    
    println("🔐 Vault created: \$filepath")
    return vault
end

function open_vault(filepath::String, password::String; config::VaultConfig=DEFAULT_CONFIG)
    !isfile(filepath) && error("Vault not found: \$filepath")
    
    raw = read(filepath)
    salt = raw[1:32]
    encrypted = raw[33:end]
    
    key = derive_key(password, salt, config=config)
    
    try
        decrypted = decrypt_data(encrypted, key)
        entries = deserialize(IOBuffer(decrypted))
        
        vault = Vault("", filepath, entries, key, salt, false, now(), now(), config.lock_timeout, "2.0.0")
        config.audit_enabled && log_event(vault, "VAULT_OPENED", "", filepath)
        
        return vault
    catch
        error("🚫 Invalid password or corrupted vault")
    end
end

function save_vault(vault::Vault)
    vault.locked && error("Vault is locked")
    vault.modified = now()
    
    data = IOBuffer()
    serialize(data, vault.entries)
    encrypted = encrypt_data(take!(data), vault.master_key)
    
    write(vault.filepath, vcat(vault.salt, encrypted))
end

function lock_vault(vault::Vault)
    vault.locked = true
    fill!(vault.master_key, 0x00)
    println("🔒 Vault locked")
end

function close_vault(vault::Vault)
    save_vault(vault)
    lock_vault(vault)
end
