# Vault entry management

function add_entry(vault::Vault, title::String, username::String, password::String;
                   url::String="", notes::String="", category::EntryCategory=LOGIN,
                   tags::Vector{String}=String[], totp::String="")
    vault.locked && error("Vault is locked")
    
    id = bytes2hex(sha256(string(now(), rand()))[1:8])
    entry = VaultEntry(id, title, username, password, url, notes,
                       category, tags, now(), now(), now(), false, totp)
    
    vault.entries[id] = entry
    save_vault(vault)
    
    log_event(vault, "ENTRY_ADDED", id, "Added: \$title")
    return id
end

function get_entry(vault::Vault, id::String)
    vault.locked && error("Vault is locked")
    haskey(vault.entries, id) || error("Entry not found: \$id")
    
    entry = vault.entries[id]
    # Update access time
    vault.entries[id] = VaultEntry(
        entry.id, entry.title, entry.username, entry.password,
        entry.url, entry.notes, entry.category, entry.tags,
        entry.created, entry.modified, now(), entry.favorite, entry.totp_secret
    )
    
    log_event(vault, "ENTRY_ACCESSED", id, "Accessed: \$(entry.title)")
    return entry
end

function update_entry(vault::Vault, id::String; title=nothing, username=nothing,
                      password=nothing, url=nothing, notes=nothing, tags=nothing)
    vault.locked && error("Vault is locked")
    old = get_entry(vault, id)
    
    vault.entries[id] = VaultEntry(
        old.id,
        something(title, old.title),
        something(username, old.username),
        something(password, old.password),
        something(url, old.url),
        something(notes, old.notes),
        old.category, something(tags, old.tags),
        old.created, now(), old.accessed,
        old.favorite, old.totp_secret
    )
    
    save_vault(vault)
    log_event(vault, "ENTRY_UPDATED", id, "Updated: \$(old.title)")
end

function delete_entry(vault::Vault, id::String)
    vault.locked && error("Vault is locked")
    entry = vault.entries[id]
    delete!(vault.entries, id)
    save_vault(vault)
    log_event(vault, "ENTRY_DELETED", id, "Deleted: \$(entry.title)")
end

function list_entries(vault::Vault; category::Union{EntryCategory,Nothing}=nothing)
    vault.locked && error("Vault is locked")
    entries = collect(values(vault.entries))
    !isnothing(category) && filter!(e -> e.category == category, entries)
    sort!(entries, by=e -> e.title)
    return entries
end
