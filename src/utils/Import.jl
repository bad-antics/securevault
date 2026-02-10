# Import from other formats

function import_vault(vault::Vault, filepath::String; format::Symbol=:csv)
    vault.locked && error("Vault is locked")
    
    if format == :csv
        return import_csv(vault, filepath)
    else
        error("Unsupported format: \$format")
    end
end

function import_csv(vault::Vault, filepath::String)
    count = 0
    for line in readlines(filepath)[2:end]  # skip header
        parts = split(line, ",", limit=5)
        length(parts) < 4 && continue
        
        title = strip(parts[1], '"')
        username = strip(parts[2], '"')
        password = strip(parts[3], '"')
        url = length(parts) >= 4 ? strip(parts[4], '"') : ""
        
        add_entry(vault, title, username, password, url=url)
        count += 1
    end
    
    println("📥 Imported \$count entries from CSV")
    return count
end
