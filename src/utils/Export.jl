# Export vault data

function export_vault(vault::Vault, filepath::String; format::Symbol=:csv, include_passwords::Bool=false)
    vault.locked && error("Vault is locked")
    
    if format == :csv
        export_csv(vault, filepath, include_passwords)
    elseif format == :json
        export_json(vault, filepath, include_passwords)
    end
end

function export_csv(vault::Vault, filepath::String, include_passwords::Bool)
    open(filepath, "w") do f
        header = include_passwords ? "title,username,password,url,category,tags" : "title,username,url,category,tags"
        println(f, header)
        
        for entry in sort(collect(values(vault.entries)), by=e->e.title)
            tags = join(entry.tags, ";")
            if include_passwords
                println(f, "\"\$(entry.title)\",\"\$(entry.username)\",\"\$(entry.password)\",\"\$(entry.url)\",\$(entry.category),\"\$tags\"")
            else
                println(f, "\"\$(entry.title)\",\"\$(entry.username)\",\"\$(entry.url)\",\$(entry.category),\"\$tags\"")
            end
        end
    end
    println("📤 Exported to \$filepath")
end

function export_json(vault::Vault, filepath::String, include_passwords::Bool)
    open(filepath, "w") do f
        println(f, "{\n  \"entries\": [")
        entries = sort(collect(values(vault.entries)), by=e->e.title)
        for (i, e) in enumerate(entries)
            comma = i < length(entries) ? "," : ""
            pw = include_passwords ? e.password : "********"
            println(f, "    {\"title\": \"\$(e.title)\", \"username\": \"\$(e.username)\", \"password\": \"\$pw\", \"url\": \"\$(e.url)\"}\$comma")
        end
        println(f, "  ]\n}")
    end
end
