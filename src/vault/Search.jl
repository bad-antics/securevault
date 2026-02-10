# Search and filter vault entries

function search_entries(vault::Vault, query::String; fields=[:title, :username, :url, :notes, :tags])
    vault.locked && error("Vault is locked")
    q = lowercase(query)
    results = VaultEntry[]
    
    for entry in values(vault.entries)
        matched = false
        :title in fields && occursin(q, lowercase(entry.title)) && (matched = true)
        :username in fields && occursin(q, lowercase(entry.username)) && (matched = true)
        :url in fields && occursin(q, lowercase(entry.url)) && (matched = true)
        :notes in fields && occursin(q, lowercase(entry.notes)) && (matched = true)
        :tags in fields && any(t -> occursin(q, lowercase(t)), entry.tags) && (matched = true)
        matched && push!(results, entry)
    end
    
    sort!(results, by=e -> e.title)
    return results
end

function filter_by_tags(vault::Vault, tags::Vector{String})
    vault.locked && error("Vault is locked")
    return filter(e -> !isempty(intersect(e.tags, tags)), collect(values(vault.entries)))
end

function filter_by_date(vault::Vault; after::DateTime=DateTime(2000), before::DateTime=now())
    vault.locked && error("Vault is locked")
    return filter(e -> after <= e.modified <= before, collect(values(vault.entries)))
end

function find_weak_passwords(vault::Vault; min_length::Int=12)
    vault.locked && error("Vault is locked")
    weak = VaultEntry[]
    for entry in values(vault.entries)
        p = entry.password
        score = 0
        length(p) >= min_length && (score += 1)
        occursin(r"[A-Z]", p) && (score += 1)
        occursin(r"[a-z]", p) && (score += 1)
        occursin(r"[0-9]", p) && (score += 1)
        occursin(r"[^A-Za-z0-9]", p) && (score += 1)
        score < 4 && push!(weak, entry)
    end
    return weak
end
