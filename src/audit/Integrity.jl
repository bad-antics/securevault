# Vault integrity verification

function verify_integrity(vault::Vault)
    println("🔍 Verifying vault integrity...")
    issues = String[]
    
    # Check entry consistency
    for (id, entry) in vault.entries
        id != entry.id && push!(issues, "ID mismatch: \$id vs \$(entry.id)")
        entry.created > entry.modified && push!(issues, "Time anomaly: \$(entry.title)")
        isempty(entry.title) && push!(issues, "Empty title: \$id")
    end
    
    # Check audit log integrity
    prev_checksum = ""
    for event in AUDIT_LOG
        expected = bytes2hex(sha256(string(event.timestamp, event.action, event.entry_id, event.details))[1:16])
        if event.checksum != expected
            push!(issues, "Audit tamper detected at \$(event.timestamp)")
        end
    end
    
    if isempty(issues)
        println("  ✅ All checks passed (\$(length(vault.entries)) entries)")
    else
        println("  ⚠️  Found \$(length(issues)) issues:")
        for issue in issues
            println("    - \$issue")
        end
    end
    
    return issues
end

function vault_stats(vault::Vault)
    vault.locked && error("Vault is locked")
    
    categories = Dict{EntryCategory, Int}()
    for entry in values(vault.entries)
        categories[entry.category] = get(categories, entry.category, 0) + 1
    end
    
    weak = find_weak_passwords(vault)
    
    println("\n🔐 Vault Statistics")
    println("═" ^ 40)
    println("  Total entries: \$(length(vault.entries))")
    println("  Weak passwords: \$(length(weak))")
    println("  Categories:")
    for (cat, count) in sort(collect(categories), by=x->x[2], rev=true)
        println("    \$cat: \$count")
    end
end
