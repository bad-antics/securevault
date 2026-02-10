# Audit trail logging

const AUDIT_LOG = AuditEvent[]

function log_event(vault::Vault, action::String, entry_id::String, details::String)
    checksum = bytes2hex(sha256(string(now(), action, entry_id, details))[1:16])
    event = AuditEvent(now(), action, entry_id, details, checksum)
    push!(AUDIT_LOG, event)
    
    # Write to audit file
    audit_path = vault.filepath * ".audit"
    open(audit_path, "a") do f
        println(f, "[\$(Dates.format(now(), "yyyy-mm-dd HH:MM:SS"))] \$action | \$entry_id | \$details | \$checksum")
    end
end

function get_audit_log(; last_n::Int=50)
    return AUDIT_LOG[max(1, end-last_n+1):end]
end

function print_audit_log(; last_n::Int=20)
    println("\n📋 Audit Trail (last \$last_n events)")
    println("═" ^ 70)
    for event in get_audit_log(last_n=last_n)
        ts = Dates.format(event.timestamp, "yyyy-mm-dd HH:MM:SS")
        @printf("  %s  %-16s  %s\n", ts, event.action, event.details)
    end
end
