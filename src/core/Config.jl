# SecureVault configuration

mutable struct VaultConfig
    kdf_iterations::Int
    kdf_memory::Int        # KB
    kdf_parallelism::Int
    key_length::Int        # bytes
    salt_length::Int       # bytes
    lock_timeout::Int      # seconds, 0 = never
    clipboard_clear::Int   # seconds
    backup_enabled::Bool
    audit_enabled::Bool
    max_history::Int
end

const DEFAULT_CONFIG = VaultConfig(
    100_000,   # iterations
    65536,     # 64MB memory
    4,         # parallelism
    32,        # 256-bit key
    32,        # 256-bit salt
    300,       # 5 min lock
    30,        # 30s clipboard clear
    true,      # backup on save
    true,      # audit logging
    50         # max password history
)

function load_config(path::String="")
    isempty(path) && return deepcopy(DEFAULT_CONFIG)
    cfg = deepcopy(DEFAULT_CONFIG)
    if isfile(path)
        for line in readlines(path)
            startswith(line, "#") && continue
            parts = split(strip(line), "=", limit=2)
            length(parts) != 2 && continue
            k, v = strip.(parts)
            k == "kdf_iterations" && (cfg.kdf_iterations = parse(Int, v))
            k == "lock_timeout" && (cfg.lock_timeout = parse(Int, v))
            k == "clipboard_clear" && (cfg.clipboard_clear = parse(Int, v))
            k == "audit_enabled" && (cfg.audit_enabled = v == "true")
        end
    end
    return cfg
end
