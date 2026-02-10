# Key derivation functions

function derive_key(password::String, salt::Vector{UInt8}; config::VaultConfig=DEFAULT_CONFIG)
    # PBKDF2-SHA256 implementation
    key = pbkdf2_sha256(password, salt, config.kdf_iterations, config.key_length)
    return key
end

function pbkdf2_sha256(password::String, salt::Vector{UInt8}, iterations::Int, key_length::Int)
    # PBKDF2 with HMAC-SHA256
    password_bytes = Vector{UInt8}(password)
    
    blocks_needed = ceil(Int, key_length / 32)
    derived = UInt8[]
    
    for block_num in 1:blocks_needed
        # U1 = HMAC(password, salt || INT_32_BE(block_num))
        block_bytes = UInt8[
            (block_num >> 24) & 0xff,
            (block_num >> 16) & 0xff,
            (block_num >> 8) & 0xff,
            block_num & 0xff
        ]
        
        u = hmac_sha256(password_bytes, vcat(salt, block_bytes))
        result = copy(u)
        
        for i in 2:iterations
            u = hmac_sha256(password_bytes, u)
            result .= result .⊻ u
        end
        
        append!(derived, result)
    end
    
    return derived[1:key_length]
end

function generate_salt(length::Int=32)
    return rand(UInt8, length)
end
