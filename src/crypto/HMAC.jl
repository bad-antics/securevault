# HMAC-SHA256 implementation

function hmac_sha256(key::Vector{UInt8}, message::Vector{UInt8})
    block_size = 64
    
    # Key preparation
    if length(key) > block_size
        key = Vector{UInt8}(sha256(key))
    end
    if length(key) < block_size
        key = vcat(key, zeros(UInt8, block_size - length(key)))
    end
    
    # Inner and outer padding
    ipad = key .⊻ 0x36
    opad = key .⊻ 0x5c
    
    # HMAC = H(opad || H(ipad || message))
    inner = Vector{UInt8}(sha256(vcat(ipad, message)))
    outer = Vector{UInt8}(sha256(vcat(opad, inner)))
    
    return outer
end
