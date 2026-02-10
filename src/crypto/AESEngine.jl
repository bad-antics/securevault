# AES-256 encryption engine (simplified XOR-based for demo)

function encrypt_data(data::Vector{UInt8}, key::Vector{UInt8})
    # XOR stream cipher with key-derived keystream
    iv = rand(UInt8, 16)
    keystream = generate_keystream(key, iv, length(data))
    ciphertext = data .⊻ keystream
    
    # Compute authentication tag
    tag = sha256(vcat(key, iv, ciphertext))
    
    return vcat(iv, ciphertext, Vector{UInt8}(tag[1:16]))
end

function decrypt_data(encrypted::Vector{UInt8}, key::Vector{UInt8})
    length(encrypted) < 32 && error("Invalid ciphertext")
    
    iv = encrypted[1:16]
    tag = encrypted[end-15:end]
    ciphertext = encrypted[17:end-16]
    
    # Verify authentication tag
    expected_tag = sha256(vcat(key, iv, ciphertext))
    tag != Vector{UInt8}(expected_tag[1:16]) && error("Authentication failed - data tampered")
    
    keystream = generate_keystream(key, iv, length(ciphertext))
    return ciphertext .⊻ keystream
end

function generate_keystream(key::Vector{UInt8}, iv::Vector{UInt8}, length::Int)
    stream = UInt8[]
    counter = copy(iv)
    while Base.length(stream) < length
        block = Vector{UInt8}(sha256(vcat(key, counter)))
        append!(stream, block)
        counter[end] = (counter[end] + 1) % 256
    end
    return stream[1:length]
end
