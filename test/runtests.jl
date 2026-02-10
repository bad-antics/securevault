using Test
using SecureVault

@testset "SecureVault Tests" begin
    @testset "Key Derivation" begin
        salt = generate_salt(32)
        key1 = derive_key("test_password", salt)
        key2 = derive_key("test_password", salt)
        @test key1 == key2
        @test length(key1) == 32
        
        key3 = derive_key("different", salt)
        @test key1 != key3
    end
    
    @testset "Encryption" begin
        key = rand(UInt8, 32)
        data = Vector{UInt8}("Hello SecureVault!")
        encrypted = encrypt_data(data, key)
        decrypted = decrypt_data(encrypted, key)
        @test decrypted == data
    end
    
    @testset "HMAC" begin
        key = Vector{UInt8}("secret_key")
        msg = Vector{UInt8}("test message")
        h1 = hmac_sha256(key, msg)
        h2 = hmac_sha256(key, msg)
        @test h1 == h2
        @test length(h1) == 32
    end
    
    @testset "Password Generator" begin
        pw = generate_password(length=20)
        @test length(pw) == 20
        
        pp = generate_passphrase(words=4)
        @test count(c -> c == '-', pp) == 3
    end
    
    @testset "Password Strength" begin
        weak = password_strength("abc")
        strong = password_strength("C0mpl3x!P@ss#2024")
        @test strong.score > weak.score
    end
end
