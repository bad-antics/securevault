# Password and passphrase generator

const WORDLIST = ["correct", "horse", "battery", "staple", "phantom", "cipher",
    "quantum", "nebula", "aurora", "vertex", "prism", "matrix", "vector",
    "signal", "binary", "crypto", "shield", "forge", "nexus", "pulse",
    "ember", "frost", "storm", "blaze", "shadow", "wraith", "spectre",
    "vortex", "zenith", "omega", "delta", "sigma", "theta", "lambda"]

function generate_password(; length::Int=20, uppercase::Bool=true, lowercase::Bool=true,
                            digits::Bool=true, symbols::Bool=true)
    charset = ""
    lowercase && (charset *= "abcdefghijklmnopqrstuvwxyz")
    uppercase && (charset *= "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    digits && (charset *= "0123456789")
    symbols && (charset *= "!@#\\$%^&*()-_=+[]{}|;:,.<>?")
    
    isempty(charset) && error("At least one character class required")
    
    password = String([charset[rand(1:Base.length(charset))] for _ in 1:length])
    return password
end

function generate_passphrase(; words::Int=4, separator::String="-", capitalize::Bool=true)
    selected = [WORDLIST[rand(1:Base.length(WORDLIST))] for _ in 1:words]
    capitalize && (selected = [uppercasefirst(w) for w in selected])
    return join(selected, separator) * string(rand(10:99))
end

function password_strength(password::String)
    score = 0
    n = length(password)
    
    n >= 8 && (score += 1)
    n >= 12 && (score += 1)
    n >= 16 && (score += 1)
    occursin(r"[a-z]", password) && (score += 1)
    occursin(r"[A-Z]", password) && (score += 1)
    occursin(r"[0-9]", password) && (score += 1)
    occursin(r"[^A-Za-z0-9]", password) && (score += 1)
    
    labels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong", "Excellent"]
    idx = min(score, length(labels))
    return (score=score, max_score=7, label=labels[idx], entropy=n * 4.7)
end
