# REST API for SecureVault

function start_vault_server(vault::Vault; port::Int=8090)
    server = listen(port)
    println("🔐 SecureVault API on http://localhost:\$port")
    println("  GET  /entries - list all entries")
    println("  GET  /search?q=X - search entries")
    println("  GET  /stats - vault statistics")
    println("  GET  /health - health check")
    
    while true
        sock = accept(server)
        @async handle_vault_request(sock, vault)
    end
end

function handle_vault_request(sock, vault)
    try
        req = readline(sock)
        path = split(split(req)[2], "?")[1]
        
        resp = if path == "/health"
            "{\"status\":\"ok\",\"version\":\"2.0.0\",\"locked\":\$(vault.locked)}"
        elseif path == "/stats"
            "{\"entries\":\$(length(vault.entries)),\"locked\":\$(vault.locked)}"
        else
            "{\"error\":\"use /entries, /search, /stats, or /health\"}"
        end
        
        write(sock, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\$resp")
    catch; end
    close(sock)
end
