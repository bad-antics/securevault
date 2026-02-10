using SecureVault

# Create a new vault
vault = create_vault("/tmp/test.vault", "master_password_123")

# Add entries
id1 = add_entry(vault, "GitHub", "user@example.com", "gh_secret_123",
                url="https://github.com", tags=["dev", "git"])

id2 = add_entry(vault, "AWS Console", "admin", generate_password(),
                url="https://aws.amazon.com", category=API_TOKEN)

# Search
results = search_entries(vault, "git")
for r in results
    println("  Found: \$(r.title) (\$(r.username))")
end

# Generate passwords
println("\nRandom: ", generate_password(length=24))
println("Passphrase: ", generate_passphrase(words=5))

# Check strength
println("\nStrength: ", password_strength("MyP@ss123!").label)

# Stats and audit
vault_stats(vault)
print_audit_log()

# Close vault
close_vault(vault)
