module SecureVault

using SHA
using Dates
using Random
using Printf
using Serialization

include("core/Types.jl")
include("core/Config.jl")

include("crypto/KeyDerivation.jl")
include("crypto/AESEngine.jl")
include("crypto/HMAC.jl")

include("vault/Storage.jl")
include("vault/Entries.jl")
include("vault/Search.jl")
include("vault/Generator.jl")

include("audit/Logger.jl")
include("audit/Integrity.jl")

include("utils/Import.jl")
include("utils/Export.jl")

include("api/Server.jl")

export create_vault, open_vault, lock_vault, close_vault
export add_entry, get_entry, update_entry, delete_entry
export search_entries, list_entries
export generate_password, generate_passphrase
export export_vault, import_vault
export start_vault_server

end
