# SecureVault Installation

## Requirements
- Julia 1.9+

## Install
```julia
using Pkg
Pkg.add(url="https://github.com/bad-antics/securevault")
```

## From Source
```bash
git clone https://github.com/bad-antics/securevault
cd securevault
julia --project -e 'using Pkg; Pkg.instantiate()'
```
