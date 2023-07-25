# Usage:
```bash
export VAULT_ADDR="https://vault.example.com:8200"
export APPROLE_ROLE_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export APPROLE_SECRET_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

blowfish -encrypt -key <key> -input <input> -output <output>
blowfish -decrypt -key <key> -input <input> -output <output>
```