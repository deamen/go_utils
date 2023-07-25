package cipherkey

import (
	"context"
	"fmt"
	"os"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
)

func GetSecretWithAppRole(keyPath string) (string, error) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		return "", fmt.Errorf("no Vault address was provided in VAULT_ADDR env var")
	}
	config := vault.DefaultConfig()
	config.Address = vaultAddr

	client, err := vault.NewClient(config)
	if err != nil {
		return "", fmt.Errorf("unable to initialize Vault client: %w", err)
	}

	roleID := os.Getenv("APPROLE_ROLE_ID")
	if roleID == "" {
		return "", fmt.Errorf("no role ID provided in APPROLE_ROLE_ID env var")
	}

	secretID := os.Getenv("APPROLE_SECRET_ID")
	if secretID == "" {
		return "", fmt.Errorf("no secret ID was provided in APPROLE_SECRET_ID env var")
	}

	appRoleAuth, err := auth.NewAppRoleAuth(
		roleID,
		&auth.SecretID{FromString: secretID},
	)
	if err != nil {
		return "", fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}

	authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return "", fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return "", fmt.Errorf("no auth info was returned after login")
	}

	// get secret from the mount path, "secret"
	secret, err := client.KVv2("secret").Get(context.Background(), keyPath)
	if err != nil {
		return "", fmt.Errorf("unable to read secret: %w", err)
	}

	// data map can contain more than one key-value pair,
	// in this case we're just grabbing one of them
	value, ok := secret.Data["cipher_key"].(string)
	if !ok {
		return "", fmt.Errorf("value type assertion failed: %T %#v", secret.Data[keyPath], secret.Data[keyPath])
	}

	return value, nil
}
