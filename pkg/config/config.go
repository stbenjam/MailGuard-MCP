package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

// Config holds global settings loaded from environment variables.
type Config struct {
	TrustStoreDBPath string
}

// AccountConfig holds connection settings for a single mail account.
type AccountConfig struct {
	Provider     string `yaml:"provider"`
	IMAPHost     string `yaml:"imap_host"`
	IMAPPort     int    `yaml:"imap_port"`
	IMAPUsername string `yaml:"imap_username"`
	IMAPPassword string `yaml:"-"`
	IMAPTLS      bool   `yaml:"imap_tls"`
	IMAPMailbox  string `yaml:"imap_mailbox"`

	IMAPDraftsMailbox string `yaml:"imap_drafts_mailbox"`

	// IMAPPasswordEnv is the name of the environment variable holding the password.
	IMAPPasswordEnv string `yaml:"imap_password_env"`
}

// accountsFile is the YAML structure for the accounts config file.
type accountsFile struct {
	Accounts map[string]*AccountConfig `yaml:"accounts"`
}

func LoadConfig() (*Config, error) {
	_ = godotenv.Load()

	return &Config{
		TrustStoreDBPath: getEnv("TRUSTSTORE_DB_PATH", "./truststore.db"),
	}, nil
}

// LoadAccounts reads account definitions from a YAML file.
// Passwords are resolved from environment variables referenced by imap_password_env.
func LoadAccounts(path string) (map[string]*AccountConfig, error) {
	_ = godotenv.Load()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read accounts file: %w", err)
	}

	var f accountsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse accounts file: %w", err)
	}

	if len(f.Accounts) == 0 {
		return nil, fmt.Errorf("no accounts defined in %s", path)
	}

	for name, acct := range f.Accounts {
		if err := acct.applyDefaults(); err != nil {
			return nil, fmt.Errorf("account %q: %w", name, err)
		}
		if err := acct.resolvePassword(); err != nil {
			return nil, fmt.Errorf("account %q: %w", name, err)
		}
		if err := acct.validate(name); err != nil {
			return nil, err
		}
	}

	return f.Accounts, nil
}

// DefaultAccountFromEnv builds a single "default" account from environment variables
// for backward compatibility when no accounts file is provided.
func DefaultAccountFromEnv() (map[string]*AccountConfig, error) {
	_ = godotenv.Load()

	acct := &AccountConfig{
		Provider:     getEnv("MAIL_PROVIDER", "imap"),
		IMAPHost:     os.Getenv("IMAP_HOST"),
		IMAPPort:     getEnvInt("IMAP_PORT", 993),
		IMAPUsername: os.Getenv("IMAP_USERNAME"),
		IMAPPassword: os.Getenv("IMAP_PASSWORD"),
		IMAPTLS:      getEnvBool("IMAP_TLS", true),
		IMAPMailbox:       getEnv("IMAP_MAILBOX", "INBOX"),
		IMAPDraftsMailbox: getEnv("IMAP_DRAFTS_MAILBOX", "Drafts"),
	}

	if err := acct.validate("default"); err != nil {
		return nil, err
	}

	return map[string]*AccountConfig{"default": acct}, nil
}

func (a *AccountConfig) applyDefaults() error {
	if a.Provider == "" {
		a.Provider = "imap"
	}
	if a.IMAPPort == 0 {
		a.IMAPPort = 993
	}
	if a.IMAPMailbox == "" {
		a.IMAPMailbox = "INBOX"
	}
	if a.IMAPDraftsMailbox == "" {
		a.IMAPDraftsMailbox = "Drafts"
	}
	return nil
}

func (a *AccountConfig) resolvePassword() error {
	if a.IMAPPasswordEnv != "" {
		a.IMAPPassword = os.Getenv(a.IMAPPasswordEnv)
		if a.IMAPPassword == "" {
			return fmt.Errorf("environment variable %s is not set or empty", a.IMAPPasswordEnv)
		}
	}
	return nil
}

func (a *AccountConfig) validate(name string) error {
	switch a.Provider {
	case "imap":
		if a.IMAPHost == "" {
			return fmt.Errorf("account %q: imap_host is required", name)
		}
		if a.IMAPUsername == "" {
			return fmt.Errorf("account %q: imap_username is required", name)
		}
		if a.IMAPPassword == "" {
			return fmt.Errorf("account %q: imap_password_env is required and must reference a non-empty env var", name)
		}
	default:
		return fmt.Errorf("account %q: unsupported provider: %s", name, a.Provider)
	}
	return nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}
