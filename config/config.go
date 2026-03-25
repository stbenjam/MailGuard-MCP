package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	MailProvider     string
	IMAPHost         string
	IMAPPort         int
	IMAPUsername     string
	IMAPPassword     string
	IMAPTLS          bool
	IMAPMailbox      string
	TrustStoreDBPath string
	AttachmentDir    string
	MaxBodySize      int
	TrustedSenders   []string
}

func LoadConfig() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		MailProvider:     getEnv("MAIL_PROVIDER", "imap"),
		IMAPHost:         os.Getenv("IMAP_HOST"),
		IMAPPort:         getEnvInt("IMAP_PORT", 993),
		IMAPUsername:     os.Getenv("IMAP_USERNAME"),
		IMAPPassword:     os.Getenv("IMAP_PASSWORD"),
		IMAPTLS:          getEnvBool("IMAP_TLS", true),
		IMAPMailbox:      getEnv("IMAP_MAILBOX", "INBOX"),
		TrustStoreDBPath: getEnv("TRUSTSTORE_DB_PATH", "./truststore.db"),
		AttachmentDir:    getEnv("ATTACHMENT_DIR", "./attachments"),
		MaxBodySize:      getEnvInt("MAX_BODY_SIZE", 32768),
	}

	if seeds := os.Getenv("TRUSTED_SENDERS"); seeds != "" {
		for _, s := range strings.Split(seeds, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				cfg.TrustedSenders = append(cfg.TrustedSenders, strings.ToLower(s))
			}
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	switch c.MailProvider {
	case "imap":
		if c.IMAPHost == "" {
			return fmt.Errorf("IMAP_HOST is required when MAIL_PROVIDER=imap")
		}
		if c.IMAPUsername == "" {
			return fmt.Errorf("IMAP_USERNAME is required when MAIL_PROVIDER=imap")
		}
		if c.IMAPPassword == "" {
			return fmt.Errorf("IMAP_PASSWORD is required when MAIL_PROVIDER=imap")
		}
	default:
		return fmt.Errorf("unsupported MAIL_PROVIDER: %s", c.MailProvider)
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
