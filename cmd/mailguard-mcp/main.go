package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"

	"github.com/stbenjam/mailguard-mcp/pkg/config"
	"github.com/stbenjam/mailguard-mcp/pkg/policy"
	"github.com/stbenjam/mailguard-mcp/pkg/provider"
	imapprovider "github.com/stbenjam/mailguard-mcp/pkg/provider/imap"
	"github.com/stbenjam/mailguard-mcp/pkg/tools"
	"github.com/stbenjam/mailguard-mcp/pkg/truststore"
)

func main() {
	var (
		policyPath   string
		accountsPath string
	)

	cmd := &cobra.Command{
		Use:   "mailguard-mcp",
		Short: "MCP server for secure LLM email access",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(policyPath, accountsPath)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to policy YAML file (uses built-in defaults if not set)")
	cmd.Flags().StringVar(&accountsPath, "accounts", "", "Path to accounts YAML file (falls back to env vars for a single account if not set)")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(policyPath, accountsPath string) error {
	// Configure structured logging to stderr
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	// Load policy
	var pol *policy.Policy
	if policyPath != "" {
		var err error
		pol, err = policy.Load(policyPath)
		if err != nil {
			return fmt.Errorf("failed to load policy: %w", err)
		}
		slog.Info("loaded policy", "path", policyPath)
	} else {
		pol = policy.Default()
		slog.Info("using default policy")
	}

	// Load accounts
	var accounts map[string]*config.AccountConfig
	if accountsPath != "" {
		var err error
		accounts, err = config.LoadAccounts(accountsPath)
		if err != nil {
			return fmt.Errorf("failed to load accounts: %w", err)
		}
		slog.Info("loaded accounts", "path", accountsPath, "count", len(accounts))
	} else {
		var err error
		accounts, err = config.DefaultAccountFromEnv()
		if err != nil {
			return fmt.Errorf("failed to load config from environment: %w", err)
		}
		slog.Info("using single account from environment")
	}

	// Load global config (trust store path)
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	ts, err := truststore.New(cfg.TrustStoreDBPath)
	if err != nil {
		return fmt.Errorf("failed to open trust store: %w", err)
	}
	defer ts.Close()

	// Seed trusted senders from policy
	for _, addr := range pol.Trust.Senders {
		if err := ts.Add(addr); err != nil {
			slog.Warn("failed to seed trusted sender", "email", addr, "error", err)
		} else {
			slog.Info("seeded trusted sender", "email", addr)
		}
	}

	// Create mail providers
	providers := make(map[string]provider.MailProvider, len(accounts))
	for name, acct := range accounts {
		switch acct.Provider {
		case "imap":
			providers[name] = imapprovider.New(acct)
		default:
			return fmt.Errorf("account %q: unsupported provider: %s", name, acct.Provider)
		}
	}

	// Connect all providers
	for name, mp := range providers {
		if err := mp.Connect(); err != nil {
			return fmt.Errorf("account %q: failed to connect: %w", name, err)
		}
		defer mp.Close()
		slog.Info("connected account", "name", name)
	}

	// Create MCP server
	s := server.NewMCPServer(
		"MailGuard-MCP",
		"0.1.0",
	)

	// Register tools
	h := tools.NewHandler(providers, ts, pol)
	h.Register(s)

	// Serve via stdio
	slog.Info("starting MailGuard-MCP server",
		"accounts", len(providers),
		"read_only", pol.Tools.ReadOnly,
		"trust_enabled", pol.Trust.Enabled,
	)
	return server.ServeStdio(s)
}
