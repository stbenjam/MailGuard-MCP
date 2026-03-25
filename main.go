package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"

	"github.com/stbenjam/mailguard-mcp/config"
	"github.com/stbenjam/mailguard-mcp/policy"
	"github.com/stbenjam/mailguard-mcp/provider"
	imapprovider "github.com/stbenjam/mailguard-mcp/provider/imap"
	"github.com/stbenjam/mailguard-mcp/tools"
	"github.com/stbenjam/mailguard-mcp/truststore"
)

func main() {
	var policyPath string

	cmd := &cobra.Command{
		Use:   "mailguard-mcp",
		Short: "MCP server for secure LLM email access",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(policyPath)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to policy YAML file (uses built-in defaults if not set)")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(policyPath string) error {
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

	// Create mail provider
	var mp provider.MailProvider
	switch cfg.MailProvider {
	case "imap":
		mp = imapprovider.New(cfg)
	default:
		return fmt.Errorf("unsupported mail provider: %s", cfg.MailProvider)
	}

	if err := mp.Connect(); err != nil {
		return fmt.Errorf("failed to connect to mail provider: %w", err)
	}
	defer mp.Close()

	// Create MCP server
	s := server.NewMCPServer(
		"MailGuard-MCP",
		"0.1.0",
	)

	// Register tools
	h := tools.NewHandler(mp, ts, pol)
	h.Register(s)

	// Serve via stdio
	slog.Info("starting MailGuard-MCP server",
		"read_only", pol.Tools.ReadOnly,
		"trust_enabled", pol.Trust.Enabled,
	)
	return server.ServeStdio(s)
}
