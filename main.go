package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"

	"github.com/stbenjam/mailguard-mcp/config"
	"github.com/stbenjam/mailguard-mcp/provider"
	imapprovider "github.com/stbenjam/mailguard-mcp/provider/imap"
	"github.com/stbenjam/mailguard-mcp/tools"
	"github.com/stbenjam/mailguard-mcp/truststore"
)

func main() {
	var (
		readOnly bool
		trusted  bool
	)

	cmd := &cobra.Command{
		Use:   "mailguard-mcp",
		Short: "MCP server for secure LLM email access",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(readOnly, trusted)
		},
		SilenceUsage: true,
	}

	cmd.Flags().BoolVar(&readOnly, "read-only", false, "Only register read-only tools (no trust changes or message updates)")
	cmd.Flags().BoolVar(&trusted, "trusted", true, "Enforce trusted sender boundary (set to false to show all mail, useful for sandboxed agents)")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(readOnly, trusted bool) error {
	// Configure structured logging to stderr
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	ts, err := truststore.New(cfg.TrustStoreDBPath)
	if err != nil {
		return fmt.Errorf("failed to open trust store: %w", err)
	}
	defer ts.Close()

	// Seed trusted senders from config
	for _, addr := range cfg.TrustedSenders {
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
	h := tools.NewHandler(mp, ts, cfg.AttachmentDir, cfg.MaxBodySize, trusted)
	h.Register(s, readOnly)

	// Serve via stdio
	slog.Info("starting MailGuard-MCP server", "read_only", readOnly, "trust_enabled", trusted)
	return server.ServeStdio(s)
}
