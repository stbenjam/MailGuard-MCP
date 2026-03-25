package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/mark3labs/mcp-go/server"

	"github.com/stbenjam/mailguard-mcp/config"
	imapprovider "github.com/stbenjam/mailguard-mcp/provider/imap"
	"github.com/stbenjam/mailguard-mcp/provider"
	"github.com/stbenjam/mailguard-mcp/tools"
	"github.com/stbenjam/mailguard-mcp/truststore"
)

func main() {
	// Configure structured logging to stderr
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ts, err := truststore.New(cfg.TrustStoreDBPath)
	if err != nil {
		slog.Error("failed to open trust store", "error", err)
		os.Exit(1)
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
		slog.Error("unsupported mail provider", "provider", cfg.MailProvider)
		os.Exit(1)
	}

	if err := mp.Connect(); err != nil {
		slog.Error("failed to connect to mail provider", "error", err)
		os.Exit(1)
	}
	defer mp.Close()

	// Create MCP server
	s := server.NewMCPServer(
		"MailGuard-MCP",
		"0.1.0",
	)

	// Register tools
	h := tools.NewHandler(mp, ts, cfg.AttachmentDir, cfg.MaxBodySize)
	h.Register(s)

	// Serve via stdio
	slog.Info("starting MailGuard-MCP server")
	if err := server.ServeStdio(s); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
