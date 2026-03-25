package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/stbenjam/mailguard-mcp/provider"
	"github.com/stbenjam/mailguard-mcp/security"
	"github.com/stbenjam/mailguard-mcp/truststore"
)

type Handler struct {
	provider      provider.MailProvider
	trustStore    *truststore.TrustStore
	attachmentDir string
	maxBodySize   int
}

func NewHandler(p provider.MailProvider, ts *truststore.TrustStore, attachmentDir string, maxBodySize int) *Handler {
	return &Handler{
		provider:      p,
		trustStore:    ts,
		attachmentDir: attachmentDir,
		maxBodySize:   maxBodySize,
	}
}

func (h *Handler) Register(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("get_unread_emails",
			mcp.WithDescription("Fetches unread emails from the inbox. Trusted senders show full details; untrusted senders show only a sanitized address."),
		),
		h.getUnreadEmails,
	)

	s.AddTool(
		mcp.NewTool("trust_sender",
			mcp.WithDescription("Adds an email address (or @domain.com for domain trust) to the trusted sender list."),
			mcp.WithString("email_address",
				mcp.Required(),
				mcp.Description("The email address or @domain to trust."),
			),
		),
		h.trustSender,
	)

	s.AddTool(
		mcp.NewTool("untrust_sender",
			mcp.WithDescription("Removes an email address (or @domain.com) from the trusted sender list."),
			mcp.WithString("email_address",
				mcp.Required(),
				mcp.Description("The email address or @domain to remove from trusted senders."),
			),
		),
		h.untrustSender,
	)

	s.AddTool(
		mcp.NewTool("fetch_message",
			mcp.WithDescription("Fetches the full plain-text body of an email by its message ID. Only works for trusted senders."),
			mcp.WithString("message_id",
				mcp.Required(),
				mcp.Description("The message ID of the email to fetch."),
			),
		),
		h.fetchMessage,
	)

	s.AddTool(
		mcp.NewTool("fetch_attachment",
			mcp.WithDescription("Downloads an attachment from a trusted sender's email to disk and returns the file path."),
			mcp.WithString("message_id",
				mcp.Required(),
				mcp.Description("The message ID of the email."),
			),
			mcp.WithString("filename",
				mcp.Required(),
				mcp.Description("The filename of the attachment to download."),
			),
		),
		h.fetchAttachment,
	)
}

func (h *Handler) getUnreadEmails(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	envelopes, err := h.provider.GetUnreadMessages()
	if err != nil {
		slog.Error("get_unread_emails failed", "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch emails: %v", err)), nil
	}

	if len(envelopes) == 0 {
		return mcp.NewToolResultText("No unread emails."), nil
	}

	var lines []string
	for _, env := range envelopes {
		addr, err := security.SanitizeAddress(env.From)
		if err != nil {
			lines = append(lines, fmt.Sprintf("<untrusted_sender>[invalid address]</untrusted_sender> | MessageID: %s", env.MessageID))
			continue
		}

		trusted, err := h.trustStore.IsTrusted(addr)
		if err != nil {
			slog.Error("trust check failed", "email", addr, "error", err)
			trusted = false
		}

		if trusted {
			line := fmt.Sprintf("From: %s | Subject: %s | Date: %s | MessageID: %s",
				addr,
				security.SanitizeContent(env.Subject),
				env.Date.Format("2006-01-02T15:04:05Z"),
				env.MessageID,
			)

			// Attachment metadata
			if len(env.Attachments) > 0 {
				var attachInfo []string
				for _, att := range env.Attachments {
					attachInfo = append(attachInfo, fmt.Sprintf("%s (%s, %s)",
						security.SanitizeFilename(att.Filename),
						att.ContentType,
						formatSize(att.Size),
					))
				}
				line += " | Attachments: " + strings.Join(attachInfo, ", ")
			}

			// Reply-To warning
			if env.ReplyTo != "" {
				replyAddr, err := security.SanitizeAddress(env.ReplyTo)
				if err == nil && replyAddr != addr {
					line += fmt.Sprintf(" | [WARNING: Reply-To (%s) differs from From]", replyAddr)
				}
			}

			lines = append(lines, line)
		} else {
			lines = append(lines, fmt.Sprintf("<untrusted_sender>%s</untrusted_sender> | MessageID: %s", addr, env.MessageID))
		}
	}

	return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
}

func (h *Handler) trustSender(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	emailAddress, err := request.RequireString("email_address")
	if err != nil {
		return mcp.NewToolResultError("email_address is required"), nil
	}

	addr := strings.ToLower(strings.TrimSpace(emailAddress))
	if err := security.ValidateAddress(addr); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid address: %v", err)), nil
	}

	if err := h.trustStore.Add(addr); err != nil {
		slog.Error("trust_sender failed", "email", addr, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to add trusted sender: %v", err)), nil
	}

	slog.Info("trust_sender", "email", addr, "result", "added")
	return mcp.NewToolResultText(fmt.Sprintf("Successfully added %s to trusted senders.", addr)), nil
}

func (h *Handler) untrustSender(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	emailAddress, err := request.RequireString("email_address")
	if err != nil {
		return mcp.NewToolResultError("email_address is required"), nil
	}

	addr := strings.ToLower(strings.TrimSpace(emailAddress))
	if err := security.ValidateAddress(addr); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid address: %v", err)), nil
	}

	if err := h.trustStore.Remove(addr); err != nil {
		slog.Error("untrust_sender failed", "email", addr, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to remove trusted sender: %v", err)), nil
	}

	slog.Info("untrust_sender", "email", addr, "result", "removed")
	return mcp.NewToolResultText(fmt.Sprintf("Successfully removed %s from trusted senders.", addr)), nil
}

func (h *Handler) fetchMessage(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	messageID, err := request.RequireString("message_id")
	if err != nil {
		return mcp.NewToolResultError("message_id is required"), nil
	}

	body, err := h.provider.FetchMessage(messageID)
	if err != nil {
		slog.Error("fetch_message failed", "message_id", messageID, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch message: %v", err)), nil
	}

	// Re-verify sender trust from actual message
	addr, err := security.SanitizeAddress(body.From)
	if err != nil {
		slog.Info("fetch_message", "message_id", messageID, "sender", body.From, "result", "denied_invalid_address")
		return mcp.NewToolResultError("Permission Denied: Cannot fetch body from untrusted sender."), nil
	}

	trusted, err := h.trustStore.IsTrusted(addr)
	if err != nil {
		slog.Error("trust check failed", "email", addr, "error", err)
		return mcp.NewToolResultError("Permission Denied: Cannot fetch body from untrusted sender."), nil
	}

	if !trusted {
		slog.Info("fetch_message", "message_id", messageID, "sender", addr, "result", "denied")
		return mcp.NewToolResultError("Permission Denied: Cannot fetch body from untrusted sender."), nil
	}

	slog.Info("fetch_message", "message_id", messageID, "sender", addr, "result", "trusted")

	text := security.SanitizeContent(body.PlainText)

	// Apply body size cap
	if h.maxBodySize > 0 && len(text) > h.maxBodySize {
		text = text[:h.maxBodySize] + "\n\n[Message truncated at " + fmt.Sprintf("%d", h.maxBodySize) + " bytes]"
	}

	return mcp.NewToolResultText(text), nil
}

func (h *Handler) fetchAttachment(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	messageID, err := request.RequireString("message_id")
	if err != nil {
		return mcp.NewToolResultError("message_id is required"), nil
	}

	filename, err := request.RequireString("filename")
	if err != nil {
		return mcp.NewToolResultError("filename is required"), nil
	}

	// First verify the sender is trusted by fetching the message
	body, err := h.provider.FetchMessage(messageID)
	if err != nil {
		slog.Error("fetch_attachment failed", "message_id", messageID, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch message: %v", err)), nil
	}

	addr, err := security.SanitizeAddress(body.From)
	if err != nil {
		slog.Info("fetch_attachment", "message_id", messageID, "filename", filename, "result", "denied_invalid_address")
		return mcp.NewToolResultError("Permission Denied: Cannot fetch attachments from untrusted sender."), nil
	}

	trusted, err := h.trustStore.IsTrusted(addr)
	if err != nil || !trusted {
		slog.Info("fetch_attachment", "message_id", messageID, "sender", addr, "filename", filename, "result", "denied")
		return mcp.NewToolResultError("Permission Denied: Cannot fetch attachments from untrusted sender."), nil
	}

	// Fetch the attachment
	content, contentType, err := h.provider.FetchAttachment(messageID, filename)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch attachment: %v", err)), nil
	}

	// Save to disk
	safeFilename := security.SanitizeFilename(filename)
	// Use a sanitized message ID for the directory name
	safeMsgID := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
			return '_'
		}
		return r
	}, messageID)

	dir := filepath.Join(h.attachmentDir, safeMsgID)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create attachment directory: %v", err)), nil
	}

	path := filepath.Join(dir, safeFilename)
	if err := os.WriteFile(path, content, 0640); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to save attachment: %v", err)), nil
	}

	slog.Info("fetch_attachment", "message_id", messageID, "sender", addr, "filename", safeFilename, "content_type", contentType, "size", len(content), "path", path, "result", "saved")

	return mcp.NewToolResultText(fmt.Sprintf("Attachment saved to: %s", path)), nil
}

func formatSize(bytes int64) string {
	switch {
	case bytes >= 1024*1024:
		return fmt.Sprintf("%.1fMB", float64(bytes)/(1024*1024))
	case bytes >= 1024:
		return fmt.Sprintf("%.1fKB", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}
