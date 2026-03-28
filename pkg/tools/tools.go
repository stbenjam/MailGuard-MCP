package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/stbenjam/mailguard-mcp/pkg/policy"
	"github.com/stbenjam/mailguard-mcp/pkg/provider"
	"github.com/stbenjam/mailguard-mcp/pkg/security"
	"github.com/stbenjam/mailguard-mcp/pkg/truststore"
)

type Handler struct {
	provider   provider.MailProvider
	trustStore *truststore.TrustStore
	policy     *policy.Policy
}

func NewHandler(p provider.MailProvider, ts *truststore.TrustStore, pol *policy.Policy) *Handler {
	return &Handler{
		provider:   p,
		trustStore: ts,
		policy:     pol,
	}
}

// isTrusted returns true if the sender is trusted or if trust enforcement is disabled.
func (h *Handler) isTrusted(addr string) (bool, error) {
	if !h.policy.Trust.Enabled {
		return true, nil
	}
	return h.trustStore.IsTrusted(addr)
}

// filterContent applies the content filtering rules from the policy.
func (h *Handler) filterContent(text string) string {
	if h.policy.Content.SanitizePromptInjection {
		text = security.SanitizeContent(text)
	}

	if h.policy.Content.StripHTML {
		text = security.StripHTMLTags(text)
	}

	if h.policy.Content.StripQuotedReplies {
		text = security.StripQuotedReplies(text)
	}

	if h.policy.Content.StripSignatures {
		text = security.StripSignatures(text)
	}

	return text
}

func (h *Handler) Register(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("fetch_mail",
			mcp.WithDescription("Fetches emails from the inbox. Trusted senders show full details; untrusted senders show only a sanitized address."),
			mcp.WithString("since",
				mcp.Description("How far back to fetch mail. Examples: \"1h\", \"24h\", \"7d\", \"30d\". Default: \"24h\"."),
			),
			mcp.WithBoolean("read",
				mcp.Description("Include already-read emails. Default: false (unread only)."),
			),
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of emails to return. Default: 50."),
			),
		),
		h.fetchMail,
	)

	s.AddTool(
		mcp.NewTool("search_mail",
			mcp.WithDescription("Searches emails by query. Trusted senders show full details; untrusted senders show only a sanitized address."),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("Search terms to match against subject, body, and sender."),
			),
			mcp.WithString("since",
				mcp.Description("How far back to search. Examples: \"1h\", \"24h\", \"7d\", \"30d\". Default: \"7d\"."),
			),
			mcp.WithBoolean("read",
				mcp.Description("Include already-read emails. Default: true."),
			),
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of emails to return. Default: 50."),
			),
		),
		h.searchMail,
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

	if h.policy.Tools.ReadOnly {
		slog.Info("read-only mode enabled: write tools are disabled")
		return
	}

	s.AddTool(
		mcp.NewTool("send_mail",
			mcp.WithDescription("Composes an email and saves it as a draft for user review. Does NOT send the email."),
			mcp.WithString("to",
				mcp.Required(),
				mcp.Description("Comma-separated list of recipient email addresses."),
			),
			mcp.WithString("cc",
				mcp.Description("Comma-separated list of CC email addresses."),
			),
			mcp.WithString("subject",
				mcp.Required(),
				mcp.Description("The email subject line."),
			),
			mcp.WithString("body",
				mcp.Required(),
				mcp.Description("The plain-text email body."),
			),
		),
		h.sendMail,
	)

	s.AddTool(
		mcp.NewTool("reply_mail",
			mcp.WithDescription("Composes a reply to an existing email and saves it as a draft for user review. Does NOT send the email. Only works for trusted senders."),
			mcp.WithString("message_id",
				mcp.Required(),
				mcp.Description("The message ID of the email to reply to."),
			),
			mcp.WithString("body",
				mcp.Required(),
				mcp.Description("The plain-text reply body."),
			),
			mcp.WithBoolean("reply_all",
				mcp.Description("Include all original recipients (To/CC) in the reply. Default: true."),
			),
		),
		h.replyMail,
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
		mcp.NewTool("update_message",
			mcp.WithDescription("Updates flags on an email. Can mark as read/unread or flag/unflag. Only works for trusted senders."),
			mcp.WithString("message_id",
				mcp.Required(),
				mcp.Description("The message ID of the email to update."),
			),
			mcp.WithBoolean("read",
				mcp.Description("Set to true to mark as read, false to mark as unread."),
			),
			mcp.WithBoolean("flagged",
				mcp.Description("Set to true to flag/star, false to unflag."),
			),
		),
		h.updateMessage,
	)
}

func (h *Handler) fetchMail(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	since, err := parseSince(request.GetString("since", "24h"))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid 'since' value: %v", err)), nil
	}

	includeRead := request.GetBool("read", false)

	opts := provider.FetchOptions{
		Since:       time.Now().Add(-since),
		IncludeRead: includeRead,
	}

	limit := request.GetInt("limit", 50)

	envelopes, err := h.provider.FetchMail(opts)
	if err != nil {
		slog.Error("fetch_mail failed", "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch emails: %v", err)), nil
	}

	if len(envelopes) == 0 {
		return mcp.NewToolResultText("No emails found."), nil
	}

	truncated := false
	if limit > 0 && len(envelopes) > limit {
		envelopes = envelopes[:limit]
		truncated = true
	}

	result := h.formatEnvelopes(envelopes)
	if truncated {
		result += fmt.Sprintf("\n\n[Results limited to %d messages. Use a narrower 'since' or add 'limit' to see more.]", limit)
	}

	return mcp.NewToolResultText(result), nil
}

func (h *Handler) searchMail(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := request.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError("query is required"), nil
	}

	since, err := parseSince(request.GetString("since", "7d"))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid 'since' value: %v", err)), nil
	}

	includeRead := request.GetBool("read", true)

	opts := provider.SearchOptions{
		FetchOptions: provider.FetchOptions{
			Since:       time.Now().Add(-since),
			IncludeRead: includeRead,
		},
		Query: query,
	}

	limit := request.GetInt("limit", 50)

	envelopes, err := h.provider.SearchMail(opts)
	if err != nil {
		slog.Error("search_mail failed", "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to search emails: %v", err)), nil
	}

	if len(envelopes) == 0 {
		return mcp.NewToolResultText("No emails found matching the search."), nil
	}

	truncated := false
	if limit > 0 && len(envelopes) > limit {
		envelopes = envelopes[:limit]
		truncated = true
	}

	result := h.formatEnvelopes(envelopes)
	if truncated {
		result += fmt.Sprintf("\n\n[Results limited to %d messages. Use a narrower 'since' or add 'limit' to see more.]", limit)
	}

	return mcp.NewToolResultText(result), nil
}

func (h *Handler) formatEnvelopes(envelopes []provider.EmailEnvelope) string {
	var lines []string
	for _, env := range envelopes {
		addr, err := security.SanitizeAddress(env.From)
		if err != nil {
			lines = append(lines, fmt.Sprintf("<untrusted_sender>[invalid address]</untrusted_sender> | MessageID: %s", env.MessageID))
			continue
		}

		trusted, err := h.isTrusted(addr)
		if err != nil {
			slog.Error("trust check failed", "email", addr, "error", err)
			trusted = false
		}

		if trusted {
			line := fmt.Sprintf("From: %s | Subject: %s | Date: %s | MessageID: %s",
				addr,
				h.filterContent(env.Subject),
				env.Date.Format("2006-01-02T15:04:05Z"),
				env.MessageID,
			)

			if env.IsBulk {
				line += " | [Bulk/List mail]"
			}

			if env.ListUnsubscribe != "" {
				line += fmt.Sprintf(" | Unsubscribe: %s", env.ListUnsubscribe)
			}

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

	return strings.Join(lines, "\n")
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

	addr, err := security.SanitizeAddress(body.From)
	if err != nil {
		slog.Info("fetch_message", "message_id", messageID, "sender", body.From, "result", "denied_invalid_address")
		return mcp.NewToolResultError("Permission Denied: Cannot fetch body from untrusted sender."), nil
	}

	trusted, err := h.isTrusted(addr)
	if err != nil {
		slog.Error("trust check failed", "email", addr, "error", err)
		return mcp.NewToolResultError("Permission Denied: Cannot fetch body from untrusted sender."), nil
	}

	if !trusted {
		slog.Info("fetch_message", "message_id", messageID, "sender", addr, "result", "denied")
		return mcp.NewToolResultError("Permission Denied: Cannot fetch body from untrusted sender."), nil
	}

	slog.Info("fetch_message", "message_id", messageID, "sender", addr, "result", "trusted")

	text := h.filterContent(body.PlainText)

	maxBody := h.policy.Content.MaxBodySize
	if maxBody > 0 && len(text) > maxBody {
		text = text[:maxBody] + "\n\n[Message truncated at " + fmt.Sprintf("%d", maxBody) + " bytes]"
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

	trusted, err := h.isTrusted(addr)
	if err != nil || !trusted {
		slog.Info("fetch_attachment", "message_id", messageID, "sender", addr, "filename", filename, "result", "denied")
		return mcp.NewToolResultError("Permission Denied: Cannot fetch attachments from untrusted sender."), nil
	}

	content, contentType, err := h.provider.FetchAttachment(messageID, filename)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch attachment: %v", err)), nil
	}

	safeFilename := security.SanitizeFilename(filename)
	safeMsgID := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
			return '_'
		}
		return r
	}, messageID)

	dir := filepath.Join(h.policy.Attachments.Dir, safeMsgID)
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

func (h *Handler) updateMessage(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	messageID, err := request.RequireString("message_id")
	if err != nil {
		return mcp.NewToolResultError("message_id is required"), nil
	}

	// Verify the sender is trusted
	body, err := h.provider.FetchMessage(messageID)
	if err != nil {
		slog.Error("update_message failed", "message_id", messageID, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch message: %v", err)), nil
	}

	addr, err := security.SanitizeAddress(body.From)
	if err != nil {
		slog.Info("update_message", "message_id", messageID, "result", "denied_invalid_address")
		return mcp.NewToolResultError("Permission Denied: Cannot update messages from untrusted sender."), nil
	}

	trusted, err := h.isTrusted(addr)
	if err != nil || !trusted {
		slog.Info("update_message", "message_id", messageID, "sender", addr, "result", "denied")
		return mcp.NewToolResultError("Permission Denied: Cannot update messages from untrusted sender."), nil
	}

	// Parse optional boolean flags
	args := request.GetArguments()
	var read, flagged *bool

	if v, ok := args["read"]; ok {
		if b, ok := v.(bool); ok {
			read = &b
		}
	}
	if v, ok := args["flagged"]; ok {
		if b, ok := v.(bool); ok {
			flagged = &b
		}
	}

	if read == nil && flagged == nil {
		return mcp.NewToolResultError("Provide at least one of 'read' or 'flagged' to update."), nil
	}

	if err := h.provider.UpdateMessage(messageID, read, flagged); err != nil {
		slog.Error("update_message failed", "message_id", messageID, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to update message: %v", err)), nil
	}

	var updates []string
	if read != nil {
		if *read {
			updates = append(updates, "marked as read")
		} else {
			updates = append(updates, "marked as unread")
		}
	}
	if flagged != nil {
		if *flagged {
			updates = append(updates, "flagged")
		} else {
			updates = append(updates, "unflagged")
		}
	}

	slog.Info("update_message", "message_id", messageID, "sender", addr, "updates", strings.Join(updates, ", "), "result", "updated")
	return mcp.NewToolResultText(fmt.Sprintf("Message %s: %s.", messageID, strings.Join(updates, ", "))), nil
}

func (h *Handler) sendMail(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	toRaw, err := request.RequireString("to")
	if err != nil {
		return mcp.NewToolResultError("to is required"), nil
	}

	subject, err := request.RequireString("subject")
	if err != nil {
		return mcp.NewToolResultError("subject is required"), nil
	}

	body, err := request.RequireString("body")
	if err != nil {
		return mcp.NewToolResultError("body is required"), nil
	}

	to := parseAddressList(toRaw)
	if len(to) == 0 {
		return mcp.NewToolResultError("at least one valid recipient is required"), nil
	}

	var cc []string
	if ccRaw := request.GetString("cc", ""); ccRaw != "" {
		cc = parseAddressList(ccRaw)
	}

	if err := h.provider.CreateDraft(to, cc, subject, body); err != nil {
		slog.Error("send_mail failed", "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create draft: %v", err)), nil
	}

	slog.Info("send_mail", "to", to, "cc", cc, "subject", subject, "result", "draft_created")
	return mcp.NewToolResultText(fmt.Sprintf("Draft created (to: %s, subject: %q). The message has been saved to Drafts for your review — it has NOT been sent.", strings.Join(to, ", "), subject)), nil
}

func (h *Handler) replyMail(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	messageID, err := request.RequireString("message_id")
	if err != nil {
		return mcp.NewToolResultError("message_id is required"), nil
	}

	replyBody, err := request.RequireString("body")
	if err != nil {
		return mcp.NewToolResultError("body is required"), nil
	}

	replyAll := request.GetBool("reply_all", true)

	// Fetch original message for headers
	original, err := h.provider.FetchMessage(messageID)
	if err != nil {
		slog.Error("reply_mail failed", "message_id", messageID, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch original message: %v", err)), nil
	}

	addr, err := security.SanitizeAddress(original.From)
	if err != nil {
		return mcp.NewToolResultError("Permission Denied: Cannot reply to message from untrusted sender."), nil
	}

	trusted, err := h.isTrusted(addr)
	if err != nil || !trusted {
		slog.Info("reply_mail", "message_id", messageID, "sender", addr, "result", "denied")
		return mcp.NewToolResultError("Permission Denied: Cannot reply to message from untrusted sender."), nil
	}

	// Determine recipients
	replyTo := addr
	if original.ReplyTo != "" {
		replyTo = original.ReplyTo
	}
	to := []string{replyTo}

	var cc []string
	if replyAll {
		// Add original To recipients (minus our own address, which we don't know here)
		for _, a := range original.To {
			if a != replyTo {
				to = append(to, a)
			}
		}
		cc = original.CC
	}

	// Build subject
	subject := original.Subject
	if !strings.HasPrefix(strings.ToLower(subject), "re:") {
		subject = "Re: " + subject
	}

	// Build reply body with quoted original
	var buf strings.Builder
	buf.WriteString(replyBody)
	buf.WriteString("\n\n")
	buf.WriteString("--- Original Message ---\n")
	for _, line := range strings.Split(original.PlainText, "\n") {
		buf.WriteString("> ")
		buf.WriteString(line)
		buf.WriteString("\n")
	}

	if err := h.provider.CreateDraft(to, cc, subject, buf.String()); err != nil {
		slog.Error("reply_mail failed", "message_id", messageID, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create reply draft: %v", err)), nil
	}

	slog.Info("reply_mail", "message_id", messageID, "to", to, "cc", cc, "reply_all", replyAll, "result", "draft_created")
	return mcp.NewToolResultText(fmt.Sprintf("Reply draft created (to: %s, subject: %q). The message has been saved to Drafts for your review — it has NOT been sent.", strings.Join(to, ", "), subject)), nil
}

// parseAddressList splits a comma-separated list of email addresses and trims whitespace.
func parseAddressList(raw string) []string {
	var addrs []string
	for _, a := range strings.Split(raw, ",") {
		a = strings.TrimSpace(a)
		if a != "" {
			addrs = append(addrs, a)
		}
	}
	return addrs
}

// parseSince parses a duration string supporting "d" suffix for days in addition
// to standard Go duration suffixes (h, m, s).
func parseSince(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 24 * time.Hour, nil
	}

	// Handle "d" suffix for days
	if strings.HasSuffix(s, "d") {
		numStr := strings.TrimSuffix(s, "d")
		days, err := strconv.Atoi(numStr)
		if err != nil {
			return 0, fmt.Errorf("invalid days value: %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	return time.ParseDuration(s)
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
