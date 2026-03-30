package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
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
	providers    map[string]provider.MailProvider
	accountOrder []string // deterministic iteration order
	trustStore   *truststore.TrustStore
	policy       *policy.Policy
}

func NewHandler(providers map[string]provider.MailProvider, ts *truststore.TrustStore, pol *policy.Policy) *Handler {
	// Sort account names for deterministic ordering
	order := make([]string, 0, len(providers))
	for name := range providers {
		order = append(order, name)
	}
	sort.Strings(order)

	return &Handler{
		providers:    providers,
		accountOrder: order,
		trustStore:   ts,
		policy:       pol,
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

// getProvider returns the provider for the given account name.
func (h *Handler) getProvider(account string) (provider.MailProvider, error) {
	p, ok := h.providers[account]
	if !ok {
		return nil, fmt.Errorf("unknown account: %q (available: %s)", account, strings.Join(h.accountOrder, ", "))
	}
	return p, nil
}

// getProviderForMessage resolves the provider from the account parameter (defaulting to
// first account in single-account mode) and selects the folder before message operations.
func (h *Handler) getProviderForMessage(request mcp.CallToolRequest) (provider.MailProvider, string, error) {
	account := request.GetString("account", "")
	if account == "" {
		if len(h.providers) == 1 {
			account = h.accountOrder[0]
		} else {
			return nil, "", fmt.Errorf("account is required in multi-account mode")
		}
	}

	p, err := h.getProvider(account)
	if err != nil {
		return nil, "", err
	}

	folder := request.GetString("folder", "")
	if folder != "" {
		if err := p.SelectFolder(folder); err != nil {
			return nil, "", err
		}
	}

	return p, account, nil
}

func (h *Handler) Register(s *server.MCPServer) {
	accountDesc := ""
	if len(h.providers) > 1 {
		accountDesc = fmt.Sprintf(" Available accounts: %s.", strings.Join(h.accountOrder, ", "))
	}

	s.AddTool(
		mcp.NewTool("list_folders",
			mcp.WithDescription("Lists all available mailbox folders for an account."),
			mcp.WithString("account",
				mcp.Description("List folders for a specific account. If omitted, lists folders for all accounts."+accountDesc),
			),
		),
		h.listFolders,
	)

	s.AddTool(
		mcp.NewTool("fetch_mail",
			mcp.WithDescription("Fetches emails from a mailbox folder. Trusted senders show full details; untrusted senders show only a sanitized address."),
			mcp.WithString("folder",
				mcp.Description("Mailbox folder to fetch from. Use list_folders to see available folders. Default: configured inbox."),
			),
			mcp.WithString("since",
				mcp.Description("How far back to fetch mail. Examples: \"1h\", \"24h\", \"7d\", \"30d\". Default: \"24h\"."),
			),
			mcp.WithBoolean("read",
				mcp.Description("Include already-read emails. Default: false (unread only)."),
			),
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of emails to return. Default: 50."),
			),
			mcp.WithString("account",
				mcp.Description("Fetch from a specific account only. If omitted, fetches from all accounts."+accountDesc),
			),
		),
		h.fetchMail,
	)

	s.AddTool(
		mcp.NewTool("search_mail",
			mcp.WithDescription("Searches emails by query in a mailbox folder. Trusted senders show full details; untrusted senders show only a sanitized address."),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("Search terms to match against subject, body, and sender."),
			),
			mcp.WithString("folder",
				mcp.Description("Mailbox folder to search in. Use list_folders to see available folders. Default: configured inbox."),
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
			mcp.WithString("account",
				mcp.Description("Search a specific account only. If omitted, searches all accounts."+accountDesc),
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
			mcp.WithString("account",
				mcp.Description("The account the message belongs to."+accountDesc),
			),
			mcp.WithString("folder",
				mcp.Description("The folder the message is in. Speeds up lookup if provided."),
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
			mcp.WithString("account",
				mcp.Description("The account the message belongs to."+accountDesc),
			),
			mcp.WithString("folder",
				mcp.Description("The folder the message is in."),
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
			mcp.WithString("account",
				mcp.Description("Account to create the draft in. Defaults to the first configured account."+accountDesc),
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
			mcp.WithString("account",
				mcp.Description("The account the message belongs to."+accountDesc),
			),
			mcp.WithString("folder",
				mcp.Description("The folder the message is in."),
			),
		),
		h.replyMail,
	)

	s.AddTool(
		mcp.NewTool("forward_mail",
			mcp.WithDescription("Forwards an email to new recipients and saves it as a draft for user review. Does NOT send the email. Only works for messages from trusted senders."),
			mcp.WithString("message_id",
				mcp.Required(),
				mcp.Description("The message ID of the email to forward."),
			),
			mcp.WithString("to",
				mcp.Required(),
				mcp.Description("Comma-separated list of recipient email addresses."),
			),
			mcp.WithString("comment",
				mcp.Description("Optional text to include above the forwarded message."),
			),
			mcp.WithString("account",
				mcp.Description("The account the message belongs to."+accountDesc),
			),
			mcp.WithString("folder",
				mcp.Description("The folder the message is in."),
			),
		),
		h.forwardMail,
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
			mcp.WithString("account",
				mcp.Description("The account the message belongs to."+accountDesc),
			),
			mcp.WithString("folder",
				mcp.Description("The folder the message is in."),
			),
		),
		h.updateMessage,
	)
}

func (h *Handler) listFolders(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	accountFilter := request.GetString("account", "")

	accounts, err := h.resolveAccounts(accountFilter)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	var buf strings.Builder
	for _, name := range accounts {
		p := h.providers[name]
		folders, err := p.ListFolders()
		if err != nil {
			slog.Error("list_folders failed", "account", name, "error", err)
			return mcp.NewToolResultError(fmt.Sprintf("Failed to list folders for %s: %v", name, err)), nil
		}

		if len(h.providers) > 1 {
			buf.WriteString(fmt.Sprintf("## %s\n", name))
		}
		for _, f := range folders {
			buf.WriteString(fmt.Sprintf("- %s\n", f))
		}
		if len(h.providers) > 1 {
			buf.WriteString("\n")
		}
	}

	return mcp.NewToolResultText(buf.String()), nil
}

func (h *Handler) fetchMail(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	since, err := parseSince(request.GetString("since", "24h"))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid 'since' value: %v", err)), nil
	}

	includeRead := request.GetBool("read", false)

	folder := request.GetString("folder", "")

	baseOpts := provider.FetchOptions{
		Since:       time.Now().Add(-since),
		IncludeRead: includeRead,
	}

	limit := request.GetInt("limit", 50)
	accountFilter := request.GetString("account", "")

	accounts, err := h.resolveAccounts(accountFilter)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	var allEnvelopes []accountEnvelope
	for _, name := range accounts {
		p := h.providers[name]
		folders, err := h.resolveFolders(p, folder)
		if err != nil {
			slog.Error("fetch_mail failed to resolve folders", "account", name, "error", err)
			continue
		}
		for _, f := range folders {
			opts := baseOpts
			opts.Folder = f
			envelopes, err := p.FetchMail(opts)
			if err != nil {
				slog.Error("fetch_mail failed", "account", name, "folder", f, "error", err)
				continue
			}
			for i := range envelopes {
				allEnvelopes = append(allEnvelopes, accountEnvelope{account: name, envelope: envelopes[i]})
			}
		}
	}

	if len(allEnvelopes) == 0 {
		return mcp.NewToolResultText("No emails found."), nil
	}

	// Sort by date descending
	sort.Slice(allEnvelopes, func(i, j int) bool {
		return allEnvelopes[i].envelope.Date.After(allEnvelopes[j].envelope.Date)
	})

	truncated := false
	if limit > 0 && len(allEnvelopes) > limit {
		allEnvelopes = allEnvelopes[:limit]
		truncated = true
	}

	result := h.formatAccountEnvelopes(allEnvelopes)
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
	folder := request.GetString("folder", "")

	baseOpts := provider.SearchOptions{
		FetchOptions: provider.FetchOptions{
			Since:       time.Now().Add(-since),
			IncludeRead: includeRead,
		},
		Query: query,
	}

	limit := request.GetInt("limit", 50)
	accountFilter := request.GetString("account", "")

	accounts, err := h.resolveAccounts(accountFilter)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	var allEnvelopes []accountEnvelope
	for _, name := range accounts {
		p := h.providers[name]
		folders, err := h.resolveFolders(p, folder)
		if err != nil {
			slog.Error("search_mail failed to resolve folders", "account", name, "error", err)
			continue
		}
		for _, f := range folders {
			opts := baseOpts
			opts.Folder = f
			envelopes, err := p.SearchMail(opts)
			if err != nil {
				slog.Error("search_mail failed", "account", name, "folder", f, "error", err)
				continue
			}
			for i := range envelopes {
				allEnvelopes = append(allEnvelopes, accountEnvelope{account: name, envelope: envelopes[i]})
			}
		}
	}

	if len(allEnvelopes) == 0 {
		return mcp.NewToolResultText("No emails found matching the search."), nil
	}

	sort.Slice(allEnvelopes, func(i, j int) bool {
		return allEnvelopes[i].envelope.Date.After(allEnvelopes[j].envelope.Date)
	})

	truncated := false
	if limit > 0 && len(allEnvelopes) > limit {
		allEnvelopes = allEnvelopes[:limit]
		truncated = true
	}

	result := h.formatAccountEnvelopes(allEnvelopes)
	if truncated {
		result += fmt.Sprintf("\n\n[Results limited to %d messages. Use a narrower 'since' or add 'limit' to see more.]", limit)
	}

	return mcp.NewToolResultText(result), nil
}

// accountEnvelope pairs an envelope with its source account name.
type accountEnvelope struct {
	account  string
	envelope provider.EmailEnvelope
}

// resolveAccounts returns the list of account names to query.
// If filter is empty, returns all accounts. If filter is set, validates it exists.
func (h *Handler) resolveAccounts(filter string) ([]string, error) {
	if filter == "" {
		return h.accountOrder, nil
	}
	if _, ok := h.providers[filter]; !ok {
		return nil, fmt.Errorf("unknown account: %q (available: %s)", filter, strings.Join(h.accountOrder, ", "))
	}
	return []string{filter}, nil
}

// resolveFolders returns the list of folders to search. If a specific folder is
// given, it returns just that folder. Otherwise it returns all searchable folders
// (all folders minus the configured exclude list).
func (h *Handler) resolveFolders(p provider.MailProvider, folder string) ([]string, error) {
	if folder != "" {
		return []string{folder}, nil
	}
	return p.SearchableFolders()
}

// emailResult is the JSON structure returned by fetch_mail and search_mail.
type emailResult struct {
	MessageID   string   `json:"message_id"`
	From        string   `json:"from"`
	Subject     string   `json:"subject,omitempty"`
	Date        string   `json:"date"`
	Folder      string   `json:"folder"`
	Account     string   `json:"account,omitempty"`
	Trusted     bool     `json:"trusted"`
	IsBulk      bool     `json:"is_bulk,omitempty"`
	Unsubscribe string   `json:"unsubscribe,omitempty"`
	Attachments []string `json:"attachments,omitempty"`
	ReplyTo     string   `json:"reply_to_warning,omitempty"`
}

func (h *Handler) formatAccountEnvelopes(envelopes []accountEnvelope) string {
	multiAccount := len(h.providers) > 1
	var results []emailResult

	for _, ae := range envelopes {
		addr, err := security.SanitizeAddress(ae.envelope.From)
		if err != nil {
			addr = "[invalid address]"
		}

		trusted, err := h.isTrusted(addr)
		if err != nil {
			slog.Error("trust check failed", "email", addr, "error", err)
			trusted = false
		}

		r := emailResult{
			MessageID: ae.envelope.MessageID,
			From:      addr,
			Date:      ae.envelope.Date.Format("2006-01-02T15:04:05Z"),
			Folder:    ae.envelope.Folder,
			Trusted:   trusted,
		}

		if multiAccount {
			r.Account = ae.account
		}

		if trusted {
			r.Subject = h.filterContent(ae.envelope.Subject)

			if ae.envelope.IsBulk {
				r.IsBulk = true
			}

			if ae.envelope.ListUnsubscribe != "" {
				r.Unsubscribe = ae.envelope.ListUnsubscribe
			}

			if len(ae.envelope.Attachments) > 0 {
				for _, att := range ae.envelope.Attachments {
					r.Attachments = append(r.Attachments, fmt.Sprintf("%s (%s, %s)",
						security.SanitizeFilename(att.Filename),
						att.ContentType,
						formatSize(att.Size),
					))
				}
			}

			if ae.envelope.ReplyTo != "" {
				replyAddr, err := security.SanitizeAddress(ae.envelope.ReplyTo)
				if err == nil && replyAddr != addr {
					r.ReplyTo = fmt.Sprintf("Reply-To (%s) differs from From", replyAddr)
				}
			}
		}

		results = append(results, r)
	}

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting results: %v", err)
	}
	return string(data)
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

	p, _, err := h.getProviderForMessage(request)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	body, err := p.FetchMessage(messageID)
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

	p, _, err := h.getProviderForMessage(request)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	body, err := p.FetchMessage(messageID)
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

	content, contentType, err := p.FetchAttachment(messageID, filename)
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

	p, _, err := h.getProviderForMessage(request)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Verify the sender is trusted
	body, err := p.FetchMessage(messageID)
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

	if err := p.UpdateMessage(messageID, read, flagged); err != nil {
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

	// Resolve account
	accountName := request.GetString("account", "")
	if accountName == "" {
		accountName = h.accountOrder[0]
	}
	p, err := h.getProvider(accountName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if err := p.CreateDraft(to, cc, subject, body); err != nil {
		slog.Error("send_mail failed", "account", accountName, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create draft: %v", err)), nil
	}

	slog.Info("send_mail", "account", accountName, "to", to, "cc", cc, "subject", subject, "result", "draft_created")
	return mcp.NewToolResultText(fmt.Sprintf("Draft created in %s (to: %s, subject: %q). The message has been saved to Drafts for your review — it has NOT been sent.", accountName, strings.Join(to, ", "), subject)), nil
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

	p, accountName, err := h.getProviderForMessage(request)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Fetch original message for headers
	original, err := p.FetchMessage(messageID)
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
	self := strings.ToLower(p.Address())
	to := []string{replyTo}

	var cc []string
	if replyAll {
		for _, a := range original.To {
			if a != replyTo && strings.ToLower(a) != self {
				to = append(to, a)
			}
		}
		for _, a := range original.CC {
			if strings.ToLower(a) != self {
				cc = append(cc, a)
			}
		}
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

	if err := p.CreateDraft(to, cc, subject, buf.String()); err != nil {
		slog.Error("reply_mail failed", "message_id", messageID, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create reply draft: %v", err)), nil
	}

	slog.Info("reply_mail", "account", accountName, "message_id", messageID, "to", to, "cc", cc, "reply_all", replyAll, "result", "draft_created")
	return mcp.NewToolResultText(fmt.Sprintf("Reply draft created in %s (to: %s, subject: %q). The message has been saved to Drafts for your review — it has NOT been sent.", accountName, strings.Join(to, ", "), subject)), nil
}

func (h *Handler) forwardMail(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	messageID, err := request.RequireString("message_id")
	if err != nil {
		return mcp.NewToolResultError("message_id is required"), nil
	}

	toRaw, err := request.RequireString("to")
	if err != nil {
		return mcp.NewToolResultError("to is required"), nil
	}
	to := parseAddressList(toRaw)
	if len(to) == 0 {
		return mcp.NewToolResultError("at least one recipient is required"), nil
	}

	comment := request.GetString("comment", "")

	if h.policy.Tools.ReadOnly {
		return mcp.NewToolResultError("forward_mail is disabled in read-only mode"), nil
	}

	p, accountName, err := h.getProviderForMessage(request)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	original, err := p.FetchMessage(messageID)
	if err != nil {
		slog.Error("forward_mail failed", "message_id", messageID, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch original message: %v", err)), nil
	}

	addr, err := security.SanitizeAddress(original.From)
	if err != nil {
		return mcp.NewToolResultError("Permission Denied: Cannot forward message from untrusted sender."), nil
	}

	trusted, err := h.isTrusted(addr)
	if err != nil || !trusted {
		slog.Info("forward_mail", "message_id", messageID, "sender", addr, "result", "denied")
		return mcp.NewToolResultError("Permission Denied: Cannot forward message from untrusted sender."), nil
	}

	// Build subject
	subject := original.Subject
	if !strings.HasPrefix(strings.ToLower(subject), "fwd:") {
		subject = "Fwd: " + subject
	}

	// Build forwarded body
	var buf strings.Builder
	if comment != "" {
		buf.WriteString(comment)
		buf.WriteString("\n\n")
	}
	buf.WriteString("---------- Forwarded message ----------\n")
	buf.WriteString(fmt.Sprintf("From: %s\n", original.From))
	buf.WriteString(fmt.Sprintf("Subject: %s\n", original.Subject))
	buf.WriteString(fmt.Sprintf("To: %s\n", strings.Join(original.To, ", ")))
	buf.WriteString("\n")
	buf.WriteString(original.PlainText)

	if err := p.CreateDraft(to, nil, subject, buf.String()); err != nil {
		slog.Error("forward_mail failed", "message_id", messageID, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create forward draft: %v", err)), nil
	}

	slog.Info("forward_mail", "account", accountName, "message_id", messageID, "to", to, "result", "draft_created")
	return mcp.NewToolResultText(fmt.Sprintf("Forward draft created in %s (to: %s, subject: %q). The message has been saved to Drafts for your review — it has NOT been sent.", accountName, strings.Join(to, ", "), subject)), nil
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
