package tools

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/stbenjam/mailguard-mcp/provider"
	"github.com/stbenjam/mailguard-mcp/truststore"
)

type mockProvider struct {
	envelopes      []provider.EmailEnvelope
	bodies         map[string]*provider.EmailBody
	attachments    map[string]map[string][]byte
	lastFetchOpts  *provider.FetchOptions
	lastSearchOpts *provider.SearchOptions
	updatedFlags   map[string]map[string]*bool // messageID -> flag name -> value
}

func (m *mockProvider) Connect() error { return nil }
func (m *mockProvider) Close() error   { return nil }

func (m *mockProvider) FetchMail(opts provider.FetchOptions) ([]provider.EmailEnvelope, error) {
	m.lastFetchOpts = &opts
	return m.envelopes, nil
}

func (m *mockProvider) SearchMail(opts provider.SearchOptions) ([]provider.EmailEnvelope, error) {
	m.lastSearchOpts = &opts
	return m.envelopes, nil
}

func (m *mockProvider) FetchMessage(messageID string) (*provider.EmailBody, error) {
	if body, ok := m.bodies[messageID]; ok {
		return body, nil
	}
	return nil, fmt.Errorf("message not found")
}

func (m *mockProvider) UpdateMessage(messageID string, read *bool, flagged *bool) error {
	if _, ok := m.bodies[messageID]; !ok {
		return fmt.Errorf("message not found")
	}
	if m.updatedFlags == nil {
		m.updatedFlags = make(map[string]map[string]*bool)
	}
	m.updatedFlags[messageID] = map[string]*bool{"read": read, "flagged": flagged}
	return nil
}

func (m *mockProvider) FetchAttachment(messageID string, filename string) ([]byte, string, error) {
	if msgAttachments, ok := m.attachments[messageID]; ok {
		if content, ok := msgAttachments[filename]; ok {
			return content, "application/octet-stream", nil
		}
	}
	return nil, "", fmt.Errorf("attachment not found")
}

func newTestHandler(t *testing.T, mp *mockProvider) *Handler {
	t.Helper()
	ts, err := truststore.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ts.Close() })

	return NewHandler(mp, ts, t.TempDir(), 32768)
}

func callTool(h *Handler, name string, args map[string]any) (*mcp.CallToolResult, error) {
	req := mcp.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args
	ctx := context.Background()

	switch name {
	case "fetch_mail":
		return h.fetchMail(ctx, req)
	case "search_mail":
		return h.searchMail(ctx, req)
	case "trust_sender":
		return h.trustSender(ctx, req)
	case "untrust_sender":
		return h.untrustSender(ctx, req)
	case "fetch_message":
		return h.fetchMessage(ctx, req)
	case "fetch_attachment":
		return h.fetchAttachment(ctx, req)
	case "update_message":
		return h.updateMessage(ctx, req)
	}
	return nil, fmt.Errorf("unknown tool: %s", name)
}

func resultText(r *mcp.CallToolResult) string {
	if len(r.Content) > 0 {
		if tc, ok := r.Content[0].(mcp.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}

// --- fetch_mail tests ---

func TestFetchMail_TrustedAndUntrusted(t *testing.T) {
	mp := &mockProvider{
		envelopes: []provider.EmailEnvelope{
			{MessageID: "msg1", From: "trusted@example.com", Subject: "Hello", Date: time.Date(2026, 3, 24, 10, 0, 0, 0, time.UTC)},
			{MessageID: "msg2", From: "untrusted@evil.com", Subject: "Phishing", Date: time.Date(2026, 3, 24, 11, 0, 0, 0, time.UTC)},
		},
	}

	h := newTestHandler(t, mp)
	h.trustStore.Add("trusted@example.com")

	result, err := callTool(h, "fetch_mail", nil)
	if err != nil {
		t.Fatal(err)
	}

	text := resultText(result)

	if !strings.Contains(text, "From: trusted@example.com") {
		t.Error("expected trusted sender details")
	}
	if !strings.Contains(text, "Subject: Hello") {
		t.Error("expected subject for trusted sender")
	}
	if !strings.Contains(text, "<untrusted_sender>untrusted@evil.com</untrusted_sender>") {
		t.Error("expected untrusted sender in tags")
	}
	if strings.Contains(text, "Phishing") {
		t.Error("untrusted sender subject should be redacted")
	}
}

func TestFetchMail_DefaultSince(t *testing.T) {
	mp := &mockProvider{}
	h := newTestHandler(t, mp)

	callTool(h, "fetch_mail", nil)

	if mp.lastFetchOpts == nil {
		t.Fatal("expected FetchMail to be called")
	}
	// Default since is 24h, so Since should be roughly 24h ago
	expectedSince := time.Now().Add(-24 * time.Hour)
	diff := mp.lastFetchOpts.Since.Sub(expectedSince)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expected Since ~24h ago, got %v", mp.lastFetchOpts.Since)
	}
	if mp.lastFetchOpts.IncludeRead {
		t.Error("expected IncludeRead=false by default")
	}
}

func TestFetchMail_WithSinceAndRead(t *testing.T) {
	mp := &mockProvider{}
	h := newTestHandler(t, mp)

	callTool(h, "fetch_mail", map[string]any{"since": "7d", "read": true})

	if mp.lastFetchOpts == nil {
		t.Fatal("expected FetchMail to be called")
	}
	expectedSince := time.Now().Add(-7 * 24 * time.Hour)
	diff := mp.lastFetchOpts.Since.Sub(expectedSince)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expected Since ~7d ago, got %v", mp.lastFetchOpts.Since)
	}
	if !mp.lastFetchOpts.IncludeRead {
		t.Error("expected IncludeRead=true")
	}
}

func TestFetchMail_ReplyToWarning(t *testing.T) {
	mp := &mockProvider{
		envelopes: []provider.EmailEnvelope{
			{MessageID: "msg1", From: "trusted@example.com", ReplyTo: "attacker@evil.com", Subject: "Hey", Date: time.Now()},
		},
	}

	h := newTestHandler(t, mp)
	h.trustStore.Add("trusted@example.com")

	result, _ := callTool(h, "fetch_mail", nil)
	text := resultText(result)

	if !strings.Contains(text, "WARNING: Reply-To") {
		t.Error("expected Reply-To warning")
	}
}

func TestFetchMail_NoMessages(t *testing.T) {
	mp := &mockProvider{}
	h := newTestHandler(t, mp)

	result, _ := callTool(h, "fetch_mail", nil)
	text := resultText(result)

	if text != "No emails found." {
		t.Errorf("expected 'No emails found.', got %q", text)
	}
}

func TestFetchMail_Limit(t *testing.T) {
	var envelopes []provider.EmailEnvelope
	for i := 0; i < 10; i++ {
		envelopes = append(envelopes, provider.EmailEnvelope{
			MessageID: fmt.Sprintf("msg%d", i),
			From:      "trusted@example.com",
			Subject:   fmt.Sprintf("Email %d", i),
			Date:      time.Now(),
		})
	}

	mp := &mockProvider{envelopes: envelopes}
	h := newTestHandler(t, mp)
	h.trustStore.Add("trusted@example.com")

	result, _ := callTool(h, "fetch_mail", map[string]any{"limit": 3})
	text := resultText(result)

	if !strings.Contains(text, "Results limited to 3 messages") {
		t.Error("expected truncation notice")
	}
	// Should have exactly 3 "From:" lines
	count := strings.Count(text, "From: trusted@example.com")
	if count != 3 {
		t.Errorf("expected 3 results, got %d", count)
	}
}

func TestFetchMail_DefaultLimitNotShownWhenUnderLimit(t *testing.T) {
	mp := &mockProvider{
		envelopes: []provider.EmailEnvelope{
			{MessageID: "msg1", From: "trusted@example.com", Subject: "Hello", Date: time.Now()},
		},
	}
	h := newTestHandler(t, mp)
	h.trustStore.Add("trusted@example.com")

	result, _ := callTool(h, "fetch_mail", nil)
	text := resultText(result)

	if strings.Contains(text, "Results limited") {
		t.Error("should not show truncation notice when under limit")
	}
}

func TestFetchMail_InvalidSince(t *testing.T) {
	mp := &mockProvider{}
	h := newTestHandler(t, mp)

	result, _ := callTool(h, "fetch_mail", map[string]any{"since": "garbage"})
	if !result.IsError {
		t.Error("expected error for invalid since")
	}
}

// --- search_mail tests ---

func TestSearchMail_PassesQuery(t *testing.T) {
	mp := &mockProvider{}
	h := newTestHandler(t, mp)

	callTool(h, "search_mail", map[string]any{"query": "invoice"})

	if mp.lastSearchOpts == nil {
		t.Fatal("expected SearchMail to be called")
	}
	if mp.lastSearchOpts.Query != "invoice" {
		t.Errorf("expected query 'invoice', got %q", mp.lastSearchOpts.Query)
	}
}

func TestSearchMail_DefaultsSince7dReadTrue(t *testing.T) {
	mp := &mockProvider{}
	h := newTestHandler(t, mp)

	callTool(h, "search_mail", map[string]any{"query": "test"})

	if mp.lastSearchOpts == nil {
		t.Fatal("expected SearchMail to be called")
	}
	expectedSince := time.Now().Add(-7 * 24 * time.Hour)
	diff := mp.lastSearchOpts.Since.Sub(expectedSince)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expected Since ~7d ago, got %v", mp.lastSearchOpts.Since)
	}
	if !mp.lastSearchOpts.IncludeRead {
		t.Error("expected IncludeRead=true by default for search")
	}
}

func TestSearchMail_TrustedAndUntrusted(t *testing.T) {
	mp := &mockProvider{
		envelopes: []provider.EmailEnvelope{
			{MessageID: "msg1", From: "trusted@example.com", Subject: "Invoice #123", Date: time.Now()},
			{MessageID: "msg2", From: "untrusted@evil.com", Subject: "Fake invoice", Date: time.Now()},
		},
	}

	h := newTestHandler(t, mp)
	h.trustStore.Add("trusted@example.com")

	result, _ := callTool(h, "search_mail", map[string]any{"query": "invoice"})
	text := resultText(result)

	if !strings.Contains(text, "Subject: Invoice #123") {
		t.Error("expected trusted sender subject in results")
	}
	if strings.Contains(text, "Fake invoice") {
		t.Error("untrusted sender subject should be redacted in search results")
	}
	if !strings.Contains(text, "<untrusted_sender>untrusted@evil.com</untrusted_sender>") {
		t.Error("expected untrusted sender in tags")
	}
}

func TestSearchMail_NoResults(t *testing.T) {
	mp := &mockProvider{}
	h := newTestHandler(t, mp)

	result, _ := callTool(h, "search_mail", map[string]any{"query": "nonexistent"})
	text := resultText(result)

	if text != "No emails found matching the search." {
		t.Errorf("expected no results message, got %q", text)
	}
}

func TestFetchMail_BulkMailIndicator(t *testing.T) {
	mp := &mockProvider{
		envelopes: []provider.EmailEnvelope{
			{MessageID: "msg1", From: "newsletter@example.com", Subject: "Weekly digest", Date: time.Now(), IsBulk: true, ListUnsubscribe: "https://example.com/unsub"},
		},
	}

	h := newTestHandler(t, mp)
	h.trustStore.Add("newsletter@example.com")

	result, _ := callTool(h, "fetch_mail", nil)
	text := resultText(result)

	if !strings.Contains(text, "[Bulk/List mail]") {
		t.Error("expected bulk mail indicator")
	}
	if !strings.Contains(text, "Unsubscribe: https://example.com/unsub") {
		t.Error("expected unsubscribe URL")
	}
}

// --- parseSince tests ---

func TestParseSince(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
		err   bool
	}{
		{"1h", time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"", 24 * time.Hour, false},
		{"garbage", 0, true},
		{"xd", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseSince(tt.input)
			if (err != nil) != tt.err {
				t.Errorf("parseSince(%q) error = %v, wantErr %v", tt.input, err, tt.err)
				return
			}
			if got != tt.want {
				t.Errorf("parseSince(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- trust/untrust tests ---

func TestTrustSender(t *testing.T) {
	mp := &mockProvider{}
	h := newTestHandler(t, mp)

	result, _ := callTool(h, "trust_sender", map[string]any{"email_address": "alice@example.com"})
	text := resultText(result)

	if !strings.Contains(text, "Successfully added") {
		t.Error("expected success message")
	}

	trusted, _ := h.trustStore.IsTrusted("alice@example.com")
	if !trusted {
		t.Error("expected sender to be trusted")
	}
}

func TestTrustSender_Domain(t *testing.T) {
	mp := &mockProvider{}
	h := newTestHandler(t, mp)

	result, _ := callTool(h, "trust_sender", map[string]any{"email_address": "@example.com"})
	if result.IsError {
		t.Errorf("expected success, got error: %s", resultText(result))
	}

	trusted, _ := h.trustStore.IsTrusted("anyone@example.com")
	if !trusted {
		t.Error("expected domain trust to work")
	}
}

func TestTrustSender_InvalidAddress(t *testing.T) {
	mp := &mockProvider{}
	h := newTestHandler(t, mp)

	result, _ := callTool(h, "trust_sender", map[string]any{"email_address": "not-valid"})
	if !result.IsError {
		t.Error("expected error for invalid address")
	}
}

func TestUntrustSender(t *testing.T) {
	mp := &mockProvider{}
	h := newTestHandler(t, mp)

	h.trustStore.Add("alice@example.com")
	result, _ := callTool(h, "untrust_sender", map[string]any{"email_address": "alice@example.com"})

	if !strings.Contains(resultText(result), "Successfully removed") {
		t.Error("expected success message")
	}

	trusted, _ := h.trustStore.IsTrusted("alice@example.com")
	if trusted {
		t.Error("expected sender to be untrusted")
	}
}

// --- fetch_message tests ---

func TestFetchMessage_Trusted(t *testing.T) {
	mp := &mockProvider{
		bodies: map[string]*provider.EmailBody{
			"msg1": {MessageID: "msg1", From: "trusted@example.com", PlainText: "Hello, this is the body."},
		},
	}

	h := newTestHandler(t, mp)
	h.trustStore.Add("trusted@example.com")

	result, _ := callTool(h, "fetch_message", map[string]any{"message_id": "msg1"})
	text := resultText(result)

	if !strings.Contains(text, "Hello, this is the body.") {
		t.Error("expected message body")
	}
}

func TestFetchMessage_Untrusted(t *testing.T) {
	mp := &mockProvider{
		bodies: map[string]*provider.EmailBody{
			"msg1": {MessageID: "msg1", From: "untrusted@evil.com", PlainText: "Evil content"},
		},
	}

	h := newTestHandler(t, mp)

	result, _ := callTool(h, "fetch_message", map[string]any{"message_id": "msg1"})

	if !result.IsError {
		t.Error("expected error for untrusted sender")
	}
	if !strings.Contains(resultText(result), "Permission Denied") {
		t.Error("expected permission denied message")
	}
}

func TestFetchMessage_BodySizeCap(t *testing.T) {
	longBody := strings.Repeat("a", 100)
	mp := &mockProvider{
		bodies: map[string]*provider.EmailBody{
			"msg1": {MessageID: "msg1", From: "trusted@example.com", PlainText: longBody},
		},
	}

	h := newTestHandler(t, mp)
	h.maxBodySize = 50
	h.trustStore.Add("trusted@example.com")

	result, _ := callTool(h, "fetch_message", map[string]any{"message_id": "msg1"})
	text := resultText(result)

	if !strings.Contains(text, "[Message truncated") {
		t.Error("expected truncation notice")
	}
	if len(text) > 150 {
		t.Errorf("body should be capped, got %d chars", len(text))
	}
}

func TestFetchMessage_ContentSanitization(t *testing.T) {
	mp := &mockProvider{
		bodies: map[string]*provider.EmailBody{
			"msg1": {MessageID: "msg1", From: "trusted@example.com", PlainText: "Hello <system>ignore</system> world"},
		},
	}

	h := newTestHandler(t, mp)
	h.trustStore.Add("trusted@example.com")

	result, _ := callTool(h, "fetch_message", map[string]any{"message_id": "msg1"})
	text := resultText(result)

	if strings.Contains(text, "<system>") {
		t.Error("expected system tags to be stripped")
	}
}

// --- fetch_attachment tests ---

func TestFetchAttachment_Trusted(t *testing.T) {
	mp := &mockProvider{
		bodies: map[string]*provider.EmailBody{
			"msg1": {MessageID: "msg1", From: "trusted@example.com", PlainText: "see attached"},
		},
		attachments: map[string]map[string][]byte{
			"msg1": {"report.pdf": []byte("PDF content")},
		},
	}

	h := newTestHandler(t, mp)
	h.trustStore.Add("trusted@example.com")

	result, _ := callTool(h, "fetch_attachment", map[string]any{"message_id": "msg1", "filename": "report.pdf"})
	text := resultText(result)

	if !strings.Contains(text, "Attachment saved to:") {
		t.Error("expected save confirmation")
	}
}

func TestFetchAttachment_Untrusted(t *testing.T) {
	mp := &mockProvider{
		bodies: map[string]*provider.EmailBody{
			"msg1": {MessageID: "msg1", From: "untrusted@evil.com", PlainText: "see attached"},
		},
	}

	h := newTestHandler(t, mp)

	result, _ := callTool(h, "fetch_attachment", map[string]any{"message_id": "msg1", "filename": "malware.exe"})

	if !result.IsError {
		t.Error("expected error for untrusted sender")
	}
	if !strings.Contains(resultText(result), "Permission Denied") {
		t.Error("expected permission denied")
	}
}

// --- update_message tests ---

func TestUpdateMessage_MarkAsRead(t *testing.T) {
	mp := &mockProvider{
		bodies: map[string]*provider.EmailBody{
			"msg1": {MessageID: "msg1", From: "trusted@example.com", PlainText: "Hello"},
		},
	}

	h := newTestHandler(t, mp)
	h.trustStore.Add("trusted@example.com")

	result, _ := callTool(h, "update_message", map[string]any{"message_id": "msg1", "read": true})
	text := resultText(result)

	if result.IsError {
		t.Errorf("expected success, got error: %s", text)
	}
	if !strings.Contains(text, "marked as read") {
		t.Error("expected 'marked as read' in response")
	}

	flags := mp.updatedFlags["msg1"]
	if flags["read"] == nil || !*flags["read"] {
		t.Error("expected read flag to be set to true")
	}
}

func TestUpdateMessage_FlagAndUnread(t *testing.T) {
	mp := &mockProvider{
		bodies: map[string]*provider.EmailBody{
			"msg1": {MessageID: "msg1", From: "trusted@example.com", PlainText: "Hello"},
		},
	}

	h := newTestHandler(t, mp)
	h.trustStore.Add("trusted@example.com")

	result, _ := callTool(h, "update_message", map[string]any{"message_id": "msg1", "read": false, "flagged": true})
	text := resultText(result)

	if !strings.Contains(text, "marked as unread") {
		t.Error("expected 'marked as unread'")
	}
	if !strings.Contains(text, "flagged") {
		t.Error("expected 'flagged'")
	}
}

func TestUpdateMessage_Untrusted(t *testing.T) {
	mp := &mockProvider{
		bodies: map[string]*provider.EmailBody{
			"msg1": {MessageID: "msg1", From: "untrusted@evil.com", PlainText: "Hello"},
		},
	}

	h := newTestHandler(t, mp)

	result, _ := callTool(h, "update_message", map[string]any{"message_id": "msg1", "read": true})

	if !result.IsError {
		t.Error("expected error for untrusted sender")
	}
	if !strings.Contains(resultText(result), "Permission Denied") {
		t.Error("expected permission denied")
	}
}

func TestUpdateMessage_NoFlags(t *testing.T) {
	mp := &mockProvider{
		bodies: map[string]*provider.EmailBody{
			"msg1": {MessageID: "msg1", From: "trusted@example.com", PlainText: "Hello"},
		},
	}

	h := newTestHandler(t, mp)
	h.trustStore.Add("trusted@example.com")

	result, _ := callTool(h, "update_message", map[string]any{"message_id": "msg1"})

	if !result.IsError {
		t.Error("expected error when no flags provided")
	}
	if !strings.Contains(resultText(result), "Provide at least one") {
		t.Error("expected hint about providing flags")
	}
}
