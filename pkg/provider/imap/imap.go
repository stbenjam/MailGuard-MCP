package imap

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	gomessage "github.com/emersion/go-message/mail"
	"golang.org/x/net/html"

	"github.com/stbenjam/mailguard-mcp/pkg/config"
	"github.com/stbenjam/mailguard-mcp/pkg/provider"
)

type IMAPProvider struct {
	client *imapclient.Client
	config *config.Config
}

func New(cfg *config.Config) *IMAPProvider {
	return &IMAPProvider{config: cfg}
}

func (p *IMAPProvider) Connect() error {
	addr := fmt.Sprintf("%s:%d", p.config.IMAPHost, p.config.IMAPPort)

	var client *imapclient.Client
	var err error

	if p.config.IMAPTLS {
		client, err = imapclient.DialTLS(addr, nil)
	} else {
		client, err = imapclient.DialInsecure(addr, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to connect to IMAP server: %w", err)
	}

	if err := client.Login(p.config.IMAPUsername, p.config.IMAPPassword).Wait(); err != nil {
		client.Close()
		return fmt.Errorf("failed to login: %w", err)
	}

	if _, err := client.Select(p.config.IMAPMailbox, nil).Wait(); err != nil {
		client.Close()
		return fmt.Errorf("failed to select mailbox %s: %w", p.config.IMAPMailbox, err)
	}

	p.client = client
	slog.Info("connected to IMAP server", "host", p.config.IMAPHost, "mailbox", p.config.IMAPMailbox)
	return nil
}

func (p *IMAPProvider) FetchMail(opts provider.FetchOptions) ([]provider.EmailEnvelope, error) {
	criteria := p.buildCriteria(opts)
	return p.searchAndFetch(criteria)
}

func (p *IMAPProvider) SearchMail(opts provider.SearchOptions) ([]provider.EmailEnvelope, error) {
	criteria := p.buildCriteria(opts.FetchOptions)
	if opts.Query != "" {
		criteria.Text = []string{opts.Query}
	}
	return p.searchAndFetch(criteria)
}

func (p *IMAPProvider) buildCriteria(opts provider.FetchOptions) *imap.SearchCriteria {
	criteria := &imap.SearchCriteria{}

	if !opts.IncludeRead {
		criteria.NotFlag = []imap.Flag{imap.FlagSeen}
	}

	if !opts.Since.IsZero() {
		criteria.Since = opts.Since
	}

	return criteria
}

func (p *IMAPProvider) searchAndFetch(criteria *imap.SearchCriteria) ([]provider.EmailEnvelope, error) {
	searchData, err := p.client.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("failed to search messages: %w", err)
	}

	uids := searchData.AllUIDs()
	if len(uids) == 0 {
		return nil, nil
	}

	return p.fetchEnvelopes(uids)
}

// bulkHeaders is fetched alongside the envelope to detect bulk/list mail.
var bulkHeaderSection = &imap.FetchItemBodySection{
	Specifier:    imap.PartSpecifierHeader,
	HeaderFields: []string{"List-Unsubscribe", "List-Id", "Precedence"},
	Peek:         true,
}

func (p *IMAPProvider) fetchEnvelopes(uids []imap.UID) ([]provider.EmailEnvelope, error) {
	fetchOpts := &imap.FetchOptions{
		Envelope:      true,
		BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
		UID:           true,
		BodySection:   []*imap.FetchItemBodySection{bulkHeaderSection},
	}

	uidSet := imap.UIDSetNum(uids...)
	messages, err := p.client.Fetch(uidSet, fetchOpts).Collect()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch envelopes: %w", err)
	}

	var envelopes []provider.EmailEnvelope
	for _, msg := range messages {
		env := msg.Envelope
		if env == nil {
			continue
		}

		var from string
		if len(env.From) > 0 {
			from = env.From[0].Addr()
		}

		var replyTo string
		if len(env.ReplyTo) > 0 {
			replyTo = env.ReplyTo[0].Addr()
		}

		var attachments []provider.Attachment
		if msg.BodyStructure != nil {
			msg.BodyStructure.Walk(func(path []int, part imap.BodyStructure) bool {
				if single, ok := part.(*imap.BodyStructureSinglePart); ok {
					filename := single.Filename()
					if filename != "" {
						attachments = append(attachments, provider.Attachment{
							Filename:    filename,
							ContentType: single.Type + "/" + single.Subtype,
							Size:        int64(single.Size),
						})
					}
				}
				return true
			})
		}

		// Parse extra headers for bulk/list indicators
		var listUnsubscribe string
		var isBulk bool

		if headerBytes := msg.FindBodySection(bulkHeaderSection); headerBytes != nil {
			headers := parseSimpleHeaders(headerBytes)

			if unsub, ok := headers["list-unsubscribe"]; ok {
				listUnsubscribe = extractUnsubscribeURL(unsub)
			}

			if _, ok := headers["list-id"]; ok {
				isBulk = true
			}

			if prec, ok := headers["precedence"]; ok {
				prec = strings.ToLower(strings.TrimSpace(prec))
				if prec == "bulk" || prec == "list" || prec == "junk" {
					isBulk = true
				}
			}

			// List-Unsubscribe presence also indicates bulk
			if listUnsubscribe != "" {
				isBulk = true
			}
		}

		envelopes = append(envelopes, provider.EmailEnvelope{
			MessageID:       strings.Trim(env.MessageID, "<>"),
			From:            from,
			Subject:         env.Subject,
			Date:            env.Date,
			UID:             uint32(msg.UID),
			ReplyTo:         replyTo,
			Attachments:     attachments,
			ListUnsubscribe: listUnsubscribe,
			IsBulk:          isBulk,
		})
	}

	return envelopes, nil
}

// parseSimpleHeaders parses raw RFC 822 header bytes into a lowercase key -> value map.
func parseSimpleHeaders(data []byte) map[string]string {
	headers := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			value := strings.TrimSpace(line[idx+1:])
			headers[key] = value
		}
	}
	return headers
}

// extractUnsubscribeURL extracts the first valid HTTP(S) URL from a List-Unsubscribe header.
// The header value typically looks like: <mailto:unsub@list.com>, <https://example.com/unsub>
func extractUnsubscribeURL(value string) string {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "<>")
		if u, err := url.Parse(part); err == nil && (u.Scheme == "https" || u.Scheme == "http") {
			return part
		}
	}
	return ""
}

func (p *IMAPProvider) FetchMessage(messageID string) (*provider.EmailBody, error) {
	msg, err := p.fetchByMessageID(messageID)
	if err != nil {
		return nil, err
	}

	bodySection := &imap.FetchItemBodySection{}
	fetchOpts := &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{bodySection},
	}

	uidSet := imap.UIDSetNum(imap.UID(msg.UID))
	bodyMessages, err := p.client.Fetch(uidSet, fetchOpts).Collect()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch message body: %w", err)
	}

	if len(bodyMessages) == 0 {
		return nil, fmt.Errorf("message not found")
	}

	rawBody := bodyMessages[0].FindBodySection(bodySection)
	if rawBody == nil {
		return nil, fmt.Errorf("empty message body")
	}

	mr, err := gomessage.CreateReader(bytes.NewReader(rawBody))
	if err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	from := ""
	if addrs, err := mr.Header.AddressList("From"); err == nil && len(addrs) > 0 {
		from = addrs[0].Address
	}

	plainText, err := extractPlainText(mr)
	if err != nil {
		return nil, fmt.Errorf("failed to extract text: %w", err)
	}

	return &provider.EmailBody{
		MessageID: messageID,
		From:      from,
		PlainText: plainText,
	}, nil
}

func (p *IMAPProvider) FetchAttachment(messageID string, filename string) ([]byte, string, error) {
	msg, err := p.fetchByMessageID(messageID)
	if err != nil {
		return nil, "", err
	}

	bodySection := &imap.FetchItemBodySection{}
	fetchOpts := &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{bodySection},
	}

	uidSet := imap.UIDSetNum(imap.UID(msg.UID))
	bodyMessages, err := p.client.Fetch(uidSet, fetchOpts).Collect()
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch message: %w", err)
	}

	if len(bodyMessages) == 0 {
		return nil, "", fmt.Errorf("message not found")
	}

	rawBody := bodyMessages[0].FindBodySection(bodySection)
	if rawBody == nil {
		return nil, "", fmt.Errorf("empty message body")
	}

	mr, err := gomessage.CreateReader(bytes.NewReader(rawBody))
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse message: %w", err)
	}

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("failed to read part: %w", err)
		}

		partFilename := partName(part)
		if partFilename == filename {
			content, err := io.ReadAll(part.Body)
			if err != nil {
				return nil, "", fmt.Errorf("failed to read attachment: %w", err)
			}
			ct := part.Header.Get("Content-Type")
			if ct == "" {
				ct = "application/octet-stream"
			}
			return content, ct, nil
		}
	}

	return nil, "", fmt.Errorf("attachment %q not found", filename)
}

// partName extracts the filename from a MIME part, checking both attachment
// and inline headers, and falling back to Content-Type name parameter.
func partName(part *gomessage.Part) string {
	switch h := part.Header.(type) {
	case *gomessage.AttachmentHeader:
		if name, _ := h.Filename(); name != "" {
			return name
		}
	case *gomessage.InlineHeader:
		// Check Content-Disposition params first
		if _, params, err := h.ContentDisposition(); err == nil {
			if name := params["filename"]; name != "" {
				return name
			}
		}
		// Fall back to Content-Type name parameter
		if _, params, err := h.ContentType(); err == nil {
			if name := params["name"]; name != "" {
				return name
			}
		}
	}
	return ""
}

func (p *IMAPProvider) UpdateMessage(messageID string, read *bool, flagged *bool) error {
	msg, err := p.fetchByMessageID(messageID)
	if err != nil {
		return err
	}

	uidSet := imap.UIDSetNum(imap.UID(msg.UID))

	if read != nil {
		var op imap.StoreFlagsOp
		if *read {
			op = imap.StoreFlagsAdd
		} else {
			op = imap.StoreFlagsDel
		}
		if err := p.client.Store(uidSet, &imap.StoreFlags{
			Op:    op,
			Flags: []imap.Flag{imap.FlagSeen},
		}, nil).Close(); err != nil {
			return fmt.Errorf("failed to update read flag: %w", err)
		}
	}

	if flagged != nil {
		var op imap.StoreFlagsOp
		if *flagged {
			op = imap.StoreFlagsAdd
		} else {
			op = imap.StoreFlagsDel
		}
		if err := p.client.Store(uidSet, &imap.StoreFlags{
			Op:    op,
			Flags: []imap.Flag{imap.FlagFlagged},
		}, nil).Close(); err != nil {
			return fmt.Errorf("failed to update flagged flag: %w", err)
		}
	}

	return nil
}

func (p *IMAPProvider) Close() error {
	if p.client != nil {
		if err := p.client.Logout().Wait(); err != nil {
			slog.Warn("IMAP logout failed", "error", err)
		}
		return p.client.Close()
	}
	return nil
}

func (p *IMAPProvider) fetchByMessageID(messageID string) (*imapclient.FetchMessageBuffer, error) {
	criteria := &imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{
			{Key: "Message-Id", Value: messageID},
		},
	}

	searchData, err := p.client.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("failed to search for message: %w", err)
	}

	uids := searchData.AllUIDs()
	if len(uids) == 0 {
		return nil, fmt.Errorf("message with ID %q not found", messageID)
	}

	fetchOpts := &imap.FetchOptions{
		Envelope: true,
		UID:      true,
	}

	messages, err := p.client.Fetch(imap.UIDSetNum(uids[0]), fetchOpts).Collect()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch message: %w", err)
	}

	if len(messages) == 0 {
		return nil, fmt.Errorf("message not found")
	}

	return messages[0], nil
}

func extractPlainText(mr *gomessage.Reader) (string, error) {
	var plainText string
	var htmlText string

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil
		}

		ct := part.Header.Get("Content-Type")
		body, err := io.ReadAll(part.Body)
		if err != nil {
			continue
		}

		if strings.HasPrefix(ct, "text/plain") || ct == "" {
			plainText = string(body)
		} else if strings.HasPrefix(ct, "text/html") && plainText == "" {
			htmlText = string(body)
		}
	}

	if plainText != "" {
		return plainText, nil
	}
	if htmlText != "" {
		return stripHTML(htmlText), nil
	}
	return "", nil
}

func stripHTML(htmlContent string) string {
	tokenizer := html.NewTokenizer(strings.NewReader(htmlContent))
	var result strings.Builder
	skipContent := false

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return strings.TrimSpace(result.String())
		case html.StartTagToken:
			tn, _ := tokenizer.TagName()
			tag := string(tn)
			if tag == "script" || tag == "style" {
				skipContent = true
			}
			if tag == "br" || tag == "p" || tag == "div" || tag == "li" {
				result.WriteString("\n")
			}
		case html.EndTagToken:
			tn, _ := tokenizer.TagName()
			tag := string(tn)
			if tag == "script" || tag == "style" {
				skipContent = false
			}
		case html.TextToken:
			if !skipContent {
				text := strings.TrimSpace(tokenizer.Token().Data)
				if text != "" {
					result.WriteString(text)
					result.WriteString(" ")
				}
			}
		}
	}
}
