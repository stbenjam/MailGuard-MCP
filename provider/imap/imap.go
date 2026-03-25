package imap

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	gomessage "github.com/emersion/go-message/mail"
	"golang.org/x/net/html"

	"github.com/stbenjam/mailguard-mcp/config"
	"github.com/stbenjam/mailguard-mcp/provider"
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

func (p *IMAPProvider) GetUnreadMessages() ([]provider.EmailEnvelope, error) {
	criteria := &imap.SearchCriteria{
		NotFlag: []imap.Flag{imap.FlagSeen},
	}

	searchData, err := p.client.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("failed to search for unseen messages: %w", err)
	}

	uids := searchData.AllUIDs()
	if len(uids) == 0 {
		return nil, nil
	}

	fetchOpts := &imap.FetchOptions{
		Envelope:      true,
		BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
		UID:           true,
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

		// Extract attachment metadata from body structure
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

		envelopes = append(envelopes, provider.EmailEnvelope{
			MessageID:   strings.Trim(env.MessageID, "<>"),
			From:        from,
			Subject:     env.Subject,
			Date:        env.Date,
			UID:         uint32(msg.UID),
			ReplyTo:     replyTo,
			Attachments: attachments,
		})
	}

	return envelopes, nil
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

	// Parse MIME message
	mr, err := gomessage.CreateReader(bytes.NewReader(rawBody))
	if err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	// Extract From from actual message headers
	from := ""
	if addrs, err := mr.Header.AddressList("From"); err == nil && len(addrs) > 0 {
		from = addrs[0].Address
	}

	// Extract plain text body
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

		// Check if this part is an attachment with the matching filename
		if ah, ok := part.Header.(*gomessage.AttachmentHeader); ok {
			partFilename, _ := ah.Filename()
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
	}

	return nil, "", fmt.Errorf("attachment %q not found", filename)
}

func (p *IMAPProvider) Close() error {
	if p.client != nil {
		return p.client.Close()
	}
	return nil
}

// fetchByMessageID searches for a message by Message-ID header and returns its envelope data.
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

// extractPlainText walks MIME parts to find text/plain, falling back to stripped text/html.
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

// stripHTML extracts text content from HTML using the tokenizer.
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

