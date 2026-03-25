package provider

import "time"

type Attachment struct {
	Filename    string
	ContentType string
	Size        int64
}

type EmailEnvelope struct {
	MessageID       string
	From            string
	Subject         string
	Date            time.Time
	UID             uint32
	ReplyTo         string
	Attachments     []Attachment
	ListUnsubscribe string // Normalized unsubscribe URL, if present and valid
	IsBulk          bool   // True if message has bulk/list mail indicators
}

type EmailBody struct {
	MessageID string
	From      string
	PlainText string
}

// FetchOptions controls which messages to retrieve.
type FetchOptions struct {
	Since       time.Time // Only return messages since this time. Zero value means no lower bound.
	IncludeRead bool      // If true, include already-read messages. Default false (unread only).
}

// SearchOptions extends FetchOptions with a query string.
type SearchOptions struct {
	FetchOptions
	Query string // Free-text search query (searched in subject, body, and from).
}

// MailProvider abstracts email access. Implementations exist for IMAP and (future) Gmail API.
type MailProvider interface {
	// Connect authenticates and establishes a session.
	Connect() error

	// FetchMail returns envelopes matching the given options.
	FetchMail(opts FetchOptions) ([]EmailEnvelope, error)

	// SearchMail returns envelopes matching a search query and options.
	SearchMail(opts SearchOptions) ([]EmailEnvelope, error)

	// FetchMessage retrieves the full body of a single message by its Message-ID.
	FetchMessage(messageID string) (*EmailBody, error)

	// FetchAttachment retrieves an attachment by message ID and filename.
	// Returns the raw content, content type, and any error.
	FetchAttachment(messageID string, filename string) ([]byte, string, error)

	// UpdateMessage sets flags on a message. Nil values mean no change.
	UpdateMessage(messageID string, read *bool, flagged *bool) error

	// Close tears down the connection.
	Close() error
}
