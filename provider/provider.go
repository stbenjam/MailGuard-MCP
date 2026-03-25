package provider

import "time"

type Attachment struct {
	Filename    string
	ContentType string
	Size        int64
}

type EmailEnvelope struct {
	MessageID   string
	From        string
	Subject     string
	Date        time.Time
	UID         uint32
	ReplyTo     string
	Attachments []Attachment
}

type EmailBody struct {
	MessageID string
	From      string
	PlainText string
}

// MailProvider abstracts email access. Implementations exist for IMAP and (future) Gmail API.
type MailProvider interface {
	// Connect authenticates and establishes a session.
	Connect() error

	// GetUnreadMessages returns envelopes for all UNSEEN messages in the inbox.
	GetUnreadMessages() ([]EmailEnvelope, error)

	// FetchMessage retrieves the full body of a single message by its Message-ID.
	FetchMessage(messageID string) (*EmailBody, error)

	// FetchAttachment retrieves an attachment by message ID and filename.
	// Returns the raw content, content type, and any error.
	FetchAttachment(messageID string, filename string) ([]byte, string, error)

	// Close tears down the connection.
	Close() error
}
