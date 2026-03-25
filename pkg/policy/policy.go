package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Policy defines the security and behavior configuration for MailGuard-MCP.
type Policy struct {
	Trust       Trust       `yaml:"trust"`
	Tools       Tools       `yaml:"tools"`
	Content     Content     `yaml:"content"`
	Attachments Attachments `yaml:"attachments"`
}

// Trust controls the trusted sender boundary.
type Trust struct {
	// Enabled enforces the trusted sender boundary. When false, all senders
	// are treated as trusted (useful for sandboxed agents).
	Enabled bool `yaml:"enabled"`

	// Senders is a list of pre-trusted email addresses or @domain patterns
	// that are seeded into the trust store on startup.
	Senders []string `yaml:"senders"`
}

// Tools controls which MCP tools are registered.
type Tools struct {
	// ReadOnly disables write tools (trust_sender, untrust_sender, update_message).
	ReadOnly bool `yaml:"read_only"`
}

// Content controls how message content is filtered before being returned.
type Content struct {
	// MaxBodySize is the maximum number of bytes to return for a message body.
	MaxBodySize int `yaml:"max_body_size"`

	// StripQuotedReplies removes quoted reply chains (lines starting with >).
	StripQuotedReplies bool `yaml:"strip_quoted_replies"`

	// StripSignatures removes email signatures (content after "-- ").
	StripSignatures bool `yaml:"strip_signatures"`

	// StripHTML removes any HTML tags from the plain-text body.
	StripHTML bool `yaml:"strip_html"`

	// SanitizePromptInjection strips XML-like tags that could confuse LLMs
	// (e.g. <system>, <tool>, <|endoftext|>). Always recommended.
	SanitizePromptInjection bool `yaml:"sanitize_prompt_injection"`
}

// Attachments controls attachment handling.
type Attachments struct {
	// Dir is the directory where fetched attachments are saved.
	Dir string `yaml:"dir"`
}

// Default returns a policy with sensible defaults.
func Default() *Policy {
	return &Policy{
		Trust: Trust{
			Enabled: true,
		},
		Tools: Tools{
			ReadOnly: false,
		},
		Content: Content{
			MaxBodySize:             32768,
			StripQuotedReplies:      false,
			StripSignatures:         false,
			StripHTML:               false,
			SanitizePromptInjection: true,
		},
		Attachments: Attachments{
			Dir: "./attachments",
		},
	}
}

// Load reads a policy from a YAML file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	p := Default()
	if err := yaml.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	return p, nil
}

func (p *Policy) validate() error {
	if p.Content.MaxBodySize <= 0 {
		return fmt.Errorf("content.max_body_size must be positive")
	}
	if p.Attachments.Dir == "" {
		return fmt.Errorf("attachments.dir must be set")
	}
	return nil
}
