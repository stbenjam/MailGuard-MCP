package security

import (
	"fmt"
	"mime"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// xmlLikeTagRegex matches tags that could confuse an LLM, e.g. <system>, </tool>, <|endoftext|>
var xmlLikeTagRegex = regexp.MustCompile(`<\|[^|]*\|>|</?(?:system|tool|user|assistant|function|instruction|prompt|context|message|role|human|endoftext)[^>]*>`)

var decoder = new(mime.WordDecoder)

// SanitizeAddress extracts and validates an email address from a From header value.
// It decodes RFC 2047, strips display names, lowercases, and validates format.
func SanitizeAddress(fromHeader string) (string, error) {
	if fromHeader == "" {
		return "", fmt.Errorf("empty address")
	}

	// Decode RFC 2047 encoded words
	decoded, err := decoder.DecodeHeader(fromHeader)
	if err != nil {
		decoded = fromHeader
	}

	addr, err := mail.ParseAddress(decoded)
	if err != nil {
		return "", fmt.Errorf("failed to parse address: %w", err)
	}

	email := strings.ToLower(addr.Address)

	if !emailRegex.MatchString(email) {
		return "", fmt.Errorf("invalid email address format: %s", email)
	}

	return email, nil
}

// ValidateAddress checks if a raw email address (or @domain) has valid format.
func ValidateAddress(addr string) error {
	addr = strings.ToLower(addr)

	// Allow @domain.com format for domain-level trust
	if strings.HasPrefix(addr, "@") {
		domain := addr[1:]
		if !regexp.MustCompile(`^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`).MatchString(domain) {
			return fmt.Errorf("invalid domain format: %s", addr)
		}
		return nil
	}

	if !emailRegex.MatchString(addr) {
		return fmt.Errorf("invalid email address format: %s", addr)
	}
	return nil
}

// SanitizeContent performs light sanitization on text content from trusted senders.
// Strips control characters, zero-width characters, and XML-like tags.
func SanitizeContent(text string) string {
	// Strip control characters except \n, \r, \t
	text = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		// Zero-width characters
		switch r {
		case '\u200B', '\u200C', '\u200D', '\uFEFF', '\u2060', '\u180E':
			return -1
		}
		return r
	}, text)

	// Strip XML-like tags that could confuse the LLM
	text = xmlLikeTagRegex.ReplaceAllString(text, "")

	return text
}

// StripHTMLTags removes HTML tags from text content.
func StripHTMLTags(text string) string {
	return regexp.MustCompile(`<[^>]*>`).ReplaceAllString(text, "")
}

// StripQuotedReplies removes quoted reply lines (lines starting with ">").
func StripQuotedReplies(text string) string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), ">") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

// StripSignatures removes email signatures (content after a line containing only "-- ").
func StripSignatures(text string) string {
	parts := strings.SplitN(text, "\n-- \n", 2)
	return parts[0]
}

// SanitizeFilename sanitizes an attachment filename for safe disk storage.
func SanitizeFilename(name string) string {
	if name == "" {
		return "attachment"
	}

	// Strip path traversal
	name = strings.ReplaceAll(name, "..", "")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")

	// Strip control characters
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)

	name = strings.TrimSpace(name)

	if len(name) > 255 {
		name = name[:255]
	}

	if name == "" {
		return "attachment"
	}

	return name
}
