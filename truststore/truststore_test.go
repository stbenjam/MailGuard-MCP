package truststore

import (
	"testing"
)

func newTestStore(t *testing.T) *TrustStore {
	t.Helper()
	ts, err := New(":memory:")
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	t.Cleanup(func() { ts.Close() })
	return ts
}

func TestAddAndIsTrusted(t *testing.T) {
	ts := newTestStore(t)

	trusted, err := ts.IsTrusted("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if trusted {
		t.Error("expected untrusted before adding")
	}

	if err := ts.Add("Alice@Example.COM"); err != nil {
		t.Fatal(err)
	}

	trusted, err = ts.IsTrusted("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !trusted {
		t.Error("expected trusted after adding")
	}
}

func TestAddIdempotent(t *testing.T) {
	ts := newTestStore(t)
	if err := ts.Add("alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := ts.Add("alice@example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestRemove(t *testing.T) {
	ts := newTestStore(t)

	if err := ts.Add("alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := ts.Remove("alice@example.com"); err != nil {
		t.Fatal(err)
	}

	trusted, err := ts.IsTrusted("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if trusted {
		t.Error("expected untrusted after removal")
	}
}

func TestRemoveIdempotent(t *testing.T) {
	ts := newTestStore(t)
	if err := ts.Remove("nonexistent@example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestDomainTrust(t *testing.T) {
	ts := newTestStore(t)

	if err := ts.Add("@example.com"); err != nil {
		t.Fatal(err)
	}

	trusted, err := ts.IsTrusted("anyone@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !trusted {
		t.Error("expected domain trust to match")
	}

	trusted, err = ts.IsTrusted("someone@other.com")
	if err != nil {
		t.Fatal(err)
	}
	if trusted {
		t.Error("expected different domain to not match")
	}
}

func TestExactMatchOverDomain(t *testing.T) {
	ts := newTestStore(t)

	// Add domain trust
	if err := ts.Add("@example.com"); err != nil {
		t.Fatal(err)
	}

	// Exact match should also work
	if err := ts.Add("specific@example.com"); err != nil {
		t.Fatal(err)
	}

	trusted, err := ts.IsTrusted("specific@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !trusted {
		t.Error("expected trusted via exact match")
	}

	// Remove exact, should still be trusted via domain
	if err := ts.Remove("specific@example.com"); err != nil {
		t.Fatal(err)
	}

	trusted, err = ts.IsTrusted("specific@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !trusted {
		t.Error("expected still trusted via domain")
	}
}
