package saasid

import (
	"strings"
	"testing"
)

func TestGenerateProducesLoginlessBaitAccounts(t *testing.T) {
	k := Generate(Entra, "acme.com")
	if len(k.Accounts) < 3 {
		t.Fatalf("expected several honey accounts, got %d", len(k.Accounts))
	}
	for _, a := range k.Accounts {
		if !strings.HasSuffix(a.UPN, "@acme.com") {
			t.Errorf("account %q is not in the target domain", a.UPN)
		}
	}
	// The OAuth bait must carry tempting, excessive scopes.
	if len(k.OAuthApp.Scopes) == 0 {
		t.Fatal("honey OAuth app should declare scopes")
	}
	joined := strings.Join(k.OAuthApp.Scopes, " ")
	if !strings.Contains(joined, "Mail.ReadWrite.All") {
		t.Error("expected an excessive-scope OAuth bait")
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	a := Generate(Okta, "acme.com")
	b := Generate(Okta, "acme.com")
	if a.OAuthApp.ClientID != b.OAuthApp.ClientID {
		t.Fatal("generation should be deterministic for the same domain")
	}
	c := Generate(Okta, "other.com")
	if a.OAuthApp.ClientID == c.OAuthApp.ClientID {
		t.Fatal("different domains should yield different client ids")
	}
}

func TestMatcherFlagsHoneyIdentityInAuditLog(t *testing.T) {
	k := Generate(Entra, "acme.com")
	m := NewMatcher(k)

	// A real Entra sign-in log line mentioning the honey admin.
	line := `{"userPrincipalName":"admin.svc@acme.com","status":"failure","ip":"5.6.7.8"}`
	who, hit := m.Match(line)
	if !hit {
		t.Fatal("a sign-in against a honey account must be flagged")
	}
	if !strings.Contains(who, "admin.svc@acme.com") {
		t.Fatalf("wrong identity reported: %q", who)
	}

	// A legitimate user must NOT match.
	if _, hit := m.Match(`{"userPrincipalName":"real.person@acme.com"}`); hit {
		t.Fatal("a legitimate account must not be flagged")
	}
}

func TestMatcherIsCaseInsensitive(t *testing.T) {
	k := Generate(Workspace, "acme.com")
	m := NewMatcher(k)
	if _, hit := m.Match("USER=ADMIN.SVC@ACME.COM logged in"); !hit {
		t.Fatal("matching should be case-insensitive")
	}
}

func TestWatchListIncludesAccountsAndApp(t *testing.T) {
	k := Generate(Entra, "acme.com")
	wl := k.WatchList()
	if len(wl) < len(k.Accounts)+1 {
		t.Fatalf("watch-list should cover accounts and the OAuth app, got %d", len(wl))
	}
}
