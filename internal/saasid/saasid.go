// Package saasid is SaaS / identity-provider deception (idea 11).
//
// Attacks now start in Entra ID / Okta / Google Workspace, not on the network.
// This package generates the identity-plane bait — honey users that never log
// in (so any authentication is an attack), a honey OAuth app with excessive
// scopes (consent-phishing bait), a honey conditional-access carve-out, and
// honey "IT-passwords" documents/channels — and a matcher that flags a honey
// identity's appearance in the provider's own audit log, so detection needs
// zero MIRAGE infrastructure inside the tenant.
//
// The actual push into the IdP is a future IdentityDriver; here we produce the
// artifacts and the watch-list an operator plants and monitors.
package saasid

import (
	"fmt"
	"strings"
)

// Provider is the identity platform the bait targets.
type Provider string

const (
	Entra     Provider = "entra"
	Okta      Provider = "okta"
	Workspace Provider = "workspace"
)

// HoneyAccount is a login-less bait identity. Any sign-in attempt against it is
// hostile: password spraying, MFA fatigue, or a stolen-token replay.
type HoneyAccount struct {
	UPN         string `json:"upn"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Note        string `json:"note"`
}

// HoneyOAuthApp is a fake registered application with tempting scopes, planted
// to catch consent-phishing (an attacker tricks a user into granting it).
type HoneyOAuthApp struct {
	Name        string   `json:"name"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scopes"`
	RedirectURI string   `json:"redirect_uri"`
	Note        string   `json:"note"`
}

// Kit is a generated identity-deception bundle for one tenant.
type Kit struct {
	Provider  Provider       `json:"provider"`
	Domain    string         `json:"domain"`
	Accounts  []HoneyAccount `json:"accounts"`
	OAuthApp  HoneyOAuthApp  `json:"oauth_app"`
	CAPolicy  string         `json:"conditional_access_policy"`
	Documents []string       `json:"honey_documents"`
	Channels  []string       `json:"honey_channels"`
}

// Generate builds a deterministic kit for the provider and domain. The account
// names are the ones attackers reach for first — privileged, service, and
// break-glass identities — so a spray or an enumeration hits them early.
func Generate(provider Provider, domain string) *Kit {
	if domain == "" {
		domain = "corp.example"
	}
	accounts := []HoneyAccount{
		{UPN: "admin.svc@" + domain, DisplayName: "Service Admin", Role: "Global Administrator",
			Note: "never signs in; any authentication is an attack (spray/MFA-fatigue)"},
		{UPN: "breakglass@" + domain, DisplayName: "Break Glass", Role: "Emergency Access",
			Note: "emergency account attackers specifically hunt; excluded from CA on purpose"},
		{UPN: "backup.admin@" + domain, DisplayName: "Backup Admin", Role: "Backup Operator",
			Note: "privileged, dormant — a classic lateral target"},
		{UPN: "finance.reports@" + domain, DisplayName: "Finance Reports", Role: "User",
			Note: "BEC target; watch for inbox-rule creation"},
	}
	app := HoneyOAuthApp{
		Name:        "Corp Mail Archiver",
		ClientID:    "00000000-dead-beef-cafe-" + shortHash(domain),
		Scopes:      []string{"Mail.ReadWrite.All", "Files.ReadWrite.All", "offline_access", "User.Read.All"},
		RedirectURI: "https://mail-archiver." + domain + "/oauth/callback",
		Note:        "excessive scopes; a consent grant to this app is consent-phishing",
	}
	return &Kit{
		Provider: provider, Domain: domain,
		Accounts: accounts, OAuthApp: app,
		CAPolicy:  caPolicyText(provider, domain),
		Documents: []string{"IT_Admin_Credentials_2026.xlsx", "VPN_Break_Glass.docx", "PAM_Vault_Export.csv"},
		Channels:  []string{"#it-passwords", "#infra-secrets"},
	}
}

// WatchList returns the identifiers an operator should watch for in the
// provider's sign-in / audit logs. Any hit is an alert.
func (k *Kit) WatchList() []string {
	out := make([]string, 0, len(k.Accounts)+1)
	for _, a := range k.Accounts {
		out = append(out, a.UPN)
	}
	out = append(out, k.OAuthApp.ClientID, k.OAuthApp.Name)
	return out
}

// Matcher flags a honey identity's appearance in an audit-log line. It works on
// raw text or JSON: a substring match on any watched identifier is enough,
// because a honey identity has no legitimate reason to appear anywhere.
type Matcher struct {
	watch []string
}

// NewMatcher builds a matcher for a kit's watch-list.
func NewMatcher(k *Kit) *Matcher {
	w := k.WatchList()
	lower := make([]string, len(w))
	for i, s := range w {
		lower[i] = strings.ToLower(s)
	}
	return &Matcher{watch: lower}
}

// Match reports the first watched identifier found in the log line, if any.
// A hit means a honey identity was touched — an attack, by construction.
func (m *Matcher) Match(logLine string) (string, bool) {
	l := strings.ToLower(logLine)
	for _, w := range m.watch {
		if w != "" && strings.Contains(l, w) {
			return w, true
		}
	}
	return "", false
}

func caPolicyText(p Provider, domain string) string {
	return fmt.Sprintf(
		"Honey Conditional Access (%s / %s): a named policy \"Legacy-Auth-Allow\" that "+
			"appears to permit legacy authentication for the break-glass account. It is bait: "+
			"any use of it is recorded. Do NOT actually weaken real auth — this is a decoy policy name/"+
			"documentation artifact, not a live exemption.", p, domain)
}

func shortHash(s string) string {
	// A short, stable, non-secret suffix so a client id looks plausible and is
	// deterministic per domain.
	h := uint32(2166136261)
	for _, c := range s {
		h = (h ^ uint32(c)) * 16777619
	}
	return fmt.Sprintf("%08x", h)
}
