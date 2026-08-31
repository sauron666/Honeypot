// Package bec is email / business-email-compromise deception (idea 12).
//
// Two moves. First, plant a fake finance identity on the public site — a
// plausible "chief accountant" whose address is the one a BEC operator will
// harvest and target, so the fraud attempt lands on us, not on the real person,
// often weeks before a real campaign. Second, plant honey mailboxes leaked into
// public corpora so campaigns aimed at the organisation are caught early.
//
// When a message arrives at a honey identity, AnalyzeEmail pulls the campaign's
// infrastructure out of the headers and body — sender IPs, reply-to, return
// path, URLs — and flags the classic BEC tell: a display name impersonating an
// executive while the reply address points somewhere else entirely.
package bec

import (
	"net/mail"
	"regexp"
	"sort"
	"strings"
)

// HoneyPersona is a fake finance identity placed on the public site so BEC
// operators harvest and target it instead of a real employee.
type HoneyPersona struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	Email     string `json:"email"`
	PublicBio string `json:"public_bio"`
}

// Mailbox is a honey mailbox deliberately leaked into a public corpus.
type Mailbox struct {
	Address  string `json:"address"`
	SeededIn string `json:"seeded_in"`
}

// Kit is a generated BEC-deception bundle for one domain.
type Kit struct {
	Domain    string         `json:"domain"`
	Personas  []HoneyPersona `json:"personas"`
	Mailboxes []Mailbox      `json:"mailboxes"`
}

// Generate builds a deterministic BEC kit for the domain. The finance and
// executive roles are the ones BEC targets: whoever can move money or approve
// an invoice.
func Generate(domain string) *Kit {
	if domain == "" {
		domain = "corp.example"
	}
	personas := []HoneyPersona{
		{Name: "Ivan Petrov", Role: "Chief Accountant", Email: "i.petrov@" + domain,
			PublicBio: "Responsible for accounts payable and vendor payments."},
		{Name: "Maria Kolarova", Role: "CFO", Email: "m.kolarova@" + domain,
			PublicBio: "Approves wire transfers above threshold."},
		{Name: "Georgi Dimitrov", Role: "Finance Assistant", Email: "g.dimitrov@" + domain,
			PublicBio: "Processes invoices and payment runs."},
	}
	mailboxes := []Mailbox{
		{Address: "invoices@" + domain, SeededIn: "public vendor portal / pastebin dump"},
		{Address: "ap@" + domain, SeededIn: "conference attendee list"},
		{Address: "i.petrov@" + domain, SeededIn: "company About page"},
	}
	return &Kit{Domain: domain, Personas: personas, Mailboxes: mailboxes}
}

// WatchAddresses returns every honey address a mail gateway should watch as a
// recipient. Mail to any of them is unsolicited and worth analysing.
func (k *Kit) WatchAddresses() []string {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		a = strings.ToLower(a)
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, p := range k.Personas {
		add(p.Email)
	}
	for _, m := range k.Mailboxes {
		add(m.Address)
	}
	sort.Strings(out)
	return out
}

// Campaign is what AnalyzeEmail extracts from a received message: the campaign's
// infrastructure and the BEC tells.
type Campaign struct {
	Subject       string   `json:"subject"`
	FromName      string   `json:"from_name"`
	FromAddress   string   `json:"from_address"`
	ReplyTo       string   `json:"reply_to,omitempty"`
	ReturnPath    string   `json:"return_path,omitempty"`
	SenderIPs     []string `json:"sender_ips,omitempty"`
	URLs          []string `json:"urls,omitempty"`
	Recipients    []string `json:"recipients,omitempty"`
	ReplyMismatch bool     `json:"reply_mismatch"` // reply-to domain != from domain
	IsBEC         bool     `json:"is_bec"`         // heuristic verdict
}

var (
	ipRe  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	urlRe = regexp.MustCompile(`https?://[^\s"'<>)]+`)
)

// AnalyzeEmail parses a raw RFC 5322 message and pulls out the campaign
// infrastructure and the BEC tells. It never fetches anything — it only reads
// what the message already carries.
func AnalyzeEmail(raw string) (Campaign, error) {
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		return Campaign{}, err
	}
	h := msg.Header
	c := Campaign{
		Subject:    h.Get("Subject"),
		ReturnPath: strings.Trim(h.Get("Return-Path"), "<>"),
	}

	if from, err := mail.ParseAddress(h.Get("From")); err == nil {
		c.FromName = from.Name
		c.FromAddress = from.Address
	} else {
		c.FromAddress = h.Get("From")
	}
	if rt := h.Get("Reply-To"); rt != "" {
		if a, err := mail.ParseAddress(rt); err == nil {
			c.ReplyTo = a.Address
		} else {
			c.ReplyTo = rt
		}
	}
	for _, to := range h["To"] {
		if list, err := mail.ParseAddressList(to); err == nil {
			for _, a := range list {
				c.Recipients = append(c.Recipients, a.Address)
			}
		}
	}

	// Sender IPs from Received headers.
	ipSeen := map[string]bool{}
	for _, r := range h["Received"] {
		for _, ip := range ipRe.FindAllString(r, -1) {
			if !ipSeen[ip] {
				ipSeen[ip] = true
				c.SenderIPs = append(c.SenderIPs, ip)
			}
		}
	}

	// URLs from the body.
	body := make([]byte, 64*1024)
	n, _ := msg.Body.Read(body)
	urlSeen := map[string]bool{}
	for _, u := range urlRe.FindAllString(string(body[:n]), -1) {
		if !urlSeen[u] {
			urlSeen[u] = true
			c.URLs = append(c.URLs, u)
		}
	}

	// The BEC tell: the reply address points to a different domain than the
	// From address (the fraudster wants the reply, not the spoofed identity).
	c.ReplyMismatch = c.ReplyTo != "" && domainOf(c.ReplyTo) != domainOf(c.FromAddress)
	c.IsBEC = c.ReplyMismatch || (c.FromName != "" && domainOf(c.ReturnPath) != "" &&
		domainOf(c.ReturnPath) != domainOf(c.FromAddress))
	return c, nil
}

func domainOf(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return strings.ToLower(addr[i+1:])
	}
	return ""
}
