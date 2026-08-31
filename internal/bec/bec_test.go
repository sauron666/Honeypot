package bec

import (
	"strings"
	"testing"
)

func TestGenerateHoneyFinanceIdentities(t *testing.T) {
	k := Generate("acme.com")
	if len(k.Personas) < 2 {
		t.Fatalf("expected finance personas, got %d", len(k.Personas))
	}
	for _, p := range k.Personas {
		if !strings.HasSuffix(p.Email, "@acme.com") {
			t.Errorf("persona %q not in domain", p.Email)
		}
	}
	if len(k.WatchAddresses()) == 0 {
		t.Fatal("watch addresses should not be empty")
	}
}

func TestAnalyzeEmailExtractsCampaignInfra(t *testing.T) {
	raw := "Received: from mail.evil.example (1.2.3.4) by mx.acme.com\r\n" +
		"Received: from relay.bad.example (5.6.7.8)\r\n" +
		"Return-Path: <bounce@bounce.evil.example>\r\n" +
		"From: \"Maria Kolarova\" <m.kolarova@acme.com>\r\n" +
		"Reply-To: cfo.urgent@gmail-secure.example\r\n" +
		"To: g.dimitrov@acme.com\r\n" +
		"Subject: URGENT wire transfer\r\n" +
		"\r\n" +
		"Please process this payment today: http://pay.evil.example/invoice\r\n"

	c, err := AnalyzeEmail(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.FromAddress != "m.kolarova@acme.com" {
		t.Errorf("from = %q", c.FromAddress)
	}
	if c.ReplyTo != "cfo.urgent@gmail-secure.example" {
		t.Errorf("reply-to = %q", c.ReplyTo)
	}
	if len(c.SenderIPs) != 2 {
		t.Errorf("expected 2 sender IPs, got %v", c.SenderIPs)
	}
	if len(c.URLs) != 1 || !strings.Contains(c.URLs[0], "pay.evil.example") {
		t.Errorf("expected the payload URL, got %v", c.URLs)
	}
	// The classic BEC tell: display name is our exec, reply-to is external.
	if !c.ReplyMismatch || !c.IsBEC {
		t.Errorf("a spoofed-exec / external-reply mail should be flagged as BEC: %+v", c)
	}
}

func TestAnalyzeLegitimateMailIsNotBEC(t *testing.T) {
	raw := "From: \"Real Person\" <real@acme.com>\r\n" +
		"Reply-To: real@acme.com\r\n" +
		"To: colleague@acme.com\r\n" +
		"Subject: lunch\r\n\r\nsee you at noon\r\n"
	c, err := AnalyzeEmail(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.IsBEC {
		t.Errorf("a same-domain reply-to mail must not be flagged BEC: %+v", c)
	}
}

func TestAnalyzeEmailRejectsGarbage(t *testing.T) {
	if _, err := AnalyzeEmail("not an email"); err == nil {
		t.Error("expected an error parsing a non-message")
	}
}
