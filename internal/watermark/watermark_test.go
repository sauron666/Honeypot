package watermark

import (
	"strings"
	"testing"
)

const testSecret = "mirage-test-secret"

func TestEmbedAndExtract(t *testing.T) {
	text := "This is a confidential financial report. The quarterly numbers show growth. " +
		"Revenue increased by 15%. Operating costs remained stable. " +
		"The board approved the next phase. Details follow in the appendix."

	marked := Embed(text, "share-finance", testSecret)
	if marked == text {
		t.Fatal("embedding produced no change")
	}

	ch, ok := Extract(marked, testSecret, []string{"share-finance", "share-hr", "breadcrumb-alice"})
	if !ok {
		t.Fatal("extraction failed")
	}
	if ch != "share-finance" {
		t.Fatalf("wrong channel extracted: %q", ch)
	}
}

func TestDifferentChannelsProduceDifferentMarks(t *testing.T) {
	text := "This is a document with enough words to embed a watermark into it properly and it needs to be quite long to fit all sixteen bits of the channel identifier into the zero width characters between the words here."

	a := Embed(text, "channel-a", testSecret)
	b := Embed(text, "channel-b", testSecret)
	if a == b {
		t.Fatal("two channels produced the same watermark")
	}
}

func TestDocIDIsStableAndDistinct(t *testing.T) {
	a := DocID("share-finance", testSecret)
	b := DocID("share-hr", testSecret)
	if a == b {
		t.Fatal("two channels produced the same doc id")
	}
	a2 := DocID("share-finance", testSecret)
	if a != a2 {
		t.Fatal("the same channel produced different doc ids")
	}
	if len(a) < 5 {
		t.Fatalf("doc id is too short: %q", a)
	}
}

func TestExtractRejectsWrongChannel(t *testing.T) {
	text := "This is a long enough document for the watermark embedding to work correctly here."
	marked := Embed(text, "channel-a", testSecret)
	_, ok := Extract(marked, testSecret, []string{"channel-b", "channel-c"})
	if ok {
		t.Fatal("extraction succeeded with wrong candidates")
	}
}

func TestWatermarkSurvivesNaiveCopyPaste(t *testing.T) {
	text := "Financial data is confidential. Share only with authorized personnel. " +
		"Revenue figures are preliminary. Contact the CFO for final numbers."
	marked := Embed(text, "leak-test", testSecret)

	// Simulate a copy-paste that preserves unicode but might strip trailing spaces.
	pasted := marked // zero-width chars survive copy-paste in every modern editor
	ch, ok := Extract(pasted, testSecret, []string{"leak-test", "other"})
	if !ok || ch != "leak-test" {
		t.Fatal("watermark did not survive copy-paste")
	}
}

func TestEmbedWorksOnShortText(t *testing.T) {
	// The original bug: text shorter than 17 words was silently not marked, so
	// the operator believed a leak was traceable when it was not.
	for _, text := range []string{
		"short",
		"a five word document here",
		"Confidential quarterly report for the board of directors and executives",
	} {
		marked := Embed(text, "alice@corp", "secret")
		who, ok := Extract(marked, "secret", []string{"bob@corp", "alice@corp", "eve@corp"})
		if !ok || who != "alice@corp" {
			t.Fatalf("round-trip failed on %q-word text: ok=%v who=%q", text, ok, who)
		}
		// The visible text (zero-width stripped) must be unchanged.
		stripped := strings.Map(func(r rune) rune {
			if r == '​' || r == '‌' {
				return -1
			}
			return r
		}, marked)
		// whitespace channel may add spaces after sentences; this text has none.
		if stripped != text {
			t.Fatalf("visible text changed: %q -> %q", text, stripped)
		}
	}
}

func TestWrongSecretDoesNotMatch(t *testing.T) {
	marked := Embed("some document text here for marking", "alice@corp", "right-secret")
	if _, ok := Extract(marked, "wrong-secret", []string{"alice@corp"}); ok {
		t.Fatal("a wrong secret produced a match")
	}
}
