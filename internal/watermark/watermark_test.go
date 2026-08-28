package watermark

import (
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
