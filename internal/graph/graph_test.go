package graph

import (
	"testing"
)

func testEstate() Estate {
	return Estate{
		Nodes: []Node{
			{ID: "ws-alice", Type: "endpoint"},
			{ID: "ws-bob", Type: "endpoint"},
			{ID: "jump01", Type: "server"},
			{ID: "app01", Type: "server"},
			{ID: "db01", Type: "server"},
			{ID: "dc01", Type: "dc", Crown: true},
			{ID: "backup01", Type: "backup", Crown: true},
		},
		Edges: []Edge{
			{From: "ws-alice", To: "jump01", Service: "rdp"},
			{From: "ws-alice", To: "app01", Service: "ssh"},
			{From: "ws-bob", To: "jump01", Service: "rdp"},
			{From: "jump01", To: "dc01", Service: "ldap"},
			{From: "jump01", To: "app01", Service: "ssh"},
			{From: "app01", To: "db01", Service: "mysql"},
			{From: "app01", To: "dc01", Service: "ldap"},
			{From: "db01", To: "backup01", Service: "smb"},
			{From: "dc01", To: "backup01", Service: "smb"},
		},
	}
}

func TestPathsFromEndpointToCrown(t *testing.T) {
	g, err := Build(testEstate())
	if err != nil {
		t.Fatal(err)
	}
	paths := g.PathsFrom("ws-alice")
	if len(paths) == 0 {
		t.Fatal("no paths from ws-alice to any crown jewel")
	}
	var toDC, toBackup bool
	for _, p := range paths {
		last := p.Nodes[len(p.Nodes)-1]
		if last == "dc01" {
			toDC = true
		}
		if last == "backup01" {
			toBackup = true
		}
	}
	if !toDC {
		t.Fatal("no path to dc01")
	}
	if !toBackup {
		t.Fatal("no path to backup01")
	}
}

func TestUncoveredPathsAreReportedWithoutDecoys(t *testing.T) {
	g, err := Build(testEstate())
	if err != nil {
		t.Fatal(err)
	}
	cov := g.Analyze()
	if cov.TotalPaths == 0 {
		t.Fatal("no paths computed")
	}
	if cov.CoveredPaths != 0 {
		t.Fatal("paths are covered despite no decoys being placed")
	}
	if cov.CoverageRatio != 0 {
		t.Fatal("coverage ratio should be 0 without decoys")
	}
	if len(cov.UncoveredPaths) == 0 {
		t.Fatal("uncovered paths should be listed")
	}
}

func TestDecoyOnEdgeCoversPaths(t *testing.T) {
	estate := testEstate()
	estate.Decoys = []Decoy{
		{ID: "dcy-jump", OnEdge: "jump01->dc01", Service: "ldap"},
	}
	g, err := Build(estate)
	if err != nil {
		t.Fatal(err)
	}
	cov := g.Analyze()
	if cov.CoveredPaths == 0 {
		t.Fatal("the decoy on jump01->dc01 should cover some paths")
	}
	if cov.CoverageRatio <= 0 || cov.CoverageRatio > 1 {
		t.Fatalf("coverage ratio out of range: %f", cov.CoverageRatio)
	}
}

func TestDecoyAtNodeCoversPaths(t *testing.T) {
	estate := testEstate()
	estate.Decoys = []Decoy{
		{ID: "dcy-dc", AtNode: "dc01", Service: "ldap"},
	}
	g, err := Build(estate)
	if err != nil {
		t.Fatal(err)
	}
	cov := g.Analyze()
	if cov.CoveredPaths == 0 {
		t.Fatal("a decoy at dc01 should cover paths ending there")
	}
}

func TestSuggestRecommendsChokePoints(t *testing.T) {
	g, err := Build(testEstate())
	if err != nil {
		t.Fatal(err)
	}
	suggestions := g.Suggest(3)
	if len(suggestions) == 0 {
		t.Fatal("no suggestions for an estate with uncovered paths")
	}
	if suggestions[0].Covers == 0 {
		t.Fatal("the top suggestion covers nothing")
	}
	if suggestions[0].Edge == "" || suggestions[0].Reason == "" {
		t.Fatalf("incomplete suggestion: %+v", suggestions[0])
	}
	// The top suggestion should be the choke point — the edge on the most paths.
	if len(suggestions) > 1 && suggestions[0].Covers < suggestions[1].Covers {
		t.Fatal("suggestions are not sorted by impact")
	}
}

func TestFullCoverageProducesNoSuggestions(t *testing.T) {
	estate := testEstate()
	for _, e := range estate.Edges {
		estate.Decoys = append(estate.Decoys, Decoy{
			ID: "dcy-" + e.From + "-" + e.To, OnEdge: e.From + "->" + e.To, Service: e.Service,
		})
	}
	g, err := Build(estate)
	if err != nil {
		t.Fatal(err)
	}
	cov := g.Analyze()
	if cov.CoverageRatio < 1.0 {
		t.Fatalf("full coverage expected but got %f", cov.CoverageRatio)
	}
	suggestions := g.Suggest(5)
	if len(suggestions) != 0 {
		t.Fatalf("suggestions made despite full coverage: %+v", suggestions)
	}
}

func TestBuildRejectsEmptyAndMissingCrowns(t *testing.T) {
	if _, err := Build(Estate{}); err == nil {
		t.Fatal("empty estate should fail")
	}
	if _, err := Build(Estate{Nodes: []Node{{ID: "a", Type: "endpoint"}}}); err == nil {
		t.Fatal("estate without crown jewels should fail")
	}
}

func TestBuildRejectsBadEdges(t *testing.T) {
	e := Estate{
		Nodes: []Node{{ID: "a", Crown: true}},
		Edges: []Edge{{From: "a", To: "nonexistent", Service: "ssh"}},
	}
	if _, err := Build(e); err == nil {
		t.Fatal("an edge to a nonexistent node should fail")
	}
}
