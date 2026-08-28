// Package graph models an estate's attack paths and places decoys where they
// break the most of them.
//
// The idea (docs/11-IDEAS.md #4) is the single highest-scored differentiator:
// instead of scattering decoys at random, compute the shortest paths an
// attacker would take from a compromised endpoint to the crown jewels — the DC,
// the backup server, the ERP — and place decoys on the edges those paths cross.
// The result is a coverage metric a board can read: "87% of the paths to Domain
// Admin cross a decoy at an average depth of 2.1 hops."
//
// The graph is built from a manifest the operator supplies (or exports from
// BloodHound/AD), not from live scanning. This is deliberate: a deception
// platform that scans the production network is a deception platform that
// eventually scans something it should not. The manifest says what exists; this
// package says where the gaps are.
package graph

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Node is one asset in the estate.
type Node struct {
	ID    string            `json:"id" yaml:"id"`
	Type  string            `json:"type" yaml:"type"` // "endpoint", "server", "dc", "backup", "erp", "ot", "cloud"
	Tags  map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Crown bool              `json:"crown,omitempty" yaml:"crown,omitempty"` // is this a crown jewel?
}

// Edge is a reachability between two assets: A can reach B over this service.
type Edge struct {
	From    string `json:"from" yaml:"from"`
	To      string `json:"to" yaml:"to"`
	Service string `json:"service" yaml:"service"`                   // "smb", "rdp", "ssh", "ldap", "winrm", etc.
	Weight  int    `json:"weight,omitempty" yaml:"weight,omitempty"` // lower = more likely path
}

// Decoy is a placed decoy the graph knows about.
type Decoy struct {
	ID      string `json:"id" yaml:"id"`
	OnEdge  string `json:"on_edge,omitempty" yaml:"on_edge,omitempty"` // "from->to"
	AtNode  string `json:"at_node,omitempty" yaml:"at_node,omitempty"`
	Service string `json:"service" yaml:"service"`
}

// Estate is the full model.
type Estate struct {
	Nodes  []Node  `json:"nodes" yaml:"nodes"`
	Edges  []Edge  `json:"edges" yaml:"edges"`
	Decoys []Decoy `json:"decoys,omitempty" yaml:"decoys,omitempty"`
}

// Graph is the computed attack-path model.
type Graph struct {
	nodes  map[string]*Node
	adj    map[string][]Edge
	crowns []string
	decoys map[string]bool // edges that have a decoy on them: "from->to"
}

// Build constructs the graph from an estate manifest.
func Build(e Estate) (*Graph, error) {
	if len(e.Nodes) == 0 {
		return nil, fmt.Errorf("graph: no nodes; the model needs at least endpoints and targets")
	}
	g := &Graph{
		nodes:  make(map[string]*Node, len(e.Nodes)),
		adj:    make(map[string][]Edge),
		decoys: make(map[string]bool),
	}
	for i := range e.Nodes {
		n := &e.Nodes[i]
		g.nodes[n.ID] = n
		if n.Crown {
			g.crowns = append(g.crowns, n.ID)
		}
	}
	if len(g.crowns) == 0 {
		return nil, fmt.Errorf("graph: no crown jewels marked; there is nothing to protect")
	}
	for _, edge := range e.Edges {
		if _, ok := g.nodes[edge.From]; !ok {
			return nil, fmt.Errorf("graph: edge from unknown node %q", edge.From)
		}
		if _, ok := g.nodes[edge.To]; !ok {
			return nil, fmt.Errorf("graph: edge to unknown node %q", edge.To)
		}
		if edge.Weight <= 0 {
			edge.Weight = 1
		}
		g.adj[edge.From] = append(g.adj[edge.From], edge)
	}
	for _, d := range e.Decoys {
		if d.OnEdge != "" {
			g.decoys[d.OnEdge] = true
		}
		if d.AtNode != "" {
			for _, edges := range g.adj {
				for _, edge := range edges {
					if edge.To == d.AtNode {
						g.decoys[edge.From+"->"+edge.To] = true
					}
				}
			}
		}
	}
	return g, nil
}

// Path is one attack path from a start node to a crown jewel.
type Path struct {
	Nodes        []string `json:"nodes"`
	Services     []string `json:"services"`
	Length       int      `json:"length"`
	Covered      bool     `json:"covered"`        // does it cross at least one decoy?
	FirstDecoyAt int      `json:"first_decoy_at"` // hop index of the first decoy, or -1
}

// PathsFrom computes the shortest paths from a start node to every crown jewel.
func (g *Graph) PathsFrom(start string) []Path {
	if _, ok := g.nodes[start]; !ok {
		return nil
	}

	// Dijkstra to every crown jewel.
	dist := map[string]int{start: 0}
	prev := map[string]string{}
	prevEdge := map[string]string{} // service on the edge
	visited := map[string]bool{}

	for {
		var u string
		minDist := math.MaxInt32
		for n, d := range dist {
			if !visited[n] && d < minDist {
				u = n
				minDist = d
			}
		}
		if u == "" {
			break
		}
		visited[u] = true
		for _, e := range g.adj[u] {
			alt := dist[u] + e.Weight
			if d, ok := dist[e.To]; !ok || alt < d {
				dist[e.To] = alt
				prev[e.To] = u
				prevEdge[e.To] = e.Service
			}
		}
	}

	var paths []Path
	for _, crown := range g.crowns {
		if _, ok := dist[crown]; !ok {
			continue
		}
		var nodes []string
		var services []string
		for n := crown; n != ""; n = prev[n] {
			nodes = append([]string{n}, nodes...)
			if svc, ok := prevEdge[n]; ok {
				services = append([]string{svc}, services...)
			}
		}
		if len(nodes) < 2 {
			continue
		}
		p := Path{Nodes: nodes, Services: services, Length: dist[crown], FirstDecoyAt: -1}
		for i := 0; i < len(nodes)-1; i++ {
			edgeKey := nodes[i] + "->" + nodes[i+1]
			if g.decoys[edgeKey] {
				p.Covered = true
				if p.FirstDecoyAt < 0 {
					p.FirstDecoyAt = i
				}
			}
		}
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].Length < paths[j].Length })
	return paths
}

// Coverage computes the deployment-level metric: what fraction of attack paths
// cross a decoy, and at what average depth.
type Coverage struct {
	TotalPaths     int     `json:"total_paths"`
	CoveredPaths   int     `json:"covered_paths"`
	CoverageRatio  float64 `json:"coverage_ratio"`
	AvgDecoyDepth  float64 `json:"avg_decoy_depth"`
	UncoveredPaths []Path  `json:"uncovered_paths,omitempty"`
}

// Analyze computes coverage from every non-crown node to every crown jewel.
func (g *Graph) Analyze() Coverage {
	var c Coverage
	var totalDepth float64
	for id, node := range g.nodes {
		if node.Crown {
			continue
		}
		for _, p := range g.PathsFrom(id) {
			c.TotalPaths++
			if p.Covered {
				c.CoveredPaths++
				totalDepth += float64(p.FirstDecoyAt)
			} else {
				c.UncoveredPaths = append(c.UncoveredPaths, p)
			}
		}
	}
	if c.TotalPaths > 0 {
		c.CoverageRatio = float64(c.CoveredPaths) / float64(c.TotalPaths)
	}
	if c.CoveredPaths > 0 {
		c.AvgDecoyDepth = totalDepth / float64(c.CoveredPaths)
	}
	sort.Slice(c.UncoveredPaths, func(i, j int) bool {
		return c.UncoveredPaths[i].Length < c.UncoveredPaths[j].Length
	})
	return c
}

// Suggest recommends where to place new decoys to maximise coverage. It picks
// the edges that appear in the most uncovered paths — the choke points.
type Suggestion struct {
	Edge    string `json:"edge"` // "node-a->node-b"
	Service string `json:"service"`
	Covers  int    `json:"covers"` // how many currently uncovered paths this would cover
	Reason  string `json:"reason"`
}

// Suggest returns up to n placement suggestions, best first.
func (g *Graph) Suggest(n int) []Suggestion {
	cov := g.Analyze()
	if len(cov.UncoveredPaths) == 0 {
		return nil
	}

	edgeCount := map[string]int{}
	edgeService := map[string]string{}
	for _, p := range cov.UncoveredPaths {
		for i := 0; i < len(p.Nodes)-1; i++ {
			key := p.Nodes[i] + "->" + p.Nodes[i+1]
			if !g.decoys[key] {
				edgeCount[key]++
				if i < len(p.Services) {
					edgeService[key] = p.Services[i]
				}
			}
		}
	}

	type kv struct {
		edge  string
		count int
	}
	var pairs []kv
	for k, v := range edgeCount {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].count > pairs[j].count })

	var out []Suggestion
	for _, p := range pairs {
		if len(out) >= n {
			break
		}
		parts := strings.SplitN(p.edge, "->", 2)
		from, to := parts[0], parts[1]
		out = append(out, Suggestion{
			Edge:    p.edge,
			Service: edgeService[p.edge],
			Covers:  p.count,
			Reason:  fmt.Sprintf("a decoy on the %s path from %s to %s would cover %d uncovered path(s)", edgeService[p.edge], from, to, p.count),
		})
	}
	return out
}
