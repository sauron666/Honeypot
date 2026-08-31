package packs

import (
	"embed"
	"io/fs"
	"sort"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Builtin returns the packs shipped with MIRAGE, parsed and sorted by name.
// They are the seed of the catalogue; the community and the operator add more.
func Builtin() ([]*Pack, error) {
	entries, err := fs.ReadDir(builtinFS, "builtin")
	if err != nil {
		return nil, err
	}
	var out []*Pack
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := builtinFS.ReadFile("builtin/" + e.Name())
		if err != nil {
			return nil, err
		}
		p, err := Parse(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// BuiltinByName returns a shipped pack by name.
func BuiltinByName(name string) (*Pack, bool) {
	all, err := Builtin()
	if err != nil {
		return nil, false
	}
	for _, p := range all {
		if p.Name == name {
			return p, true
		}
	}
	return nil, false
}
