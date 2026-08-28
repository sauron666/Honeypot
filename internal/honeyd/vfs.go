package honeyd

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// VNode is one entry in a decoy's virtual filesystem. Nothing here touches the
// real filesystem: the "files" an attacker reads are generated content held in
// memory, so a path traversal bug in a service handler exposes nothing.
type VNode struct {
	Name     string
	Dir      bool
	Mode     string // ls-style, e.g. "-rw-r--r--"
	Owner    string
	Group    string
	Size     int64
	MTime    time.Time
	Content  string
	Children map[string]*VNode

	// Honeytoken marks content that is deliberately baited. Reading it is a
	// high-severity event even though the read itself looks mundane.
	Honeytoken string
}

// VFS is a decoy's filesystem.
type VFS struct {
	root *VNode
}

// NewVFS creates an empty filesystem with a root directory.
func NewVFS() *VFS {
	return &VFS{root: &VNode{
		Name: "/", Dir: true, Mode: "drwxr-xr-x", Owner: "root", Group: "root",
		Children: map[string]*VNode{}, MTime: time.Now().Add(-200 * 24 * time.Hour),
	}}
}

// Mkdir creates a directory and any missing parents.
func (v *VFS) Mkdir(p, owner, group, mode string, mtime time.Time) *VNode {
	cur := v.root
	for _, part := range splitPath(p) {
		next, ok := cur.Children[part]
		if !ok {
			next = &VNode{
				Name: part, Dir: true, Mode: "drwxr-xr-x", Owner: owner, Group: group,
				Children: map[string]*VNode{}, MTime: mtime,
			}
			cur.Children[part] = next
		}
		cur = next
	}
	if mode != "" {
		cur.Mode = mode
	}
	cur.Owner, cur.Group, cur.MTime = owner, group, mtime
	return cur
}

// AddFile places a file, creating parent directories as needed.
func (v *VFS) AddFile(p, content, owner, group, mode string, mtime time.Time) *VNode {
	dir, name := path.Split(strings.TrimSuffix(p, "/"))
	parent := v.Mkdir(dir, owner, group, "", mtime)
	n := &VNode{
		Name: name, Mode: mode, Owner: owner, Group: group,
		Size: int64(len(content)), MTime: mtime, Content: content,
	}
	if mode == "" {
		n.Mode = "-rw-r--r--"
	}
	parent.Children[name] = n
	return n
}

// AddToken places a honeytoken file: content that exists to be stolen.
func (v *VFS) AddToken(p, content, owner, group, mode, token string, mtime time.Time) *VNode {
	n := v.AddFile(p, content, owner, group, mode, mtime)
	n.Honeytoken = token
	return n
}

func splitPath(p string) []string {
	p = strings.TrimSpace(p)
	var out []string
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." {
			continue
		}
		out = append(out, part)
	}
	return out
}

// Resolve turns a possibly-relative path into an absolute one, honouring "..".
func Resolve(cwd, p string) string {
	if p == "" {
		return cwd
	}
	if !strings.HasPrefix(p, "/") {
		p = path.Join(cwd, p)
	}
	cleaned := path.Clean(p)
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

// Lookup finds a node by absolute path.
func (v *VFS) Lookup(p string) (*VNode, bool) {
	cur := v.root
	for _, part := range splitPath(p) {
		if !cur.Dir {
			return nil, false
		}
		next, ok := cur.Children[part]
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// List returns the sorted children of a directory.
func (v *VFS) List(p string) ([]*VNode, bool) {
	n, ok := v.Lookup(p)
	if !ok || !n.Dir {
		return nil, false
	}
	out := make([]*VNode, 0, len(n.Children))
	for _, c := range n.Children {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, true
}

// LongFormat renders one entry the way `ls -l` would.
func (n *VNode) LongFormat() string {
	size := n.Size
	if n.Dir {
		size = 4096
	}
	stamp := n.MTime.Format("Jan _2 15:04")
	if time.Since(n.MTime) > 180*24*time.Hour {
		stamp = n.MTime.Format("Jan _2  2006")
	}
	links := 1
	if n.Dir {
		links = 2 + len(n.Children)
	}
	return fmt.Sprintf("%s %2d %-8s %-8s %8d %s %s",
		n.Mode, links, n.Owner, n.Group, size, stamp, n.Name)
}
