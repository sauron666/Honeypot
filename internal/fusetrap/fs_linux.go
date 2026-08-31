//go:build linux

package fusetrap

import (
	"context"
	"path"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// This file binds the portable Trap to a real Linux kernel through FUSE, so a
// full-OS decoy on ANY hypervisor (or a real endpoint over SMB/NFS re-export)
// can mount the trap share and every operation flows through the detector and
// tarpit. It is compiled only on Linux; fs_other.go stubs the rest.
//
// It cannot be exercised in CI without /dev/fuse and privileges, exactly like
// the DRAKVUF path. The logic is kept thin — all judgement lives in the
// portable Trap, which IS covered by tests — so what is untested here is only
// the kernel plumbing, not the defence.

// Mounted is a live trap mount. Close unmounts it.
type Mounted struct {
	server *fuse.Server
}

// Wait blocks until the filesystem is unmounted.
func (m *Mounted) Wait() { m.server.Wait() }

// Close unmounts the filesystem.
func (m *Mounted) Close() error { return m.server.Unmount() }

// Mount mounts the trap at mountpoint. The caller keeps the *Trap for metrics
// and verdicts. Debug turns on go-fuse's protocol logging.
func Mount(mountpoint string, t *Trap, debug bool) (*Mounted, error) {
	root := &trapNode{trap: t, p: "/"}
	timeout := time.Second
	server, err := fs.Mount(mountpoint, root, &fs.Options{
		EntryTimeout: &timeout,
		AttrTimeout:  &timeout,
		MountOptions: fuse.MountOptions{
			FsName: "mirage-trap",
			Name:   "miragetrap",
			Debug:  debug,
			// AllowOther lets a decoy mounting over a re-export reach the files.
			AllowOther: true,
		},
	})
	if err != nil {
		return nil, err
	}
	return &Mounted{server: server}, nil
}

// trapNode is one path in the trap tree. The tree is authoritative in the
// Trap; nodes are thin and resolve by path so a mutating tree stays consistent.
type trapNode struct {
	fs.Inode
	trap *Trap
	p    string // absolute slash path within the trap
}

var (
	_ fs.NodeLookuper  = (*trapNode)(nil)
	_ fs.NodeReaddirer = (*trapNode)(nil)
	_ fs.NodeGetattrer = (*trapNode)(nil)
	_ fs.NodeOpener    = (*trapNode)(nil)
	_ fs.NodeReader    = (*trapNode)(nil)
	_ fs.NodeWriter    = (*trapNode)(nil)
	_ fs.NodeCreater   = (*trapNode)(nil)
	_ fs.NodeUnlinker  = (*trapNode)(nil)
	_ fs.NodeMkdirer   = (*trapNode)(nil)
	_ fs.NodeRenamer   = (*trapNode)(nil)
)

func (n *trapNode) child(name string) string { return path.Join(n.p, name) }

// tarpit sleeps for d, but wakes early if the mount is torn down.
func (n *trapNode) tarpit(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

func (n *trapNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	cp := n.child(name)
	if !n.trap.Exists(cp) {
		return nil, syscall.ENOENT
	}
	isDir := n.trap.IsDir(cp)
	mode := uint32(fuse.S_IFREG | 0o644)
	if isDir {
		mode = uint32(fuse.S_IFDIR | 0o755)
	}
	out.Mode = mode
	out.Size = uint64(n.trap.Size(cp))
	child := n.NewInode(ctx, &trapNode{trap: n.trap, p: cp},
		fs.StableAttr{Mode: mode})
	return child, 0
}

func (n *trapNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	entries := n.trap.List(n.p)
	ds := make([]fuse.DirEntry, 0, len(entries))
	for _, e := range entries {
		mode := uint32(fuse.S_IFREG)
		if e.Dir {
			mode = fuse.S_IFDIR
		}
		ds = append(ds, fuse.DirEntry{Name: e.Name, Mode: mode})
	}
	return fs.NewListDirStream(ds), 0
}

func (n *trapNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if n.trap.IsDir(n.p) {
		out.Mode = fuse.S_IFDIR | 0o755
		return 0
	}
	out.Mode = fuse.S_IFREG | 0o644
	out.Size = uint64(n.trap.Size(n.p))
	return 0
}

func (n *trapNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	// A read of a file feeds the velocity/canary signals once per open; a
	// suspicious read is tarpitted too, so bulk exfiltration also drags.
	if !n.trap.IsDir(n.p) {
		n.tarpit(ctx, n.trap.Read(n.p))
	}
	return nil, 0, 0
}

func (n *trapNode) Read(ctx context.Context, f fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	data, ok := n.trap.Content(n.p)
	if !ok {
		return nil, syscall.ENOENT
	}
	if off >= int64(len(data)) {
		return fuse.ReadResultData(nil), 0
	}
	end := off + int64(len(dest))
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	return fuse.ReadResultData(data[off:end]), 0
}

func (n *trapNode) Write(ctx context.Context, f fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	// The heart of it: the write is recorded and scored before it "completes",
	// and the tarpit delay is imposed here, on the attacker's own thread.
	delay := n.trap.WriteAt(n.p, data, off)
	n.tarpit(ctx, delay)
	return uint32(len(data)), 0
}

func (n *trapNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	cp := n.child(name)
	n.tarpit(ctx, n.trap.Create(cp))
	out.Mode = fuse.S_IFREG | 0o644
	child := n.NewInode(ctx, &trapNode{trap: n.trap, p: cp},
		fs.StableAttr{Mode: fuse.S_IFREG})
	return child, nil, 0, 0
}

func (n *trapNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	cp := n.child(name)
	if !n.trap.Mkdir(cp) {
		return nil, syscall.EEXIST
	}
	out.Mode = fuse.S_IFDIR | 0o755
	child := n.NewInode(ctx, &trapNode{trap: n.trap, p: cp},
		fs.StableAttr{Mode: fuse.S_IFDIR})
	return child, 0
}

func (n *trapNode) Unlink(ctx context.Context, name string) syscall.Errno {
	n.tarpit(ctx, n.trap.Delete(n.child(name)))
	return 0
}

func (n *trapNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	np, ok := newParent.(*trapNode)
	if !ok {
		return syscall.EXDEV
	}
	from := n.child(name)
	to := np.child(newName)
	n.tarpit(ctx, n.trap.Rename(from, to))
	return 0
}
