package honeyd

import (
	"encoding/binary"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

// smbFileState tracks open handles for one SMB session.
//
// Every open file handle the attacker holds is a window into what they are
// doing: which files they read, which they write, and in what order. A
// ransomware encryptor walks a share in directory order, opens each file,
// reads it, writes the ciphertext back, and closes it — all of which is
// now visible in the evidence chain.
type smbFileState struct {
	mu      sync.Mutex
	handles map[uint64]*smbHandle
	nextID  uint64
}

type smbHandle struct {
	path   string
	node   *VNode
	isDir  bool
	offset int64
}

func newSMBFileState() *smbFileState {
	return &smbFileState{handles: map[uint64]*smbHandle{}, nextID: 1}
}

// fileID is a compound 16-byte SMB2 file id; we use only the persistent half.
func fileID(id uint64) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint64(b, id)
	binary.LittleEndian.PutUint64(b[8:], id)
	return b
}

func readFileID(body []byte) uint64 {
	if len(body) < 24 {
		return 0
	}
	return binary.LittleEndian.Uint64(body[8:16])
}

// --- SMB2 Create -----------------------------------------------------------

const (
	statusObjectNameNotFound = 0xC0000034
	statusNoSuchFile         = 0xC000000F
	statusEndOfFile          = 0xC0000011
	statusObjectPathNotFound = 0xC000003A
	statusInvalidParameter   = 0xC000000D
	statusNoMoreFiles        = 0x80000006
	statusFileIsADirectory   = 0xC00000BA
)

// smbCreate opens a file or directory. The VFS is read-only from the decoy's
// side, so every path resolves against the persona's filesystem. A path that
// does not exist is FILE_NOT_FOUND — which is what makes the persona's canary
// files sort first: an attacker who enumerates finds them before anything else.
func (s *smbSvc) smbCreate(hdr smbHeader, body []byte, fs *smbFileState, sess *Session) []byte {
	name := readCreateName(body)
	vfsPath := smbToVFS(name)

	sev := event.SeverityMedium
	node, ok := s.p.FS.Lookup(vfsPath)
	if !ok {
		sess.Emit(sess.Event(event.ClassSMBActivity, 1, sev).
			WithMessage("SMB open: %s (not found)", name).
			Set("path", name))
		return errorResponse(hdr, statusObjectNameNotFound)
	}

	// Check for honeytokens and canaries.
	if node.Honeytoken != "" {
		sev = event.SeverityCritical
		sess.Emit(sess.Event(event.ClassSMBActivity, 1, sev).
			WithMessage("SMB open honeytoken: %s (%s)", name, node.Honeytoken).
			WithAttack(event.Technique{Tactic: "TA0009", Technique: "T1039", Name: "Data from Network Shared Drive"}).
			Set("path", name).Set("honeytoken", node.Honeytoken))
	} else if node.Canary {
		sev = event.SeverityHigh
		sess.Emit(sess.Event(event.ClassSMBActivity, 1, sev).
			WithMessage("SMB open canary: %s", name).
			WithAttack(event.Technique{Tactic: "TA0040", Technique: "T1486", Name: "Data Encrypted for Impact"}).
			Set("path", name).Set("canary", true))
	} else {
		sess.Emit(sess.Event(event.ClassSMBActivity, 1, sev).
			WithMessage("SMB open: %s", name).
			WithAttack(event.Technique{Tactic: "TA0009", Technique: "T1039", Name: "Data from Network Shared Drive"}).
			Set("path", name))
	}

	fs.mu.Lock()
	id := fs.nextID
	fs.nextID++
	fs.handles[id] = &smbHandle{path: vfsPath, node: node, isDir: node.Dir}
	fs.mu.Unlock()

	return s.createResponse(hdr, id, node)
}

func (s *smbSvc) createResponse(hdr smbHeader, id uint64, node *VNode) []byte {
	resp := make([]byte, 89)
	binary.LittleEndian.PutUint16(resp[0:2], 89) // structure size
	resp[2] = 0x01                               // oplock level: none

	now := windowsTime(time.Now())
	binary.LittleEndian.PutUint64(resp[8:16], now)  // create time
	binary.LittleEndian.PutUint64(resp[16:24], now) // access time
	binary.LittleEndian.PutUint64(resp[24:32], now) // write time
	binary.LittleEndian.PutUint64(resp[32:40], now) // change time

	if node.Dir {
		binary.LittleEndian.PutUint32(resp[56:60], 0x10) // FILE_ATTRIBUTE_DIRECTORY
	} else {
		binary.LittleEndian.PutUint64(resp[48:56], uint64(node.Size)) // allocation size
		binary.LittleEndian.PutUint64(resp[40:48], uint64(node.Size)) // end of file (reuse the field position)
		binary.LittleEndian.PutUint32(resp[56:60], 0x20)              // FILE_ATTRIBUTE_ARCHIVE
	}

	copy(resp[64:80], fileID(id))
	return simpleResponse(hdr, statusSuccess, resp)
}

// --- SMB2 Read --------------------------------------------------------------

func (s *smbSvc) smbRead(hdr smbHeader, body []byte, fs *smbFileState, sess *Session) []byte {
	fid := readFileID(body)
	fs.mu.Lock()
	h, ok := fs.handles[fid]
	fs.mu.Unlock()
	if !ok {
		return errorResponse(hdr, statusAccessDenied)
	}
	if h.isDir {
		return errorResponse(hdr, statusFileIsADirectory)
	}

	offset := int64(0)
	length := uint32(65536)
	if len(body) >= 36 {
		length = binary.LittleEndian.Uint32(body[4:8])
		offset = int64(binary.LittleEndian.Uint64(body[8:16]))
	}

	content := []byte(h.node.Content)
	if offset >= int64(len(content)) {
		return errorResponse(hdr, statusEndOfFile)
	}
	end := offset + int64(length)
	if end > int64(len(content)) {
		end = int64(len(content))
	}
	data := content[offset:end]

	sess.Emit(sess.Event(event.ClassFileActivity, 2, event.SeverityLow).
		WithMessage("SMB read %d bytes from %s at offset %d", len(data), h.path, offset).
		Set("path", h.path).Set("size", len(data)).Set("offset", offset))

	resp := make([]byte, 16)
	binary.LittleEndian.PutUint16(resp[0:2], 17) // structure size
	binary.LittleEndian.PutUint16(resp[2:4], 80) // data offset (from header start)
	binary.LittleEndian.PutUint32(resp[4:8], uint32(len(data)))
	resp = append(resp, data...)
	return simpleResponse(hdr, statusSuccess, resp)
}

// --- SMB2 Write -------------------------------------------------------------

func (s *smbSvc) smbWrite(hdr smbHeader, body []byte, fs *smbFileState, sess *Session) []byte {
	fid := readFileID(body)
	fs.mu.Lock()
	h, ok := fs.handles[fid]
	fs.mu.Unlock()
	if !ok {
		return errorResponse(hdr, statusAccessDenied)
	}

	offset := int64(0)
	length := uint32(0)
	if len(body) >= 48 {
		offset = int64(binary.LittleEndian.Uint64(body[8:16]))
		length = binary.LittleEndian.Uint32(body[4:8])
	}

	var data []byte
	if len(body) >= 48 {
		dataOffset := binary.LittleEndian.Uint16(body[2:4])
		off := int(dataOffset) - 64 // offset from body start (minus header)
		if off >= 0 && off < len(body) {
			end := off + int(length)
			if end > len(body) {
				end = len(body)
			}
			data = body[off:end]
		}
	}

	sev := event.SeverityHigh
	e := sess.Event(event.ClassFileActivity, 3, sev).
		WithMessage("SMB write %d bytes to %s at offset %d", len(data), h.path, offset).
		WithAttack(event.Technique{Tactic: "TA0040", Technique: "T1486", Name: "Data Encrypted for Impact"}).
		Set("path", h.path).Set("size", len(data)).Set("offset", offset)
	if h.node.Canary {
		e.SeverityID = event.SeverityCritical
		e.Set("canary", true)
	}
	sess.Emit(e)

	resp := make([]byte, 16)
	binary.LittleEndian.PutUint16(resp[0:2], 17) // structure size
	binary.LittleEndian.PutUint32(resp[4:8], uint32(len(data)))
	return simpleResponse(hdr, statusSuccess, resp)
}

// --- SMB2 Close -------------------------------------------------------------

func (s *smbSvc) smbClose(hdr smbHeader, body []byte, fs *smbFileState) []byte {
	fid := readFileID(body)
	fs.mu.Lock()
	delete(fs.handles, fid)
	fs.mu.Unlock()

	resp := make([]byte, 60)
	binary.LittleEndian.PutUint16(resp[0:2], 60) // structure size
	return simpleResponse(hdr, statusSuccess, resp)
}

// --- SMB2 QueryDirectory ---------------------------------------------------

// smbQueryDirectory lists a directory's contents. This is what `dir`, `ls` and
// every encryptor does before walking a share. The entries come from the
// persona's VFS, so the canary files sort first — by name, which is how
// almost every encryptor walks.
func (s *smbSvc) smbQueryDirectory(hdr smbHeader, body []byte, fs *smbFileState, sess *Session) []byte {
	fid := readFileID(body)
	fs.mu.Lock()
	h, ok := fs.handles[fid]
	fs.mu.Unlock()
	if !ok {
		return errorResponse(hdr, statusAccessDenied)
	}
	if !h.isDir {
		return errorResponse(hdr, statusInvalidParameter)
	}

	children, _ := s.p.FS.List(h.path)
	if len(children) == 0 {
		return errorResponse(hdr, statusNoMoreFiles)
	}

	sess.Emit(sess.Event(event.ClassSMBActivity, 1, event.SeverityMedium).
		WithMessage("SMB directory listing: %s (%d entries)", h.path, len(children)).
		WithAttack(event.Technique{Tactic: "TA0007", Technique: "T1083", Name: "File and Directory Discovery"}).
		Set("path", h.path).Set("entries", len(children)))

	var entries []byte
	for _, child := range children {
		entry := smbDirEntry(child)
		entries = append(entries, entry...)
	}
	// Patch the last entry to have NextOffset = 0
	if len(entries) > 4 {
		binary.LittleEndian.PutUint32(entries[len(entries)-len(smbDirEntry(children[len(children)-1])):], 0)
	}

	resp := make([]byte, 8)
	binary.LittleEndian.PutUint16(resp[0:2], 9)  // structure size
	binary.LittleEndian.PutUint16(resp[2:4], 72) // output buffer offset (from header)
	binary.LittleEndian.PutUint32(resp[4:8], uint32(len(entries)))
	resp = append(resp, entries...)
	return simpleResponse(hdr, statusSuccess, resp)
}

// smbDirEntry builds a FILE_BOTH_DIR_INFORMATION entry for one child.
func smbDirEntry(n *VNode) []byte {
	nameUTF16 := utf16Encode(n.Name)
	entryLen := 94 + len(nameUTF16)
	padded := (entryLen + 7) &^ 7 // 8-byte alignment

	entry := make([]byte, padded)
	binary.LittleEndian.PutUint32(entry[0:4], uint32(padded)) // NextEntryOffset
	now := windowsTime(n.MTime)
	binary.LittleEndian.PutUint64(entry[8:16], now)  // creation
	binary.LittleEndian.PutUint64(entry[16:24], now) // last access
	binary.LittleEndian.PutUint64(entry[24:32], now) // last write
	binary.LittleEndian.PutUint64(entry[32:40], now) // change time
	binary.LittleEndian.PutUint64(entry[40:48], uint64(n.Size))
	binary.LittleEndian.PutUint64(entry[48:56], uint64(n.Size))
	if n.Dir {
		binary.LittleEndian.PutUint32(entry[56:60], 0x10) // directory
	} else {
		binary.LittleEndian.PutUint32(entry[56:60], 0x20) // archive
	}
	binary.LittleEndian.PutUint32(entry[60:64], uint32(len(nameUTF16)))
	copy(entry[94:], nameUTF16)
	return entry
}

// --- SMB2 QueryInfo --------------------------------------------------------

func (s *smbSvc) smbQueryInfo(hdr smbHeader, body []byte, fs *smbFileState) []byte {
	fid := readFileID(body)
	fs.mu.Lock()
	h, ok := fs.handles[fid]
	fs.mu.Unlock()
	if !ok {
		return errorResponse(hdr, statusAccessDenied)
	}

	now := windowsTime(time.Now())
	info := make([]byte, 40)
	binary.LittleEndian.PutUint64(info[0:8], now)   // creation
	binary.LittleEndian.PutUint64(info[8:16], now)  // last access
	binary.LittleEndian.PutUint64(info[16:24], now) // last write
	binary.LittleEndian.PutUint64(info[24:32], now) // change time
	if h.isDir {
		binary.LittleEndian.PutUint32(info[32:36], 0x10)
	} else {
		binary.LittleEndian.PutUint32(info[32:36], 0x20)
	}

	resp := make([]byte, 8)
	binary.LittleEndian.PutUint16(resp[0:2], 9)  // structure size
	binary.LittleEndian.PutUint16(resp[2:4], 72) // output buffer offset
	binary.LittleEndian.PutUint32(resp[4:8], uint32(len(info)))
	resp = append(resp, info...)
	return simpleResponse(hdr, statusSuccess, resp)
}

// --- helpers ---------------------------------------------------------------

func smbToVFS(smbPath string) string {
	p := strings.ReplaceAll(smbPath, `\`, "/")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "/"
	}
	return "/" + p
}

func windowsTime(t time.Time) uint64 {
	// Windows FILETIME: 100-nanosecond intervals since 1601-01-01.
	const epoch = 116444736000000000
	return uint64(t.UnixNano()/100) + epoch
}

func utf16Encode(s string) []byte {
	b := make([]byte, len(s)*2)
	for i, r := range s {
		if i*2+1 >= len(b) {
			break
		}
		binary.LittleEndian.PutUint16(b[i*2:], uint16(r))
	}
	return b
}

// smbShareRoot resolves the root path a tree connect should serve from.
func smbShareRoot(shareName string, fs *VFS) string {
	candidates := []string{
		"/share/" + strings.ToLower(shareName),
		"/shares/" + strings.ToLower(shareName),
		"/srv/" + strings.ToLower(shareName),
	}
	for _, c := range candidates {
		if _, ok := fs.Lookup(c); ok {
			return c
		}
	}
	if shareName == "" {
		return "/"
	}
	return "/" + path.Clean(strings.ToLower(strings.ReplaceAll(shareName, "$", "")))
}

// smbFormatBytes formats sizes the way a file listing reads.
func smbFormatBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
