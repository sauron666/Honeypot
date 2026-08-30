// Package observer holds ObserverDriver implementations: what watches inside a
// full-OS decoy and reports what the attacker actually did.
//
// The flagship is DRAKVUF, agentless VMI on Xen: it traps on the hypervisor, so
// there is nothing inside the guest for the attacker to find, disable, or feed
// false data to. That property -- unforgeable observation of a real OS -- is the
// whole reason a full-OS decoy earns its cost over an emulated one.
//
// This file is the half of the driver that needs no hypervisor: parsing
// DRAKVUF's output stream into the normalised drivers.Sighting the rest of
// MIRAGE consumes. It is tested against real DRAKVUF JSON so that when the
// launch glue runs on actual hardware, the mapping is already known-correct.
package observer

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// drakvufLine is the subset of a DRAKVUF JSON event this parser reads. DRAKVUF
// emits one JSON object per line, and every plugin shares these envelope keys;
// the plugin-specific fields are read per Plugin below.
//
// Only the fields MIRAGE attributes on are named. DRAKVUF emits many more, and
// naming only what is used keeps the parser from breaking when a DRAKVUF
// release adds a field, which they do often.
type drakvufLine struct {
	Plugin      string          `json:"Plugin"`
	TimeStamp   drakvufTime_raw `json:"TimeStamp"`
	ProcessName string          `json:"ProcessName"`
	UserId      int             `json:"UserId"`
	PID         int             `json:"PID"`
	PPID        int             `json:"PPID"`
	TID         int             `json:"TID"`

	// procmon
	ExitStatus  *int   `json:"ExitStatus"`
	CommandLine string `json:"CommandLine"`

	// filedelete / filedelete2 / filetracer
	FileName  string `json:"FileName"`
	Operation string `json:"Operation"`

	// regmon
	Key       string `json:"Key"`
	ValueName string `json:"ValueName"`

	// injection / apimon
	TargetPID  int    `json:"TargetPID"`
	TargetName string `json:"TargetName"`
	Method     string `json:"Method"`

	// ssdt / rootkit-ish
	SyscallName string `json:"SyscallName"`

	// crypto hooks (BCryptEncrypt/CryptEncrypt interceptions)
	API    string `json:"API"`
	KeyHex string `json:"KeyHex"`
	Alg    string `json:"Alg"`
}

// drakvufTime_raw handles DRAKVUF's TimeStamp field which can be either a bare
// number (older versions, our unit tests) or a JSON string "seconds.usec"
// (current DRAKVUF v1.1+). Go's encoding/json decodes a quoted number into a
// string type, not float64, so a plain float64 field silently breaks on real
// output.
type drakvufTime_raw float64

func (t *drakvufTime_raw) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}
	*t = drakvufTime_raw(v)
	return nil
}

// ParseDrakvufLine turns one line of DRAKVUF output into a Sighting.
//
// It returns ok=false for a line that carries nothing worth an event -- a
// plugin MIRAGE does not map, or a heartbeat -- rather than an error, because a
// stream where one unmapped line aborts the whole observation is a stream that
// stops the first time DRAKVUF is upgraded.
func ParseDrakvufLine(decoyID string, raw []byte) (drivers.Sighting, bool) {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || raw[0] != '{' {
		return drivers.Sighting{}, false
	}
	var l drakvufLine
	if err := json.Unmarshal(raw, &l); err != nil {
		return drivers.Sighting{}, false
	}

	s := drivers.Sighting{
		DecoyID: decoyID,
		Time:    drakvufTimeVal(float64(l.TimeStamp)),
		Process: l.ProcessName,
		PID:     l.PID,
		PPID:    l.PPID,
		User:    strconv.Itoa(l.UserId),
		Detail:  map[string]string{},
	}
	if l.UserId == 0 {
		s.User = ""
	}

	switch strings.ToLower(l.Plugin) {
	case "procmon":
		s.Kind = "process"
		s.CommandLine = l.CommandLine
		if l.ExitStatus != nil {
			s.Action = "exit"
			s.Detail["exit_status"] = strconv.Itoa(*l.ExitStatus)
		} else {
			s.Action = "exec"
		}
		s.Target = l.CommandLine

	case "filedelete", "filedelete2", "filetracer":
		s.Kind = "file"
		s.Action = normalizeFileOp(l.Operation, l.Plugin)
		s.Target = normalizePath(l.FileName)

	case "regmon":
		s.Kind = "registry"
		s.Action = normalizeRegOp(l.Operation)
		s.Target = l.Key
		if l.ValueName != "" {
			s.Detail["value"] = l.ValueName
		}

	case "injection", "memdump":
		s.Kind = "injection"
		s.Action = "inject"
		s.Target = l.TargetName
		if l.TargetPID != 0 {
			s.Detail["target_pid"] = strconv.Itoa(l.TargetPID)
		}
		if l.Method != "" {
			s.Detail["method"] = l.Method
		}

	case "ssdt", "rootkitmon":
		s.Kind = "module"
		s.Action = "hook"
		s.Target = l.SyscallName

	case "apimon":
		api := strings.ToLower(l.API)
		if strings.Contains(api, "crypt") || strings.Contains(api, "bcrypt") {
			s.Kind = "crypto"
			s.Action = "encrypt"
			s.Target = l.API
			if l.KeyHex != "" {
				s.Detail["key_hex"] = l.KeyHex
			}
			if l.Alg != "" {
				s.Detail["algorithm"] = l.Alg
			}
		} else {
			return drivers.Sighting{}, false
		}

	default:
		return drivers.Sighting{}, false
	}

	if len(s.Detail) == 0 {
		s.Detail = nil
	}
	return s, true
}

// drakvufTimeVal converts DRAKVUF's floating-point unix seconds to a time. A zero
// or absent timestamp becomes "now", so a sighting is never mis-dated to 1970,
// which would put it outside every engagement window.
func drakvufTimeVal(ts float64) time.Time {
	if ts <= 0 {
		return time.Now()
	}
	sec := int64(ts)
	nsec := int64((ts - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC()
}

// normalizePath turns a DRAKVUF device path into something readable. DRAKVUF
// reports NT paths like \Device\HarddiskVolume2\Users\...; the volume prefix is
// noise for attribution, so it is trimmed to a recognisable path.
func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	if i := strings.Index(p, `HarddiskVolume`); i >= 0 {
		if j := strings.IndexByte(p[i:], '\\'); j >= 0 {
			return `C:` + p[i+j:]
		}
	}
	return p
}

func normalizeFileOp(op, plugin string) string {
	switch {
	case strings.EqualFold(plugin, "filedelete"), strings.EqualFold(plugin, "filedelete2"):
		return "delete"
	case strings.Contains(strings.ToLower(op), "write"):
		return "write"
	case strings.Contains(strings.ToLower(op), "create"):
		return "create"
	case strings.Contains(strings.ToLower(op), "delete"):
		return "delete"
	default:
		return "access"
	}
}

func normalizeRegOp(op string) string {
	l := strings.ToLower(op)
	switch {
	case strings.Contains(l, "delete"):
		return "delete"
	case strings.Contains(l, "set"), strings.Contains(l, "write"):
		return "write"
	default:
		return "read"
	}
}
