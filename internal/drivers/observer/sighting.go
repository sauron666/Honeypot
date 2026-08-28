package observer

import (
	"strings"

	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/event"
)

// SightingToEvent maps a normalised sighting to an OCSF event.
//
// This is where inside-the-decoy observation joins the rest of MIRAGE: once a
// sighting is an event, the engagement tracker stitches it into the attacker's
// story, the ransomware detector sees the file activity, and the chain seals
// it as evidence. The severity and ATT&CK mapping encode what actually matters
// about being *inside* a decoy -- an interactive shell there is not routine the
// way a probe of an emulated port is; it means the attacker got a foothold on a
// real machine, and every action they take is high signal.
//
// tenant and site tag the event; decoyID and persona come from the sighting and
// the deployment. It never returns nil: an unmapped kind still becomes a
// low-severity record, because on a decoy that no one legitimately uses, even an
// action MIRAGE does not specifically understand is worth keeping.
func SightingToEvent(s drivers.Sighting, tenant, site, persona string) *event.Event {
	class := event.ClassProcessActivity
	sev := event.SeverityMedium
	var techniques []event.Technique
	msg := ""

	switch s.Kind {
	case "process":
		class = event.ClassProcessActivity
		if s.Action == "exec" {
			// A process starting inside a decoy is the attacker's hands on the
			// keyboard. The command line is the intent.
			sev = event.SeverityHigh
			msg = "process launched in decoy: " + processLabel(s)
			techniques = append(techniques,
				event.Technique{Tactic: "TA0002", Technique: "T1059", Name: "Command and Scripting Interpreter"})
			if looksLikeDiscovery(s.CommandLine) {
				techniques = append(techniques,
					event.Technique{Tactic: "TA0007", Technique: "T1057", Name: "Process Discovery"})
			}
		} else {
			sev = event.SeverityLow
			msg = "process exited in decoy: " + processLabel(s)
		}

	case "file":
		class = event.ClassFileActivity
		switch s.Action {
		case "delete":
			// Mass deletion inside a decoy is a ransomware or wiper signal; the
			// ransomware detector will corroborate across many of these.
			sev = event.SeverityHigh
			msg = "file deleted in decoy: " + s.Target
			techniques = append(techniques,
				event.Technique{Tactic: "TA0040", Technique: "T1485", Name: "Data Destruction"})
		case "write", "create":
			sev = event.SeverityMedium
			msg = "file " + s.Action + " in decoy: " + s.Target
		default:
			sev = event.SeverityLow
			msg = "file access in decoy: " + s.Target
		}

	case "registry":
		class = event.ClassRegistryKey
		sev = event.SeverityMedium
		msg = "registry " + s.Action + " in decoy: " + s.Target
		if isPersistenceKey(s.Target) {
			sev = event.SeverityHigh
			techniques = append(techniques,
				event.Technique{Tactic: "TA0003", Technique: "T1547.001", Name: "Registry Run Keys / Startup Folder"})
		}

	case "injection":
		class = event.ClassProcessActivity
		sev = event.SeverityCritical
		msg = "process injection in decoy: " + s.Process + " -> " + s.Target
		techniques = append(techniques,
			event.Technique{Tactic: "TA0004", Technique: "T1055", Name: "Process Injection"})

	case "module":
		class = event.ClassModuleActivity
		sev = event.SeverityHigh
		msg = "kernel hook in decoy: " + s.Target
		techniques = append(techniques,
			event.Technique{Tactic: "TA0005", Technique: "T1014", Name: "Rootkit"})

	default:
		class = event.ClassProcessActivity
		sev = event.SeverityLow
		msg = "activity in decoy: " + s.Kind + " " + s.Action
	}

	e := event.New(class, 1, sev, event.PlaneObserver).WithMessage("%s", msg)
	e.Mirage.TenantID, e.Mirage.SiteID = tenant, site
	e.Mirage.DecoyID = s.DecoyID
	e.Mirage.Persona = persona
	if len(techniques) > 0 {
		e.WithAttack(techniques...)
	}
	if s.Process != "" {
		e.Set("process", s.Process)
	}
	if s.PID != 0 {
		e.Set("pid", s.PID)
	}
	if s.PPID != 0 {
		e.Set("ppid", s.PPID)
	}
	if s.CommandLine != "" {
		e.Set("command_line", s.CommandLine)
	}
	if s.Target != "" {
		e.Set("target", s.Target)
	}
	if s.User != "" {
		e.Set("user", s.User)
	}
	for k, v := range s.Detail {
		e.Set(k, v)
	}
	return e
}

func processLabel(s drivers.Sighting) string {
	if s.CommandLine != "" {
		return s.CommandLine
	}
	return s.Process
}

func looksLikeDiscovery(cmd string) bool {
	l := strings.ToLower(cmd)
	for _, tool := range []string{"whoami", "net user", "net group", "nltest", "systeminfo",
		"ipconfig", "arp -a", "quser", "tasklist", "netstat", "wmic"} {
		if strings.Contains(l, tool) {
			return true
		}
	}
	return false
}

func isPersistenceKey(key string) bool {
	l := strings.ToLower(key)
	return strings.Contains(l, `\run`) || strings.Contains(l, "runonce") ||
		strings.Contains(l, "currentversion\\run") || strings.Contains(l, "userinit") ||
		strings.Contains(l, "winlogon")
}
