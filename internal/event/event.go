// Package event defines MIRAGE's canonical event model.
//
// The wire format follows OCSF (Open Cybersecurity Schema Framework) so that
// events are consumable by Splunk, Amazon Security Lake and friends without a
// translation layer, plus a `mirage` extension object that carries the
// deception-specific context every event needs: which decoy, which engagement,
// which observation plane, and the tamper-evidence chain link.
package event

import (
	"errors"
	"fmt"
	"time"
)

// Class is an OCSF class_uid. Values below 9000 are OCSF; 9xxx are MIRAGE
// extensions registered in the vendor range.
type Class uint16

const (
	ClassFileActivity     Class = 1001
	ClassProcessActivity  Class = 1007
	ClassModuleActivity   Class = 1005
	ClassDetectionFinding Class = 2004
	ClassRegistryKey      Class = 2011
	ClassAuthentication   Class = 3002
	ClassNetworkActivity  Class = 4001
	ClassHTTPActivity     Class = 4002
	ClassDNSActivity      Class = 4003
	ClassSSHActivity      Class = 4007
	ClassSMBActivity      Class = 4006

	// MIRAGE extensions.
	ClassDecoyInteraction Class = 9001 // any touch of a decoy service
	ClassTokenTriggered   Class = 9002 // honeytoken callback
	ClassCommandExecuted  Class = 9003 // reconstructed attacker command
	ClassCredentialOffer  Class = 9004 // credentials presented to a decoy
	ClassContainment      Class = 9005 // containment guard fired
	ClassEngagement       Class = 9006 // engagement lifecycle
	ClassAssurance        Class = 9007 // self-test / fingerprint assurance
)

func (c Class) String() string {
	switch c {
	case ClassFileActivity:
		return "file_activity"
	case ClassProcessActivity:
		return "process_activity"
	case ClassModuleActivity:
		return "module_activity"
	case ClassDetectionFinding:
		return "detection_finding"
	case ClassRegistryKey:
		return "registry_key_activity"
	case ClassAuthentication:
		return "authentication"
	case ClassNetworkActivity:
		return "network_activity"
	case ClassHTTPActivity:
		return "http_activity"
	case ClassDNSActivity:
		return "dns_activity"
	case ClassSSHActivity:
		return "ssh_activity"
	case ClassSMBActivity:
		return "smb_activity"
	case ClassDecoyInteraction:
		return "decoy_interaction"
	case ClassTokenTriggered:
		return "token_triggered"
	case ClassCommandExecuted:
		return "command_executed"
	case ClassCredentialOffer:
		return "credential_offer"
	case ClassContainment:
		return "containment"
	case ClassEngagement:
		return "engagement"
	case ClassAssurance:
		return "assurance"
	default:
		return fmt.Sprintf("class_%d", uint16(c))
	}
}

// Severity follows OCSF severity_id.
type Severity uint8

const (
	SeverityInformational Severity = 1
	SeverityLow           Severity = 2
	SeverityMedium        Severity = 3
	SeverityHigh          Severity = 4
	SeverityCritical      Severity = 5
	SeverityFatal         Severity = 6
)

func (s Severity) String() string {
	switch s {
	case SeverityInformational:
		return "informational"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	case SeverityFatal:
		return "fatal"
	default:
		return "unknown"
	}
}

// Plane identifies which observation plane produced the event. Knowing the
// provenance matters: a host event from VMI is trustworthy in a way that an
// event reported by something running inside the decoy never is.
type Plane string

const (
	PlaneHoneyd     Plane = "honeyd"     // emulated service farm
	PlaneObserver   Plane = "observer"   // agentless host introspection
	PlaneTap        Plane = "tap"        // network capture and reconstruction
	PlaneGateway    Plane = "gateway"    // egress broker
	PlaneToken      Plane = "token"      // honeytoken callback
	PlaneBreadcrumb Plane = "breadcrumb" // lure agent on a real endpoint
	PlaneDirector   Plane = "director"   // control plane itself
	PlaneAssure     Plane = "assure"     // self-test
)

// Technique is a MITRE ATT&CK mapping carried on the event itself, so that a
// consumer never has to re-derive it.
type Technique struct {
	Tactic    string `json:"tactic,omitempty"`    // e.g. TA0006
	Technique string `json:"technique,omitempty"` // e.g. T1110.001
	Name      string `json:"name,omitempty"`
}

// Endpoint is a trimmed OCSF endpoint object.
type Endpoint struct {
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	MAC      string `json:"mac,omitempty"`
	SvcName  string `json:"svc_name,omitempty"`
}

// Actor describes who acted, as far as we can tell.
type Actor struct {
	User    string `json:"user,omitempty"`
	Process string `json:"process,omitempty"`
	Session string `json:"session_uid,omitempty"`
}

// Product identifies the emitting software.
type Product struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
	Feature    string `json:"feature,omitempty"`
}

// Metadata is the OCSF metadata object.
type Metadata struct {
	Version  string  `json:"version"`
	Product  Product `json:"product"`
	UID      string  `json:"uid"`
	Sequence uint64  `json:"sequence"`
	LogName  string  `json:"log_name,omitempty"`
}

// ChainLink is the tamper-evidence record. Hash covers the canonical encoding
// of the whole event with Hash itself blanked, chained to the previous event.
type ChainLink struct {
	Seq      uint64 `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Mirage is the deception-specific extension object.
type Mirage struct {
	TenantID     string      `json:"tenant_id"`
	SiteID       string      `json:"site_id"`
	DecoyID      string      `json:"decoy_id,omitempty"`
	Persona      string      `json:"decoy_persona,omitempty"`
	EngagementID string      `json:"engagement_id,omitempty"`
	Plane        Plane       `json:"source_plane"`
	Service      string      `json:"service,omitempty"`
	Confidence   int         `json:"confidence"`
	Attack       []Technique `json:"attack,omitempty"`
	ArtifactRefs []string    `json:"artifact_refs,omitempty"`
	Chain        *ChainLink  `json:"chain,omitempty"`
}

// Event is one observation.
type Event struct {
	Time        int64    `json:"time"` // unix milliseconds
	ClassUID    Class    `json:"class_uid"`
	CategoryUID uint16   `json:"category_uid"`
	ActivityID  int      `json:"activity_id"`
	TypeUID     int64    `json:"type_uid"`
	SeverityID  Severity `json:"severity_id"`
	Message     string   `json:"message,omitempty"`

	Metadata Metadata  `json:"metadata"`
	Src      *Endpoint `json:"src_endpoint,omitempty"`
	Dst      *Endpoint `json:"dst_endpoint,omitempty"`
	Actor    *Actor    `json:"actor,omitempty"`

	Mirage Mirage `json:"mirage"`

	// Data carries class-specific fields that have no OCSF home yet. Keys are
	// sorted on encode, so it does not break the hash chain.
	Data map[string]any `json:"unmapped,omitempty"`
}

// SchemaVersion is the OCSF version we claim compatibility with.
const SchemaVersion = "1.3.0"

// New builds an event with the mandatory scaffolding filled in. Callers set the
// rest through the With* helpers or directly.
func New(class Class, activityID int, sev Severity, plane Plane) *Event {
	return &Event{
		Time:        time.Now().UnixMilli(),
		ClassUID:    class,
		CategoryUID: categoryFor(class),
		ActivityID:  activityID,
		TypeUID:     int64(class)*100 + int64(activityID),
		SeverityID:  sev,
		Metadata: Metadata{
			Version: SchemaVersion,
			UID:     NewID(),
		},
		Mirage: Mirage{Plane: plane, Confidence: 100},
	}
}

func categoryFor(c Class) uint16 {
	switch {
	case c >= 1000 && c < 2000:
		return 1 // System Activity
	case c >= 2000 && c < 3000:
		return 2 // Findings
	case c >= 3000 && c < 4000:
		return 3 // Identity & Access Management
	case c >= 4000 && c < 5000:
		return 4 // Network Activity
	default:
		return 9 // MIRAGE extension category
	}
}

// Set stores a class-specific field.
func (e *Event) Set(key string, val any) *Event {
	if e.Data == nil {
		e.Data = map[string]any{}
	}
	e.Data[key] = val
	return e
}

// Get reads a class-specific field.
func (e *Event) Get(key string) (any, bool) {
	v, ok := e.Data[key]
	return v, ok
}

// GetString reads a class-specific string field.
func (e *Event) GetString(key string) string {
	if s, ok := e.Data[key].(string); ok {
		return s
	}
	return ""
}

// WithSrc sets the source endpoint.
func (e *Event) WithSrc(ip string, port int) *Event {
	e.Src = &Endpoint{IP: ip, Port: port}
	return e
}

// WithDst sets the destination endpoint.
func (e *Event) WithDst(ip string, port int, svc string) *Event {
	e.Dst = &Endpoint{IP: ip, Port: port, SvcName: svc}
	return e
}

// WithAttack appends ATT&CK mappings.
func (e *Event) WithAttack(t ...Technique) *Event {
	e.Mirage.Attack = append(e.Mirage.Attack, t...)
	return e
}

// WithMessage sets the human-readable summary.
func (e *Event) WithMessage(format string, args ...any) *Event {
	if len(args) == 0 {
		e.Message = format
	} else {
		e.Message = fmt.Sprintf(format, args...)
	}
	return e
}

// Timestamp returns the event time.
func (e *Event) Timestamp() time.Time { return time.UnixMilli(e.Time) }

var (
	ErrNoTime     = errors.New("event: time is zero")
	ErrNoClass    = errors.New("event: class_uid is zero")
	ErrNoUID      = errors.New("event: metadata.uid is empty")
	ErrNoPlane    = errors.New("event: mirage.source_plane is empty")
	ErrNoSeverity = errors.New("event: severity_id is zero")
)

// Validate rejects events that would be useless or unattributable downstream.
// It is deliberately strict: a malformed event is a bug we want to find in
// tests, not a mystery in production.
func (e *Event) Validate() error {
	switch {
	case e.Time == 0:
		return ErrNoTime
	case e.ClassUID == 0:
		return ErrNoClass
	case e.Metadata.UID == "":
		return ErrNoUID
	case e.SeverityID == 0:
		return ErrNoSeverity
	case e.Mirage.Plane == "":
		return ErrNoPlane
	}
	return nil
}

// Clone returns a deep-enough copy for safe fan-out to multiple subscribers.
func (e *Event) Clone() *Event {
	cp := *e
	if e.Src != nil {
		s := *e.Src
		cp.Src = &s
	}
	if e.Dst != nil {
		d := *e.Dst
		cp.Dst = &d
	}
	if e.Actor != nil {
		a := *e.Actor
		cp.Actor = &a
	}
	if e.Mirage.Chain != nil {
		c := *e.Mirage.Chain
		cp.Mirage.Chain = &c
	}
	if e.Mirage.Attack != nil {
		cp.Mirage.Attack = append([]Technique(nil), e.Mirage.Attack...)
	}
	if e.Mirage.ArtifactRefs != nil {
		cp.Mirage.ArtifactRefs = append([]string(nil), e.Mirage.ArtifactRefs...)
	}
	if e.Data != nil {
		cp.Data = make(map[string]any, len(e.Data))
		for k, v := range e.Data {
			cp.Data[k] = v
		}
	}
	return &cp
}
