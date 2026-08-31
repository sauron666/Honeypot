//go:build windows

package main

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// Windows collector: reads Sysmon process-create events (Event ID 1) from the
// Windows event log via PowerShell. Sysmon is standard enterprise telemetry, so
// a decoy that runs it looks MORE like a real corporate machine, not less.
// Requires Sysmon installed and logging to Microsoft-Windows-Sysmon/Operational.
//
// Not exercised in CI (needs Windows + Sysmon); the forwarder it feeds is tested.

func collect(ctx context.Context, decoyID string, fwd *forwarder) error {
	last := time.Now().Add(-1 * time.Minute)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			events, newest := readSysmon(ctx, last)
			for _, e := range events {
				fwd.enqueue(sysmonToSighting(decoyID, e))
			}
			if newest.After(last) {
				last = newest
			}
		}
	}
}

type sysmonEvent struct {
	TimeCreated string `json:"TimeCreated"`
	Image       string `json:"Image"`
	CommandLine string `json:"CommandLine"`
	User        string `json:"User"`
	ProcessId   string `json:"ProcessId"`
	ParentImage string `json:"ParentImage"`
}

// readSysmon queries Sysmon Event ID 1 (process create) newer than `since`.
// It asks PowerShell to project the Sysmon XML fields into flat JSON.
func readSysmon(ctx context.Context, since time.Time) ([]sysmonEvent, time.Time) {
	newest := since
	ps := `$since=[datetime]'` + since.UTC().Format("2006-01-02T15:04:05") + `Z';` +
		`Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1;StartTime=$since} -ErrorAction SilentlyContinue |` +
		`ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' };` +
		`[pscustomobject]@{TimeCreated=$_.TimeCreated.ToUniversalTime().ToString('o');Image=$d['Image'];CommandLine=$d['CommandLine'];User=$d['User'];ProcessId=$d['ProcessId'];ParentImage=$d['ParentImage']} } |` +
		`ConvertTo-Json -AsArray`
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		logf("sysmon query: %v", err)
		return nil, newest
	}
	var events []sysmonEvent
	if err := json.Unmarshal(out, &events); err != nil {
		return nil, newest
	}
	for _, e := range events {
		if t, err := time.Parse(time.RFC3339, e.TimeCreated); err == nil && t.After(newest) {
			newest = t
		}
	}
	return events, newest
}

func sysmonToSighting(decoyID string, e sysmonEvent) drivers.Sighting {
	pid, _ := strconv.Atoi(strings.TrimSpace(e.ProcessId))
	t, err := time.Parse(time.RFC3339, e.TimeCreated)
	if err != nil {
		t = time.Now()
	}
	return drivers.Sighting{
		DecoyID: decoyID, Time: t, Kind: "process", Action: "exec",
		Process: e.Image, CommandLine: e.CommandLine, User: e.User, PID: pid,
		Detail: map[string]string{"parent_image": e.ParentImage},
	}
}
