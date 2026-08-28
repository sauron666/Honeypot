// Package insider implements deception specifically for insider threats.
//
// A honeypot catches external attackers by existing where they are not supposed
// to be. An insider threat is harder: the person is supposed to be on the
// network, and they have credentials that work. What they are not supposed to
// do is read the layoff list, copy the customer database, or browse the CEO's
// salary file. Insider deception works by placing exactly those artefacts where
// only someone doing something wrong would find them.
//
// Legal note (EU): deploying insider-threat deception in a workplace requires
// agreement with a works council or DPO under GDPR Art. 6(1)(f) and national
// labour law. This package ships a ready DPIA template and a policy template
// so the customer can get started without a lawyer from scratch.
package insider

import (
	"fmt"
	"strings"
	"time"
)

// Lure is one piece of insider-threat bait.
type Lure struct {
	// Type is what the lure looks like: "document", "database-record",
	// "share-folder", "email-draft", "registry-key".
	Type string `json:"type" yaml:"type"`
	// Name is the filename or object name the insider sees.
	Name string `json:"name" yaml:"name"`
	// Description is why it is tempting — what it looks like it contains.
	Description string `json:"description" yaml:"description"`
	// VisibleTo restricts which groups can see the lure, so it only fires for
	// people who had to go looking for it.
	VisibleTo []string `json:"visible_to,omitempty" yaml:"visible_to,omitempty"`
	// TokenID is the honeytoken that fires when the lure is accessed.
	TokenID string `json:"token_id" yaml:"token_id"`
	// Location is where it is placed: a share path, a database table, a folder.
	Location string `json:"location" yaml:"location"`
}

// InsiderKit generates lures appropriate for a given department/vertical.
type InsiderKit struct {
	Vertical string
	Domain   string
	Year     int
}

// NewKit builds a kit for the given vertical.
func NewKit(vertical, domain string) *InsiderKit {
	return &InsiderKit{
		Vertical: vertical, Domain: domain, Year: time.Now().Year(),
	}
}

// GenerateLures produces a set of tempting insider-bait for the vertical.
func (k *InsiderKit) GenerateLures() []Lure {
	year := k.Year
	var lures []Lure

	// Universal lures — tempting in every organisation
	lures = append(lures, []Lure{
		{Type: "document", Name: fmt.Sprintf("Salary_Review_%d_CONFIDENTIAL.xlsx", year),
			Description: "Salary review spreadsheet with every employee's compensation",
			VisibleTo:   []string{"HR", "Finance", "Executive"},
			Location:    `\\fileserver\HR$\Compensation`},
		{Type: "document", Name: fmt.Sprintf("Restructuring_Plan_%d_DRAFT.docx", year),
			Description: "Draft restructuring plan with affected departments and headcount",
			VisibleTo:   []string{"HR", "Executive"},
			Location:    `\\fileserver\Executive$\Strategic`},
		{Type: "document", Name: fmt.Sprintf("Layoffs_%d_Q4_NOT_FINAL.xlsx", year),
			Description: "Layoff list by department — the document everyone fears",
			VisibleTo:   []string{"HR"},
			Location:    `\\fileserver\HR$\Confidential`},
		{Type: "document", Name: "Board_Minutes_Emergency_Session.pdf",
			Description: "Emergency board meeting minutes — M&A discussion",
			VisibleTo:   []string{"Executive", "Legal"},
			Location:    `\\fileserver\Board$`},
		{Type: "document", Name: "Customer_Database_Export_FULL.csv",
			Description: "Full customer database export with contact details and revenue",
			VisibleTo:   []string{"Sales", "IT"},
			Location:    `\\fileserver\Sales$\Exports`},
		{Type: "share-folder", Name: "IT-Passwords",
			Description: "Shared folder named to suggest it contains admin credentials",
			VisibleTo:   []string{"IT"},
			Location:    `\\fileserver\IT$`},
		{Type: "document", Name: fmt.Sprintf("IT_Admin_Credentials_%d.kdbx", year),
			Description: "KeePass database file — the most tempting file an insider can find",
			VisibleTo:   []string{"IT"},
			Location:    `\\fileserver\IT$\IT-Passwords`},
		{Type: "database-record", Name: "vip_customers",
			Description: "Database table with VIP customer financial details",
			Location:    "billing.vip_customers"},
	}...)

	// Vertical-specific lures
	switch strings.ToLower(k.Vertical) {
	case "healthcare":
		lures = append(lures,
			Lure{Type: "document", Name: "Patient_Records_Export.csv",
				Description: "Patient records with PII — HIPAA violation if exfiltrated",
				VisibleTo:   []string{"Medical", "IT"},
				Location:    `\\fileserver\Medical$\Records`},
			Lure{Type: "document", Name: "Drug_Trial_Results_Phase3_EMBARGOED.pdf",
				Description: "Embargoed clinical trial results — insider trading material",
				VisibleTo:   []string{"Research"},
				Location:    `\\fileserver\Research$\Trials`})
	case "finance", "banking":
		lures = append(lures,
			Lure{Type: "document", Name: fmt.Sprintf("Trading_Positions_%d_LIVE.xlsx", year),
				Description: "Live trading positions — market-moving if leaked",
				VisibleTo:   []string{"Trading", "Risk"},
				Location:    `\\fileserver\Trading$`},
			Lure{Type: "document", Name: "AML_Suspicious_Accounts.xlsx",
				Description: "Anti-money-laundering flagged accounts",
				VisibleTo:   []string{"Compliance"},
				Location:    `\\fileserver\Compliance$\AML`})
	case "legal":
		lures = append(lures,
			Lure{Type: "document", Name: "Merger_Target_Valuation_PRIVILEGED.xlsx",
				Description: "M&A target valuation — attorney-client privileged",
				VisibleTo:   []string{"Legal", "Executive"},
				Location:    `\\fileserver\Legal$\MA`})
	case "technology", "it":
		lures = append(lures,
			Lure{Type: "document", Name: "Source_Code_Audit_Vulnerabilities.pdf",
				Description: "Security audit findings with unpatched vulnerabilities",
				VisibleTo:   []string{"Security", "IT"},
				Location:    `\\fileserver\Security$\Audits`},
			Lure{Type: "document", Name: "AWS_Root_Credentials_BACKUP.txt",
				Description: "Backup of cloud root credentials",
				VisibleTo:   []string{"IT", "DevOps"},
				Location:    `\\fileserver\IT$\Cloud`})
	}

	return lures
}

// DPIATemplate returns a Data Protection Impact Assessment template for
// insider-threat deception, pre-filled with the standard justification and
// risk analysis. This exists because without it the feature stays turned off:
// a legal department that has to write the DPIA from scratch will say no.
func DPIATemplate(org, dpo string) string {
	return fmt.Sprintf(`DATA PROTECTION IMPACT ASSESSMENT
Insider-Threat Deception Deployment

Organisation: %s
Data Protection Officer: %s
Date: %s

1. DESCRIPTION OF PROCESSING
The organisation deploys decoy files and database records ("lures") in
shared network locations. These lures contain no real personal data. They
are monitored for access: any access is logged with the accessing account
name, timestamp and source IP.

2. LEGAL BASIS
Article 6(1)(f) GDPR — legitimate interest of the controller in detecting
and preventing insider threats, data theft and unauthorised access.

3. NECESSITY AND PROPORTIONALITY
- Lures contain NO real personal data — they are generated fakes.
- Only the fact of access is recorded, not the content of legitimate work.
- The measure is targeted: only access to specifically planted bait triggers
  an alert. Normal work activity is not monitored.
- Less intrusive alternatives (DLP, UEBA) produce high false-positive rates
  and monitor all activity; deception monitors only illegitimate access.

4. RISKS TO DATA SUBJECTS
- Risk: an employee's access to a lure is recorded. Mitigation: this is
  equivalent to any other security log entry (firewall, badge reader) and
  is processed under the same retention and access policies.
- Risk: false accusation based on accidental access. Mitigation: a single
  access to a clearly-labelled confidential file is an investigation trigger,
  not an accusation. Multiple accesses and exfiltration patterns raise the
  severity. HR and legal review before any action.

5. CONSULTATION
- Works council / employee representatives: [TO BE COMPLETED]
- DPO review: [TO BE COMPLETED]

6. DECISION
[TO BE COMPLETED BY CONTROLLER]

This template is provided by MIRAGE as a starting point. It does not
constitute legal advice. Consult with your DPO and legal counsel.
`, org, dpo, time.Now().Format("2006-01-02"))
}

// PolicyTemplate returns an acceptable-use policy addendum covering deception.
func PolicyTemplate(org string) string {
	return fmt.Sprintf(`ACCEPTABLE USE POLICY ADDENDUM — DECEPTION CONTROLS

Organisation: %s
Effective: %s

1. The organisation deploys security monitoring controls that include decoy
   files, accounts and network services ("deception controls") in its IT
   environment.

2. These controls exist solely to detect unauthorised access, data theft
   and security breaches. They do not monitor or restrict normal work activity.

3. Accessing a resource clearly marked as confidential, restricted or
   belonging to a department the employee does not work in may trigger a
   security investigation under existing incident response procedures.

4. Employees are not expected to identify which resources are decoy controls.
   The purpose is to detect malicious or unauthorised activity, not to test
   employees.

5. All alerts generated by deception controls are reviewed by the security
   team and, where applicable, HR and legal, before any action is taken.

This addendum supplements the existing Acceptable Use Policy.
`, org, time.Now().Format("2006-01-02"))
}
