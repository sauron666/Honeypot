package breadcrumbs

import (
	"fmt"
	"path"
	"strings"

	"github.com/sauron666/Honeypot/internal/tokens"
)

// This file is the catalogue: one generator per kind of artefact an attacker
// harvests on a machine they have landed on. Each renders a lure that looks
// exactly like the real thing a careless user leaves behind, points it at a
// decoy, and carries a honeytoken so its use is attributed.
//
// The formats are deliberately faithful. An .rdp file that Windows would not
// open, or an aws credentials file the CLI would reject, is not a lure -- it is
// a note that says "honeypot" to anyone who looks. Where a real artefact has a
// syntax, these match it.

func defaultCatalog() []generator {
	return []generator{
		{kind: "rdp-file", services: []string{"rdp", "smb"}, os: Windows, build: buildRDP},
		{kind: "ssh-config", services: []string{"ssh"}, os: Linux, build: buildSSHConfig},
		{kind: "bash-history", services: []string{"ssh", "mysql", "smb", "http"}, os: Linux, build: buildBashHistory},
		{kind: "ps-history", services: []string{"rdp", "smb", "mssql"}, os: Windows, build: buildPSHistory},
		{kind: "aws-credentials", services: []string{"http", "smb"}, os: Any, build: buildAWSCreds},
		{kind: "git-credentials", services: []string{"http"}, os: Any, build: buildGitCreds},
		{kind: "winscp-session", services: []string{"ssh", "ftp"}, os: Windows, build: buildWinSCP},
		{kind: "db-config", services: []string{"mssql", "mysql"}, os: Any, build: buildDBConfig},
		{kind: "creds-file", services: []string{"http", "ssh", "rdp"}, os: Any, build: buildCredsFile},
		{kind: "llm-key", services: []string{"http"}, os: Any, build: buildLLMKey},
	}
}

// join builds a path under the target home, using the OS's separator so the
// lure looks native: backslashes on Windows, forward slashes elsewhere.
func join(tgt Target, parts ...string) string {
	if tgt.OS == Windows {
		all := append([]string{strings.TrimRight(tgt.Home, `\/`)}, parts...)
		return strings.Join(all, `\`)
	}
	return path.Join(append([]string{tgt.Home}, parts...)...)
}

// buildRDP writes a saved Remote Desktop connection. A .rdp file in Documents
// is one of the first things a hands-on-keyboard attacker looks for, because it
// names an interesting host and often a username.
func buildRDP(p *Planner, d Decoy, tgt Target) (*Crumb, error) {
	tok, err := p.minter.Mint(tokens.TypeURL, "breadcrumb rdp "+d.Host, "rdp file on "+tgt.User+"'s endpoint")
	if err != nil {
		return nil, err
	}
	user := userOr(d, "administrator")
	content := strings.Join([]string{
		"full address:s:" + d.Host + ":3389",
		"username:s:" + user,
		"screen mode id:i:2",
		"desktopwidth:i:1920",
		"desktopheight:i:1080",
		"authentication level:i:2",
		"prompt for credentials:i:0",
		"administrative session:i:1",
		// The comment carries the token URL. RDP ignores unknown keys, so a
		// client opens the file cleanly; a human reading it sees a plausible
		// note, and the platform sees the token if it is ever fetched.
		"# provisioned by IT automation: " + tok.Value,
	}, "\r\n") + "\r\n"
	return &Crumb{
		Kind: "rdp-file", Path: join(tgt, "Documents", d.Host+".rdp"),
		Content: content, Mode: "0644", TokenID: tok.ID, Decoy: d.ID,
		Explain: "saved RDP connection to " + d.Host + " (user " + user + ")",
	}, nil
}

// buildSSHConfig appends a Host block to ~/.ssh/config. It is appended, never
// written whole, because a real config almost always already exists and must
// be preserved. The block is delimited so removal takes out exactly these lines.
func buildSSHConfig(p *Planner, d Decoy, tgt Target) (*Crumb, error) {
	tok, err := p.minter.Mint(tokens.TypeSSHKey, "breadcrumb ssh "+d.Host, "ssh config on "+tgt.User+"'s endpoint")
	if err != nil {
		return nil, err
	}
	user := userOr(d, "deploy")
	alias := strings.Split(d.Host, ".")[0]
	block := fmt.Sprintf("Host %s\n    HostName %s\n    User %s\n    # IdentityFile ~/.ssh/%s_id_rsa  # %s\n",
		alias, d.Host, user, alias, tok.Value)
	return &Crumb{
		Kind: "ssh-config", Path: join(tgt, ".ssh", "config"),
		Content: block, Append: true, Mode: "0600", TokenID: tok.ID, Decoy: d.ID,
		Explain: "ssh config alias '" + alias + "' -> " + d.Host + " (user " + user + ")",
	}, nil
}

// buildBashHistory appends commands mentioning the decoy to ~/.bash_history.
// Recent history is where an attacker learns what a box talks to.
func buildBashHistory(p *Planner, d Decoy, tgt Target) (*Crumb, error) {
	tok, err := p.minter.Mint(tokens.TypeCredential, "breadcrumb history "+d.Host, "shell history on "+tgt.User+"'s endpoint")
	if err != nil {
		return nil, err
	}
	user := userOr(d, "svc_backup")
	var line string
	switch strings.ToLower(d.Service) {
	case "mysql":
		line = fmt.Sprintf("mysql -h %s -u %s -p'%s' billing", d.Host, user, tok.Secret)
	case "smb":
		line = fmt.Sprintf("smbclient //%s/backups -U %s%%%s", d.Host, user, tok.Secret)
	case "http":
		line = fmt.Sprintf("curl -u %s:%s https://%s/admin/api", user, tok.Secret, d.Host)
	default:
		line = fmt.Sprintf("sshpass -p '%s' ssh %s@%s", tok.Secret, user, d.Host)
	}
	block := line + "\n"
	return &Crumb{
		Kind: "bash-history", Path: join(tgt, ".bash_history"),
		Content: block, Append: true, Mode: "0600", TokenID: tok.ID, Decoy: d.ID,
		Explain: "shell history: a command against " + d.Host + " with credentials",
	}, nil
}

// buildPSHistory is the Windows equivalent: a PowerShell console history line.
func buildPSHistory(p *Planner, d Decoy, tgt Target) (*Crumb, error) {
	tok, err := p.minter.Mint(tokens.TypeCredential, "breadcrumb ps "+d.Host, "powershell history on "+tgt.User+"'s endpoint")
	if err != nil {
		return nil, err
	}
	user := userOr(d, "svc_backup")
	var line string
	switch strings.ToLower(d.Service) {
	case "mssql":
		line = fmt.Sprintf("Invoke-Sqlcmd -ServerInstance %s -Username %s -Password '%s' -Query 'SELECT name FROM sys.databases'",
			d.Host, user, tok.Secret)
	case "smb":
		line = fmt.Sprintf("net use \\\\%s\\backups /user:%s '%s'", d.Host, user, tok.Secret)
	default:
		line = fmt.Sprintf("mstsc /v:%s   # %s / %s", d.Host, user, tok.Secret)
	}
	block := line + "\r\n"
	return &Crumb{
		Kind: "ps-history",
		Path: join(tgt, "AppData", "Roaming", "Microsoft", "Windows",
			"PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
		Content: block, Append: true, Mode: "0600", TokenID: tok.ID, Decoy: d.ID,
		Explain: "PowerShell history: a command against " + d.Host,
	}, nil
}

// buildAWSCreds writes a [decoy] profile into ~/.aws/credentials. A canary AWS
// key is the single most reliably harvested cloud artefact there is. The profile
// is a named one, appended, so real profiles are untouched.
func buildAWSCreds(p *Planner, d Decoy, tgt Target) (*Crumb, error) {
	tok, err := p.minter.Mint(tokens.TypeAWSKey, "breadcrumb aws "+d.Host, "aws credentials on "+tgt.User+"'s endpoint")
	if err != nil {
		return nil, err
	}
	profile := "prod-backup"
	// endpoint_url points the profile at the decoy's own object-storage
	// endpoint -- a real AWS CLI feature people use for MinIO and on-prem S3 --
	// so an attacker who runs `aws --profile prod-backup s3 ls` reaches the
	// decoy rather than AWS, and the platform catches it. The key stays a
	// canary too, in case they try it against AWS proper.
	block := fmt.Sprintf("\n[%s]\naws_access_key_id = %s\naws_secret_access_key = %s\n"+
		"endpoint_url = https://%s\n",
		profile, tok.Value, tok.Secret, d.Host)
	return &Crumb{
		Kind: "aws-credentials", Path: join(tgt, ".aws", "credentials"),
		Content: block, Append: true, Mode: "0600", TokenID: tok.ID, Decoy: d.ID,
		Explain: "AWS profile [" + profile + "] with a canary key, endpoint -> " + d.Host,
	}, nil
}

// buildGitCreds writes ~/.git-credentials with a token-bearing URL to a decoy
// git host. Git stores these in the clear, and attackers know it.
func buildGitCreds(p *Planner, d Decoy, tgt Target) (*Crumb, error) {
	tok, err := p.minter.Mint(tokens.TypeAPIToken, "breadcrumb git "+d.Host, "git credentials on "+tgt.User+"'s endpoint")
	if err != nil {
		return nil, err
	}
	user := userOr(d, "ci-deploy")
	block := fmt.Sprintf("https://%s:%s@%s\n", user, tok.Value, d.Host)
	return &Crumb{
		Kind: "git-credentials", Path: join(tgt, ".git-credentials"),
		Content: block, Append: true, Mode: "0600", TokenID: tok.ID, Decoy: d.ID,
		Explain: "git credential for https://" + d.Host + " with a bearer token",
	}, nil
}

// buildWinSCP writes a WinSCP session export. Saved SFTP sessions with stored
// passwords are a staple of Windows lateral movement.
func buildWinSCP(p *Planner, d Decoy, tgt Target) (*Crumb, error) {
	tok, err := p.minter.Mint(tokens.TypeCredential, "breadcrumb winscp "+d.Host, "winscp session on "+tgt.User+"'s endpoint")
	if err != nil {
		return nil, err
	}
	user := userOr(d, "backup")
	// WinSCP stores passwords lightly obscured; a plausible-looking opaque blob
	// is enough for the lure, and the real credential is the honeytoken secret,
	// watched wherever it appears.
	content := fmt.Sprintf("[Sessions\\%s]\nHostName=%s\nUserName=%s\nPortNumber=22\n"+
		"FSProtocol=2\nPassword=%s\n", user+"@"+d.Host, d.Host, user, obscure(tok.Secret))
	return &Crumb{
		Kind:    "winscp-session",
		Path:    join(tgt, "AppData", "Roaming", "WinSCP.ini"),
		Content: content, Append: true, Mode: "0600", TokenID: tok.ID, Decoy: d.ID,
		Explain: "WinSCP saved session to " + d.Host + " (user " + user + ")",
	}, nil
}

// buildDBConfig writes an application config with a decoy database connection
// string, the kind left in a project directory or an app's config folder.
func buildDBConfig(p *Planner, d Decoy, tgt Target) (*Crumb, error) {
	tok, err := p.minter.Mint(tokens.TypeDBString, "breadcrumb db "+d.Host, "db config on "+tgt.User+"'s endpoint")
	if err != nil {
		return nil, err
	}
	driver := "sqlserver"
	if strings.EqualFold(d.Service, "mysql") {
		driver = "mysql"
	}
	content := fmt.Sprintf("# database.conf\nDB_DRIVER=%s\nDB_HOST=%s\nDB_NAME=billing\n"+
		"DB_CONNECTION=\"%s\"\n", driver, d.Host, strings.Replace(tok.Value, "sql01", d.Host, 1))
	return &Crumb{
		Kind: "db-config", Path: join(tgt, ".config", "app", "database.conf"),
		Content: content, Mode: "0600", TokenID: tok.ID, Decoy: d.ID,
		Explain: "app database config pointing at " + d.Host,
	}, nil
}

// buildCredsFile writes the artefact everyone pretends they do not keep: a plain
// file of passwords. It names a decoy admin portal and an account.
func buildCredsFile(p *Planner, d Decoy, tgt Target) (*Crumb, error) {
	tok, err := p.minter.Mint(tokens.TypeCredential, "breadcrumb creds "+d.Host, "password file on "+tgt.User+"'s endpoint")
	if err != nil {
		return nil, err
	}
	user := userOr(d, "admin")
	scheme := "https"
	content := fmt.Sprintf("# passwords - do not share\n%s admin portal: %s://%s/admin\n  user: %s\n  pass: %s\n",
		strings.Split(d.Host, ".")[0], scheme, d.Host, user, tok.Secret)
	return &Crumb{
		Kind: "creds-file", Path: join(tgt, "Documents", "passwords.txt"),
		Content: content, Append: true, Mode: "0600", TokenID: tok.ID, Decoy: d.ID,
		Explain: "a passwords.txt entry for " + d.Host,
	}, nil
}

// obscure renders a secret as a short opaque blob, so a saved-session file does
// not carry the honeytoken secret in the clear where a casual glance would spot
// it. The real secret is what the watcher matches; this is only for looks.
// buildLLMKey plants a file that looks like an LLM provider's API key config.
// These are the most stolen credentials of 2025-2026: every attacker who finds
// one tries it immediately, and the moment they do the platform catches them.
func buildLLMKey(p *Planner, d Decoy, tgt Target) (*Crumb, error) {
	tok, err := p.minter.Mint(tokens.TypeLLMKey, "breadcrumb llm-key "+d.Host, "llm key on "+tgt.User+"'s endpoint")
	if err != nil {
		return nil, err
	}
	content := fmt.Sprintf("# OpenAI API configuration\n# Project: internal-analytics (%s)\nOPENAI_API_KEY=%s\nOPENAI_ORG=org-mirage\n",
		d.Host, tok.Value)
	return &Crumb{
		Kind: "llm-key", Path: join(tgt, ".config", "openai", "credentials"),
		Content: content, Mode: "0600", TokenID: tok.ID, Decoy: d.ID,
		Explain: "LLM provider API key (canary) referencing " + d.Host,
	}, nil
}

func obscure(secret string) string {
	var b strings.Builder
	for _, r := range secret {
		b.WriteString(fmt.Sprintf("%02X", byte(r)^0x5A))
	}
	return b.String()
}
