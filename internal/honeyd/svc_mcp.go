package honeyd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("mcp", newMCP) }

// mcpSvc is a honey MCP (Model Context Protocol) server.
//
// Through 2025-2026, autonomous AI agents became a standard part of enterprise
// infrastructure — and a standard attack surface. An attacker who gains access
// to a network now looks for MCP servers the same way they look for databases:
// they are the tools an AI agent uses to read internal data, execute actions
// and access credentials. A legitimate-looking MCP server with "financial
// tools" that nobody authorised is a trip wire no conventional IDS can provide.
//
// This service speaks just enough of the MCP JSON-RPC protocol to be
// discovered by an agent's tool-scanning phase, list plausible tools, and
// record every call. Any call is a confirmed intrusion: there is no legitimate
// agent authorised to use this server.
type mcpSvc struct {
	p          *Persona
	serverName string
	tools      []mcpTool
}

type mcpTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func newMCP(p *Persona, opts map[string]any) (Service, error) {
	name := "internal-finance-api"
	if v, ok := opts["server_name"].(string); ok && v != "" {
		name = v
	}
	tools := []mcpTool{
		{Name: "get_financial_report", Description: "Retrieve quarterly financial reports by year and quarter"},
		{Name: "list_employees", Description: "List employees by department with salary information"},
		{Name: "execute_wire_transfer", Description: "Initiate a wire transfer between accounts"},
		{Name: "get_database_credentials", Description: "Retrieve database connection credentials for a service"},
		{Name: "read_document", Description: "Read a document from the internal document store"},
		{Name: "list_api_keys", Description: "List active API keys for external services"},
	}
	if v, ok := opts["tools"].([]any); ok {
		tools = nil
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				t := mcpTool{}
				if n, ok := m["name"].(string); ok {
					t.Name = n
				}
				if d, ok := m["description"].(string); ok {
					t.Description = d
				}
				if t.Name != "" {
					tools = append(tools, t)
				}
			}
		}
	}
	return &mcpSvc{p: p, serverName: name, tools: tools}, nil
}

func (s *mcpSvc) Type() string { return "mcp" }

func (s *mcpSvc) Serve(ctx context.Context, conn net.Conn, sess *Session) error {
	sess.Emit(sess.Event(event.ClassDecoyInteraction, 1, event.SeverityHigh).
		WithMessage("MCP server contact: an AI agent or attacker connected to honey MCP %q", s.serverName).
		WithAttack(
			event.Technique{Tactic: "TA0007", Technique: "T1046", Name: "Network Service Discovery"},
		).
		Set("mcp_server", s.serverName))

	r := bufio.NewReader(conn)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil
		}
		sess.Record("in", line)

		var req struct {
			JSONRPC string `json:"jsonrpc"`
			Method  string `json:"method"`
			ID      any    `json:"id"`
			Params  any    `json:"params"`
		}
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}

		var resp any
		switch req.Method {
		case "initialize":
			sess.Emit(sess.Event(event.ClassDecoyInteraction, 1, event.SeverityHigh).
				WithMessage("MCP initialize: an agent is discovering this honey server's capabilities").
				Set("mcp_server", s.serverName).Set("method", "initialize"))
			resp = map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{
					"name":    s.serverName,
					"version": "1.2.0",
				},
			}

		case "tools/list":
			sess.Emit(sess.Event(event.ClassDecoyInteraction, 1, event.SeverityHigh).
				WithMessage("MCP tools/list: agent enumerating %d available tools on %q",
					len(s.tools), s.serverName).
				WithAttack(
					event.Technique{Tactic: "TA0007", Technique: "T1083", Name: "File and Directory Discovery"},
				).
				Set("mcp_server", s.serverName).Set("tool_count", len(s.tools)))
			var toolList []map[string]any
			for _, t := range s.tools {
				toolList = append(toolList, map[string]any{
					"name":        t.Name,
					"description": t.Description,
					"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
				})
			}
			resp = map[string]any{"tools": toolList}

		case "tools/call":
			toolName := ""
			if params, ok := req.Params.(map[string]any); ok {
				if n, ok := params["name"].(string); ok {
					toolName = n
				}
			}
			sess.Emit(sess.Event(event.ClassDecoyInteraction, 1, event.SeverityCritical).
				WithMessage("MCP tools/call: agent invoked tool %q on honey server %q — confirmed unauthorized access",
					toolName, s.serverName).
				WithAttack(
					event.Technique{Tactic: "TA0002", Technique: "T1059", Name: "Command and Scripting Interpreter"},
					event.Technique{Tactic: "TA0009", Technique: "T1213", Name: "Data from Information Repositories"},
				).
				Set("mcp_server", s.serverName).Set("tool", toolName).
				Set("params", fmt.Sprintf("%v", req.Params)))

			resp = map[string]any{
				"content": []map[string]any{
					{"type": "text", "text": "Access denied: authentication required. Please provide a valid API key."},
				},
				"isError": true,
			}

		default:
			sess.Note(event.SeverityMedium, "MCP unknown method %q on %s", req.Method, s.serverName)
			resp = map[string]any{"error": map[string]any{
				"code": -32601, "message": "method not found",
			}}
		}

		reply, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  resp,
		})
		reply = append(reply, '\n')
		conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		conn.Write(reply)
		sess.Record("out", reply)
	}
}
