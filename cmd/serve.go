package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"secagent/internal/formatter"
	"secagent/internal/scanner"
)

// jsonRPCRequest is a minimal JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// jsonRPCResponse is a minimal JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   any    `json:"error,omitempty"`
}

// mcpToolDef is the tool definition in MCP list_tools response.
type mcpToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// RunServe starts a stdio MCP server exposing SCALIBR scanning tools.
//
// Configure in Claude Code settings as:
//
//	{
//	  "mcpServers": {
//	    "scalibr": {
//	      "command": "/path/to/secagent",
//	      "args": ["serve"]
//	    }
//	  }
//	}
func RunServe(ctx context.Context) error {
	fmt.Fprintln(os.Stderr, "secagent MCP server starting on stdio...")

	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 1024*1024), 1024*1024)

	for s.Scan() {
		line := s.Bytes()
		if len(line) == 0 {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}

		resp := handleMCPRequest(ctx, &req)
		if resp == nil {
			continue // notification, no response needed
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
	}

	return s.Err()
}

func handleMCPRequest(ctx context.Context, req *jsonRPCRequest) *jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
				"serverInfo": map[string]any{
					"name":    "secagent-scalibr",
					"version": "1.0.0",
				},
			},
		}

	case "notifications/initialized":
		return nil // notification, no response

	case "tools/list":
		tools := []mcpToolDef{
			{
				Name:        "scan_path",
				Description: "Scan a filesystem path for software packages and known vulnerabilities (CVEs).",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path":      map[string]any{"type": "string", "description": "Filesystem path to scan"},
						"osv_match": map[string]any{"type": "boolean", "description": "Match against OSV database (default: true)"},
					},
					"required": []string{"path"},
				},
			},
			{
				Name:        "scan_secrets",
				Description: "Scan a filesystem path for secrets, credentials, and API keys.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path": map[string]any{"type": "string", "description": "Filesystem path to scan"},
					},
					"required": []string{"path"},
				},
			},
			{
				Name:        "scan_image",
				Description: "Scan a container image for packages and vulnerabilities.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"image_ref": map[string]any{"type": "string", "description": "Image reference (e.g. alpine:latest, /path/to/image.tar)"},
					},
					"required": []string{"image_ref"},
				},
			},
		}
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{"tools": tools},
		}

	case "tools/call":
		return handleToolCall(ctx, req)

	default:
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: map[string]any{
				"code":    -32601,
				"message": fmt.Sprintf("method not found: %s", req.Method),
			},
		}
	}
}

func handleToolCall(ctx context.Context, req *jsonRPCRequest) *jsonRPCResponse {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   map[string]any{"code": -32602, "message": "invalid params"},
		}
	}

	var text string
	var isError bool

	switch params.Name {
	case "scan_path":
		path, _ := params.Arguments["path"].(string)
		if path == "" {
			path = "."
		}
		osvMatch := true
		if v, ok := params.Arguments["osv_match"].(bool); ok {
			osvMatch = v
		}
		result, err := scanner.Scan(ctx, scanner.ScanOptions{
			Target:       path,
			Mode:         scanner.ModeSCA,
			WithOSVMatch: osvMatch,
		})
		if err != nil {
			text = fmt.Sprintf("Scan error: %v", err)
			isError = true
		} else {
			text = formatter.FormatForClaude(result)
		}

	case "scan_secrets":
		path, _ := params.Arguments["path"].(string)
		if path == "" {
			path = "."
		}
		result, err := scanner.Scan(ctx, scanner.ScanOptions{
			Target: path,
			Mode:   scanner.ModeSecrets,
		})
		if err != nil {
			text = fmt.Sprintf("Scan error: %v", err)
			isError = true
		} else if !result.HasSecrets() {
			text = "No secrets detected."
		} else {
			text = formatter.FormatSecretsOnly(result.Secrets())
		}

	case "scan_image":
		ref, _ := params.Arguments["image_ref"].(string)
		if ref == "" {
			text = "image_ref is required"
			isError = true
		} else {
			result, err := scanner.ScanImage(ctx, scanner.ImageScanOptions{
				ImageRef:     ref,
				WithOSVMatch: true,
			})
			if err != nil {
				text = fmt.Sprintf("Image scan error: %v", err)
				isError = true
			} else {
				defer result.Image.CleanUp()
				text = formatter.FormatImageLayers(result)
			}
		}

	default:
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   map[string]any{"code": -32602, "message": fmt.Sprintf("unknown tool: %s", params.Name)},
		}
	}

	return &jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": text},
			},
			"isError": isError,
		},
	}
}
