package cmd

import (
	"context"
	"encoding/json"
	"testing"
)

func TestHandleMCPRequest_Initialize(t *testing.T) {
	req := &jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}

	resp := handleMCPRequest(context.Background(), req)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.ID != 1 {
		t.Error("response ID should match request")
	}
	if resp.Error != nil {
		t.Errorf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result should be a map")
	}
	if result["protocolVersion"] != "2024-11-05" {
		t.Error("wrong protocol version")
	}
	info, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatal("serverInfo should be a map")
	}
	if info["name"] != "secagent-scalibr" {
		t.Errorf("wrong server name: %v", info["name"])
	}
}

func TestHandleMCPRequest_Initialized(t *testing.T) {
	req := &jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}

	resp := handleMCPRequest(context.Background(), req)
	if resp != nil {
		t.Error("notifications should return nil response")
	}
}

func TestHandleMCPRequest_ToolsList(t *testing.T) {
	req := &jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}

	resp := handleMCPRequest(context.Background(), req)
	if resp == nil {
		t.Fatal("expected response")
	}

	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result should be a map")
	}
	tools, ok := result["tools"].([]mcpToolDef)
	if !ok {
		t.Fatal("tools should be []mcpToolDef")
	}
	if len(tools) != 3 {
		t.Errorf("expected 3 tools, got %d", len(tools))
	}

	names := map[string]bool{}
	for _, tool := range tools {
		names[tool.Name] = true
	}
	for _, expected := range []string{"scan_path", "scan_secrets", "scan_image"} {
		if !names[expected] {
			t.Errorf("missing tool: %s", expected)
		}
	}
}

func TestHandleMCPRequest_UnknownMethod(t *testing.T) {
	req := &jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "resources/list",
	}

	resp := handleMCPRequest(context.Background(), req)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error == nil {
		t.Error("expected error for unknown method")
	}
}

func TestHandleToolCall_UnknownTool(t *testing.T) {
	params, _ := json.Marshal(map[string]any{
		"name":      "nonexistent_tool",
		"arguments": map[string]any{},
	})
	req := &jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params:  params,
	}

	resp := handleToolCall(context.Background(), req)
	if resp.Error == nil {
		t.Error("expected error for unknown tool")
	}
}

func TestHandleToolCall_ScanImageMissingRef(t *testing.T) {
	params, _ := json.Marshal(map[string]any{
		"name":      "scan_image",
		"arguments": map[string]any{},
	})
	req := &jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "tools/call",
		Params:  params,
	}

	resp := handleToolCall(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("should not be a JSON-RPC error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result should be a map")
	}
	if result["isError"] != true {
		t.Error("should be a tool error when image_ref is missing")
	}
}

func TestHandleToolCall_InvalidParams(t *testing.T) {
	req := &jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      6,
		Method:  "tools/call",
		Params:  json.RawMessage(`{invalid`),
	}

	resp := handleToolCall(context.Background(), req)
	if resp.Error == nil {
		t.Error("expected error for invalid params")
	}
}
