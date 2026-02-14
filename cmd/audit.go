package cmd

import (
	"context"
	"fmt"

	claudecode "github.com/severity1/claude-agent-sdk-go"

	"secagent/internal/agent"
	"secagent/internal/formatter"
	"secagent/internal/scanner"
)

// JSON schema for audit command structured output.
var auditSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"risk_score": map[string]any{"type": "number"},
		"layers": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"index":  map[string]any{"type": "number"},
					"issues": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
				"required": []string{"index", "issues"},
			},
		},
		"recommendations": map[string]any{
			"type":  "array",
			"items": map[string]any{"type": "string"},
		},
	},
	"required": []string{"risk_score", "layers", "recommendations"},
}

// RunAuditImage scans a container image and asks Claude to produce a security audit.
func RunAuditImage(ctx context.Context, imageRef string, jsonOutput bool, model string) error {
	fmt.Println("Scanning image", imageRef, "...")

	result, err := scanner.ScanImage(ctx, scanner.ImageScanOptions{
		ImageRef:     imageRef,
		WithOSVMatch: true,
	})
	if err != nil {
		return fmt.Errorf("image scan failed: %w", err)
	}
	defer result.Image.CleanUp()

	report := formatter.FormatImageLayers(result)
	prompt := "Audit the following container image scan results and provide a security assessment:\n\n" + report

	fmt.Println("Querying Claude for audit...")

	opts := []claudecode.Option{
		claudecode.WithSystemPrompt(agent.AuditPrompt),
		claudecode.WithMaxTurns(1),
	}
	if model != "" {
		opts = append(opts, claudecode.WithModel(model))
	}

	if jsonOutput {
		response, err := agent.QueryOneShotJSON(ctx, prompt, auditSchema, opts...)
		if err != nil {
			return fmt.Errorf("claude query failed: %w", err)
		}
		fmt.Println(response)
	} else {
		response, err := agent.QueryOneShot(ctx, prompt, opts...)
		if err != nil {
			return fmt.Errorf("claude query failed: %w", err)
		}
		fmt.Println()
		fmt.Println(response)
	}
	return nil
}
