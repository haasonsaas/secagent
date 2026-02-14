package cmd

import (
	"context"
	"fmt"

	claudecode "github.com/severity1/claude-agent-sdk-go"

	"secagent/internal/agent"
	"secagent/internal/formatter"
	"secagent/internal/scanner"
)

// JSON schema for harden command structured output.
var hardenSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"findings": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":          map[string]any{"type": "string"},
					"severity":    map[string]any{"type": "string"},
					"title":       map[string]any{"type": "string"},
					"remediation": map[string]any{"type": "string"},
				},
				"required": []string{"id", "severity", "title", "remediation"},
			},
		},
	},
	"required": []string{"findings"},
}

// RunHarden scans the target for security misconfigurations and asks Claude to analyze them.
func RunHarden(ctx context.Context, target string, jsonOutput bool, model string) error {
	fmt.Println("Scanning", target, "for security misconfigurations...")

	result, err := scanner.Scan(ctx, scanner.ScanOptions{
		Target: target,
		Mode:   scanner.ModeHarden,
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if !result.HasFindings() {
		fmt.Println("No security issues detected.")
		return nil
	}

	report := formatter.FormatFindings(result.Findings())
	prompt := "Analyze the following security findings and provide a prioritized remediation plan:\n\n" + report

	fmt.Println("Querying Claude for analysis...")

	opts := []claudecode.Option{
		claudecode.WithSystemPrompt(agent.HardenPrompt),
		claudecode.WithMaxTurns(1),
	}
	if model != "" {
		opts = append(opts, claudecode.WithModel(model))
	}

	if jsonOutput {
		response, err := agent.QueryOneShotJSON(ctx, prompt, hardenSchema, opts...)
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
