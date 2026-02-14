package cmd

import (
	"context"
	"fmt"

	claudecode "github.com/severity1/claude-agent-sdk-go"

	"secagent/internal/agent"
	"secagent/internal/formatter"
	"secagent/internal/scanner"
)

// JSON schema for explain command structured output.
var explainSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"summary":    map[string]any{"type": "string"},
		"risk_level": map[string]any{"type": "string"},
		"vulnerabilities": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":             map[string]any{"type": "string"},
					"severity":       map[string]any{"type": "string"},
					"package":        map[string]any{"type": "string"},
					"recommendation": map[string]any{"type": "string"},
				},
				"required": []string{"id", "severity", "package", "recommendation"},
			},
		},
	},
	"required": []string{"summary", "risk_level", "vulnerabilities"},
}

// RunExplain scans the target for vulnerabilities and asks Claude to explain the findings.
func RunExplain(ctx context.Context, target string, reachableOnly bool, jsonOutput bool, model string) error {
	fmt.Println("Scanning", target, "for packages and vulnerabilities...")

	result, err := scanner.Scan(ctx, scanner.ScanOptions{
		Target:           target,
		Mode:             scanner.ModeSCA,
		WithOSVMatch:     true,
		WithReachability: reachableOnly,
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	report := formatter.FormatForClaude(result)
	prompt := "Analyze the following security scan results and provide a clear explanation:\n\n" + report

	fmt.Println("Querying Claude for analysis...")

	opts := []claudecode.Option{
		claudecode.WithSystemPrompt(agent.ExplainPrompt),
		claudecode.WithMaxTurns(1),
	}
	if model != "" {
		opts = append(opts, claudecode.WithModel(model))
	}

	if jsonOutput {
		response, err := agent.QueryOneShotJSON(ctx, prompt, explainSchema, opts...)
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
