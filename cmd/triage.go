package cmd

import (
	"context"
	"fmt"

	claudecode "github.com/severity1/claude-agent-sdk-go"

	"secagent/internal/agent"
	"secagent/internal/formatter"
	"secagent/internal/scanner"
)

// JSON schema for triage command structured output.
var triageSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"secrets": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"location":       map[string]any{"type": "string"},
					"classification": map[string]any{"type": "string"},
					"confidence":     map[string]any{"type": "string"},
					"reasoning":      map[string]any{"type": "string"},
				},
				"required": []string{"location", "classification", "confidence", "reasoning"},
			},
		},
	},
	"required": []string{"secrets"},
}

// RunTriageSecrets scans for secrets and uses Claude to triage each finding.
func RunTriageSecrets(ctx context.Context, target string, jsonOutput bool, model string) error {
	fmt.Println("Scanning", target, "for secrets...")

	result, err := scanner.Scan(ctx, scanner.ScanOptions{
		Target:               target,
		Mode:                 scanner.ModeSecrets,
		WithSecretValidation: true,
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if !result.HasSecrets() {
		fmt.Println("No secrets detected.")
		return nil
	}

	report := formatter.FormatSecretsOnly(result.Secrets())
	prompt := "Triage the following detected secrets by examining the source code around each location:\n\n" + report

	fmt.Println("Claude is triaging", len(result.Secrets()), "detected secrets...")

	if jsonOutput {
		opts := []claudecode.Option{
			claudecode.WithSystemPrompt(agent.TriagePrompt),
			claudecode.WithAllowedTools("Read", "Glob", "Grep"),
			claudecode.WithCwd(target),
			claudecode.WithMaxTurns(10),
		}
		if model != "" {
			opts = append(opts, claudecode.WithModel(model))
		}
		response, err := agent.QueryOneShotJSON(ctx, prompt, triageSchema, opts...)
		if err != nil {
			return fmt.Errorf("claude query failed: %w", err)
		}
		fmt.Println(response)
		return nil
	}

	opts := []claudecode.Option{
		claudecode.WithSystemPrompt(agent.TriagePrompt),
		claudecode.WithAllowedTools("Read", "Glob", "Grep"),
		claudecode.WithCwd(target),
		claudecode.WithMaxTurns(10),
	}
	if model != "" {
		opts = append(opts, claudecode.WithModel(model))
	}

	return claudecode.WithClient(ctx, func(client claudecode.Client) error {
		if err := client.Query(ctx, prompt); err != nil {
			return err
		}
		return agent.StreamToStdout(ctx, client)
	}, opts...)
}
