package cmd

import (
	"context"
	"fmt"

	claudecode "github.com/severity1/claude-agent-sdk-go"

	"secagent/internal/agent"
	"secagent/internal/formatter"
	"secagent/internal/scanner"
)

// RunTriageSecrets scans for secrets and uses Claude to triage each finding.
func RunTriageSecrets(ctx context.Context, target string) error {
	fmt.Println("Scanning", target, "for secrets...")

	result, err := scanner.Scan(ctx, scanner.ScanOptions{
		Target: target,
		Mode:   scanner.ModeSecrets,
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

	return claudecode.WithClient(ctx, func(client claudecode.Client) error {
		if err := client.Query(ctx, prompt); err != nil {
			return err
		}
		return agent.StreamToStdout(ctx, client)
	},
		claudecode.WithSystemPrompt(agent.TriagePrompt),
		claudecode.WithAllowedTools("Read", "Glob", "Grep"),
		claudecode.WithCwd(target),
		claudecode.WithMaxTurns(10),
	)
}
