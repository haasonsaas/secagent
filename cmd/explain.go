package cmd

import (
	"context"
	"fmt"

	claudecode "github.com/severity1/claude-agent-sdk-go"

	"secagent/internal/agent"
	"secagent/internal/formatter"
	"secagent/internal/scanner"
)

// RunExplain scans the target for vulnerabilities and asks Claude to explain the findings.
func RunExplain(ctx context.Context, target string) error {
	fmt.Println("Scanning", target, "for packages and vulnerabilities...")

	result, err := scanner.Scan(ctx, scanner.ScanOptions{
		Target:       target,
		Mode:         scanner.ModeSCA,
		WithOSVMatch: true,
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	report := formatter.FormatForClaude(result)
	prompt := "Analyze the following security scan results and provide a clear explanation:\n\n" + report

	fmt.Println("Querying Claude for analysis...")

	response, err := agent.QueryOneShot(ctx, prompt,
		claudecode.WithSystemPrompt(agent.ExplainPrompt),
		claudecode.WithMaxTurns(1),
	)
	if err != nil {
		return fmt.Errorf("claude query failed: %w", err)
	}

	fmt.Println()
	fmt.Println(response)
	return nil
}
