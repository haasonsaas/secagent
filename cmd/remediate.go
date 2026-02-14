package cmd

import (
	"context"
	"fmt"

	claudecode "github.com/severity1/claude-agent-sdk-go"

	"secagent/internal/agent"
	"secagent/internal/formatter"
	"secagent/internal/scanner"
)

// RunRemediate scans for vulnerabilities and uses Claude to apply fixes.
func RunRemediate(ctx context.Context, target string) error {
	fmt.Println("Scanning", target, "for vulnerabilities...")

	result, err := scanner.Scan(ctx, scanner.ScanOptions{
		Target:       target,
		Mode:         scanner.ModeSCA,
		WithOSVMatch: true,
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if !result.HasVulns() {
		fmt.Println("No vulnerabilities found — nothing to remediate.")
		return nil
	}

	report := formatter.FormatVulnsOnly(result.Vulns())
	prompt := "Remediate the following vulnerabilities by updating dependency files in this project:\n\n" + report

	fmt.Println("Claude is remediating", len(result.Vulns()), "vulnerabilities...")

	return claudecode.WithClient(ctx, func(client claudecode.Client) error {
		if err := client.Query(ctx, prompt); err != nil {
			return err
		}
		return agent.StreamToStdout(ctx, client)
	},
		claudecode.WithSystemPrompt(agent.RemediatePrompt),
		claudecode.WithAllowedTools("Read", "Write", "Edit", "Bash", "Glob", "Grep"),
		claudecode.WithCwd(target),
		claudecode.WithPermissionMode(claudecode.PermissionModeAcceptEdits),
		claudecode.WithMaxTurns(20),
	)
}
