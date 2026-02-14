package cmd

import (
	"context"
	"fmt"

	claudecode "github.com/severity1/claude-agent-sdk-go"

	"secagent/internal/agent"
	"secagent/internal/formatter"
	"secagent/internal/scanner"
)

// RunAuditImage scans a container image and asks Claude to produce a security audit.
func RunAuditImage(ctx context.Context, imageRef string) error {
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

	response, err := agent.QueryOneShot(ctx, prompt,
		claudecode.WithSystemPrompt(agent.AuditPrompt),
		claudecode.WithMaxTurns(1),
	)
	if err != nil {
		return fmt.Errorf("claude query failed: %w", err)
	}

	fmt.Println()
	fmt.Println(response)
	return nil
}
