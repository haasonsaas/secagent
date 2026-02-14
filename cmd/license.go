package cmd

import (
	"context"
	"fmt"

	claudecode "github.com/severity1/claude-agent-sdk-go"

	"secagent/internal/agent"
	"secagent/internal/formatter"
	"secagent/internal/scanner"
)

// RunLicenseAudit scans the target for packages and analyzes their licenses.
func RunLicenseAudit(ctx context.Context, target string, jsonOutput bool, model string) error {
	fmt.Println("Scanning", target, "for packages and licenses...")

	result, err := scanner.Scan(ctx, scanner.ScanOptions{
		Target:                target,
		Mode:                  scanner.ModeSCA,
		WithLicenseEnrichment: true,
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if len(result.Packages()) == 0 {
		fmt.Println("No packages found.")
		return nil
	}

	// Build license data from package metadata.
	var licData formatter.LicenseData
	for _, pkg := range result.Packages() {
		lp := formatter.LicensePackage{
			Name:    pkg.Name,
			Version: pkg.Version,
		}
		if pkg.Licenses != nil && len(pkg.Licenses) > 0 {
			lp.License = pkg.Licenses[0]
		}
		licData.Packages = append(licData.Packages, lp)
	}

	report := formatter.FormatLicenses(licData)
	prompt := "Analyze the following license audit report and provide a compliance assessment:\n\n" + report

	fmt.Println("Querying Claude for license analysis...")

	opts := []claudecode.Option{
		claudecode.WithSystemPrompt(agent.LicensePrompt),
		claudecode.WithMaxTurns(1),
	}
	if model != "" {
		opts = append(opts, claudecode.WithModel(model))
	}

	if jsonOutput {
		schema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"risk_level": map[string]any{"type": "string"},
				"copyleft_packages": map[string]any{
					"type":  "array",
					"items": map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}, "license": map[string]any{"type": "string"}, "risk": map[string]any{"type": "string"}}},
				},
				"unknown_licenses": map[string]any{
					"type":  "array",
					"items": map[string]any{"type": "string"},
				},
				"recommendations": map[string]any{
					"type":  "array",
					"items": map[string]any{"type": "string"},
				},
			},
			"required": []string{"risk_level", "copyleft_packages", "unknown_licenses", "recommendations"},
		}
		response, err := agent.QueryOneShotJSON(ctx, prompt, schema, opts...)
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
