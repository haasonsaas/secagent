package formatter

import (
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"

	"secagent/internal/scanner"
)

const maxChars = 50000

// FormatForClaude produces a full markdown report from scan results.
func FormatForClaude(result *scanner.Result) string {
	var b strings.Builder

	b.WriteString("# Security Scan Results\n\n")

	// Summary
	b.WriteString("## Summary\n\n")
	fmt.Fprintf(&b, "- **Packages found:** %d\n", len(result.Packages()))
	fmt.Fprintf(&b, "- **Vulnerabilities found:** %d\n", len(result.Vulns()))
	fmt.Fprintf(&b, "- **Secrets found:** %d\n", len(result.Secrets()))
	fmt.Fprintf(&b, "- **Generic findings:** %d\n\n", len(result.Findings()))

	// Vulnerabilities
	if result.HasVulns() {
		b.WriteString(FormatVulnsOnly(result.Vulns()))
		b.WriteString("\n")
	}

	// Secrets
	if result.HasSecrets() {
		b.WriteString(FormatSecretsOnly(result.Secrets()))
		b.WriteString("\n")
	}

	// Package inventory
	b.WriteString("## Package Inventory\n\n")
	b.WriteString("| Package | Version | Ecosystem | Location |\n")
	b.WriteString("|---------|---------|-----------|----------|\n")
	for _, pkg := range result.Packages() {
		loc := ""
		if len(pkg.Locations) > 0 {
			loc = pkg.Locations[0]
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
			pkg.Name, pkg.Version, pkg.Ecosystem(), loc)
	}

	return truncate(b.String())
}

// FormatVulnsOnly produces a focused vulnerability table.
func FormatVulnsOnly(vulns []*inventory.PackageVuln) string {
	var b strings.Builder

	b.WriteString("## Vulnerabilities\n\n")
	b.WriteString("| CVE / ID | Severity | Package | Version | Fixed Version |\n")
	b.WriteString("|----------|----------|---------|---------|---------------|\n")

	for _, v := range vulns {
		id := "unknown"
		severity := ""
		fixed := ""

		if v.Vulnerability != nil {
			id = v.Vulnerability.Id
			if len(v.Vulnerability.Severity) > 0 {
				severity = v.Vulnerability.Severity[0].Score
			}
			// Extract fixed version from affected ranges.
			for _, aff := range v.Vulnerability.Affected {
				for _, r := range aff.Ranges {
					for _, ev := range r.Events {
						if ev.Fixed != "" {
							fixed = ev.Fixed
						}
					}
				}
			}
		}

		pkgName := ""
		pkgVersion := ""
		if v.Package != nil {
			pkgName = v.Package.Name
			pkgVersion = v.Package.Version
		}

		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			id, severity, pkgName, pkgVersion, fixed)
	}

	return truncate(b.String())
}

// FormatSecretsOnly produces a table of detected secrets.
func FormatSecretsOnly(secrets []*inventory.Secret) string {
	var b strings.Builder

	b.WriteString("## Secrets Detected\n\n")
	b.WriteString("| # | Location | Status |\n")
	b.WriteString("|---|----------|--------|\n")

	for i, s := range secrets {
		status := "NOT_VALIDATED"
		if !s.Validation.At.IsZero() {
			switch string(s.Validation.Status) {
			case "VALIDATION_VALID":
				status = "**ACTIVE**"
			case "VALIDATION_INVALID":
				status = "INACTIVE"
			case "VALIDATION_FAILED":
				status = "VALIDATION_ERROR"
			default:
				status = string(s.Validation.Status)
			}
		}
		fmt.Fprintf(&b, "| %d | %s | %s |\n", i+1, s.Location, status)
	}

	return truncate(b.String())
}

// FormatImageLayers produces a report grouping packages by image layer.
func FormatImageLayers(result *scanner.ImageResult) string {
	var b strings.Builder

	b.WriteString("# Container Image Scan Results\n\n")

	// Summary
	fmt.Fprintf(&b, "- **Packages found:** %d\n", len(result.Packages()))
	fmt.Fprintf(&b, "- **Vulnerabilities found:** %d\n\n", len(result.Vulns()))

	// Group packages by layer.
	layerPkgs := make(map[int][]*extractor.Package)
	layerCmd := make(map[int]string)
	for _, pkg := range result.Packages() {
		idx := -1
		cmd := ""
		if pkg.LayerMetadata != nil {
			idx = pkg.LayerMetadata.Index
			cmd = pkg.LayerMetadata.Command
		}
		layerPkgs[idx] = append(layerPkgs[idx], pkg)
		if cmd != "" {
			layerCmd[idx] = cmd
		}
	}

	for idx := -1; idx < 100; idx++ {
		pkgs, ok := layerPkgs[idx]
		if !ok {
			continue
		}

		if idx == -1 {
			b.WriteString("## Unknown Layer\n\n")
		} else {
			fmt.Fprintf(&b, "## Layer %d", idx)
			if cmd, ok := layerCmd[idx]; ok {
				fmt.Fprintf(&b, " — `%s`", cmd)
			}
			b.WriteString("\n\n")
		}

		b.WriteString("| Package | Version | Ecosystem |\n")
		b.WriteString("|---------|---------|----------|\n")
		for _, pkg := range pkgs {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", pkg.Name, pkg.Version, pkg.Ecosystem())
		}
		b.WriteString("\n")
	}

	// Vulnerabilities
	if result.HasVulns() {
		b.WriteString(FormatVulnsOnly(result.Vulns()))
	}

	return truncate(b.String())
}

func truncate(s string) string {
	if len(s) > maxChars {
		return s[:maxChars] + "\n\n... (truncated)\n"
	}
	return s
}
