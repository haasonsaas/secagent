package formatter

import (
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/inventory"
)

// severityName maps SeverityEnum values to human-readable names.
var severityName = map[inventory.SeverityEnum]string{
	inventory.SeverityUnspecified: "UNSPECIFIED",
	inventory.SeverityMinimal:    "MINIMAL",
	inventory.SeverityLow:        "LOW",
	inventory.SeverityMedium:     "MEDIUM",
	inventory.SeverityHigh:       "HIGH",
	inventory.SeverityCritical:   "CRITICAL",
}

// FormatFindings produces a markdown table from generic findings (detector results).
func FormatFindings(findings []*inventory.GenericFinding) string {
	var b strings.Builder

	b.WriteString("## Security Findings\n\n")
	b.WriteString("| ID | Title | Severity | Description | Recommendation |\n")
	b.WriteString("|----|-------|----------|-------------|----------------|\n")

	for _, f := range findings {
		id := ""
		title := ""
		sev := ""
		desc := ""
		rec := ""

		if f.Adv != nil {
			if f.Adv.ID != nil {
				id = f.Adv.ID.Reference
			}
			title = f.Adv.Title
			sev = severityName[f.Adv.Sev]
			desc = strings.ReplaceAll(f.Adv.Description, "\n", " ")
			rec = strings.ReplaceAll(f.Adv.Recommendation, "\n", " ")
		}

		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			id, title, sev, desc, rec)
	}

	return truncate(b.String())
}

// FormatLicenses produces a license report grouped by license type.
func FormatLicenses(result LicenseData) string {
	var b strings.Builder

	b.WriteString("## License Audit Report\n\n")

	// Group packages by license.
	byLicense := make(map[string][]string)
	for _, pkg := range result.Packages {
		license := pkg.License
		if license == "" {
			license = "UNKNOWN"
		}
		byLicense[license] = append(byLicense[license], fmt.Sprintf("%s@%s", pkg.Name, pkg.Version))
	}

	// Flag problematic licenses.
	problematic := []string{"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0", "UNKNOWN"}
	var flagged []string
	for _, lic := range problematic {
		if pkgs, ok := byLicense[lic]; ok {
			flagged = append(flagged, fmt.Sprintf("- **%s**: %d packages", lic, len(pkgs)))
		}
	}

	if len(flagged) > 0 {
		b.WriteString("### Potentially Problematic Licenses\n\n")
		for _, f := range flagged {
			b.WriteString(f + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("### All Licenses\n\n")
	b.WriteString("| License | Package | Version |\n")
	b.WriteString("|---------|---------|--------|\n")

	for _, pkg := range result.Packages {
		license := pkg.License
		if license == "" {
			license = "UNKNOWN"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", license, pkg.Name, pkg.Version)
	}

	return truncate(b.String())
}

// LicenseData holds package license information for formatting.
type LicenseData struct {
	Packages []LicensePackage
}

// LicensePackage holds license info for a single package.
type LicensePackage struct {
	Name    string
	Version string
	License string
}
