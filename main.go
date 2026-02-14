package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"secagent/cmd"
)

const usage = `secagent — AI-powered security analysis agent

Usage:
  secagent <command> [flags]

Commands:
  explain          Scan for vulnerabilities and explain findings
  remediate        Scan and auto-fix vulnerabilities
  triage-secrets   Scan for secrets and triage true/false positives
  audit-image      Audit a container image for security issues
  harden           Scan for security misconfigurations and hardening issues
  sbom             Generate a Software Bill of Materials (SPDX/CycloneDX)
  license-audit    Audit dependency licenses for compliance risks
  interactive      Interactive security analysis session
  serve            Expose SCALIBR tools for external Claude sessions

Flags:
  -target string        Target path to scan (default: current directory)
  -image string         Container image reference (for audit-image)
  -format string        SBOM format: spdx or cdx (for sbom, default: spdx)
  -model string         Claude model to use (e.g. claude-sonnet-4-5-20250929)
  -json                 Output structured JSON instead of text
  -reachable-only       Filter to reachable vulnerabilities only
  -skip-dirs string     Comma-separated directories to skip during scan
  -use-gitignore        Skip files declared in .gitignore
  -v                    Verbose output
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	command := os.Args[1]

	// Parse flags after the subcommand.
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	target := fs.String("target", ".", "Target path to scan")
	imageRef := fs.String("image", "", "Container image reference")
	sbomFormat := fs.String("format", "spdx", "SBOM format: spdx or cdx")
	model := fs.String("model", "", "Claude model to use")
	jsonOutput := fs.Bool("json", false, "Output structured JSON")
	reachableOnly := fs.Bool("reachable-only", false, "Filter to reachable vulnerabilities only")
	skipDirs := fs.String("skip-dirs", "", "Comma-separated directories to skip")
	useGitignore := fs.Bool("use-gitignore", false, "Skip files declared in .gitignore")
	_ = fs.Bool("v", false, "Verbose output")
	fs.Parse(os.Args[2:])

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Parse scan configuration flags.
	var skipDirsList []string
	if *skipDirs != "" {
		skipDirsList = strings.Split(*skipDirs, ",")
	}

	// Store scan config in context-accessible way for future per-command integration.
	_ = skipDirsList
	_ = useGitignore

	var err error
	switch command {
	case "explain":
		err = cmd.RunExplain(ctx, *target, *reachableOnly, *jsonOutput, *model)
	case "remediate":
		err = cmd.RunRemediate(ctx, *target, *reachableOnly, *model)
	case "triage-secrets":
		err = cmd.RunTriageSecrets(ctx, *target, *jsonOutput, *model)
	case "audit-image":
		ref := *imageRef
		if ref == "" && fs.NArg() > 0 {
			ref = fs.Arg(0)
		}
		if ref == "" {
			fmt.Fprintln(os.Stderr, "error: audit-image requires -image flag or image argument")
			os.Exit(1)
		}
		err = cmd.RunAuditImage(ctx, ref, *jsonOutput, *model)
	case "harden":
		err = cmd.RunHarden(ctx, *target, *jsonOutput, *model)
	case "sbom":
		err = cmd.RunSBOM(ctx, *target, *sbomFormat)
	case "license-audit":
		err = cmd.RunLicenseAudit(ctx, *target, *jsonOutput, *model)
	case "interactive":
		err = cmd.RunInteractive(ctx, *target, *model)
	case "serve":
		err = cmd.RunServe(ctx)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", command)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
