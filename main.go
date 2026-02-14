package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

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
  interactive      Interactive security analysis session
  serve            Expose SCALIBR tools for external Claude sessions

Flags:
  -target string   Target path to scan (default: current directory)
  -image string    Container image reference (for audit-image)
  -v               Verbose output
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
	_ = fs.Bool("v", false, "Verbose output")
	fs.Parse(os.Args[2:])

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var err error
	switch command {
	case "explain":
		err = cmd.RunExplain(ctx, *target)
	case "remediate":
		err = cmd.RunRemediate(ctx, *target)
	case "triage-secrets":
		err = cmd.RunTriageSecrets(ctx, *target)
	case "audit-image":
		ref := *imageRef
		if ref == "" && fs.NArg() > 0 {
			ref = fs.Arg(0)
		}
		if ref == "" {
			fmt.Fprintln(os.Stderr, "error: audit-image requires -image flag or image argument")
			os.Exit(1)
		}
		err = cmd.RunAuditImage(ctx, ref)
	case "interactive":
		err = cmd.RunInteractive(ctx, *target)
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
