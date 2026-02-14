package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	claudecode "github.com/severity1/claude-agent-sdk-go"

	"secagent/internal/agent"
	"secagent/internal/mcptools"
)

// RunInteractive starts an interactive session with Claude that has access to SCALIBR scanning tools.
func RunInteractive(ctx context.Context, target string) error {
	tools := mcptools.BuildAllTools()
	server := claudecode.CreateSDKMcpServer("scalibr", "1.0.0", tools...)

	// Build the list of allowed tool names.
	allowedTools := []string{"Read", "Glob", "Grep", "Bash"}
	for _, t := range tools {
		allowedTools = append(allowedTools, "mcp__scalibr__"+t.Name())
	}

	fmt.Println("secagent interactive mode")
	fmt.Println("Type your questions about security. Type 'exit' to quit.")
	fmt.Println()

	cwd := target
	if cwd == "" {
		cwd, _ = os.Getwd()
	}

	return claudecode.WithClient(ctx, func(client claudecode.Client) error {
		scanner := bufio.NewScanner(os.Stdin)

		for {
			fmt.Print("secagent> ")
			if !scanner.Scan() {
				break
			}

			input := strings.TrimSpace(scanner.Text())
			if input == "" {
				continue
			}
			if input == "exit" || input == "quit" {
				fmt.Println("Goodbye.")
				break
			}

			if err := client.Query(ctx, input); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				continue
			}

			if err := agent.StreamToStdout(ctx, client); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
			fmt.Println()
		}

		return scanner.Err()
	},
		claudecode.WithSystemPrompt(agent.InteractivePrompt),
		claudecode.WithSdkMcpServer("scalibr", server),
		claudecode.WithAllowedTools(allowedTools...),
		claudecode.WithCwd(cwd),
		claudecode.WithMaxTurns(20),
	)
}
