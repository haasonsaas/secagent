package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	claudecode "github.com/severity1/claude-agent-sdk-go"
)

func init() {
	// Allow running inside another Claude Code session (e.g. during development).
	os.Unsetenv("CLAUDECODE")
}

// QueryOneShot sends a single prompt to Claude and returns the concatenated text response.
func QueryOneShot(ctx context.Context, prompt string, opts ...claudecode.Option) (string, error) {
	iter, err := claudecode.Query(ctx, prompt, opts...)
	if err != nil {
		return "", fmt.Errorf("claude query: %w", err)
	}
	defer iter.Close()

	return CollectText(ctx, iter)
}

// CollectText drains a MessageIterator collecting all TextBlock content.
func CollectText(ctx context.Context, iter claudecode.MessageIterator) (string, error) {
	var sb strings.Builder

	for {
		msg, err := iter.Next(ctx)
		if err != nil {
			if errors.Is(err, claudecode.ErrNoMoreMessages) {
				break
			}
			return sb.String(), fmt.Errorf("reading message: %w", err)
		}

		switch m := msg.(type) {
		case *claudecode.AssistantMessage:
			for _, block := range m.Content {
				if textBlock, ok := block.(*claudecode.TextBlock); ok {
					sb.WriteString(textBlock.Text)
				}
			}
		case *claudecode.ResultMessage:
			if m.IsError {
				errText := "unknown error"
				if m.Result != nil {
					errText = *m.Result
				}
				return sb.String(), fmt.Errorf("claude error: %s", errText)
			}
			// If we got no text from assistant messages, check the result.
			if sb.Len() == 0 && m.Result != nil {
				sb.WriteString(*m.Result)
			}
		}
	}

	return sb.String(), nil
}

// StreamToStdout drains client.ReceiveMessages() printing text blocks in real time.
func StreamToStdout(ctx context.Context, client claudecode.Client) error {
	for msg := range client.ReceiveMessages(ctx) {
		if assistantMsg, ok := msg.(*claudecode.AssistantMessage); ok {
			for _, block := range assistantMsg.Content {
				if textBlock, ok := block.(*claudecode.TextBlock); ok {
					fmt.Print(textBlock.Text)
				}
			}
		}

		if resultMsg, ok := msg.(*claudecode.ResultMessage); ok {
			if resultMsg.IsError {
				errText := "unknown error"
				if resultMsg.Result != nil {
					errText = *resultMsg.Result
				}
				return fmt.Errorf("claude error: %s", errText)
			}
		}
	}
	fmt.Println()
	return nil
}
