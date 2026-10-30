// Package parser runs Arctic Wolf's real parser identification and parsing on raw lines by
// calling the local Python runner (poc/parser-runner), which wraps LSS's Identifier and the
// production parser engine with the parse_and_detect parser rules.
package parser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/notxdr/discovery-service/internal/upstream"
)

type Runner struct {
	Dir     string // path to poc/parser-runner
	Timeout time.Duration
}

type Suggestion struct {
	Parser          string  `json:"parser"`
	FieldsExtracted int     `json:"fieldsExtracted"`
	Score           float64 `json:"score"`
	LinesMatched    *int    `json:"linesMatched"`
}

type SuggestResult struct {
	Suggestions         []Suggestion `json:"suggestions"`
	Timezones           []string     `json:"timezones"`
	SourceHost          string       `json:"sourceHost"`
	LinesUsed           int          `json:"linesUsed"`
	IdentifiableParsers int          `json:"identifiableParsers"`
}

type PreviewLine struct {
	Raw    string         `json:"raw"`
	Fields map[string]any `json:"fields"`
	Error  *string        `json:"error"`
}

type PreviewResult struct {
	Parser string        `json:"parser"`
	Lines  []PreviewLine `json:"lines"`
}

func (r Runner) Suggest(ctx context.Context, rows []upstream.RawLogRow) (SuggestResult, error) {
	var out SuggestResult
	err := r.run(ctx, rows, &out, "suggest")
	return out, err
}

func (r Runner) Preview(ctx context.Context, rows []upstream.RawLogRow, parserName string) (PreviewResult, error) {
	var out PreviewResult
	if parserName == "" || strings.ContainsAny(parserName, " ;|&$`\\/\n") {
		return out, fmt.Errorf("invalid parser name %q", parserName)
	}
	err := r.run(ctx, rows, &out, "preview", parserName)
	return out, err
}

func (r Runner) run(ctx context.Context, rows []upstream.RawLogRow, out any, args ...string) error {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	in, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	// env.sh sets PYTHONPATH to the awn packages; args are passed positionally, never interpolated.
	script := `. ./env.sh && exec .venv/bin/python identify.py "$@"`
	cmd := exec.CommandContext(ctx, "bash", append([]string{"-c", script, "identify"}, args...)...)
	cmd.Dir = r.Dir
	cmd.Env = append(cmd.Environ(), "OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES")
	cmd.Stdin = bytes.NewReader(in)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("parser runner failed: %w: %s", err, lastLine(stderr.String()))
	}
	if err := json.Unmarshal(stdout.Bytes(), out); err != nil {
		return fmt.Errorf("parser runner returned bad JSON: %w", err)
	}
	return nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 {
		return ""
	}
	l := lines[len(lines)-1]
	if len(l) > 300 {
		l = l[:300]
	}
	return l
}
