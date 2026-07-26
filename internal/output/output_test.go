package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/direo/lynx/internal/scanner"
)

func sampleFindings() []scanner.Finding {
	return []scanner.Finding{
		{
			File:          "config/production.env",
			Line:          12,
			Column:        1,
			RuleID:        "aws-access-key",
			Description:   "AWS Access Key ID",
			Severity:      "high",
			Match:         "AKIAIOSFODNN7EXAMPLE",
			RedactedMatch: "AKIA****MPLE",
		},
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	summary := Summary{Total: 1, FilesScanned: 42, FilesWithSecrets: 1}
	if err := WriteJSON(&buf, sampleFindings(), summary); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), `"rule_id": "aws-access-key"`) {
		t.Fatalf("unexpected json: %s", buf.String())
	}
}

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	summary := Summary{Total: 1, FilesScanned: 42, FilesWithSecrets: 1}
	if err := WriteSARIF(&buf, sampleFindings(), summary); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid sarif json: %v\n%s", err, buf.String())
	}
	if parsed["version"] != "2.1.0" {
		t.Fatalf("version=%v", parsed["version"])
	}
}

func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	summary := Summary{Total: 1, FilesScanned: 42, FilesWithSecrets: 1}
	if err := WriteTable(&buf, sampleFindings(), summary); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "aws-access-key") || !strings.Contains(out, "AKIA****MPLE") {
		t.Fatalf("unexpected table: %s", out)
	}
}

func TestWriteTableWithCommit(t *testing.T) {
	findings := sampleFindings()
	findings[0].Commit = "abcdef0123456789"
	var buf bytes.Buffer
	if err := WriteTable(&buf, findings, Summary{Total: 1, FilesScanned: 1, FilesWithSecrets: 1}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "COMMIT") || !strings.Contains(out, "abcdef012345") {
		t.Fatalf("expected commit column: %s", out)
	}
}

func TestWriteSARIFWithCommit(t *testing.T) {
	findings := sampleFindings()
	findings[0].Commit = "abcdef0123456789"
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, Summary{Total: 1}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"commit": "abcdef0123456789"`) {
		t.Fatalf("expected commit property: %s", buf.String())
	}
}

func TestWriteTableClean(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTable(&buf, nil, Summary{FilesScanned: 5}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No secrets found") {
		t.Fatalf("unexpected: %s", buf.String())
	}
}

func TestReportUnknown(t *testing.T) {
	err := Report(&bytes.Buffer{}, "xml", nil, Summary{})
	if err == nil {
		t.Fatal("expected error")
	}
}
