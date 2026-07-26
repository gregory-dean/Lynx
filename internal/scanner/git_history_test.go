package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/direo/lynx/internal/config"
	"github.com/direo/lynx/internal/rules"
)

func TestShouldSkipHistoryPath(t *testing.T) {
	dirs, globs := buildExcludeSets([]string{"*.min.js", "secrets"})
	if !shouldSkipHistoryPath("node_modules/pkg/index.js", dirs, globs) {
		t.Fatal("expected node_modules skip")
	}
	if !shouldSkipHistoryPath("app/secrets/token.env", dirs, globs) {
		t.Fatal("expected secrets dir skip")
	}
	if !shouldSkipHistoryPath("static/app.min.js", dirs, globs) {
		t.Fatal("expected glob skip")
	}
	if shouldSkipHistoryPath("src/main.go", dirs, globs) {
		t.Fatal("did not expect skip")
	}
}

func TestWalkGitHistoryReportsSameBlobAtMultiplePaths(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "lynx@example.com")
	runGit(t, dir, "config", "user.name", "Lynx Test")

	content := []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	if err := os.MkdirAll(filepath.Join(dir, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "leak.env"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b", "leak.env"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "dup paths")

	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	opts := config.DefaultScanOptions()
	opts.Path = dir
	opts.History = true

	result, err := New(rs, opts).Run()
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, f := range result.Findings {
		if f.RuleID == "aws-access-key" {
			paths[f.File] = true
		}
	}
	if !paths["a/leak.env"] || !paths["b/leak.env"] {
		t.Fatalf("expected findings for both paths, got %v", paths)
	}
}

func TestWalkGitHistoryFindsDeletedSecret(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "lynx@example.com")
	runGit(t, dir, "config", "user.name", "Lynx Test")

	secretPath := filepath.Join(dir, "leak.env")
	if err := os.WriteFile(secretPath, []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "leak.env")
	runGit(t, dir, "commit", "-m", "add leak")

	if err := os.Remove(secretPath); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "leak.env")
	runGit(t, dir, "commit", "-m", "remove leak")

	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	opts := config.DefaultScanOptions()
	opts.Path = dir
	opts.History = true
	opts.Quiet = true

	result, err := New(rs, opts).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected history finding for deleted secret")
	}
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "aws-access-key" && f.File == "leak.env" && f.Commit != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing aws-access-key history finding: %+v", result.Findings)
	}

	// Working-tree scan should be clean after deletion.
	opts.History = false
	clean, err := New(rs, opts).Run()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range clean.Findings {
		if f.RuleID == "aws-access-key" && f.File == "leak.env" {
			t.Fatalf("working tree should not still contain leak.env finding: %+v", f)
		}
	}
}

func TestRunHistoryNotARepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	opts := config.DefaultScanOptions()
	opts.Path = t.TempDir()
	opts.History = true
	_, err = New(rs, opts).Run()
	if err == nil {
		t.Fatal("expected error outside git repo")
	}
	if !strings.Contains(err.Error(), "git") && !strings.Contains(err.Error(), "not a git") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMaxCommitsLimitsHistory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "lynx@example.com")
	runGit(t, dir, "config", "user.name", "Lynx Test")

	if err := os.WriteFile(filepath.Join(dir, "leak.env"), []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "leak.env")
	runGit(t, dir, "commit", "-m", "leak")

	if err := os.Remove(filepath.Join(dir, "leak.env")); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "leak.env")
	runGit(t, dir, "commit", "-m", "remove")

	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "ok.txt")
	runGit(t, dir, "commit", "-m", "ok")

	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	opts := config.DefaultScanOptions()
	opts.Path = dir
	opts.History = true
	opts.MaxCommits = 1 // only newest commit (ok.txt), leak blob not in that commit's tree as first-seen walk...
	// With max-commits=1 we only examine the newest commit. The leak blob is not in that tree,
	// and first-seen dedupe only records blobs present in the examined commits.
	result, err := New(rs, opts).Run()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "aws-access-key" {
			t.Fatalf("max-commits=1 should not reach deleted leak: %+v", f)
		}
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}
