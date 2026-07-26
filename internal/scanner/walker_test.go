package scanner

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWalkFilesSkipsBinaryAndLarge(t *testing.T) {
	dir := t.TempDir()
	textPath := filepath.Join(dir, "ok.txt")
	if err := os.WriteFile(textPath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(dir, "bin.dat")
	if err := os.WriteFile(binPath, []byte{0x00, 0x01, 0x02}, 0o644); err != nil {
		t.Fatal(err)
	}
	largePath := filepath.Join(dir, "large.txt")
	if err := os.WriteFile(largePath, []byte("abcdefghij"), 0o644); err != nil {
		t.Fatal(err)
	}

	var seen []string
	n, err := WalkFiles(WalkOptions{
		Root:        dir,
		MaxFileSize: 8,
		NoGitIgnore: true,
	}, func(path string, r io.Reader) error {
		seen = append(seen, filepath.Base(path))
		_, _ = io.Copy(io.Discard, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(seen) != 1 || seen[0] != "ok.txt" {
		t.Fatalf("scanned=%d seen=%v", n, seen)
	}
}

func TestWalkFilesRespectsExcludeAndGitignore(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("ignored.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	skipDir := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(skipDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skipDir, "pkg.js"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	var seen []string
	_, err := WalkFiles(WalkOptions{Root: dir}, func(path string, r io.Reader) error {
		seen = append(seen, filepath.Base(path))
		_, _ = io.Copy(io.Discard, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range seen {
		if name == "ignored.txt" || name == "pkg.js" {
			t.Fatalf("should have skipped %s, seen=%v", name, seen)
		}
	}
	foundKeep := false
	for _, name := range seen {
		if name == "keep.txt" {
			foundKeep = true
		}
	}
	if !foundKeep {
		t.Fatalf("expected keep.txt, seen=%v", seen)
	}
}

func TestWalkSingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "one.txt")
	if err := os.WriteFile(path, []byte("line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := WalkFiles(WalkOptions{Root: path, NoGitIgnore: true}, func(p string, r io.Reader) error {
		_, _ = io.Copy(io.Discard, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("n=%d", n)
	}
}

func TestScanReader(t *testing.T) {
	findings, err := ScanReader("f.txt", strings.NewReader("AKIAIOSFODNN7EXAMPLE\n"), func(lineNum int, line string) []Finding {
		return []Finding{{File: "f.txt", Line: lineNum, Match: line}}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings=%d", len(findings))
	}
}
