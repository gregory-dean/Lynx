package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	ignore "github.com/sabhiram/go-gitignore"

	"github.com/gregory-dean/lynx/internal/config"
)

// WalkOptions controls filesystem traversal.
type WalkOptions struct {
	Root        string
	Exclude     []string
	MaxFileSize int64
	NoGitIgnore bool
	OnFile      func(path string) // optional progress callback per scanned file
}

// FileVisitor is called for each scannable text file.
type FileVisitor func(path string, r io.Reader) error

// WalkFiles walks root and invokes visitor for each eligible file.
func WalkFiles(opts WalkOptions, visitor FileVisitor) (filesScanned int, err error) {
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return 0, fmt.Errorf("resolve path: %w", err)
	}

	info, err := os.Stat(root)
	if err != nil {
		return 0, err
	}

	var gi *ignore.GitIgnore
	if !opts.NoGitIgnore {
		gi = loadGitIgnore(root)
	}

	excludeDirs := make(map[string]struct{}, len(config.DefaultExcludeDirs)+len(opts.Exclude))
	for _, d := range config.DefaultExcludeDirs {
		excludeDirs[d] = struct{}{}
	}
	extraGlobs := make([]string, 0, len(opts.Exclude))
	for _, e := range opts.Exclude {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.ContainsAny(e, "*?[") && !strings.Contains(e, "/") && !strings.Contains(e, `\`) {
			excludeDirs[e] = struct{}{}
		} else {
			extraGlobs = append(extraGlobs, e)
		}
	}

	maxSize := opts.MaxFileSize
	if maxSize <= 0 {
		maxSize = config.DefaultMaxFileSize
	}

	scanOne := func(path string) error {
		scanned, vErr := visitFile(path, maxSize, visitor)
		if vErr != nil {
			return vErr
		}
		if scanned {
			filesScanned++
			if opts.OnFile != nil {
				opts.OnFile(path)
			}
		}
		return nil
	}

	if !info.IsDir() {
		if shouldSkipFile(root, root, gi, extraGlobs) {
			return 0, nil
		}
		if err := scanOne(root); err != nil {
			return filesScanned, err
		}
		return filesScanned, nil
	}

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := d.Name()
		if d.IsDir() {
			if _, skip := excludeDirs[name]; skip {
				return filepath.SkipDir
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil && rel != "." && gi != nil && gi.MatchesPath(filepath.ToSlash(rel)) {
				return filepath.SkipDir
			}
			return nil
		}

		if shouldSkipFile(root, path, gi, extraGlobs) {
			return nil
		}
		return scanOne(path)
	})
	return filesScanned, err
}

func loadGitIgnore(root string) *ignore.GitIgnore {
	path := filepath.Join(root, ".gitignore")
	gi, err := ignore.CompileIgnoreFile(path)
	if err != nil {
		return nil
	}
	return gi
}

func shouldSkipFile(root, path string, gi *ignore.GitIgnore, globs []string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	relSlash := filepath.ToSlash(rel)
	if gi != nil && gi.MatchesPath(relSlash) {
		return true
	}
	base := filepath.Base(path)
	for _, g := range globs {
		ok, matchErr := filepath.Match(g, base)
		if matchErr == nil && ok {
			return true
		}
		ok, matchErr = filepath.Match(g, relSlash)
		if matchErr == nil && ok {
			return true
		}
	}
	return false
}

// visitFile opens path and calls visitor if the file is a scannable text file.
// Returns whether the file was scanned.
func visitFile(path string, maxSize int64, visitor FileVisitor) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if fi.Size() > maxSize {
		return false, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	header := make([]byte, 512)
	n, _ := io.ReadFull(f, header)
	header = header[:n]
	if bytes.IndexByte(header, 0) >= 0 {
		return false, nil // binary
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	if err := visitor(path, f); err != nil {
		return false, err
	}
	return true, nil
}

// ScanReader scans an open reader line by line using the provided match function.
func ScanReader(path string, r io.Reader, match func(lineNum int, line string) []Finding) ([]Finding, error) {
	var findings []Finding
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		findings = append(findings, match(lineNum, sc.Text())...)
	}
	if err := sc.Err(); err != nil {
		return findings, fmt.Errorf("scan %s: %w", path, err)
	}
	return findings, nil
}
