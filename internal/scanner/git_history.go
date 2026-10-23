package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gregory-dean/lynx/internal/config"
)

// HistoryOptions controls git history traversal.
type HistoryOptions struct {
	Root        string
	Exclude     []string
	MaxFileSize int64
	MaxCommits  int
	OnBlob      func(path string) // optional progress callback per scanned blob
}

// HistoryVisitor is called for each unique scannable blob path.
// path is repo-relative (slash-separated); commit is the first-seen full SHA.
type HistoryVisitor func(path, commit string, r io.Reader) error

type blobRef struct {
	oid    string
	path   string
	commit string
	size   int64
}

// WalkGitHistory enumerates unique (blob OID, path) pairs reachable from HEAD.
// Content is fetched once per OID and reported for each distinct path.
func WalkGitHistory(opts HistoryOptions, visitor HistoryVisitor) (blobsScanned int, err error) {
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return 0, fmt.Errorf("resolve path: %w", err)
	}

	gitRootRaw, err := gitOutput(root, "rev-parse", "--show-toplevel")
	if err != nil {
		return 0, fmt.Errorf("not a git repository (or git not available): %w", err)
	}
	gitRoot, err := filepath.Abs(filepath.Clean(strings.TrimSpace(gitRootRaw)))
	if err != nil {
		return 0, fmt.Errorf("resolve git root: %w", err)
	}

	prefix, err := relPrefix(gitRoot, root)
	if err != nil {
		return 0, err
	}

	maxSize := opts.MaxFileSize
	if maxSize <= 0 {
		maxSize = config.DefaultMaxFileSize
	}

	excludeDirs, extraGlobs := buildExcludeSets(opts.Exclude)

	commits, err := listCommits(gitRoot, opts.MaxCommits)
	if err != nil {
		return 0, err
	}
	if len(commits) == 0 {
		return 0, nil
	}

	// Dedupe by oid+path so the same content at different paths is reported
	// for each path. Oversized OIDs are remembered so we skip them everywhere.
	seenPath := make(map[string]struct{})
	oversized := make(map[string]struct{})
	var blobs []blobRef

	for _, commit := range commits {
		entries, lsErr := listTree(gitRoot, commit)
		if lsErr != nil {
			return blobsScanned, lsErr
		}
		for _, e := range entries {
			if _, ok := oversized[e.oid]; ok {
				continue
			}
			if prefix != "" && e.path != prefix && !strings.HasPrefix(e.path, prefix+"/") {
				continue
			}
			relPath := e.path
			if prefix != "" {
				relPath = strings.TrimPrefix(e.path, prefix+"/")
				if relPath == e.path && e.path == prefix {
					relPath = filepath.Base(e.path)
				}
			}
			if shouldSkipHistoryPath(relPath, excludeDirs, extraGlobs) {
				continue
			}
			if e.size > maxSize {
				oversized[e.oid] = struct{}{}
				continue
			}
			key := e.oid + "\x00" + relPath
			if _, ok := seenPath[key]; ok {
				continue
			}
			seenPath[key] = struct{}{}
			blobs = append(blobs, blobRef{
				oid:    e.oid,
				path:   relPath,
				commit: commit,
				size:   e.size,
			})
		}
	}

	if len(blobs) == 0 {
		return 0, nil
	}

	return scanBlobs(gitRoot, blobs, visitor, opts.OnBlob)
}

func relPrefix(gitRoot, path string) (string, error) {
	rel, err := filepath.Rel(gitRoot, path)
	if err != nil {
		return "", fmt.Errorf("path %q is not inside git root %q", path, gitRoot)
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return "", nil
	}
	if strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("path %q is not inside git root %q", path, gitRoot)
	}
	return rel, nil
}

func buildExcludeSets(exclude []string) (map[string]struct{}, []string) {
	excludeDirs := make(map[string]struct{}, len(config.DefaultExcludeDirs)+len(exclude))
	for _, d := range config.DefaultExcludeDirs {
		if d == ".git" {
			continue
		}
		excludeDirs[d] = struct{}{}
	}
	extraGlobs := make([]string, 0, len(exclude))
	for _, e := range exclude {
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
	return excludeDirs, extraGlobs
}

func shouldSkipHistoryPath(relSlash string, excludeDirs map[string]struct{}, globs []string) bool {
	relSlash = filepath.ToSlash(relSlash)
	for _, part := range strings.Split(relSlash, "/") {
		if _, ok := excludeDirs[part]; ok {
			return true
		}
	}
	base := filepath.Base(relSlash)
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

func listCommits(gitRoot string, maxCommits int) ([]string, error) {
	args := []string{"rev-list", "--reverse"}
	if maxCommits > 0 {
		args = append(args, fmt.Sprintf("--max-count=%d", maxCommits))
	}
	args = append(args, "HEAD")
	out, err := gitOutput(gitRoot, args...)
	if err != nil {
		return nil, fmt.Errorf("list commits: %w", err)
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}

type treeEntry struct {
	oid  string
	path string
	size int64
}

func listTree(gitRoot, commit string) ([]treeEntry, error) {
	out, err := gitOutputBytes(gitRoot, "ls-tree", "-r", "-l", "-z", commit)
	if err != nil {
		short := commit
		if len(short) > 12 {
			short = short[:12]
		}
		return nil, fmt.Errorf("ls-tree %s: %w", short, err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	parts := bytes.Split(out, []byte{0})
	entries := make([]treeEntry, 0, len(parts))
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		tab := bytes.IndexByte(p, '\t')
		if tab < 0 {
			continue
		}
		meta := string(p[:tab])
		path := string(p[tab+1:])
		fields := strings.Fields(meta)
		if len(fields) < 4 || fields[1] != "blob" {
			continue
		}
		size, szErr := strconv.ParseInt(fields[3], 10, 64)
		if szErr != nil {
			continue
		}
		entries = append(entries, treeEntry{
			oid:  fields[2],
			path: filepath.ToSlash(path),
			size: size,
		})
	}
	return entries, nil
}

func scanBlobs(gitRoot string, blobs []blobRef, visitor HistoryVisitor, onBlob func(string)) (int, error) {
	cmd := exec.Command("git", "-C", gitRoot, "cat-file", "--batch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return 0, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return 0, err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return 0, fmt.Errorf("git cat-file: %w", err)
	}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	}()

	scanned := 0
	reader := bufio.NewReader(stdout)
	contentCache := make(map[string][]byte)

	for _, b := range blobs {
		content, ok := contentCache[b.oid]
		if !ok {
			var readErr error
			content, readErr = readBatchObject(stdin, reader, b.oid)
			if readErr != nil {
				return scanned, readErr
			}
			if content == nil {
				continue // missing
			}
			contentCache[b.oid] = content
		}

		if bytes.IndexByte(content[:min(512, len(content))], 0) >= 0 {
			continue
		}

		if vErr := visitor(b.path, b.commit, bytes.NewReader(content)); vErr != nil {
			return scanned, vErr
		}
		scanned++
		if onBlob != nil {
			onBlob(b.path)
		}
	}
	return scanned, nil
}

// readBatchObject writes oid to cat-file --batch and reads one object.
// Returns (nil, nil) when the object is missing.
func readBatchObject(stdin io.Writer, reader *bufio.Reader, oid string) ([]byte, error) {
	if _, err := fmt.Fprintln(stdin, oid); err != nil {
		return nil, err
	}
	header, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read blob header: %w", err)
	}
	header = strings.TrimSpace(header)
	fields := strings.Fields(header)
	if len(fields) >= 2 && fields[1] == "missing" {
		return nil, nil
	}
	if len(fields) < 3 {
		return nil, fmt.Errorf("unexpected cat-file header: %q", header)
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse blob size: %w", err)
	}
	content := make([]byte, size)
	if _, err := io.ReadFull(reader, content); err != nil {
		return nil, fmt.Errorf("read blob %s: %w", oid, err)
	}
	if _, err := reader.ReadByte(); err != nil && err != io.EOF {
		return nil, fmt.Errorf("read blob trailer: %w", err)
	}
	return content, nil
}

func gitOutput(dir string, args ...string) (string, error) {
	b, err := gitOutputBytes(dir, args...)
	return string(b), err
}

func gitOutputBytes(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return out, nil
}
