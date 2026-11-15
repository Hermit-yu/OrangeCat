package actions

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// composeRoots are the directories scanned for compose projects. They are a fixed
// allowlist rather than a recursive walk: a single request must never be able to
// point the panel at an arbitrary file on the host, because compose files
// routinely carry secrets and reading one through the web would leak them to a
// browser. Up/down are deliberately NOT implemented here.
var composeRoots = []string{"/home/web", "/opt"}

// composeFileNames are the only filenames treated as a compose project. Files
// with other names (docker-compose1.yml etc.) are intentionally invisible.
var composeFileNames = []string{
	"docker-compose.yml", "docker-compose.yaml",
	"compose.yml", "compose.yaml",
}

// composeProjectPaths returns the allowlisted project files. Each root is
// searched one level deep so projects living in a subdirectory (e.g.
// /opt/horizon/docker-compose.yml) are found, but arbitrary deeper paths are not.
func composeProjectPaths() []string {
	var paths []string
	for _, root := range composeRoots {
		for _, fname := range composeFileNames {
			paths = append(paths, filepath.Join(root, fname))
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			for _, fname := range composeFileNames {
				paths = append(paths, filepath.Join(root, entry.Name(), fname))
			}
		}
	}
	return paths
}

// isKnownComposePath re-derives the allowlist on every call rather than caching it,
// so a root added or renamed later cannot be validated through a stale check.
func isKnownComposePath(path string) bool {
	for _, known := range composeProjectPaths() {
		if path == known {
			return true
		}
	}
	return false
}

// ComposeProjects discovers compose projects under the fixed roots. It reports
// existence only and never reads file contents, so discovery cannot leak a
// secret even if a project is misconfigured.
func ComposeProjects(ctx context.Context, p map[string]any) (map[string]any, error) {
	if len(p) != 0 {
		return nil, fmt.Errorf("compose.projects accepts no parameters")
	}
	found := []map[string]any{}
	for _, path := range composeProjectPaths() {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		project := strings.Trim(strings.TrimPrefix(filepath.Dir(path), "/"), "/")
		if project == "" {
			project = "root"
		}
		found = append(found, map[string]any{
			"path":    path,
			"project": project,
			"root":    filepath.Dir(path),
		})
	}
	sort.Slice(found, func(i, j int) bool {
		return found[i]["path"].(string) < found[j]["path"].(string)
	})
	return map[string]any{"available": true, "projects": found, "count": len(found)}, nil
}

// ComposeValidate runs `docker compose config --quiet` against an already-known
// project file. That command is a pure interpolation/syntax check — it starts
// nothing and modifies nothing — so it is safe to expose as a read-only action.
//
// The path is re-checked against the discovery allowlist at call time. Without
// that check this endpoint would be a general-purpose "run docker compose in any
// directory" primitive, which is how a web process ends up with a shell over the
// host's containers.
func ComposeValidate(ctx context.Context, p map[string]any) (map[string]any, error) {
	for key := range p {
		if key != "path" {
			return nil, fmt.Errorf("compose.validate accepts only path")
		}
	}
	path := strings.TrimSpace(mustString(p, "path"))
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if !isKnownComposePath(path) {
		return nil, fmt.Errorf("path is not a known compose project file")
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "compose", "-f", path, "config", "--quiet").CombinedOutput()
	result := map[string]any{"available": true, "path": path, "valid": err == nil}
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 500 {
			msg = msg[:500]
		}
		if msg == "" {
			msg = err.Error()
		}
		result["error"] = msg
	}
	return result, nil
}
