package actions

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestComposeProjectName: derive compose project from path (P2 convention).
func TestComposeProjectName(t *testing.T) {
	cases := map[string]string{
		"/home/web/docker-compose.yml":     "docker-compose",
		"/opt/horizon/docker-compose.yaml": "docker-compose",
		"/tmp/compose/sub.yml":             "sub",
	}
	for path, want := range cases {
		if got := composeProjectName(path); got != want {
			t.Fatalf("composeProjectName(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestAppsCatalogEmpty: missing catalog = honest empty (not error).
func TestAppsCatalogEmpty(t *testing.T) {
	// 用临时路径替换全局 catalog 路径
	orig := appsCatalogPath
	appsCatalogPath = filepath.Join(t.TempDir(), "missing.json")
	defer func() { appsCatalogPath = orig }()
	res, err := AppsCatalog(context.Background(), nil)
	if err != nil {
		t.Fatalf("empty catalog should not error: %v", err)
	}
	if res["count"] != 0 {
		t.Fatalf("count = %v, want 0", res["count"])
	}
}

// TestAppsCatalogValid: valid catalog entries are listed.
func TestAppsCatalogValid(t *testing.T) {
	orig := appsCatalogPath
	dir := t.TempDir()
	appsCatalogPath = filepath.Join(dir, "catalog.json")
	defer func() { appsCatalogPath = orig }()
	os.WriteFile(appsCatalogPath, []byte(`[{"name":"nginx-proxy","description":"test","category":"proxy","compose_path":"/home/web/docker-compose.yml"}]`), 0600)
	res, err := AppsCatalog(context.Background(), nil)
	if err != nil {
		t.Fatalf("catalog error: %v", err)
	}
	if res["count"] != 1 {
		t.Fatalf("count = %v, want 1", res["count"])
	}
	cat, _ := res["catalog"].([]map[string]any)
	if len(cat) != 1 || cat[0]["name"] != "nginx-proxy" {
		t.Fatalf("catalog entry wrong: %+v", cat)
	}
}

// TestFindApp: lookup by name.
func TestFindApp(t *testing.T) {
	orig := appsCatalogPath
	dir := t.TempDir()
	appsCatalogPath = filepath.Join(dir, "catalog.json")
	defer func() { appsCatalogPath = orig }()
	os.WriteFile(appsCatalogPath, []byte(`[{"name":"a","description":"","category":"","compose_path":"/x"}]`), 0600)
	if findApp("a") == nil {
		t.Fatalf("findApp(a) should exist")
	}
	if findApp("missing") != nil {
		t.Fatalf("findApp(missing) should be nil")
	}
}
