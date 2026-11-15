package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// P11 应用目录与生态适配。
//
// 目录源 = /var/lib/ocp/apps/catalog.json（管理员可维护的真实应用定义）。
// 每个应用声明 name/desc/category/compose_path（compose 路径复用 P2 白名单）。
// apps.catalog 只读目录；apps.install 走 compose up -d；apps.status 检测已装；
// apps.uninstall 走 compose down（不删卷，安全默认）。

// appsCatalogPath is the catalog source (var for test override).
var appsCatalogPath = "/var/lib/ocp/apps/catalog.json"

// appDef is one catalog entry.
type appDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	ComposePath string `json:"compose_path"`
	Icon        string `json:"icon"`
}

// loadAppsCatalog reads the catalog; missing file = empty (honest, not error).
func loadAppsCatalog() []appDef {
	b, err := os.ReadFile(appsCatalogPath)
	if err != nil {
		return []appDef{}
	}
	var defs []appDef
	if err := json.Unmarshal(b, &defs); err != nil {
		return []appDef{}
	}
	return defs
}

// AppsCatalog lists catalog entries with install status merged.
func AppsCatalog(ctx context.Context, _ map[string]any) (map[string]any, error) {
	defs := loadAppsCatalog()
	statuses := detectInstalled(ctx, defs)
	out := make([]map[string]any, 0, len(defs))
	for _, d := range defs {
		out = append(out, map[string]any{
			"name":        d.Name,
			"description": d.Description,
			"category":    d.Category,
			"compose_path": d.ComposePath,
			"icon":        d.Icon,
			"installed":   statuses[d.Name],
		})
	}
	return map[string]any{"catalog": out, "source": appsCatalogPath, "count": len(out)}, nil
}

// detectInstalled checks which catalog apps are actually running via compose ps.
func detectInstalled(ctx context.Context, defs []appDef) map[string]bool {
	res := map[string]bool{}
	for _, d := range defs {
		if !isKnownComposePath(d.ComposePath) {
			res[d.Name] = false
			continue
		}
		st := composeProjectStatus(ctx, d.ComposePath, composeProjectName(d.ComposePath))
		res[d.Name] = st["running"] == true
	}
	return res
}

// composeProjectName derives a compose project name from a path (P2 convention).
func composeProjectName(path string) string {
	base := filepath.Base(filepath.Clean(path))
	base = strings.TrimSuffix(base, ".yml")
	base = strings.TrimSuffix(base, ".yaml")
	return base
}

// AppsInstall installs a catalog app: validate compose path, then `compose up -d`.
func AppsInstall(ctx context.Context, p map[string]any) (map[string]any, error) {
	name, _ := p["name"].(string)
	def := findApp(name)
	if def == nil {
		return nil, fmt.Errorf("应用不存在：%s", name)
	}
	if !isKnownComposePath(def.ComposePath) {
		return nil, fmt.Errorf("compose 路径不在白名单：%s", def.ComposePath)
	}
	if !fileExists(def.ComposePath) {
		return nil, fmt.Errorf("compose 文件不存在：%s", def.ComposePath)
	}
	// compose up -d（复用 P2 的 docker compose 调用语义）
	out, err := runComposeCommand(ctx, def.ComposePath, "up", "-d")
	if err != nil {
		return map[string]any{"ok": false, "app": name, "error": err.Error(), "output": out}, nil
	}
	return map[string]any{"ok": true, "app": name, "installed": true, "output": out}, nil
}

// AppsUninstall stops a catalog app: compose down (keep volumes, safe default).
func AppsUninstall(ctx context.Context, p map[string]any) (map[string]any, error) {
	name, _ := p["name"].(string)
	def := findApp(name)
	if def == nil {
		return nil, fmt.Errorf("应用不存在：%s", name)
	}
	if !isKnownComposePath(def.ComposePath) {
		return nil, fmt.Errorf("compose 路径不在白名单：%s", def.ComposePath)
	}
	out, err := runComposeCommand(ctx, def.ComposePath, "down")
	if err != nil {
		return map[string]any{"ok": false, "app": name, "error": err.Error(), "output": out}, nil
	}
	return map[string]any{"ok": true, "app": name, "installed": false, "output": out}, nil
}

// runComposeCommand wraps `docker compose -f <path> <args...>`.
func runComposeCommand(ctx context.Context, path string, args ...string) (string, error) {
	full := append([]string{"compose", "-f", path}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func findApp(name string) *appDef {
	for i := range loadAppsCatalog() {
		if loadAppsCatalog()[i].Name == name {
			return &loadAppsCatalog()[i]
		}
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
