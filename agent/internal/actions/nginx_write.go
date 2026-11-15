package actions

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// P3 写切片：nginx 配置校验与重载。
//
// 本切片只做两个动作，安全边界刻意收窄：
//   - nginx.test  — 在 nginx 容器内跑 `nginx -t`（只读校验，不改变任何状态）。
//   - nginx.reload — 跑 `nginx -s reload`（重新加载配置）。
//
// 配置文件的创建/修改/删除（写 vhost）需要模板渲染 + 原子替换 + 备份 + 回滚，
// 涉及"写宿主 /home/web/conf.d"这个更大的写面，留到 P3 后半切片，不在本文件。
//
// 之所以走 docker exec nginx 而不是宿主 nginx，是因为线上 nginx 是
// kjlion/nginx:alpine 容器（宿主 nginx inactive），宿主 nginx -t 校验的是
// 另一套未用的配置，结果无意义。容器名固定白名单，不可参数化。
//
// 安全模型：容器名/动作/路径全部固定常量，不接收用户输入；任何失败都返回
// 结构化错误，不吞 stderr。

// NginxTest validates the live nginx config inside the container.
func NginxTest(ctx context.Context, p map[string]any) (map[string]any, error) {
	if len(p) != 0 {
		return nil, fmt.Errorf("nginx.test accepts no parameters")
	}
	ctx, cancel := context.WithTimeout(ctx, nginxTestTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec", nginxContainer, "nginx", "-t").CombinedOutput()
	if err != nil {
		return map[string]any{
			"ok":      false,
			"running": false,
			"output":  boundedNginxOutput(out, err),
		}, nil
	}
	return map[string]any{
		"ok":      true,
		"running": true,
		"output":  strings.TrimSpace(string(out)),
	}, nil
}

// NginxReload reloads the live nginx config inside the container.
func NginxReload(ctx context.Context, p map[string]any) (map[string]any, error) {
	if len(p) != 0 {
		return nil, fmt.Errorf("nginx.reload accepts no parameters")
	}
	ctx, cancel := context.WithTimeout(ctx, nginxTestTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec", nginxContainer, "nginx", "-s", "reload").CombinedOutput()
	if err != nil {
		return map[string]any{
			"ok":      false,
			"running": false,
			"output":  boundedNginxOutput(out, err),
		}, nil
	}
	return map[string]any{
		"ok":      true,
		"running": true,
		"output":  strings.TrimSpace(string(out)),
	}, nil
}

// boundedNginxOutput keeps error text small and never echoes the command.
func boundedNginxOutput(out []byte, err error) string {
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		msg = err.Error()
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}
