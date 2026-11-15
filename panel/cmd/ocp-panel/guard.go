// Package main — 写操作鉴权守卫。
//
// 容器生命周期与进程结束都是破坏性写路径，必须走同一套三重门。守卫集中在这
// 一个文件里，是为了让每条写路径都不再各自重写一遍 session/CSRF/Origin 校验
// ——过去进程结束把这段内联在 handler 里，原站失败只回了裸 http.Error，
// 审计里查不到 origin_mismatch 的原因，等于留痕缺口。
package main

import (
	"crypto/subtle"
	"net/http"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// requireWriteAccess 执行写操作的三重门，全部通过才返回会话与 true：
//
//  1. 原站：Origin 头存在且与请求 Host 的 scheme/host/port 一致（sameOriginHost
//     已严格解析，拒绝 userinfo/查询串/路径/协议混用）。失败 → 403 并留痕
//     origin_mismatch。
//  2. 会话：ocp_session cookie 必须能查到当前有效会话。缺失 → 401，失效 → 401。
//  3. CSRF 双提交：ocp_csrf cookie、会话内记录的令牌、X-CSRF-Token 头三者必须
//     全部等值，且都用常量时间比较，避免时序侧信道。任一不成立 → 403。
//
// 每个失败分支都经 rejectAuth 落审计（审计不可用时返回 503 而不是放行），
// 与 requireAuth 只验 session 的行为不同：读接口允许匿名探测被 401 挡回，
// 写接口则必须留下"谁在什么时候被哪一扇门挡下"。
func (p *panel) requireWriteAccess(w http.ResponseWriter, r *http.Request, eventType string) (session, bool) {
	if !p.sameOriginHost(r) {
		p.rejectAuth(w, r, eventType, authaudit.ReasonOriginMismatch, http.StatusForbidden, "跨站请求已拒绝")
		return session{}, false
	}
	c, err := r.Cookie("ocp_session")
	if err != nil {
		p.rejectAuth(w, r, eventType, authaudit.ReasonSessionMissing, http.StatusUnauthorized, "未登录")
		return session{}, false
	}
	s, ok := lookupSession(c.Value, p.loginNow())
	if !ok {
		p.rejectAuth(w, r, eventType, authaudit.ReasonSessionExpiredUnknown, http.StatusUnauthorized, "会话失效")
		return session{}, false
	}
	csfCookie, cookieErr := r.Cookie("ocp_csrf")
	csfHeader := r.Header.Get("X-CSRF-Token")
	if cookieErr != nil || s.csrf == "" ||
		subtle.ConstantTimeCompare([]byte(csfCookie.Value), []byte(s.csrf)) != 1 ||
		subtle.ConstantTimeCompare([]byte(csfHeader), []byte(s.csrf)) != 1 {
		p.rejectAuth(w, r, eventType, authaudit.ReasonCSRFFailed, http.StatusForbidden, "安全校验失败")
		return session{}, false
	}
	return s, true
}
