import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)];
assert.equal(scripts.length, 1, "expected one inline application script");
assert.match(scripts[0][0], /nonce="__OCP_CSP_NONCE__"/, "application script must carry the CSP nonce placeholder");

function createApp(cookie) {
  const calls = [];
  const el = () => ({
    addEventListener() {},
    querySelectorAll: () => [],
    dataset: {},
    classList: { add() {}, remove() {} },
    value: "",
    textContent: "",
    innerHTML: "",
  });
  const docEl = el();
  const sandbox = {
    document: {
      cookie,
      getElementById: (id) => (id === "btnHealth" ? docEl : (id === "btnDiag" ? docEl : (id === "svcFilter" ? docEl : docEl))),
      querySelector: el,
    },
    location: { pathname: "/orangecat/", reload() {} },
    // implicit named-element globals referenced by the inline script
    svcFilter: docEl,
    chartInfo: docEl,
    confirm() { return false; },
    alert() {},
    setInterval() {},
    fetch: async (url, options = {}) => {
      calls.push({ url, options });
      const status = url.endsWith("/api/overview") ? 401 : 200;
      return { status, ok: status >= 200 && status < 300, text: async () => '{"ok":true}', json: async () => ({}) };
    },
  };
  vm.runInNewContext(`${scripts[0][1]}\nglobalThis.postJSONUnderTest = postJSON;`, sandbox);
  return { calls, postJSON: sandbox.postJSONUnderTest };
}

test("POST mutations send the readable CSRF cookie as a request header", async () => {
  const { calls, postJSON } = createApp("ocp_csrf=feedface");
  await postJSON("/api/logout", {});
  const call = calls.find(({ url }) => url.endsWith("/api/logout"));
  assert.equal(call.url, "/orangecat/api/logout");
  assert.equal(call.options.headers["X-CSRF-Token"], "feedface");
});

test("login does not require a pre-existing CSRF token", async () => {
  const { calls, postJSON } = createApp("");
  await postJSON("/api/login", { username: "admin", password: "secret" });
  const call = calls.find(({ url }) => url.endsWith("/api/login"));
  assert.equal(call.options.headers["X-CSRF-Token"], undefined);
});

test("missing CSRF cookie does not fabricate a token", async () => {
  const { calls, postJSON } = createApp("");
  await postJSON("/api/logout", {});
  const call = calls.find(({ url }) => url.endsWith("/api/logout"));
  assert.equal(call.options.headers["X-CSRF-Token"], undefined);
});

// /api/history 返回 Go 结构体字段（Ts/CPU/Mem），前端必须做大写→小写归一化，
// 否则图表永远画不出线。锁住这处映射，防止字段名回归。
test("history chart normalizes the Go sample field names", () => {
  const js = scripts[0][1];
  assert.match(js, /p\.CPU!==undefined\?p\.CPU:p\.cpu/, "must read the uppercase CPU field");
  assert.match(js, /p\.Mem!==undefined\?p\.Mem:p\.mem/, "must read the uppercase Mem field");
  assert.match(js, /p\.Ts!==undefined\?p\.Ts:p\.ts/, "must read the uppercase Ts field");
});

// 进程结束的成功判定必须用面板的 ok 字段，而不是只信 result.sent；
// 面板把 Agent 拒绝（信号非法 / 缺 force / pid 不存在）统一标为失败。
test("process kill success is decided by the ok flag", () => {
  const js = scripts[0][1];
  assert.match(js, /j\.ok===true/, "kill confirmation must honor the ok flag");
  assert.doesNotMatch(js, /result\|\|\{\}\)\.sent===true/, "must not rely on result.sent alone");
});
