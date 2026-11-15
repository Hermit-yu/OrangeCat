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
    imgRefresh: docEl,
    logName: docEl,
    logLines: docEl,
    logOut: docEl,
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

// P2：容器生命周期请求体必须带上后端 DisallowUnknownFields 只认的三个键，
// 而且 force 只在强杀时为 true（与面板层的 force=true 门槛一一对应）。
test("container action posts only the allowed keys and gates force on kill", () => {
  const js = scripts[0][1];
  assert.match(js, /\/api\/docker\/action/, "must call the container action endpoint");
  assert.match(js, /\{name,action,force:kill\}/, "request body must carry name/action/force");
  assert.match(js, /const action=kill\?"KILL":stop\?"STOP":restart\?"RESTART":"START"/,
    "all four lifecycle verbs must map to an action");
  assert.doesNotMatch(js, /\{name,name:name/, "must not emit a duplicated name key");
});

// P2：强杀必须二次确认，且是唯一带危险标记的按钮。
test("container kill asks for a second confirmation", () => {
  const js = scripts[0][1];
  assert.match(js, /if\(kill\)ok=confirm\(/, "kill must ask twice");
  assert.match(js, /actdanger/, "kill button must be visually marked dangerous");
});

// P2：容器日志必须走有界接口，且行数取自用户输入而不是写死的 500。
test("container logs use the bounded endpoint with user line count", () => {
  const js = scripts[0][1];
  assert.match(js, /\/api\/docker\/logs\?name=/, "must query the bounded logs endpoint");
  assert.ok(js.includes('&lines="+encodeURIComponent(logLines.value'),
      "line count must come from the input");
  assert.match(js, /payload\.truncated/, "must surface the truncation flag");
});

// P2：镜像/网络/卷是三张只读表，字段映射要锁住，避免后端字段改名前端静默空表。
test("docker resources render the documented fields", () => {
  const js = scripts[0][1];
  assert.match(js, /m\.repo\|\|"—"/, "images must read repo");
  assert.match(js, /n\.containers\|\|\[\]\)\.join/, "networks must read member containers");
  assert.match(js, /v\.used_by\|\|\[\]/, "volumes must read using containers");
  assert.match(js, /im\.images&&im\.images\.images/, "images must unwrap the api envelope");
});
