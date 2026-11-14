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
  const sandbox = {
    document: { cookie, getElementById: () => ({ addEventListener() {} }) },
    location: { pathname: "/orangecat/", reload() {} },
    setInterval() {},
    fetch: async (url, options = {}) => {
      calls.push({ url, options });
      const status = url.endsWith("/api/overview") ? 401 : 200;
      return { status, ok: status >= 200 && status < 300, text: async () => '{"ok":true}' };
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
