#!/usr/bin/env node
// Мок Wazuh manager API для разработки консоли без живого менеджера:
//   node scripts/mock-wazuh-api.mjs   # слушает http://localhost:55001
//   WAZUH_API_URL=http://localhost:55001 npm run dev
// Покрывает ровно те эндпоинты, которые использует web/src/lib/wazuh-api.ts.
// Состояние в памяти, любые креды принимаются.
import http from "http";

const PORT = Number(process.env.PORT ?? 55001);

const state = {
  agents: [
    { id: "000", name: "wazuh-manager", ip: "127.0.0.1", status: "active", version: "v4.9.2", group: null, lastKeepAlive: "9999-12-31T23:59:59Z", os: { name: "Ubuntu 22.04" } },
    { id: "001", name: "web-01", ip: "10.0.10.11", status: "active", version: "v4.9.2", group: ["default", "webservers"], lastKeepAlive: new Date().toISOString(), os: { name: "Debian 12" } },
    { id: "002", name: "db-01", ip: "10.0.10.12", status: "active", version: "v4.7.2", group: ["default"], lastKeepAlive: new Date().toISOString(), os: { name: "Debian 12" } },
    { id: "003", name: "app-01", ip: "10.0.10.13", status: "disconnected", version: "v4.9.2", group: ["default"], lastKeepAlive: "2026-08-20T10:00:00Z", os: { name: "AlmaLinux 9" } },
  ],
  groups: { default: "<agent_config>\n</agent_config>\n", webservers: "<agent_config>\n  <!-- nginx-мониторинг -->\n</agent_config>\n" },
  ruleFiles: { "local_rules.xml": '<group name="local,">\n  <rule id="100001" level="10">\n    <if_sid>5763</if_sid>\n    <description>sshd brute force (локальная копия)</description>\n  </rule>\n</group>\n' },
};

const mockAgentCount = Math.min(5000, Math.max(0, Number(process.env.MOCK_WAZUH_AGENTS ?? 0) || 0));
for (let i = state.agents.length; i < mockAgentCount; i++) {
  state.agents.push({ id: String(i).padStart(3, "0"), name: `mock-${i}`, ip: `10.0.${Math.floor(i / 254)}.${i % 254 + 1}`, status: "active", version: "v4.9.2", group: ["default"] });
}

const ok = (items) => ({
  data: { affected_items: items, total_affected_items: items.length, failed_items: [] },
  message: "ok",
  error: 0,
});

const page = (items, url) => {
  const offset = Math.max(0, Number(url.searchParams.get("offset") ?? 0));
  const limit = Math.max(1, Number(url.searchParams.get("limit") ?? 500));
  return { data: { affected_items: items.slice(offset, offset + limit), total_affected_items: items.length, failed_items: [] }, message: "ok", error: 0 };
};

function readBody(req) {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => resolve(body));
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const p = url.pathname;
  const send = (code, data, type = "application/json") => {
    res.writeHead(code, { "Content-Type": type });
    res.end(typeof data === "string" ? data : JSON.stringify(data));
  };
  const body = await readBody(req);
  console.log(`${req.method} ${p}${url.search}`);

  if (req.method === "POST" && p === "/security/user/authenticate") {
    return send(200, "mock-jwt-token-" + Date.now(), "text/plain");
  }
  if (req.method === "GET" && p === "/manager/info") {
    return send(200, ok([{ version: "v4.9.2 (mock)", type: "master", name: "wazuh-manager" }]));
  }
  if (req.method === "GET" && p === "/manager/configuration/validation") {
    return send(200, ok([{ name: "wazuh-manager", status: "OK" }]));
  }
  if (req.method === "PUT" && p === "/manager/restart") {
    return send(200, ok(["wazuh-manager"]));
  }
  if (req.method === "GET" && p === "/agents") {
    return send(200, page(state.agents, url));
  }
  let m = p.match(/^\/agents\/([^/]+)\/restart$/);
  if (req.method === "PUT" && m) return send(200, ok([m[1]]));
  m = p.match(/^\/agents\/([^/]+)\/group\/([^/]+)$/);
  if (m) {
    const agent = state.agents.find((a) => a.id === m[1]);
    if (!agent) return send(404, { detail: "агент не найден", error: 1701 });
    if (!state.groups[m[2]]) return send(404, { detail: "группа не найдена", error: 1710 });
    agent.group = agent.group ?? [];
    if (req.method === "PUT" && !agent.group.includes(m[2])) agent.group.push(m[2]);
    if (req.method === "DELETE") agent.group = agent.group.filter((g) => g !== m[2]);
    return send(200, ok([agent.id]));
  }
  if (req.method === "GET" && p === "/groups") {
    return send(
      200,
      ok(
        Object.keys(state.groups).map((name) => ({
          name,
          count: state.agents.filter((a) => (a.group ?? []).includes(name)).length,
          configSum: "ab" + name.length + "c0ffee",
        })),
      ),
    );
  }
  if (req.method === "POST" && p === "/groups") {
    const { group_id } = JSON.parse(body || "{}");
    if (!group_id || state.groups[group_id]) return send(400, { detail: "группа уже есть", error: 1711 });
    state.groups[group_id] = "<agent_config>\n</agent_config>\n";
    return send(200, ok([group_id]));
  }
  if (req.method === "DELETE" && p === "/groups") {
    const list = (url.searchParams.get("groups_list") ?? "").split(",");
    for (const g of list) if (g !== "default") delete state.groups[g];
    for (const a of state.agents) a.group = (a.group ?? []).filter((g) => !list.includes(g) || g === "default");
    return send(200, ok(list));
  }
  m = p.match(/^\/groups\/([^/]+)\/agents$/);
  if (req.method === "GET" && m) {
    return send(200, page(state.agents.filter((a) => (a.group ?? []).includes(m[1])), url));
  }
  m = p.match(/^\/groups\/([^/]+)\/files\/agent\.conf$/);
  if (req.method === "GET" && m) {
    const conf = state.groups[m[1]];
    if (conf === undefined) return send(404, { detail: "группа не найдена", error: 1710 });
    return send(200, conf, "application/xml");
  }
  m = p.match(/^\/groups\/([^/]+)\/configuration$/);
  if (req.method === "PUT" && m) {
    if (state.groups[m[1]] === undefined) return send(404, { detail: "группа не найдена", error: 1710 });
    if (!body.includes("<agent_config>")) return send(400, { detail: "невалидный agent.conf: нет <agent_config>", error: 1114 });
    state.groups[m[1]] = body;
    return send(200, ok([m[1]]));
  }
  if (req.method === "GET" && p === "/rules/files") {
    return send(
      200,
      ok(Object.keys(state.ruleFiles).map((filename) => ({ filename, relative_dirname: "etc/rules", status: "enabled" }))),
    );
  }
  m = p.match(/^\/rules\/files\/([^/]+)$/);
  if (req.method === "GET" && m) {
    const xml = state.ruleFiles[decodeURIComponent(m[1])];
    if (xml === undefined) return send(404, { detail: "файл не найден", error: 1415 });
    return send(200, xml, "application/xml");
  }
  if (req.method === "PUT" && m) {
    if (!body.includes("<group")) return send(400, { detail: "невалидный файл правил: нет <group>", error: 1113 });
    state.ruleFiles[decodeURIComponent(m[1])] = body;
    return send(200, ok([decodeURIComponent(m[1])]));
  }

  send(404, { detail: `mock: нет обработчика ${req.method} ${p}`, error: 9999 });
});

server.listen(PORT, () => console.log(`mock wazuh api on http://localhost:${PORT}`));
