// Исполняем настоящий entrypoint с подставными caddy и /proc/net/route:
// ACL не должен расширяться из-за опечатки или общего шлюза rootless Docker.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const entrypoint = path.resolve(__dirname, "../../caddy/entrypoint.sh");
const gateway = "172.18.0.1/32";

function harness(t: TestContext) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "argus-caddy-acl-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const realAwk = ["/usr/bin/awk", "/bin/awk"].find(existsSync);
  assert.ok(realAwk, "для entrypoint требуется системный awk");
  const routeReads = path.join(dir, "route-reads");
  writeFileSync(path.join(dir, "awk"), `#!/bin/sh
for arg do
  if [ "$arg" = /proc/net/route ]; then
    printf 'read\\n' >> "$ARGUS_TEST_ROUTE_READS"
    printf '010012AC\\n'
    exit 0
  fi
done
exec ${realAwk} "$@"
`, { mode: 0o700 });
  writeFileSync(path.join(dir, "caddy"), `#!/bin/sh
[ "$*" = 'run --config /etc/caddy/Caddyfile --adapter caddyfile' ] || exit 9
printf '%s\\n' "$MCP_ALLOWED_NETS"
`, { mode: 0o700 });
  return {
    run(env: Record<string, string>, args: string[] = []) {
      const result = spawnSync("sh", [entrypoint, ...args], {
        encoding: "utf8", timeout: 5_000, maxBuffer: 64 * 1024,
        env: {
          PATH: `${dir}:/usr/bin:/bin`, HOME: dir, TMPDIR: dir, LANG: "C", LC_ALL: "C", NODE_ENV: "test",
          ARGUS_TEST_ROUTE_READS: routeReads, ...env,
        },
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      return result;
    },
    routeReads: () => existsSync(routeReads) ? readFileSync(routeReads, "utf8").trim().split("\n").length : 0,
  };
}

test("MCP ACL: строгие IPv4/IPv6 и CIDR, включая 10.0.0.1a", (t) => {
  const h = harness(t);
  const valid = ["0.0.0.0", "255.255.255.255/32", "10.0.0.0/8", "0.0.0.0/0", "::", "::1/128", "2001:db8::/32", "1:2:3:4:5:6:7:8"];
  const invalid = [
    "10.0.0.1a", "10.0.0.1a/24", "10.0.0.256", "10.0.0", "10.00.0.1", "10.0.0.-1", "10.0.0.1/33",
    "10.0.0.1/", "10.0.0.1/24/1", "10.0.0.1/01", "10.0.0.1/24a", "10.0.0.1/+24",
    "2001:db8::/129", "2001::db8::1", "2001:::1", "12345::1", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8::", "fe80::1%eth0",
  ];
  const result = h.run({}, ["--check", ...valid, ...invalid]);
  assert.deepEqual(result.stdout.trim().split("\n"), [...valid.map((s) => `ok  ${s}`), ...invalid.map((s) => `bad ${s}`)]);
  assert.equal(h.routeReads(), 0, "проверка адресов не читает маршруты");
});

test("MCP ACL: плохие адреса отбрасываются, пустой результат сужается до loopback", (t) => {
  const h = harness(t);
  const mixed = h.run({ MCP_BIND: "0.0.0.0", MCP_ALLOWED_NETS: "10.0.0.1a,192.0.2.44/32 2001:db8::/32,10.0.0.256" });
  assert.equal(mixed.stdout.trim(), "192.0.2.44/32 2001:db8::/32");
  assert.match(mixed.stderr, /10\.0\.0\.1a/);
  assert.equal(h.run({ MCP_BIND: "0.0.0.0", MCP_ALLOWED_NETS: "10.0.0.1a,::1/129" }).stdout.trim(), "127.0.0.1/32");
  assert.equal(h.routeReads(), 0);
});

test("MCP ACL: внешний bind не добавляет общий шлюз без явного согласия", (t) => {
  const h = harness(t);
  for (const bind of ["0.0.0.0", "::", "198.51.100.10"]) {
    const result = h.run({ MCP_BIND: bind, MCP_ALLOWED_NETS: "192.0.2.44/32" });
    assert.equal(result.stdout.trim(), "192.0.2.44/32", `bind=${bind}: общий адрес rootless-клиентов не разрешён`);
  }
  assert.equal(h.routeReads(), 0, "нет даже чтения шлюза для внешнего bind");
});

test("MCP ACL: loopback по умолчанию допускает хост, явный запрет важнее bind", (t) => {
  const h = harness(t);
  for (const bind of [undefined, "127.0.0.1", "::1", "[::1]", "localhost"]) {
    const env: Record<string, string> = { MCP_ALLOWED_NETS: "192.0.2.44/32" };
    if (bind) env.MCP_BIND = bind;
    assert.equal(h.run(env).stdout.trim(), `192.0.2.44/32 ${gateway}`, String(bind));
    const reads = h.routeReads();
    assert.equal(h.run({ ...env, MCP_ALLOW_HOST: "0" }).stdout.trim(), "192.0.2.44/32");
    assert.equal(h.routeReads(), reads, "явный запрет не читает шлюз");
  }
});

test("MCP ACL: явное включение шлюза работает и не дублирует уже разрешённый адрес", (t) => {
  const h = harness(t);
  for (const allow of ["1", "true", "yes", "on"]) {
    const env = { MCP_BIND: "0.0.0.0", MCP_ALLOW_HOST: allow, MCP_ALLOWED_NETS: `192.0.2.44/32,${gateway}` };
    assert.equal(h.run(env).stdout.trim(), `192.0.2.44/32 ${gateway}`);
  }
  assert.equal(h.routeReads(), 4);
});
