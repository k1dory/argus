import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { blockCandidates, isNonRoutableIpv4, publicIpsFromChain } from "../src/lib/shared/respond";
import { isIncidentStatus } from "../src/lib/shared/incidents";

test("publicIpsFromChain: публичные адреса из текста цепочки, частные и служебные — нет", () => {
  const chain = [
    "ssh: Failed password from 203.0.113.7 port 22",
    "src 10.1.2.3 → dst 198.51.100.9",
    "172.16.5.5 172.31.255.255 172.32.0.1 192.168.1.1 127.0.0.1",
    "link-local 169.254.1.1, cgnat 100.64.0.1 100.127.255.255, but 100.128.0.1 is public",
    "multicast 224.0.0.1 239.255.255.255, reserved 240.0.0.1, broadcast 255.255.255.255, zero 0.1.2.3",
  ];
  assert.deepEqual(publicIpsFromChain(chain), ["203.0.113.7", "198.51.100.9", "172.32.0.1", "100.128.0.1"]);
});

test("publicIpsFromChain: октеты ≤255, версии и длинные последовательности цифр — не адреса", () => {
  assert.deepEqual(publicIpsFromChain(["version 4.7.2.1 installed"]), []);
  assert.deepEqual(publicIpsFromChain(["wazuh-agent v4.7.2.1, addr 8.8.8.8"]), ["8.8.8.8"]);
  assert.deepEqual(publicIpsFromChain(["Ver. 4.7.2.1; VERSION 4.7.2.1"]), []);
  assert.deepEqual(publicIpsFromChain(["from 4.7.2.1"]), ["4.7.2.1"], "без префикса версии — адрес");
  assert.deepEqual(publicIpsFromChain(["256.1.1.1 999.1.1.1 1.2.3.256"]), []);
  assert.deepEqual(publicIpsFromChain(["8.8.8.8.5 5.8.8.8.8"]), []);
  assert.deepEqual(publicIpsFromChain(["18.8.8.8.5"]), []);
  assert.deepEqual(publicIpsFromChain(["x8.8.8.8 8.8.8.8x"]), ["8.8.8.8"]);
  assert.deepEqual(publicIpsFromChain(["[8.8.4.4]:443", "(1.1.1.1)", "9.9.9.9."]), ["8.8.4.4", "1.1.1.1"]);
  assert.deepEqual(publicIpsFromChain(["01.2.3.4"]), [], "ведущий ноль — не адрес");
});

test("publicIpsFromChain: лимит 5 — после фильтра, дубли схлопываются", () => {
  const chain = [
    "10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5 10.0.0.6",
    "1.1.1.1 2.2.2.2 1.1.1.1 3.3.3.3 4.4.4.4 5.5.5.5 6.6.6.6 7.7.7.7",
  ];
  assert.deepEqual(publicIpsFromChain(chain), ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]);
  assert.deepEqual(publicIpsFromChain([]), []);
});

test("isNonRoutableIpv4: границы диапазонов", () => {
  for (const ip of ["0.0.0.0", "0.255.255.255", "10.0.0.0", "10.255.255.255", "100.64.0.0", "100.127.255.255", "127.0.0.1", "169.254.0.0", "169.254.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.0", "224.0.0.0", "239.255.255.255", "240.0.0.0", "255.255.255.255", "1.2.3", "1.2.3.256", "a.b.c.d"]) {
    assert.ok(isNonRoutableIpv4(ip), `${ip} — не публичный`);
  }
  for (const ip of ["1.0.0.0", "9.255.255.255", "11.0.0.0", "100.63.255.255", "100.128.0.0", "126.255.255.255", "128.0.0.1", "169.253.255.255", "169.255.0.0", "172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.0", "223.255.255.255"]) {
    assert.ok(!isNonRoutableIpv4(ip), `${ip} — публичный`);
  }
});

test("net.isIP — проверка адреса из формы: IPv4/IPv6 принимаются, мусор и версии — нет", () => {
  assert.equal(net.isIP("203.0.113.7"), 4);
  assert.equal(net.isIP("2001:db8::1"), 6);
  assert.equal(net.isIP("::1"), 6);
  assert.equal(net.isIP("4.7.2.1.1"), 0);
  assert.equal(net.isIP("256.1.1.1"), 0);
  assert.equal(net.isIP("1.2.3"), 0);
  assert.equal(net.isIP("abc"), 0);
  assert.equal(net.isIP("::::"), 0, "старый IP_RE пропускал строки из двоеточий");
  assert.equal(net.isIP("1.2.3.4; rm -rf /"), 0);
  assert.equal(net.isIP(""), 0);
});

test("isIncidentStatus: реальные статусы — да; toString/constructor/прочее — нет", () => {
  for (const s of ["new", "escalated", "in_progress", "waiting_owner", "observing", "closed", "false_positive"]) assert.ok(isIncidentStatus(s), s);
  for (const s of ["toString", "constructor", "__proto__", "hasOwnProperty", "valueOf", "", "NEW", undefined, null, 1, {}]) assert.ok(!isIncidentStatus(s), String(s));
});

test("blockCandidates: субъект-адрес — единственный кандидат; наши цели и экспортёр из цепочки не предлагаются", () => {
  const chain = [
    "08:22:27  netflow.core     172.16.0.1     flow                     185.25.9.138:9000",
    "08:23:22  netflow.core     185.25.9.1     flow                     185.25.9.53:9000",
  ];
  assert.deepEqual(blockCandidates("94.154.43.7", chain), ["94.154.43.7"]);
  assert.deepEqual(blockCandidates("10.0.0.5", chain), [], "частный субъект — блокировать нечего, цели не подставляются");
});

test("blockCandidates: субъект-логин — публичные адреса цепочки без колонки узла", () => {
  const chain = [
    "10:00:01  host.sshd        203.0.113.9    auth.ssh                 root from 198.51.100.7",
    "10:00:02  host.sshd        203.0.113.9    auth.ssh                 root from 198.51.100.8",
  ];
  assert.deepEqual(blockCandidates("root", chain), ["198.51.100.7", "198.51.100.8"]);
  assert.deepEqual(blockCandidates("root", ["Failed password from 203.0.113.7"]), ["203.0.113.7"], "строка без колонок — как раньше");
});
