// Свои сети инсталляции (INTERNAL_NETS) в кандидатах на блокировку: argus-queries читает
// переменную при каждом вызове, без моков модуля — здесь настоящий ownNets/blockCandidatesFor.
import { test } from "node:test";
import assert from "node:assert/strict";
import { blockCandidatesFor, ownNets } from "../src/lib/argus-queries";

const chain = [
  "08:22:27  netflow.core     172.16.0.1     flow                     185.25.9.138:9000",
  "08:27:27  netflow.core     172.16.0.1     flow                     203.0.113.44:443",
];

test("ownNets: пусто, список через запятую с пробелами и пустыми элементами", () => {
  delete process.env.INTERNAL_NETS;
  assert.deepEqual(ownNets(), []);
  process.env.INTERNAL_NETS = " 192.168.0.0/20, 185.25.9.0/24,,";
  assert.deepEqual(ownNets(), ["192.168.0.0/20", "185.25.9.0/24"]);
});

test("blockCandidatesFor: белые адреса из INTERNAL_NETS не предлагаются ни субъектом, ни целью", () => {
  process.env.INTERNAL_NETS = "185.25.9.0/24";
  assert.deepEqual(blockCandidatesFor({ actor_name: "10.1.2.3", chain }), ["203.0.113.44"], "исходящее правило: внешний C2, свой белый блок исключён");
  assert.deepEqual(blockCandidatesFor({ actor_name: "185.25.9.7", chain }), ["203.0.113.44"], "свой белый субъект — не кандидат");
  assert.deepEqual(blockCandidatesFor({ actor_name: "94.154.43.7", chain }), ["94.154.43.7"]);
  delete process.env.INTERNAL_NETS;
  assert.deepEqual(blockCandidatesFor({ actor_name: "10.1.2.3", chain }), ["185.25.9.138", "203.0.113.44"], "без INTERNAL_NETS публичные цели цепочки предлагаются");
});
