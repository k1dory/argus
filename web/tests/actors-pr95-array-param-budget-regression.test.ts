// URLSearchParams is the independent wire-format oracle, including USVString
// replacement of unpaired UTF-16 surrogates and the encoded array brackets.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ARRAY_PARAM_CHUNK, arrayParam, formEncodedBytes, parseAliasInput } from "../src/lib/shared/actors";

const wireBytes = (value: string) => new URLSearchParams({ v: value }).toString().slice(2).length;

test("PR #95: formEncodedBytes agrees with URLSearchParams for malformed UTF-16", async (t) => {
  for (const [label, value] of [
    ["ASCII and form punctuation", "aZ09 *-._~',+&="],
    ["Unicode and a real surrogate pair", "é漢😀"],
    ["unpaired high surrogate at the end", "\ud800"],
    ["two unpaired high surrogates", "\ud800\ud800"],
    ["high surrogate followed by a BMP character", "\ud800漢"],
  ]) {
    await t.test(label, () => assert.equal(formEncodedBytes(value), wireBytes(value)));
  }
});

test("PR #95: an array chunk includes both percent-encoded brackets in its budget", () => {
  for (const count of [14_999, 15_000]) {
    const params: Record<string, string | number> = {};
    const elements = Array<string>(count).fill("1");
    arrayParam(params, "owners", "Array(UInt32)", elements);
    const chunks = Object.values(params).map(String);
    assert.deepEqual(chunks.flatMap((chunk) => chunk.slice(1, -1).split(",")), elements);
    assert.ok(chunks.every((chunk) => wireBytes(chunk) <= ARRAY_PARAM_CHUNK),
      `${count} elements: encoded chunk sizes ${chunks.map(wireBytes).join(", ")} exceed ${ARRAY_PARAM_CHUNK}`);
  }
});

test("PR #95: accepted aliases containing unpaired surrogates cannot undercount chunk bytes", () => {
  const elements = Array.from({ length: 80 }, (_, i) => {
    const value = "\ud800".repeat(252) + String(i).padStart(4, "0");
    const parsed = parseAliasInput({ kind: "uid", value });
    assert.equal(parsed.ok, true, "the public alias parser accepts this UTF-16 input");
    return `'${value}'`;
  });
  const params: Record<string, string | number> = {};
  arrayParam(params, "uids", "Array(String)", elements);
  const chunks = Object.values(params).map(String);
  assert.deepEqual(chunks.flatMap((chunk) => chunk.slice(1, -1).split(",")), elements);
  assert.ok(chunks.every((chunk) => wireBytes(chunk) <= ARRAY_PARAM_CHUNK),
    `encoded chunk sizes ${chunks.map(wireBytes).join(", ")} exceed ${ARRAY_PARAM_CHUNK}`);
});
