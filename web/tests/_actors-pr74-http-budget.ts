// Только перехват HTTP: listPersons/actorReport и клиент ClickHouse настоящие.
// SQL не исполняется и не эмулируется; проверяются размеры отправленного запроса.
import type { TestContext } from "node:test";
import assert from "node:assert/strict";
import { parseIdentitiesDoc, type Person } from "../src/lib/shared/actors";
import { importDocument, type ActivityFixture } from "./_actors-pr74-fixtures";

export const HTTP_URI_MAX_BYTES = 1024 * 1024;
export const HTTP_FIELD_MAX_BYTES = 128 * 1024;

type FieldSize = { name: string; bytes: number };
export type ActorRequest = {
  sql: string;
  uriBytes: number;
  urlFields: FieldSize[];
  formFields: FieldSize[];
};

export function captureActorReads(t: TestContext, fixture: ActivityFixture) {
  assert.equal(parseIdentitiesDoc(importDocument(fixture)).ok, true, "допустимый импорт персон и алиасов");
  const persons: Person[] = fixture.map((p) => ({ person_id: p.id, display: p.id, kind: "person", team: "", note: "" }));
  const aliases = fixture.flatMap((p) => p.aliases.map((a) => ({ person_id: p.id,
    alias_kind: a.kind, alias_value: a.value, valid_from: a.valid_from, valid_to_raw: a.valid_to,
    source: a.source, confidence: a.confidence, note: a.note })));
  const requests: ActorRequest[] = [];
  const rows = (data: object[]) => new Response(data.map((r) => JSON.stringify(r)).join("\n"));
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const headers = new Headers(init?.headers);
    let sql = String(init?.body ?? "");
    const formFields: FieldSize[] = [];
    if (headers.get("content-type")?.startsWith("multipart/form-data")) {
      const form = await new Response(init?.body, { headers }).formData();
      const query: string[] = [];
      for (const [name, value] of form) {
        assert.equal(typeof value, "string", "ожидается обычное поле формы");
        formFields.push({ name, bytes: Buffer.byteLength(String(value), "utf8") });
        if (name === "query") query.push(String(value));
      }
      sql = query.join("");
    }
    if (url.searchParams.has("query")) sql = url.searchParams.get("query") + "\n" + sql;
    // ClickHouse 24.8 HTMLForm::readQuery проверяет длину ДО URI::decode:
    // https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Server/HTTP/HTMLForm.cpp#L142-L160
    const urlFields = url.search.slice(1).split("&").filter(Boolean).map((part) => {
      const eq = part.indexOf("=");
      return { name: decodeURIComponent(eq < 0 ? part : part.slice(0, eq)),
        bytes: Buffer.byteLength(eq < 0 ? "" : part.slice(eq + 1), "utf8") };
    });
    requests.push({ sql, uriBytes: Buffer.byteLength(url.pathname + url.search, "utf8"), urlFields, formFields });
    if (/\bFROM identity_aliases\b/.test(sql)) return rows(aliases);
    if (/\bFROM identities\b/.test(sql)) return rows(persons);
    if (/\bFROM events\b/.test(sql)) return rows([]);
    if (/\bFROM incidents_current\b/.test(sql)) {
      const columns = [...sql.matchAll(/\bAS (i\d+)\b/g)];
      return rows(columns.length ? [Object.fromEntries(columns.map((m) => [m[1], 0]))] : []);
    }
    assert.fail(`неожиданный запрос: ${sql.slice(0, 100)}`);
  });
  return { requests, persons };
}

export function invalidEnvelopes(requests: ActorRequest[]) {
  return requests.flatMap((r, request) => [
    ...(r.uriBytes > HTTP_URI_MAX_BYTES ? [{ request, where: "URI", name: "", bytes: r.uriBytes }] : []),
    ...r.urlFields.filter((f) => f.bytes > HTTP_FIELD_MAX_BYTES).map((f) => ({ request, where: "URL field", ...f })),
    ...r.formFields.filter((f) => f.bytes > HTTP_FIELD_MAX_BYTES).map((f) => ({ request, where: "multipart field", ...f })),
  ]);
}
