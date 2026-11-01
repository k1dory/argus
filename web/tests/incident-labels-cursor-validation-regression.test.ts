// PR #13: календарная проверка cursor должна быть не слабее проверки since.
import { test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { decodeLabelCursor, encodeLabelCursor } from "../src/lib/label-cursor";

const mocks = installNextMocks();
const auth = loadAuth();
/* eslint-disable @typescript-eslint/no-require-imports -- настоящий route после Next/auth mocks */
const { GET } = require("../src/app/api/incidents/labels/route") as { GET: (req: Request) => Promise<Response> };
/* eslint-enable @typescript-eslint/no-require-imports */

const row = {
  incident_id: "INC-4", event_id: "12345678-9abc-4def-8abc-123456789abc", changed_at: "2026-11-01 10:00:00.123",
};
const impossible = [
  "2026-02-30 10:00:00.123",
  "2026-02-29 10:00:00.123",
  "2026-13-01 10:00:00.123",
  "2026-00-01 10:00:00.123",
  "2026-11-00 10:00:00.123",
  "2026-11-01 24:00:00.123",
  "2026-11-01 10:60:00.123",
  "2026-11-01 10:00:60.123",
];

for (const changed_at of impossible) {
  test(`labels cursor: отклоняется несуществующее время ${changed_at}`, () => {
    // Реальный формат next_cursor; меняется только его календарное значение.
    const forged = encodeLabelCursor({ ...row, changed_at });
    assert.equal(decodeLabelCursor(forged), null, "синтаксически корректная base64url-строка ещё не является допустимой позицией");
  });
}

test("labels API: поддельная дата в cursor даёт 400 до обращения к хранилищу", async () => {
  await auth.createSession("sso:cursor-invalid-calendar", "viewer", true);
  let queries = 0;
  mocks.queries.incidentLabels = async () => { queries++; return []; };
  const cursor = encodeLabelCursor({ ...row, changed_at: impossible[0] });
  const response = await GET(new Request(`http://x/api/incidents/labels?${new URLSearchParams({ cursor })}`));
  assert.equal(response.status, 400, "повреждённый cursor — ошибка клиента, а не успешная выдача/ошибка ClickHouse");
  assert.equal(queries, 0, "невалидная граница не должна передаваться parseDateTime64BestEffort");
});

test("labels cursor: валидный високосный день, миллисекунды и event_id сохраняются", () => {
  for (const event_id of [row.event_id, "12345678-9abc-4def-8abc-123456789abd"]) {
    const changed_at = "2024-02-29 23:59:59.999";
    assert.deepEqual(decodeLabelCursor(encodeLabelCursor({ ...row, changed_at, event_id })), {
      changedAt: changed_at, incidentId: row.incident_id, eventId: event_id,
    }, "у меток одного инцидента одной миллисекунды сохраняется третий компонент порядка");
  }
});

test("labels API: since отвергает те же невозможные даты, сохраняя допустимое ISO UTC", async () => {
  let serial = 0;
  let queries = 0;
  mocks.queries.incidentLabels = async () => { queries++; return []; };
  for (const since of ["2026-02-30", "2026-02-29", "2026-11-01T24:00:00Z", "2026-11-01T10:00:00+03:00"]) {
    await auth.createSession(`sso:since-invalid-${++serial}`, "viewer", true);
    const response = await GET(new Request(`http://x/api/incidents/labels?${new URLSearchParams({ since })}`));
    assert.equal(response.status, 400, since);
  }
  assert.equal(queries, 0);
  for (const since of ["2024-02-29", "2026-11-01T10:00Z", "2026-11-01T10:00:00.123456789Z"]) {
    await auth.createSession(`sso:since-valid-${++serial}`, "viewer", true);
    const response = await GET(new Request(`http://x/api/incidents/labels?${new URLSearchParams({ since })}`));
    assert.equal(response.status, 200, since);
  }
  assert.equal(queries, 3);
});
