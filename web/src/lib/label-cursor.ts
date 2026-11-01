import "server-only";

/** Позиция в выгрузке меток (GET /api/incidents/labels): (changed_at, incident_id,
 *  event_id) последней выданной строки — тот же ключ, что ORDER BY запроса.
 *  Одного changed_at мало: у меток бывает одна миллисекунда, и продолжение
 *  «с последнего времени» либо повторяет порцию, либо теряет строки. */
export type LabelCursor = { changedAt: string; incidentId: string; eventId: string };

const TS_RE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d{1,3})?$/;
const ID_RE = /^INC-\d{1,9}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Непрозрачный курсор для клиента: base64url от «changed_at|incident_id|event_id». */
export function encodeLabelCursor(row: { changed_at: string; incident_id: string; event_id: string }): string {
  return Buffer.from(`${row.changed_at}|${row.incident_id}|${row.event_id}`).toString("base64url");
}

/** null — курсор повреждён или подделан (400 в API, а не запрос с мусором). */
export function decodeLabelCursor(raw: string): LabelCursor | null {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(raw)) return null;
  const [changedAt = "", incidentId = "", eventId = "", ...rest] = Buffer.from(raw, "base64url").toString("utf8").split("|");
  if (rest.length || !TS_RE.test(changedAt) || !ID_RE.test(incidentId) || !UUID_RE.test(eventId)) return null;
  return { changedAt, incidentId, eventId };
}
