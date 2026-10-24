// Дочерний процесс triage-claim-ch.test.ts: отдельный Node-процесс, который
// занимает отметки вердиктов инцидентов и печатает победителей (JSON).
import { claimTriageVerdict } from "../src/lib/argus-queries";

async function main(): Promise<void> {
  const [prefix, count, session] = process.argv.slice(2);
  const out: Record<string, string> = {};
  await Promise.all(
    Array.from({ length: Number(count) }, (_, i) => `${prefix}${i}`).map(async (incidentId) => {
      out[incidentId] = await claimTriageVerdict({ incidentId, sessionId: session, actor: "triage-issuer" });
    }),
  );
  process.stdout.write(JSON.stringify(out));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
