// Справочник ATT&CK Enterprise для метки закрытия (attack-enterprise.json; генерирует
// scripts/attack-enterprise.py, та же копия — engine/internal/attack/enterprise.json).
// Тактика по умолчанию — из тегов attack.<tactic> правила; кандидаты техники —
// техники из тегов правила (attack.tNNNN[.NNN]), затем соседние в той же тактике,
// всего не больше ATTACK_MAX_CANDIDATES, плюс «другое».
import dictionary from "./attack-enterprise.json";

export const ATTACK_OTHER = "other";
export const ATTACK_MAX_CANDIDATES = 20;
export const ATTACK_VERSION: string = dictionary.version;

export type AttackTechnique = { id: string; name: string; tactics: string[] };

/** Тактики в порядке матрицы: shortname → название. */
export const ATTACK_TACTICS: Record<string, string> = Object.fromEntries(dictionary.tactics.map((t) => [t.shortname, t.name]));
const TECHNIQUES: AttackTechnique[] = dictionary.techniques;
const BY_ID = new Map(TECHNIQUES.map((t) => [t.id, t]));

export const isAttackTactic = (v: string): boolean => v === ATTACK_OTHER || Object.hasOwn(ATTACK_TACTICS, v);
export const isAttackTechnique = (v: string): boolean => v === ATTACK_OTHER || BY_ID.has(v);
export const attackTechnique = (id: string): AttackTechnique | undefined => BY_ID.get(id);

const parentOf = (id: string) => id.split(".")[0];

/** Тактики из тегов attack.<tactic> (credential_access → credential-access), что есть в справочнике. */
export function ruleTactics(tags: readonly string[]): string[] {
  const out: string[] = [];
  for (const tag of tags) {
    const m = /^attack\.([a-z][a-z_-]*)$/.exec(tag.trim().toLowerCase());
    const short = m?.[1].replaceAll("_", "-");
    if (short && Object.hasOwn(ATTACK_TACTICS, short) && !out.includes(short)) out.push(short);
  }
  return out;
}

/** Техники из тегов attack.tNNNN[.NNN], что есть в справочнике, в порядке тегов. */
export function ruleTechniques(tags: readonly string[]): string[] {
  const out: string[] = [];
  for (const tag of tags) {
    const m = /^attack\.(t\d{4}(?:\.\d{3})?)$/.exec(tag.trim().toLowerCase());
    const id = m?.[1].toUpperCase();
    if (id && BY_ID.has(id) && !out.includes(id)) out.push(id);
  }
  return out;
}

/** Тактика по умолчанию: первая из тегов правила; иначе — общая для всех техник из тегов, если она одна. */
export function defaultTactic(tags: readonly string[]): string {
  const [first] = ruleTactics(tags);
  if (first) return first;
  const techniques = ruleTechniques(tags).map((id) => BY_ID.get(id)!);
  if (!techniques.length) return "";
  const common = techniques.reduce<string[]>((acc, t) => acc.filter((x) => t.tactics.includes(x)), techniques[0].tactics);
  return common.length === 1 ? common[0] : "";
}

/**
 * Кандидаты техники для выбранной тактики, не больше ATTACK_MAX_CANDIDATES:
 * 1) техники из тегов правила; 2) родитель и подтехники того же родителя;
 * 3) остальные техники тактики по возрастанию ID (сначала техники, потом подтехники).
 * Шаги 2–3 — только в выбранной тактике; без тактики («другое» или пусто) —
 * в тактиках техник из тегов. «Другое» в список не входит — форма добавляет его сама.
 */
export function techniqueCandidates(tags: readonly string[], tactic: string): AttackTechnique[] {
  const tagged = ruleTechniques(tags);
  const scope = new Set(Object.hasOwn(ATTACK_TACTICS, tactic) ? [tactic] : tagged.flatMap((id) => BY_ID.get(id)!.tactics));
  const out: string[] = [];
  const add = (id: string) => {
    if (out.length < ATTACK_MAX_CANDIDATES && !out.includes(id)) out.push(id);
  };
  tagged.forEach(add);
  const inScope = (t: AttackTechnique) => t.tactics.some((x) => scope.has(x));
  for (const id of tagged) {
    const parent = parentOf(id);
    for (const t of TECHNIQUES) if ((t.id === parent || parentOf(t.id) === parent) && inScope(t)) add(t.id);
  }
  for (const t of TECHNIQUES) if (!t.id.includes(".") && inScope(t)) add(t.id);
  for (const t of TECHNIQUES) if (t.id.includes(".") && inScope(t)) add(t.id);
  return out.map((id) => BY_ID.get(id)!);
}

export type AttackFormOptions = {
  version: string;
  defaultTactic: string;
  /** Кандидаты техники для каждой тактики и для «другого»: ID и название. */
  candidates: Record<string, { id: string; name: string }[]>;
};

/** Варианты для формы закрытия: тактика по умолчанию и кандидаты по каждой тактике —
 *  считаются на сервере, в браузер весь справочник не уходит. */
export function attackFormOptions(tags: readonly string[]): AttackFormOptions {
  const candidates: AttackFormOptions["candidates"] = {};
  for (const tactic of [...Object.keys(ATTACK_TACTICS), ATTACK_OTHER]) {
    candidates[tactic] = techniqueCandidates(tags, tactic).map(({ id, name }) => ({ id, name }));
  }
  return { version: ATTACK_VERSION, defaultTactic: defaultTactic(tags), candidates };
}
