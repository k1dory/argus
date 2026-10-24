import { toDate } from "./time";

/** Целевое время первичной реакции от создания инцидента (24/7, UTC). */
export const REACTION_SECONDS: Record<string, number> = {
  critical: 15 * 60,
  high: 60 * 60,
  medium: 4 * 60 * 60,
  low: 24 * 60 * 60,
};

export function reactionDeadline(createdAt: string, level: string): Date | null {
  const created = toDate(createdAt);
  if (!created) return null;
  return new Date(created.getTime() + (REACTION_SECONDS[level] ?? REACTION_SECONDS.low) * 1000);
}

export function reactionOverdue(createdAt: string, level: string, status: string, now = new Date()): boolean {
  const deadline = reactionDeadline(createdAt, level);
  return status === "new" && deadline !== null && deadline.getTime() < now.getTime();
}

/** null означает, что время первой реакции не зафиксировано в журнале. */
export function reactionLate(createdAt: string, level: string, firstResponseAt: string | null): boolean | null {
	const deadline = reactionDeadline(createdAt, level);
	const response = firstResponseAt ? toDate(firstResponseAt) : null;
	if (!deadline || !response) return null;
	return response.getTime() > deadline.getTime();
}
