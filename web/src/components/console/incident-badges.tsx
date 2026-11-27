import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { INCIDENT_STATUSES } from "@/lib/shared/incidents";
import { incidentLevelLabel } from "@/lib/shared/labels";
import { LEVEL_TONE, STATUS_TONE, TONE_CLASS, TONE_OUTLINE_CLASS, TONE_SOLID_CLASS, toneFor } from "./tone";

/**
 * Уровень инцидента: критичный и высокий — заливкой (главный сигнал строки),
 * средний и низкий — контуром. Подпись — человеческое слово, шрифт sans.
 */
export function LevelBadge({ level, className }: { level: string; className?: string }) {
  const tone = toneFor(LEVEL_TONE, level);
  return <Badge variant="outline" data-tone={tone} className={cn("font-sans", TONE_SOLID_CLASS[tone] ?? TONE_CLASS[tone], className)}>{incidentLevelLabel(level)}</Badge>;
}

/** Статус инцидента: только контур — не путается с уровнем рядом в строке. */
export function StatusBadge({ status, className }: { status: string; className?: string }) {
  const label = INCIDENT_STATUSES[status as keyof typeof INCIDENT_STATUSES] ?? status;
  const tone = toneFor(STATUS_TONE, status);
  return <Badge variant="outline" data-tone={tone} className={cn("font-sans", TONE_OUTLINE_CLASS[tone], className)}>{label}</Badge>;
}
