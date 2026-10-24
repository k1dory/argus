import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { INCIDENT_STATUSES } from "@/lib/shared/incidents";
import { incidentLevelLabel } from "@/lib/shared/labels";
import { LEVEL_TONE, STATUS_TONE, TONE_CLASS, toneFor } from "./tone";

export function LevelBadge({ level }: { level: string }) {
  return <Badge variant="outline" className={cn("font-mono", TONE_CLASS[toneFor(LEVEL_TONE, level)])}>{incidentLevelLabel(level)}</Badge>;
}

export function StatusBadge({ status }: { status: string }) {
  const label = INCIDENT_STATUSES[status as keyof typeof INCIDENT_STATUSES] ?? status;
  return <Badge variant="outline" className={cn("font-mono", TONE_CLASS[toneFor(STATUS_TONE, status)])}>{label}</Badge>;
}
