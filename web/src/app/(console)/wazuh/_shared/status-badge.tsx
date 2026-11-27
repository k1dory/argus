import { Badge } from "@/components/ui/badge";
import { AGENT_STATUS_TONE, TONE_OUTLINE_CLASS, toneFor, type Tone } from "@/components/console/tone";
import { agentStatusLabel } from "@/lib/shared/labels";
import { cn } from "@/lib/utils";

/**
 * Бейдж статуса из словаря: подпись и тон — только из labels/tone, без сырых
 * значений API. Кандидат в общий <StatusBadge map value> (сейчас — локально).
 */
export function StatusBadge({ label, tone, className }: { label: string; tone: Tone; className?: string }) {
  return <Badge variant="outline" className={cn("whitespace-nowrap", TONE_OUTLINE_CLASS[tone], className)}>{label}</Badge>;
}

/** Статус агента Wazuh: AGENT_STATUS_LABELS + AGENT_STATUS_TONE. */
export function AgentStatusBadge({ status }: { status: string }) {
  return <StatusBadge label={agentStatusLabel(status)} tone={toneFor(AGENT_STATUS_TONE, status)} />;
}
